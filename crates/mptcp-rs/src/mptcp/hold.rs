//! The per-subflow hold buffer of a checksummed connection (M4b spec G6, G7): a mapping's
//! octets wait here, by SSN, until the whole mapping has arrived and its DSS checksum verifies;
//! only then do they reach the connection level (`RecvAssembler`).
//!
//! Memory: a subflow holds at most `cap` octets (`recv_buffer + 65,535`) plus those of two
//! exempt frontier mappings (at most 65,535 each), so `recv_buffer + 3 × 65,535` per subflow
//! and `SUBFLOW_CAP` times that per connection. Two, as an exemption granted on a free range
//! slot can be overtaken by another subflow, leaving that mapping held, refused, while the next
//! frontier mapping is exempt. Past `cap` other mappings' octets are refused at the TCP level
//! (the peer retransmits them); held octets are never evicted, short of the reset of a subflow
//! whose frontier can never be taken. Held runs are bounded too (`PIECE_CAP`).
use std::collections::VecDeque;
use std::ops::Range;

use crate::wire::mptcp::dss_checksum_ok;

/// A DSS mapping as its checksum covers it. `len` is the payload length; the pseudo-header's
/// Data-Level Length is `len + data_fin` (RFC 8684 L1402–1430; Linux `validate_data_csum`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HoldMap {
    pub ssn: u32,
    pub dsn: u64,
    pub len: u32,
    pub data_fin: bool,
    pub checksum: u16,
}

/// A mapping whose octets have all arrived.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Complete {
    /// Taken by the caller's `deliver`, every octet whatever was delivered already (coverage
    /// is not delivery, spec G7).
    Verified { dsn: u64, len: u32, data_fin: bool },
    /// Reported once; its octets stay held (`drain`) until the caller drains them (M4b spec
    /// G11: kept for the replay of a single-subflow fallback, else discarded with the reset).
    Failed { dsn: u64, ssn: u32 },
}

/// Held runs per subflow, as the TCB's out-of-order ranges (`MAX_OOO_RANGES`) and
/// `RecvAssembler`'s `range_cap` bound theirs: past it, a run that would start a new disjoint
/// run is refused at the TCP level unless it starts at the frontier.
const PIECE_CAP: usize = 64;

/// Held mappings per subflow, as `RxMaps` bounds its own: one more is invalid and resets the
/// subflow. Only a peer re-declaring parts of a mapping it already sent reaches it.
const ENTRY_CAP: usize = 1024;

struct Entry {
    map: HoldMap,
    /// Held runs by offset in the mapping: sorted, disjoint, never adjacent.
    pieces: Vec<(u32, VecDeque<u8>)>,
    /// Complete with a checksum that failed (`Complete::Failed`, reported once).
    failed: bool,
    /// Complete and verified, but `deliver` refused it: held until it takes it.
    verified: bool,
}

impl Entry {
    fn end(&self) -> u32 {
        self.map.ssn.wrapping_add(self.map.len)
    }
    /// Stores the octets of `data` (at mapping offset `off`) not held yet: returns how many,
    /// and the change in the number of runs. A run touching no held one is refused (`None`)
    /// unless `may_split`.
    fn put(&mut self, off: u32, data: &[u8], may_split: bool) -> Option<(usize, isize)> {
        let (lo, hi) = (off as usize, off as usize + data.len());
        let span = |p: &(u32, VecDeque<u8>)| (p.0 as usize, p.0 as usize + p.1.len());
        // The runs that overlap or touch [lo, hi].
        let i = self.pieces.partition_point(|p| span(p).1 < lo);
        let j = self.pieces.partition_point(|p| span(p).0 <= hi);
        if i == j {
            if !may_split {
                return None;
            }
            self.pieces.insert(i, (off, data.iter().copied().collect()));
            return Some((data.len(), 1));
        }
        // Merge into the largest touched run, copying only what lies outside it.
        let b = (i..j).max_by_key(|&k| self.pieces[k].1.len()).unwrap();
        let (s_b, e_b) = span(&self.pieces[b]);
        let start = lo.min(span(&self.pieces[i]).0);
        let stop = hi.max(span(&self.pieces[j - 1]).1);
        // Between touched runs, [at, to) lies inside [lo, hi].
        let gap = |at: usize, to: usize| {
            if at < to {
                &data[at - lo..to - lo]
            } else {
                &[][..]
            }
        };
        let mut left = Vec::with_capacity(s_b - start);
        let mut at = start;
        for p in &self.pieces[i..b] {
            left.extend_from_slice(gap(at, p.0 as usize));
            left.extend(p.1.iter());
            at = span(p).1;
        }
        left.extend_from_slice(gap(at, s_b));
        let mut right = Vec::with_capacity(stop - e_b);
        at = e_b;
        for p in &self.pieces[b + 1..j] {
            right.extend_from_slice(gap(at, p.0 as usize));
            right.extend(p.1.iter());
            at = span(p).1;
        }
        right.extend_from_slice(gap(at, stop));
        let had: usize = self.pieces[i..j].iter().map(|p| p.1.len()).sum();
        let mut run = std::mem::take(&mut self.pieces[b].1);
        for &x in left.iter().rev() {
            run.push_front(x);
        }
        run.extend(right);
        self.pieces.splice(i..j, [(start as u32, run)]);
        Some((stop - start - had, 1 - (j - i) as isize))
    }
}

#[derive(Default)]
pub(crate) struct Hold {
    entries: Vec<Entry>,
    held: usize,
    /// Held runs, over all entries (at most `PIECE_CAP` plus those at the frontier).
    pieces: usize,
    /// The frontier of the last `prune`: TCP took every octet below it.
    frontier: Option<u32>,
    /// Entries `verified`: complete and verified, refused by `deliver` so far.
    refused: usize,
    /// The last `insert` refused the octet at the frontier for the cap alone, its mapping not
    /// exempt and no failed mapping held: nothing would ever take it (`blocked`).
    blocked: bool,
}

impl Hold {
    /// Registers a mapping. An equal repeat is a no-op; another mapping over the same SSNs is
    /// invalid (false), as a conflicting one is for `RxMaps::install`, and so is one past
    /// `ENTRY_CAP`. One wholly below the frontier is not kept: it could never complete.
    pub fn install(&mut self, map: HoldMap) -> bool {
        for e in &mut self.entries {
            let off = map.ssn.wrapping_sub(e.map.ssn) as i32 as i64;
            if off < i64::from(e.map.len) && off + i64::from(map.len) > 0 {
                // Linux folds a late DATA_FIN into the final mapping it already declared
                // (`mptcp_write_data_fin`), though a sender MUST NOT change a declared mapping
                // (RFC 8684 L1369–1371). As Linux's receiver (`get_mapping_status`), we take it
                // as the same mapping; its DATA_FIN, with the checksum covering it, is kept.
                if (e.map.ssn, e.map.dsn, e.map.len) == (map.ssn, map.dsn, map.len)
                    && e.map.data_fin != map.data_fin
                {
                    if map.data_fin {
                        e.map = map;
                        self.refused -= usize::from(std::mem::take(&mut e.verified));
                    }
                    return true;
                }
                return e.map == map;
            }
        }
        let end = map.ssn.wrapping_add(map.len);
        if self
            .frontier
            .is_some_and(|f| end.wrapping_sub(f) as i32 <= 0)
        {
            return true;
        }
        if self.entries.len() == ENTRY_CAP {
            return false;
        }
        self.entries.push(Entry {
            map,
            pieces: Vec::new(),
            failed: false,
            verified: false,
        });
        true
    }

    pub fn held(&self) -> usize {
        self.held
    }

    /// The last `insert` refused the frontier octet at a full hold, its mapping not exempt and
    /// no failed one held: the subflow can make no progress (M4b spec G7).
    pub fn blocked(&self) -> bool {
        self.blocked
    }

    /// Verified mappings `deliver` refused, held until it takes them.
    pub fn refused(&self) -> usize {
        self.refused
    }

    /// Every held mapping, failed ones included.
    #[cfg(test)]
    pub fn maps(&self) -> impl Iterator<Item = &HoldMap> {
        self.entries.iter().map(|e| &e.map)
    }

    /// Takes the octets of `bytes` (from SSN `ssn`) that known mappings cover and returns the
    /// ranges accepted at the TCP level. `frontier` is the subflow's cumulative TCP receive
    /// point: octets below it arrived before. An octet at or past `right_edge` is refused, as
    /// `RecvAssembler::accept` refuses it; one below `recv.next` is kept for the checksum (spec
    /// G7). With `cap` octets held, only the mapping covering `frontier` is accepted further,
    /// and only if `would_take` (`RecvAssembler::would_take`) says its completion would be
    /// taken now, and no failed mapping is held; with `PIECE_CAP` runs held, only runs touching
    /// a held one or starting at `frontier`.
    pub fn insert(
        &mut self,
        ssn: u32,
        bytes: &[u8],
        frontier: u32,
        right_edge: u64,
        cap: usize,
        would_take: impl Fn(u64, u32) -> bool,
    ) -> Vec<Range<usize>> {
        self.prune(frontier);
        // The frontier mapping is exempt only if its completion would leave the hold: no
        // failed mapping is held (MP_FAIL waits, spec G11), and the assembler would take it
        // now. Otherwise each new frontier could add a complete mapping that stays held (G7).
        let failed = self.entries.iter().any(|e| e.failed);
        self.blocked = false;
        let mut accepted = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let pos = ssn.wrapping_add(at as u32);
            let rest = bytes.len() - at;
            let behind = frontier.wrapping_sub(pos) as i32;
            if behind > 0 {
                at += (behind as usize).min(rest);
                continue;
            }
            let covering = |e: &Entry, p: u32| p.wrapping_sub(e.map.ssn) < e.map.len;
            let Some(e) = self.entries.iter_mut().find(|e| covering(e, pos)) else {
                let next = (self.entries.iter())
                    .map(|e| e.map.ssn.wrapping_sub(pos) as usize)
                    .min()
                    .unwrap_or(rest);
                at += next.min(rest);
                continue;
            };
            let off = pos.wrapping_sub(e.map.ssn);
            let n = rest.min((e.map.len - off) as usize);
            let dsn = e.map.dsn.wrapping_add(u64::from(off));
            let mut k = (right_edge.wrapping_sub(dsn) as i64).clamp(0, n as i64) as usize;
            let exempt = !failed && covering(e, frontier) && would_take(e.map.dsn, e.map.len);
            if !exempt {
                let room = cap.saturating_sub(self.held);
                self.blocked |= pos == frontier && !failed && k > 0 && room == 0;
                k = k.min(room);
            }
            let may_split = self.pieces < PIECE_CAP || pos == frontier;
            if k > 0 {
                if let Some((added, runs)) = e.put(off, &bytes[at..at + k], may_split) {
                    self.held += added;
                    self.pieces = self.pieces.wrapping_add_signed(runs);
                    accepted.push(at..at + k);
                }
            }
            at += n;
        }
        accepted
    }

    /// Drops every mapping wholly below `frontier` that is not failed, also as the receipt
    /// advances with no mapped octet, so stale mappings never pile up (spec G7). The only
    /// exception to "held octets are never dropped": such a mapping can never complete, as
    /// TCP already took the octets it lacks (unmapped, or it is a repeat of one taken before).
    pub fn prune(&mut self, frontier: u32) {
        self.frontier = Some(frontier);
        let (held, pieces) = (&mut self.held, &mut self.pieces);
        self.entries.retain(|e| {
            let live = e.failed || e.verified || e.end().wrapping_sub(frontier) as i32 > 0;
            if !live {
                *held -= e.pieces.iter().map(|p| p.1.len()).sum::<usize>();
                *pieces -= e.pieces.len();
            }
            live
        });
    }

    /// Hands every mapping whose octets have all arrived and verify to `deliver` (its DSN and
    /// octets) and takes it once `deliver` does; one it refuses stays held, verified, and is
    /// offered again on the next call (its octets are TCP-ACKed: spec G7, G15). Reports, once,
    /// each mapping that fails and keeps it.
    pub fn take_complete(&mut self, mut deliver: impl FnMut(u64, &[u8]) -> bool) -> Vec<Complete> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.entries.len() {
            let e = &mut self.entries[i];
            let m = e.map;
            let Some(b) = (e.pieces.first_mut())
                .filter(|p| !e.failed && p.0 == 0 && p.1.len() == m.len as usize)
            else {
                i += 1;
                continue;
            };
            let data_len = (m.len + u32::from(m.data_fin)) as u16;
            let (head, tail) = b.1.as_slices();
            if !e.verified && !dss_checksum_ok(m.dsn, m.ssn, data_len, &[head, tail], m.checksum) {
                e.failed = true;
                out.push(Complete::Failed {
                    dsn: m.dsn,
                    ssn: m.ssn,
                });
                i += 1;
                continue;
            }
            if !deliver(m.dsn, b.1.make_contiguous()) {
                self.refused += usize::from(!std::mem::replace(&mut e.verified, true));
                i += 1;
                continue;
            }
            self.refused -= usize::from(e.verified);
            self.entries.remove(i);
            self.held -= m.len as usize;
            self.pieces -= 1;
            out.push(Complete::Verified {
                dsn: m.dsn,
                len: m.len,
                data_fin: m.data_fin,
            });
        }
        out
    }

    /// Empties the buffer: every held run with its SSN, in SSN order.
    pub fn drain(&mut self) -> Vec<(u32, Vec<u8>)> {
        self.held = 0;
        self.pieces = 0;
        self.refused = 0;
        let mut runs: Vec<(u32, Vec<u8>)> = (self.entries.drain(..))
            .flat_map(|e| {
                let ssn = e.map.ssn;
                (e.pieces.into_iter()).map(move |(off, b)| (ssn.wrapping_add(off), Vec::from(b)))
            })
            .collect();
        let first = runs.first().map_or(0, |r| r.0);
        // Runs lie within 2^31 of one another, so offsets from any one of them order them.
        let lowest = (runs.iter())
            .map(|r| r.0)
            .min_by_key(|s| s.wrapping_sub(first) as i32)
            .unwrap_or(0);
        runs.sort_by_key(|r| r.0.wrapping_sub(lowest));
        runs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::mptcp::dss_checksum;

    const BIG: usize = 1 << 30;
    /// An offered edge far past every DSN the tests use.
    const EDGE: u64 = 1 << 40;

    /// An assembler that would take any completion.
    fn any(_: u64, _: u32) -> bool {
        true
    }

    /// `Complete` with the octets `take_complete` delivered.
    #[derive(Debug, PartialEq)]
    enum Done {
        Verified {
            dsn: u64,
            bytes: Vec<u8>,
            data_fin: bool,
        },
        Failed {
            dsn: u64,
            ssn: u32,
        },
    }

    fn take(h: &mut Hold) -> Vec<Done> {
        let mut got = Vec::new();
        let out = h.take_complete(|_, b| {
            got.push(b.to_vec());
            true
        });
        let mut got = got.into_iter();
        (out.into_iter())
            .map(|c| match c {
                Complete::Verified { dsn, data_fin, .. } => Done::Verified {
                    dsn,
                    bytes: got.next().unwrap(),
                    data_fin,
                },
                Complete::Failed { dsn, ssn } => Done::Failed { dsn, ssn },
            })
            .collect()
    }

    fn map(ssn: u32, dsn: u64, data: &[u8], data_fin: bool) -> HoldMap {
        let len = data.len() as u32;
        let data_len = (len + u32::from(data_fin)) as u16;
        HoldMap {
            ssn,
            dsn,
            len,
            data_fin,
            checksum: dss_checksum(dsn, ssn, data_len, &[data]),
        }
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 13 + i / 256) as u8).collect()
    }

    #[test]
    fn hold_completes_out_of_order() {
        let data = pattern(3000);
        let mut h = Hold::default();
        assert!(h.install(map(1, 500, &data, false)));
        assert_eq!(
            h.insert(2001, &data[2000..], 1, EDGE, BIG, any),
            vec![0..1000]
        );
        assert_eq!(h.insert(1, &data[..1000], 1, EDGE, BIG, any), vec![0..1000]);
        assert!(take(&mut h).is_empty());
        assert_eq!(h.held(), 2000);
        assert_eq!(
            h.insert(1001, &data[1000..2000], 1001, EDGE, BIG, any),
            vec![0..1000]
        );
        let done = take(&mut h);
        assert_eq!(
            done,
            [Done::Verified {
                dsn: 500,
                bytes: data,
                data_fin: false
            }]
        );
        assert!(take(&mut h).is_empty());
        assert_eq!(h.held(), 0);
    }

    #[test]
    fn hold_failed_on_bad_checksum() {
        let data = pattern(100);
        let mut h = Hold::default();
        h.install(map(7, 900, &data, false));
        let mut bad = data.clone();
        bad[40] ^= 1;
        h.insert(7, &bad, 7, EDGE, BIG, any);
        assert_eq!(take(&mut h), [Done::Failed { dsn: 900, ssn: 7 }]);
        // Kept, reported once, and not pruned below the frontier (spec G11, G15).
        assert_eq!(h.held(), 100);
        assert!(take(&mut h).is_empty());
        h.insert(107, b"", 107, EDGE, BIG, any);
        assert_eq!(h.drain(), [(7, bad)]);
        assert_eq!(h.held(), 0);
    }

    #[test]
    fn hold_data_fin_folded() {
        let data = pattern(50);
        for flip in [false, true] {
            let mut h = Hold::default();
            let m = map(1, 10, &data, true);
            assert_eq!(m.checksum, dss_checksum(10, 1, 51, &[&data]));
            h.install(m);
            let mut sent = data.clone();
            sent[0] ^= u8::from(flip);
            h.insert(1, &sent, 1, EDGE, BIG, any);
            let want = if flip {
                Done::Failed { dsn: 10, ssn: 1 }
            } else {
                Done::Verified {
                    dsn: 10,
                    bytes: data.clone(),
                    data_fin: true,
                }
            };
            assert_eq!(take(&mut h), [want]);
        }
    }

    /// A repeat of a held mapping with the same SSN, DSN and length that folds in a DATA_FIN
    /// (Linux's `mptcp_write_data_fin` on a declared mapping) is the same mapping, in either
    /// order: it verifies with the DATA_FIN. Any other change is a conflict.
    #[test]
    fn hold_late_data_fin_fold_is_the_same_mapping() {
        let data = pattern(1783);
        let (plain, folded) = (map(1, 10, &data, false), map(1, 10, &data, true));
        for order in [[plain, folded], [folded, plain]] {
            let mut h = Hold::default();
            assert!(h.install(order[0]));
            h.insert(1, &data[..1436], 1, EDGE, BIG, any);
            assert!(h.install(order[1]));
            h.insert(1437, &data[1436..], 1437, EDGE, BIG, any);
            let want = Done::Verified {
                dsn: 10,
                bytes: data.clone(),
                data_fin: true,
            };
            assert_eq!(take(&mut h), [want]);
        }
        for other in [
            HoldMap {
                len: 1782,
                ..folded
            },
            HoldMap { dsn: 11, ..plain },
            HoldMap {
                checksum: plain.checksum ^ 1,
                ..plain
            },
        ] {
            let mut h = Hold::default();
            assert!(h.install(plain));
            assert!(!h.install(other), "{other:?}");
        }
    }

    #[test]
    fn hold_refuses_past_right_edge() {
        let data = pattern(100);
        let mut h = Hold::default();
        h.install(map(1, 1000, &data, false));
        // DSNs [1000, 1050) are inside the edge; [1050, 1100) are not.
        assert_eq!(h.insert(1, &data, 1, 1050, BIG, any), vec![0..50]);
        assert_eq!(h.held(), 50);
        // A mapping wholly below `recv.next` (say 5000, edge 6000) is still held in full.
        let mut h = Hold::default();
        h.install(map(1, 1000, &data, false));
        assert_eq!(h.insert(1, &data[..60], 1, 6000, BIG, any), vec![0..60]);
        assert_eq!(h.held(), 60);
        assert!(take(&mut h).is_empty());
    }

    #[test]
    fn hold_overlap_and_duplicate_segments() {
        let data = pattern(1000);
        let mut h = Hold::default();
        h.install(map(1, 0, &data, false));
        assert!(h.install(map(1, 0, &data, false)), "an equal repeat");
        h.insert(1, &data[..400], 1, EDGE, BIG, any);
        h.insert(601, &data[600..800], 401, EDGE, BIG, any);
        // A repeat of held octets, then one overlapping both held runs.
        assert_eq!(
            h.insert(601, &data[600..800], 401, EDGE, BIG, any),
            vec![0..200]
        );
        assert_eq!(h.held(), 600);
        h.insert(301, &data[300..700], 401, EDGE, BIG, any);
        assert_eq!(h.held(), 800);
        h.insert(801, &data[800..], 401, EDGE, BIG, any);
        assert_eq!(h.held(), 1000);
        let done = take(&mut h);
        assert_eq!(
            done,
            [Done::Verified {
                dsn: 0,
                bytes: data,
                data_fin: false
            }]
        );
    }

    /// Spec §7, the reinjection counterexample: B repeats A's DSNs at fresh SSNs while A waits
    /// for its last octet.
    #[test]
    fn hold_cap_refuses_non_frontier_keeps_frontier() {
        let cap = 4096 + 65_535;
        let data = pattern(65_535);
        let mut h = Hold::default();
        let (a, b) = (1u32, 1 + 65_535);
        h.install(map(a, 0, &data, false));
        h.install(map(b, 0, &data, false));
        assert_eq!(
            h.insert(a, &data[..65_534], a, EDGE, cap, any),
            vec![0..65_534]
        );
        // The frontier is A's last octet: B is not exempt past the cap.
        let mut accepted = 0;
        for chunk in (0..65_535).step_by(1460) {
            let end = (chunk + 1460).min(65_535);
            let got = h.insert(
                b + chunk as u32,
                &data[chunk..end],
                a + 65_534,
                EDGE,
                cap,
                any,
            );
            accepted += got.iter().map(Range::len).sum::<usize>();
        }
        assert_eq!(accepted, cap - 65_534);
        assert_eq!(h.held(), cap);
        // A's last octet is the frontier mapping's: accepted, and A completes.
        let last = a + 65_534;
        assert_eq!(
            h.insert(last, &data[65_534..], last, EDGE, cap, any),
            vec![0..1]
        );
        assert_eq!(h.held(), cap + 1);
        let done = take(&mut h);
        assert!(matches!(&done[..], [Done::Verified { dsn: 0, bytes, .. }] if *bytes == data));
        // B's held octets are all still there.
        assert_eq!(h.held(), cap - 65_534);
    }

    /// Three copies of one DSN range at non-overlapping SSNs arrive in descending SSN order,
    /// each missing its last octet.
    #[test]
    fn hold_cap_descending_ssn_bound() {
        let cap = 4096 + 65_535;
        let data = pattern(65_535);
        let mut h = Hold::default();
        let ssns = [1u32, 1 + 65_535, 1 + 2 * 65_535];
        for &s in &ssns {
            h.install(map(s, 0, &data, false));
        }
        for &s in ssns.iter().rev() {
            for chunk in (0..65_534).step_by(1460) {
                let end = (chunk + 1460).min(65_534);
                h.insert(s + chunk as u32, &data[chunk..end], 1, EDGE, cap, any);
                assert!(h.held() <= 4096 + 2 * 65_535, "{}", h.held());
            }
        }
        assert!(h.held() > cap, "the frontier mapping is exempt");
    }

    #[test]
    fn hold_drain_gives_ssn_ordered_runs() {
        let data = pattern(300);
        let mut h = Hold::default();
        h.install(map(u32::MAX - 99, 0, &data[..200], false));
        h.install(map(101, 200, &data[200..], false));
        h.insert(101, &data[200..250], 0, EDGE, BIG, any);
        h.insert(u32::MAX - 99, &data[..50], u32::MAX - 99, EDGE, BIG, any);
        h.insert(u32::MAX - 9, &data[90..120], u32::MAX - 99, EDGE, BIG, any);
        let runs = h.drain();
        assert_eq!(
            runs,
            [
                (u32::MAX - 99, data[..50].to_vec()),
                (u32::MAX - 9, data[90..120].to_vec()),
                (101, data[200..250].to_vec()),
            ]
        );
        assert_eq!(h.held(), 0);
    }

    /// Runs past `PIECE_CAP` that would start a new disjoint run are refused; a run touching a
    /// held one, or starting at the frontier, is still taken.
    #[test]
    fn hold_piece_cap_refuses_new_runs() {
        let data = pattern(1000);
        let mut h = Hold::default();
        h.install(map(1, 0, &data, false));
        // One octet at every other offset from 2: disjoint runs.
        let mut taken = 0;
        for off in (2..400).step_by(2) {
            let got = h.insert(1 + off as u32, &data[off..off + 1], 1, EDGE, BIG, any);
            taken += got.len();
        }
        assert_eq!(
            (taken, h.held(), h.pieces),
            (PIECE_CAP, PIECE_CAP, PIECE_CAP)
        );
        // Past the cap: a new disjoint run is refused; one touching a held run is taken.
        assert!(
            h.insert(1 + 500, &data[500..501], 1, EDGE, BIG, any)
                .is_empty()
        );
        assert_eq!(h.insert(1 + 3, &data[3..4], 1, EDGE, BIG, any), vec![0..1]);
        assert_eq!(h.pieces, PIECE_CAP - 1, "offsets 2..5 merged");
        // The run at the frontier is exempt.
        assert_eq!(h.insert(1, &data[..1], 1, EDGE, BIG, any), vec![0..1]);
        // Past the cap, a run far ahead is still refused; filling on from the frontier, each
        // run touching the last, completes the mapping.
        assert!(
            h.insert(1 + 999, &data[999..], 2, EDGE, BIG, any)
                .is_empty()
        );
        for off in 1..1000 {
            let got = h.insert(
                1 + off as u32,
                &data[off..off + 1],
                1 + off as u32,
                EDGE,
                BIG,
                any,
            );
            assert_eq!(got, vec![0..1]);
        }
        let done = take(&mut h);
        assert!(matches!(&done[..], [Done::Verified { bytes, .. }] if *bytes == data));
        assert_eq!((h.held(), h.pieces), (0, 0));
    }

    /// A mapping taken, then repeated with its DSS option (a stale re-install): nothing stays
    /// held once the frontier passes it, whether its octets were behind the frontier or held
    /// out of order above it.
    #[test]
    fn hold_stale_reinstall_is_pruned() {
        let a = pattern(100);
        let b = pattern(200);
        let mut h = Hold::default();
        // In order: B taken, then its last segment repeated behind the frontier.
        h.install(map(1, 0, &b, false));
        h.insert(1, &b, 1, EDGE, BIG, any);
        assert_eq!(take(&mut h).len(), 1);
        assert!(h.install(map(1, 0, &b, false)));
        h.insert(151, &b[150..], 201, EDGE, BIG, any);
        assert_eq!(h.held(), 0);
        assert!(h.entries.is_empty());
        // Out of order: B (SSN 101) taken above a hole at A (SSN 1), then B's last segment
        // repeated with its option: held again until the frontier passes B.
        let mut h = Hold::default();
        h.install(map(1, 0, &a, false));
        h.install(map(101, 100, &b, false));
        h.insert(101, &b, 1, EDGE, BIG, any);
        assert_eq!(take(&mut h).len(), 1);
        assert!(h.install(map(101, 100, &b, false)));
        h.insert(251, &b[150..], 1, EDGE, BIG, any);
        assert_eq!(h.held(), 50);
        h.insert(1, &a, 1, EDGE, BIG, any);
        assert_eq!(take(&mut h).len(), 1);
        h.insert(301, &[], 301, EDGE, BIG, any);
        assert_eq!((h.held(), h.pieces), (0, 0));
    }
}
