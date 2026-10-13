//! The per-subflow hold buffer of a checksummed connection (M4b spec G6, G7): a mapping's
//! octets wait here, by SSN, until the whole mapping has arrived and its DSS checksum verifies;
//! only then do they reach the connection level (`RecvAssembler`).
//!
//! Memory: a subflow holds at most `cap` octets (`recv_buffer + 65,535`) plus those of the
//! frontier mapping (at most 65,535), so `recv_buffer + 2 × 65,535` per subflow and
//! `SUBFLOW_CAP` times that per connection. Past `cap` other mappings' octets are refused at
//! the TCP level (the peer retransmits them); held octets are never evicted.
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
    /// Every octet, whatever was delivered already (coverage is not delivery, spec G7).
    Verified {
        dsn: u64,
        bytes: Vec<u8>,
        data_fin: bool,
    },
    // Task 5 (MP_FAIL) reads the fields.
    #[allow(dead_code)]
    Failed { dsn: u64, ssn: u32 },
}

struct Entry {
    map: HoldMap,
    /// Held runs by offset in the mapping: sorted, disjoint, never adjacent.
    pieces: Vec<(u32, Vec<u8>)>,
}

impl Entry {
    fn end(&self) -> u32 {
        self.map.ssn.wrapping_add(self.map.len)
    }
    /// Stores the octets of `data` (at mapping offset `off`) not held yet; returns how many.
    fn put(&mut self, off: u32, data: &[u8]) -> usize {
        let (lo, hi) = (off as usize, off as usize + data.len());
        let mut gaps = Vec::new();
        let mut at = lo;
        for (s, b) in &self.pieces {
            let (s, e) = (*s as usize, *s as usize + b.len());
            if s >= hi {
                break;
            }
            if s > at {
                gaps.push(at..s);
            }
            at = at.max(e);
        }
        if at < hi {
            gaps.push(at..hi);
        }
        let added = gaps.iter().map(Range::len).sum();
        for g in gaps {
            (self.pieces).push((g.start as u32, data[g.start - lo..g.end - lo].to_vec()));
        }
        self.pieces.sort_by_key(|p| p.0);
        let mut merged: Vec<(u32, Vec<u8>)> = Vec::with_capacity(self.pieces.len());
        for (s, b) in self.pieces.drain(..) {
            match merged.last_mut() {
                Some((ps, pb)) if *ps as usize + pb.len() == s as usize => pb.extend_from_slice(&b),
                _ => merged.push((s, b)),
            }
        }
        self.pieces = merged;
        added
    }
}

#[derive(Default)]
pub(crate) struct Hold {
    entries: Vec<Entry>,
    held: usize,
}

impl Hold {
    /// Registers a mapping. An equal repeat is a no-op; another mapping over the same SSNs is
    /// invalid (false), as a conflicting one is for `RxMaps::install`.
    pub fn install(&mut self, map: HoldMap) -> bool {
        for e in &self.entries {
            let off = map.ssn.wrapping_sub(e.map.ssn) as i32 as i64;
            if off < i64::from(e.map.len) && off + i64::from(map.len) > 0 {
                return e.map == map;
            }
        }
        self.entries.push(Entry {
            map,
            pieces: Vec::new(),
        });
        true
    }

    pub fn held(&self) -> usize {
        self.held
    }

    /// Takes the octets of `bytes` (from SSN `ssn`) that known mappings cover and returns the
    /// ranges accepted at the TCP level. `frontier` is the subflow's cumulative TCP receive
    /// point: octets below it arrived before. An octet at or past `right_edge` is refused, as
    /// `RecvAssembler::accept` refuses it; one below `recv.next` is kept for the checksum (spec
    /// G7). With `cap` octets held, only the mapping covering `frontier` is accepted further.
    pub fn insert(
        &mut self,
        ssn: u32,
        bytes: &[u8],
        frontier: u32,
        right_edge: u64,
        cap: usize,
    ) -> Vec<Range<usize>> {
        // A mapping wholly below the frontier and not complete lost octets that TCP already
        // took (unmapped, or a repeat of a mapping taken before): it can never complete.
        let held = &mut self.held;
        self.entries.retain(|e| {
            let live = e.end().wrapping_sub(frontier) as i32 > 0;
            if !live {
                *held -= e.pieces.iter().map(|p| p.1.len()).sum::<usize>();
            }
            live
        });
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
            if !covering(e, frontier) {
                k = k.min(cap.saturating_sub(self.held));
            }
            if k > 0 {
                self.held += e.put(off, &bytes[at..at + k]);
                accepted.push(at..at + k);
            }
            at += n;
        }
        accepted
    }

    /// Removes every mapping whose octets have all arrived, verified or failed.
    pub fn take_complete(&mut self) -> Vec<Complete> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.entries.len() {
            let e = &self.entries[i];
            if !matches!(e.pieces.as_slice(), [(0, b)] if b.len() == e.map.len as usize) {
                i += 1;
                continue;
            }
            let e = self.entries.remove(i);
            let (m, bytes) = (e.map, e.pieces.into_iter().next().unwrap().1);
            self.held -= bytes.len();
            let data_len = (m.len + u32::from(m.data_fin)) as u16;
            out.push(
                if dss_checksum_ok(m.dsn, m.ssn, data_len, &[&bytes], m.checksum) {
                    Complete::Verified {
                        dsn: m.dsn,
                        bytes,
                        data_fin: m.data_fin,
                    }
                } else {
                    Complete::Failed {
                        dsn: m.dsn,
                        ssn: m.ssn,
                    }
                },
            );
        }
        out
    }

    /// Empties the buffer: every held run with its SSN, in SSN order.
    // Task 4 replays these on fallback.
    #[allow(dead_code)]
    pub fn drain(&mut self) -> Vec<(u32, Vec<u8>)> {
        self.held = 0;
        let mut runs: Vec<(u32, Vec<u8>)> = (self.entries.drain(..))
            .flat_map(|e| {
                let ssn = e.map.ssn;
                (e.pieces.into_iter()).map(move |(off, b)| (ssn.wrapping_add(off), b))
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
        assert_eq!(h.insert(2001, &data[2000..], 1, EDGE, BIG), vec![0..1000]);
        assert_eq!(h.insert(1, &data[..1000], 1, EDGE, BIG), vec![0..1000]);
        assert!(h.take_complete().is_empty());
        assert_eq!(h.held(), 2000);
        assert_eq!(
            h.insert(1001, &data[1000..2000], 1001, EDGE, BIG),
            vec![0..1000]
        );
        let done = h.take_complete();
        assert_eq!(
            done,
            [Complete::Verified {
                dsn: 500,
                bytes: data,
                data_fin: false
            }]
        );
        assert!(h.take_complete().is_empty());
        assert_eq!(h.held(), 0);
    }

    #[test]
    fn hold_failed_on_bad_checksum() {
        let data = pattern(100);
        let mut h = Hold::default();
        h.install(map(7, 900, &data, false));
        let mut bad = data.clone();
        bad[40] ^= 1;
        h.insert(7, &bad, 7, EDGE, BIG);
        assert_eq!(h.take_complete(), [Complete::Failed { dsn: 900, ssn: 7 }]);
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
            h.insert(1, &sent, 1, EDGE, BIG);
            let want = if flip {
                Complete::Failed { dsn: 10, ssn: 1 }
            } else {
                Complete::Verified {
                    dsn: 10,
                    bytes: data.clone(),
                    data_fin: true,
                }
            };
            assert_eq!(h.take_complete(), [want]);
        }
    }

    #[test]
    fn hold_refuses_past_right_edge() {
        let data = pattern(100);
        let mut h = Hold::default();
        h.install(map(1, 1000, &data, false));
        // DSNs [1000, 1050) are inside the edge; [1050, 1100) are not.
        assert_eq!(h.insert(1, &data, 1, 1050, BIG), vec![0..50]);
        assert_eq!(h.held(), 50);
        // A mapping wholly below `recv.next` (say 5000, edge 6000) is still held in full.
        let mut h = Hold::default();
        h.install(map(1, 1000, &data, false));
        assert_eq!(h.insert(1, &data[..60], 1, 6000, BIG), vec![0..60]);
        assert_eq!(h.held(), 60);
        assert!(h.take_complete().is_empty());
    }

    #[test]
    fn hold_overlap_and_duplicate_segments() {
        let data = pattern(1000);
        let mut h = Hold::default();
        h.install(map(1, 0, &data, false));
        assert!(h.install(map(1, 0, &data, false)), "an equal repeat");
        h.insert(1, &data[..400], 1, EDGE, BIG);
        h.insert(601, &data[600..800], 401, EDGE, BIG);
        // A repeat of held octets, then one overlapping both held runs.
        assert_eq!(h.insert(601, &data[600..800], 401, EDGE, BIG), vec![0..200]);
        assert_eq!(h.held(), 600);
        h.insert(301, &data[300..700], 401, EDGE, BIG);
        assert_eq!(h.held(), 800);
        h.insert(801, &data[800..], 401, EDGE, BIG);
        assert_eq!(h.held(), 1000);
        let done = h.take_complete();
        assert_eq!(
            done,
            [Complete::Verified {
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
        assert_eq!(h.insert(a, &data[..65_534], a, EDGE, cap), vec![0..65_534]);
        // The frontier is A's last octet: B is not exempt past the cap.
        let mut accepted = 0;
        for chunk in (0..65_535).step_by(1460) {
            let end = (chunk + 1460).min(65_535);
            let got = h.insert(b + chunk as u32, &data[chunk..end], a + 65_534, EDGE, cap);
            accepted += got.iter().map(Range::len).sum::<usize>();
        }
        assert_eq!(accepted, cap - 65_534);
        assert_eq!(h.held(), cap);
        // A's last octet is the frontier mapping's: accepted, and A completes.
        let last = a + 65_534;
        assert_eq!(h.insert(last, &data[65_534..], last, EDGE, cap), vec![0..1]);
        assert_eq!(h.held(), cap + 1);
        let done = h.take_complete();
        assert!(matches!(&done[..], [Complete::Verified { dsn: 0, bytes, .. }] if *bytes == data));
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
                h.insert(s + chunk as u32, &data[chunk..end], 1, EDGE, cap);
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
        h.insert(101, &data[200..250], 0, EDGE, BIG);
        h.insert(u32::MAX - 99, &data[..50], u32::MAX - 99, EDGE, BIG);
        h.insert(u32::MAX - 9, &data[90..120], u32::MAX - 99, EDGE, BIG);
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
}
