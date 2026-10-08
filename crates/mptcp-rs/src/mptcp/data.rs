#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promotion_handles_reordering_and_full_wrap() {
        assert_eq!(promote32(2, 0xffff_fffe), 0x1_0000_0002);
        assert_eq!(promote32(0xffff_fffe, 0x1_0000_0002), 0xffff_fffe);
        assert_eq!(promote32(2, u64::MAX - 1), 2);
        assert_eq!(promote32(u32::MAX, 1), u64::MAX);
    }

    #[test]
    fn send_retention_requires_both_acks_and_all_mappings() {
        for data_first in [true, false] {
            let mut s = SendStore::new(u64::MAX - 1, 4);
            let mut m = TxMaps::new(u32::MAX - 1, 4);
            assert_eq!(s.write(b"abcd"), 4);
            assert!(s.assign(&mut m, u64::MAX - 1, 4));
            assert_eq!(
                m.peek_with(u32::MAX, 9, |b| b.to_vec()),
                Some(b"bcd".to_vec())
            );
            assert!(s.assign(&mut m, u64::MAX - 1, 4)); // reinjection, fresh SSNs
            if data_first {
                assert!(s.ack(2));
            } else {
                m.mark_acked(2);
            }
            assert_eq!(s.write(b"e"), 0);
            if data_first {
                m.mark_acked(2);
            } else {
                assert!(s.ack(2));
            }
            assert_eq!(s.write(b"e"), 0); // second mapping still owns bytes
            m.mark_acked(6);
            assert_eq!(s.write(b"e"), 1);
            assert!(!s.ack(99));
        }
    }

    #[test]
    fn receive_wrap_overlap_duplicate_and_window() {
        let mut r = RecvAssembler::new(u64::MAX - 2, 8, 4);
        assert_eq!(r.accept(0, b"def"), (Outcome::Stored, 3));
        assert_eq!(r.accept(u64::MAX - 2, b"abcde"), (Outcome::Stored, 5));
        assert_eq!(r.next, 3);
        assert_eq!(r.accept(u64::MAX - 2, b"abcdef"), (Outcome::Duplicate, 6));
        let mut out = [0; 8];
        assert_eq!(r.read(&mut out), 6);
        assert_eq!(&out[..6], b"abcdef");
        assert_eq!(r.accept(4, b"xyzz"), (Outcome::Stored, 1));
        assert_eq!(r.accept(5, b"x"), (Outcome::OutOfWindow, 0));
    }

    #[test]
    fn receive_pressure_holds_promised_data_and_delivers_it_on_read() {
        let mut r = RecvAssembler::new(100, 4, 2);
        r.right_edge = 110; // rounding or earlier advertisement can promise more than free memory
        assert_eq!(r.accept(106, b"xy"), (Outcome::Stored, 2));
        assert_eq!(r.accept(104, b"zz"), (Outcome::Stored, 2));
        assert_eq!(r.accept(102, b"cd"), (Outcome::Stored, 2));
        assert_eq!(r.accept(100, b"abcd"), (Outcome::Stored, 4));
        assert_eq!(r.next, 104); // DATA_ACK stops at the memory edge
        assert_eq!(r.accept(104, b"ef"), (Outcome::Duplicate, 2));
        assert!(!r.window_update_due(0, 536));
        let mut out = [0; 4];
        assert_eq!(r.read(&mut out), 4);
        assert_eq!(&out, b"abcd");
        assert_eq!(r.next, 108);
        assert!(r.window_update_due(0, 536)); // the new DATA_ACK goes out at once
        r.window_sent(r.window_offer(0, 536), 0);
        assert!(!r.window_update_due(0, 536));
        assert_eq!(r.read(&mut out), 4);
        assert_eq!(&out, b"zzxy");
    }

    #[test]
    fn mapping_equivalence_conflict_and_ssn_wrap() {
        let mut maps = RxMaps::new(4);
        assert!(maps.install(u32::MAX - 1, u64::MAX - 1, 4));
        assert!(maps.install(u32::MAX, u64::MAX, 2));
        assert_eq!(maps.translate(0), Some((0, 2)));
        assert!(!maps.install(0, 9, 2));
        assert!(maps.install(2, 2, 2));
    }
}

use crate::tcp::SendBuf;
use std::collections::VecDeque;
use std::sync::{Arc, Weak};

pub(crate) fn promote32(value: u32, head: u64) -> u64 {
    head.wrapping_add_signed(value.wrapping_sub(head as u32) as i32 as i64)
}

struct Chunk {
    dsn: u64,
    bytes: Arc<Vec<u8>>,
    start: usize,
    end: usize,
}
impl Chunk {
    fn len(&self) -> usize {
        self.end - self.start
    }
}

pub(crate) struct SendStore {
    pub una: u64,
    pub next: u64,
    pub end: u64,
    chunks: VecDeque<Chunk>,
    allocations: Vec<(Weak<Vec<u8>>, usize)>,
    cap: usize,
}
impl SendStore {
    pub fn new(head: u64, cap: usize) -> Self {
        Self {
            una: head,
            next: head,
            end: head,
            chunks: VecDeque::new(),
            allocations: Vec::new(),
            cap,
        }
    }
    pub fn write(&mut self, data: &[u8]) -> usize {
        self.allocations.retain(|(p, _)| p.strong_count() > 0);
        let used: usize = self.allocations.iter().map(|(_, n)| n).sum();
        let n = data.len().min(self.cap.saturating_sub(used));
        if n > 0 {
            let bytes: Arc<Vec<u8>> = Arc::new(data[..n].to_vec());
            self.allocations.push((Arc::downgrade(&bytes), n));
            self.chunks.push_back(Chunk {
                dsn: self.end,
                bytes,
                start: 0,
                end: n,
            });
            self.end = self.end.wrapping_add(n as u64);
        }
        n
    }
    /// Stored octets from `dsn` to the end. Chunks are contiguous in DSN space, so a mapping
    /// may span application writes: a write boundary is not a mapping or segment boundary.
    pub fn run_len(&self, dsn: u64) -> usize {
        let off = dsn.wrapping_sub(self.una);
        let len = self.end.wrapping_sub(self.una);
        if off < len { (len - off) as usize } else { 0 }
    }
    /// Assigns one contiguous stored run; repeated DSNs use fresh SSNs for reinjection.
    pub fn assign(&mut self, maps: &mut TxMaps, dsn: u64, len: usize) -> bool {
        if len == 0 || len > u16::MAX as usize || maps.is_full() {
            return false;
        }
        // New assignments are contiguous; reinjections cover previously assigned DSNs only.
        if dsn != self.next && (self.next.wrapping_sub(dsn) as i64) < len as i64 {
            return false;
        }
        if len > self.run_len(dsn) {
            return false;
        }
        let end = dsn.wrapping_add(len as u64);
        let mut pieces = VecDeque::new();
        let mut at = dsn;
        for c in &self.chunks {
            let off = at.wrapping_sub(c.dsn);
            if off >= c.len() as u64 {
                continue;
            }
            let off = off as usize;
            let n = (c.len() - off).min(end.wrapping_sub(at) as usize);
            pieces.push_back(Chunk {
                dsn: at,
                bytes: c.bytes.clone(),
                start: c.start + off,
                end: c.start + off + n,
            });
            at = at.wrapping_add(n as u64);
            if at == end {
                break;
            }
        }
        maps.maps.push_back(TxMap {
            ssn: maps.end,
            mapping: crate::wire::mptcp::Mapping {
                dsn: crate::wire::mptcp::Dsn::Dsn64(dsn),
                ssn: maps.end,
                data_len: len as u16,
                checksum: None,
            },
            reinjected: dsn != self.next,
            data_fin: false,
            dsn,
            len,
            pieces,
        });
        maps.end = maps.end.wrapping_add(len as u32);
        if dsn == self.next {
            self.next = self.next.wrapping_add(len as u64);
        }
        true
    }
    pub fn ack(&mut self, ack: u64) -> bool {
        if (ack.wrapping_sub(self.una) as i64) < 0 || (self.next.wrapping_sub(ack) as i64) < 0 {
            return false;
        }
        self.una = ack;
        while let Some(c) = self.chunks.front_mut() {
            let n = ack.wrapping_sub(c.dsn) as i64;
            if n <= 0 {
                break;
            }
            if n as usize >= c.len() {
                self.chunks.pop_front();
            } else {
                c.start += n as usize;
                c.dsn = ack;
                break;
            }
        }
        true
    }
}
struct TxMap {
    ssn: u32,
    mapping: crate::wire::mptcp::Mapping,
    reinjected: bool,
    data_fin: bool,
    /// First unacknowledged DSN and octet count; `pieces` hold exactly these octets.
    dsn: u64,
    len: usize,
    pieces: VecDeque<Chunk>,
}
impl TxMap {
    fn covers(&self, ssn: u32) -> bool {
        (ssn.wrapping_sub(self.ssn) as usize) < self.len
    }
}
pub(crate) struct TxMaps {
    maps: VecDeque<TxMap>,
    end: u32,
    cap: usize,
}
impl TxMaps {
    pub fn acked_dsn(&self, ack: u32) -> Option<u64> {
        self.maps
            .iter()
            .filter_map(|m| {
                let n = ack.wrapping_sub(m.ssn) as i32;
                (n > 0).then(|| m.dsn.wrapping_add((n as usize).min(m.len) as u64))
            })
            .next_back()
    }
    /// End DSN of an un-subflow-ACKed mapping covering `dsn`, if any.
    pub fn covering_end(&self, dsn: u64) -> Option<u64> {
        self.maps
            .iter()
            .find(|m| dsn.wrapping_sub(m.dsn) < m.len as u64)
            .map(|m| m.dsn.wrapping_add(m.len as u64))
    }
    /// `(dsn, len)` of every un-subflow-ACKed mapping, in SSN order.
    pub fn ranges(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.maps.iter().map(|m| (m.dsn, m.len as u64))
    }
    /// Drops every mapping (the subflow is torn down); `assigned_end` is kept.
    pub fn clear(&mut self) {
        self.maps.clear();
    }
    /// Every mapping slot is taken: `SendStore::assign` fails until a TCP ACK frees one.
    pub fn is_full(&self) -> bool {
        self.maps.len() >= self.cap
    }
    /// Prefix without a live TCP copy, clipped at the next active mapping.
    pub fn uncovered_len(&self, dsn: u64, max: usize) -> usize {
        self.maps.iter().fold(max, |len, m| {
            let off = m.dsn.wrapping_sub(dsn) as i64;
            if off <= 0 && off + m.len as i64 > 0 {
                0
            } else if off > 0 {
                len.min(off as usize)
            } else {
                len
            }
        })
    }

    pub fn attach_fin(&mut self) {
        if let Some(m) = self.maps.back_mut() {
            m.data_fin = true;
            m.mapping.data_len += 1;
        }
    }
    pub fn data_fin(&self, ssn: u32) -> bool {
        self.maps.iter().any(|m| m.data_fin && m.covers(ssn))
    }
    pub fn mapping(&self, ssn: u32) -> Option<crate::wire::mptcp::Mapping> {
        self.maps.iter().find(|m| m.covers(ssn)).map(|m| m.mapping)
    }
    pub fn new(end: u32, cap: usize) -> Self {
        Self {
            maps: VecDeque::new(),
            end,
            cap,
        }
    }
}
impl SendBuf for TxMaps {
    /// Octets from `ssn` to the end of its mapping: a segment never spans two mappings.
    fn segment_limit(&self, ssn: u32) -> usize {
        self.maps
            .iter()
            .find(|m| m.covers(ssn))
            .map_or(0, |m| m.len - ssn.wrapping_sub(m.ssn) as usize)
    }
    fn is_reinjection(&self, ssn: u32) -> bool {
        self.maps.iter().any(|m| m.reinjected && m.covers(ssn))
    }
    /// The run from `ssn` to the end of its stored piece; a segment may take several runs.
    fn peek_with<R>(&self, ssn: u32, max: usize, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        let m = self.maps.iter().find(|m| m.covers(ssn))?;
        let mut off = ssn.wrapping_sub(m.ssn) as usize;
        let c = m.pieces.iter().find(|c| {
            let inside = off < c.len();
            if !inside {
                off -= c.len();
            }
            inside
        })?;
        let start = c.start + off;
        Some(f(&c.bytes[start..c.end.min(start.saturating_add(max))]))
    }
    fn assigned_end(&self) -> u32 {
        self.end
    }
    fn mark_acked(&mut self, ack: u32) {
        while let Some(m) = self.maps.front_mut() {
            let n = ack.wrapping_sub(m.ssn) as i32;
            if n <= 0 {
                break;
            }
            if n as usize >= m.len {
                self.maps.pop_front();
            } else {
                m.ssn = ack;
                m.dsn = m.dsn.wrapping_add(n as u64);
                m.len -= n as usize;
                let mut n = n as usize;
                while let Some(c) = m.pieces.front_mut() {
                    if n < c.len() {
                        c.start += n;
                        c.dsn = c.dsn.wrapping_add(n as u64);
                        break;
                    }
                    n -= c.len();
                    m.pieces.pop_front();
                }
                break;
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Stored,
    Duplicate,
    Discarded,
    OutOfWindow,
}
struct Piece {
    dsn: u64,
    bytes: VecDeque<u8>,
}
/// DSN reassembly. Every octet inside the advertised window `[next, right_edge)` is stored
/// (only the range cap can refuse it), but at most `cap` octets are delivered in order: `next`
/// (the DATA_ACK) stops at the memory edge `base + cap`, where `base` is the first unread DSN,
/// and held octets above it are delivered as reads make room.
///
/// Bound: stored octets lie in `[base, right_edge)`, so memory above `cap` is at most the
/// advertised overshoot `right_edge − (base + cap)`, at most `right_edge − next`. That
/// window never exceeds `ceil(cap / 2^scale) · 2^scale`: a fresh offer is at most
/// `floor(cap / 2^scale)` units, a re-advertisement rounds an older window up from a later
/// `next` (RFC 8684 must-not-shrink), and `next` only moves forward. So memory stays below
/// `2·cap + 2^scale`. The rounding creeps the edge by less than 2^scale per DATA_ACK that
/// moved `next`, and only until `next` reaches the memory edge: with the application not
/// reading and full segments of L octets the overshoot is about `cap · (−L mod 2^scale) / L`
/// (2% at 4 MiB, scale 7, L 1436); approaching the worst case needs segments shorter than
/// 2^scale.
pub(crate) struct RecvAssembler {
    pub next: u64,
    pub right_edge: u64,
    ready: VecDeque<u8>,
    pieces: Vec<Piece>,
    cap: usize,
    range_cap: usize,
    fin: Option<u64>,
    /// A read moved `next` over held octets; the new DATA_ACK is not advertised yet.
    read_advanced: bool,
}
impl RecvAssembler {
    pub fn new(head: u64, cap: usize, range_cap: usize) -> Self {
        Self {
            next: head,
            right_edge: head.wrapping_add(cap as u64),
            ready: VecDeque::new(),
            pieces: Vec::new(),
            cap,
            range_cap,
            fin: None,
            read_advanced: false,
        }
    }
    pub fn has_fin(&self) -> bool {
        self.fin.is_some()
    }
    pub fn eof(&self) -> bool {
        self.fin.is_some_and(|fin| self.next == fin.wrapping_add(1))
    }
    pub fn finish(&mut self, fin: u64) -> bool {
        if let Some(old) = self.fin {
            return old == fin;
        }
        if (fin.wrapping_sub(self.next) as i64) < 0
            || (fin.wrapping_sub(self.right_edge) as i64) >= 0
            || self
                .pieces
                .iter()
                .any(|p| p.dsn.wrapping_add(p.bytes.len() as u64).wrapping_sub(fin) as i64 > 0)
        {
            return false;
        }
        self.fin = Some(fin);
        self.advance_fin();
        true
    }
    fn advance_fin(&mut self) {
        if self.fin == Some(self.next) {
            self.next = self.next.wrapping_add(1);
        }
    }
    pub fn window_offer(&self, scale: u8, mss: u16) -> u16 {
        let remaining = self.right_edge.wrapping_sub(self.next) as i64;
        let free = self.free() as i64;
        let threshold = (self.cap / 2).min(usize::from(mss)) as i64;
        let floor = if free - remaining >= threshold {
            (free as u64 >> scale).min(65535)
        } else {
            0
        };
        floor
            .max((remaining.max(0) as u64).div_ceil(1 << scale))
            .min(65535) as u16
    }
    pub fn window_sent(&mut self, field: u16, scale: u8) {
        self.read_advanced = false;
        let edge = self.next.wrapping_add(u64::from(field) << scale);
        if edge.wrapping_sub(self.right_edge) as i64 > 0 {
            self.right_edge = edge;
        }
    }
    pub fn window_update_due(&self, scale: u8, mss: u16) -> bool {
        let remaining = self.right_edge.wrapping_sub(self.next) as i64;
        let offer = i64::from(self.window_offer(scale, mss)) << scale;
        // Held octets the peer has sent are DATA_ACKed at once: nothing else would announce it.
        self.read_advanced
            || self.free() as i64 - remaining >= (self.cap / 2).min(usize::from(mss)) as i64
                && offer > remaining
    }
    pub fn free(&self) -> usize {
        self.cap.saturating_sub(
            self.ready.len() + self.pieces.iter().map(|p| p.bytes.len()).sum::<usize>(),
        )
    }
    pub fn has_unread(&self) -> bool {
        !self.ready.is_empty()
    }
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.ready.len());
        for (a, b) in out.iter_mut().zip(self.ready.drain(..n)) {
            *a = b;
        }
        if self.deliver() {
            self.read_advanced = true;
            self.advance_fin();
        }
        n
    }
    /// Moves the piece at `next` into `ready`, up to the memory edge. Returns whether `next` moved.
    fn deliver(&mut self) -> bool {
        let before = self.next;
        if self.pieces.first().is_some_and(|p| p.dsn == self.next) {
            let room = self.cap - self.ready.len();
            let p = &mut self.pieces[0];
            let n = p.bytes.len().min(room);
            if n == p.bytes.len() {
                let mut p = self.pieces.remove(0);
                self.ready.append(&mut p.bytes);
            } else {
                self.ready.extend(p.bytes.drain(..n));
                p.dsn = p.dsn.wrapping_add(n as u64);
            }
            self.next = self.next.wrapping_add(n as u64);
        }
        self.next != before
    }
    /// Returns the outcome and TCP-acknowledgeable prefix, including a duplicate prefix.
    pub fn accept(&mut self, dsn: u64, data: &[u8]) -> (Outcome, usize) {
        let len = self.fin.map_or(data.len(), |fin| {
            (fin.wrapping_sub(dsn) as i64).max(0).min(data.len() as i64) as usize
        });
        let result = self.accept_inner(dsn, &data[..len], false);
        self.advance_fin();
        result
    }
    pub fn accept_tcp(&mut self, dsn: u64, data: &[u8]) -> usize {
        let before = self.next;
        let off = dsn.wrapping_sub(before) as i64;
        let (outcome, n) = self.accept_inner(dsn, data, true);
        match outcome {
            Outcome::Discarded => (-off).max(0).min(data.len() as i64) as usize,
            Outcome::Stored if off <= 0 => self.next.wrapping_sub(dsn).min(n as u64) as usize,
            _ => n,
        }
    }
    fn accept_inner(&mut self, dsn: u64, data: &[u8], tcp: bool) -> (Outcome, usize) {
        let off = dsn.wrapping_sub(self.next) as i64;
        // Peer-controlled offsets may sit at i64::MAX. Only comparisons and window
        // clipping use this end, so saturation preserves the out-of-window result.
        let end = off.saturating_add(data.len() as i64);
        if end <= 0 {
            return (Outcome::Duplicate, data.len());
        }
        let edge = self.right_edge.wrapping_sub(self.next) as i64;
        let hi = end.min(edge);
        let lo = off.max(0);
        if hi <= lo {
            return (
                Outcome::OutOfWindow,
                (-off).max(0).min(data.len() as i64) as usize,
            );
        }
        let acknowledged = (hi - off) as usize;
        // MPTCP: in-window data always fits memory (see the bound above). Fallback keeps the
        // TCP rule: what does not fit `cap` is not TCP-acknowledged, so the peer retransmits it.
        let hi = if lo == 0 && tcp {
            hi.min(self.free() as i64)
        } else {
            hi
        };
        if hi <= lo {
            return (Outcome::Discarded, acknowledged);
        }
        // ponytail: scan at most range_cap pieces; use a range tree if that cap grows.
        let gaps = {
            let mut gaps = Vec::new();
            let mut at = lo;
            for p in &self.pieces {
                let start = p.dsn.wrapping_sub(self.next) as i64;
                let stop = start + p.bytes.len() as i64;
                if start >= hi {
                    break;
                }
                if stop <= at {
                    continue;
                }
                if start > at {
                    gaps.push(at..start);
                }
                at = at.max(stop);
            }
            if at < hi {
                gaps.push(at..hi);
            }
            let needed: usize = gaps.iter().map(|g| (g.end - g.start) as usize).sum();
            if needed == 0 {
                return (Outcome::Duplicate, acknowledged);
            }
            let mut ranges: Vec<_> = self
                .pieces
                .iter()
                .map(|p| {
                    let s = p.dsn.wrapping_sub(self.next) as i64;
                    s..s + p.bytes.len() as i64
                })
                .collect();
            ranges.push(lo..hi);
            ranges.sort_by_key(|r| r.start);
            let mut count = 0;
            let mut last = -1;
            for r in ranges {
                if r.start > last && r.start != 0 {
                    count += 1;
                }
                last = last.max(r.end);
            }
            // The range at `next` is not counted, so the MPTCP head is never refused.
            if count > self.range_cap || tcp && needed > self.free() {
                return (Outcome::Discarded, acknowledged);
            }
            gaps
        };
        for g in gaps {
            self.pieces.push(Piece {
                dsn: self.next.wrapping_add(g.start as u64),
                bytes: VecDeque::from(
                    data[(g.start - off) as usize..(g.end - off) as usize].to_vec(),
                ),
            });
        }
        self.pieces.sort_by_key(|p| p.dsn.wrapping_sub(self.next));
        let mut i = 1;
        while i < self.pieces.len() {
            if self.pieces[i - 1]
                .dsn
                .wrapping_add(self.pieces[i - 1].bytes.len() as u64)
                == self.pieces[i].dsn
            {
                let mut p = self.pieces.remove(i);
                let prev = &mut self.pieces[i - 1].bytes;
                if prev.len() >= p.bytes.len() {
                    prev.append(&mut p.bytes);
                } else {
                    while let Some(byte) = prev.pop_back() {
                        p.bytes.push_front(byte);
                    }
                    *prev = p.bytes;
                }
            } else {
                i += 1;
            }
        }
        self.deliver();
        (Outcome::Stored, acknowledged)
    }
}

#[derive(Clone, Copy)]
struct RxMap {
    ssn: u32,
    dsn: u64,
    len: u32,
}
pub(crate) struct RxMaps {
    maps: Vec<RxMap>,
    cap: usize,
}
impl RxMaps {
    pub fn new(cap: usize) -> Self {
        Self {
            maps: Vec::new(),
            cap,
        }
    }
    pub fn install(&mut self, ssn: u32, dsn: u64, len: u32) -> bool {
        if len == 0 {
            return false;
        }
        for m in &self.maps {
            let off = ssn.wrapping_sub(m.ssn) as i32 as i64;
            if off < i64::from(m.len) && off + i64::from(len) > 0 {
                if m.dsn.wrapping_add_signed(off) != dsn {
                    return false;
                }
                if off >= 0 && off + i64::from(len) <= i64::from(m.len) {
                    return true;
                }
            }
        }
        if self.maps.len() == self.cap {
            return false;
        }
        self.maps.push(RxMap { ssn, dsn, len });
        true
    }
    pub fn translate(&self, ssn: u32) -> Option<(u64, usize)> {
        self.maps.iter().find_map(|m| {
            let off = ssn.wrapping_sub(m.ssn);
            (off < m.len).then(|| (m.dsn.wrapping_add(u64::from(off)), (m.len - off) as usize))
        })
    }
    pub fn unmapped_run(&self, ssn: u32, max: usize) -> usize {
        self.maps
            .iter()
            .map(|m| m.ssn.wrapping_sub(ssn) as usize)
            .filter(|&n| n > 0)
            .min()
            .unwrap_or(max)
            .min(max)
    }
    pub fn ack(&mut self, ssn: u32) {
        // Keep the newest completed mapping for retransmitted MPC/DSS equivalence checks.
        let last = self
            .maps
            .iter()
            .rposition(|m| ssn.wrapping_sub(m.ssn.wrapping_add(m.len)) as i32 >= 0);
        let mut index = 0;
        self.maps.retain(|m| {
            let keep =
                Some(index) == last || (ssn.wrapping_sub(m.ssn.wrapping_add(m.len)) as i32) < 0;
            index += 1;
            keep
        });
    }
}

#[cfg(test)]
mod pressure_tests {
    use super::*;
    #[test]
    fn head_is_accepted_when_the_range_cap_is_full() {
        let mut r = RecvAssembler::new(0, 8, 1);
        r.accept(6, b"x");
        assert_eq!(r.accept(0, b"a"), (Outcome::Stored, 1));
        assert_eq!(r.next, 1);
    }
    #[test]
    fn head_is_delivered_up_to_the_memory_edge_and_the_rest_held() {
        let mut r = RecvAssembler::new(0, 4, 4);
        r.right_edge = 20;
        r.accept(0, b"ab");
        assert_eq!(r.accept(2, b"cdef"), (Outcome::Stored, 4));
        assert_eq!(r.next, 4);
        let mut out = [0; 4];
        assert_eq!(r.read(&mut out), 4);
        assert_eq!(&out, b"abcd");
    }
    #[test]
    fn head_fills_holes_beyond_memory_without_eviction() {
        let mut r = RecvAssembler::new(0, 8, 4);
        r.right_edge = 20;
        r.accept(4, b"ef");
        r.accept(10, b"uvwxyz");
        assert_eq!(r.accept(0, b"abcdefg"), (Outcome::Stored, 7));
        assert_eq!(r.next, 7);
    }
}

#[cfg(test)]
mod bounds_tests {
    use super::*;
    #[test]
    fn mappings_bound_length_count_and_new_assignment_order() {
        let mut s = SendStore::new(100, 70000);
        s.write(&vec![0; 70000]);
        let mut maps = TxMaps::new(1, 1);
        assert!(!s.assign(&mut maps, 100, 65536));
        assert!(!s.assign(&mut maps, 101, 1));
        assert!(s.assign(&mut maps, 100, 10));
        assert!(!s.assign(&mut maps, 110, 1));
        maps.mark_acked(11);
        assert!(s.assign(&mut maps, 105, 5));
    }
}

#[cfg(test)]
mod signed_boundary_tests {
    use super::*;

    #[test]
    fn peer_dsn_near_signed_boundary_cannot_overflow_acceptance() {
        for head in [0, u64::MAX - 3] {
            for (offset, expected) in [
                (i64::MAX, (Outcome::OutOfWindow, 0)),
                (i64::MAX - 1, (Outcome::OutOfWindow, 0)),
                (i64::MIN, (Outcome::Duplicate, 2)),
                (i64::MIN + 1, (Outcome::Duplicate, 2)),
            ] {
                let mut recv = RecvAssembler::new(head, 8, 4);
                assert_eq!(
                    recv.accept(head.wrapping_add_signed(offset), b"ab"),
                    expected
                );
                let single = if offset > 0 {
                    (Outcome::OutOfWindow, 0)
                } else {
                    (Outcome::Duplicate, 1)
                };
                assert_eq!(recv.accept(head.wrapping_add_signed(offset), b"a"), single);
                assert_eq!(recv.next, head);
                assert_eq!(recv.free(), 8);
            }
        }
    }
}

#[cfg(test)]
mod overshoot_tests {
    use super::*;

    /// A long flood with segments of 1..=3·2^scale octets (shorter than 2^scale is the worst
    /// case: each DATA_ACK then creeps the rounded edge) and rare small reads.
    #[test]
    fn memory_above_cap_stays_within_the_advertised_overshoot() {
        for scale in [1u8, 3, 7] {
            let (cap, unit) = (70_000usize, 1u64 << scale);
            let bound = (cap as u64).div_ceil(unit) * unit;
            let mut r = RecvAssembler::new(1000, cap, 64);
            let (mut snd, mut read_to, mut seed, mut worst) = (1000u64, 1000u64, 1u64, 0);
            for i in 0..300_000u64 {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let len = ((seed >> 33) % (3 * unit) + 1).min(r.right_edge - snd);
                if len > 0 {
                    let data: Vec<u8> = (snd..snd + len).map(|d| d as u8).collect();
                    assert_eq!(r.accept(snd, &data), (Outcome::Stored, len as usize));
                    snd += len;
                }
                let field = r.window_offer(scale, 1460);
                r.window_sent(field, scale);
                let stored = r.ready.len() + r.pieces.iter().map(|p| p.bytes.len()).sum::<usize>();
                let base = r.next - r.ready.len() as u64;
                assert!(stored as u64 <= r.right_edge - base);
                assert!((stored.saturating_sub(cap) as u64) <= bound);
                worst = worst.max(stored.saturating_sub(cap));
                if i % 5000 == 4999 || len == 0 {
                    let mut out = vec![0; if len == 0 { 4096 } else { 3 }];
                    let n = r.read(&mut out);
                    assert!(out[..n].iter().zip(read_to..).all(|(&b, d)| b == d as u8));
                    read_to += n as u64;
                }
            }
            assert!(worst > 0, "scale {scale}: the flood never passed the cap");
        }
    }
}
