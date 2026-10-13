//! Hook traits through which the `Tcb` reaches the send and receive buffers (spec §3), and
//! `PlainHooks`, their plain-TCP implementation with real buffers.

use std::collections::{BTreeMap, VecDeque};

use super::tcb::ConnectConfig;

/// Why an ACK-only segment goes out (M3 spec §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckPurpose {
    /// TCP or the protocol needed an ACK anyway.
    Ordinary,
    /// Only to carry a protocol signal (`Tcb::request_signal_ack`).
    SignalOnly,
}

/// Send-side data source. Relative SSN: the first data octet is 1 (spec §5.3).
pub trait SendBuf {
    /// Calls `f` with the contiguous run of buffered bytes starting at `rel_ssn`, at most `max`
    /// long. The run may be shorter than `max` and than what is buffered (it ends at an internal
    /// buffer boundary). `None` if no byte at `rel_ssn` is buffered.
    fn peek_with<R>(&self, rel_ssn: u32, max: usize, f: impl FnOnce(&[u8]) -> R) -> Option<R>;
    /// Limit one segment to a protocol mapping; ordinary TCP may span buffer runs.
    fn segment_limit(&self, _ssn: u32) -> usize {
        usize::MAX
    }
    /// Reinjected bytes are retransmissions for Nagle/SWS purposes.
    fn is_reinjection(&self, _ssn: u32) -> bool {
        false
    }
    /// Pending connection bytes, used by sender SWS before assignment.
    fn unassigned_len(&self) -> usize {
        0
    }
    /// Application data exists beyond what is assigned to this `Tcb`, whatever any window
    /// admits (the app-limited check, BBRv3 spec §1.6). Plain TCP assigns every written octet.
    fn more_app_data(&self) -> bool {
        false
    }
    /// Relative SSN one past the last assigned octet.
    fn assigned_end(&self) -> u32;
    /// Releases every octet below `rel_ssn_una`.
    fn mark_acked(&mut self, rel_ssn_una: u32);
}

/// Receive-side sink. Plain TCP drops duplicates and trims to available memory before
/// `accept_payload`. MPTCP uses `receive_data` and tracks TCP receipts separately.
pub trait SegmentHooks {
    /// Called only after TCP accepts the segment, before handing over its payload.
    fn on_valid_segment(&mut self, _seg: &crate::wire::packet::Segment<'_>) {}

    /// MPTCP delegates payload acceptance to its connection-level DSN window.
    fn delegates_data(&self) -> bool {
        false
    }
    /// Connection control signals must pass the TCP sequence window even when
    /// ordinary payload acceptance is delegated to a connection sequence space.
    fn requires_tcp_sequence_check(&self, _seg: &crate::wire::packet::Segment<'_>) -> bool {
        false
    }
    /// Accepted byte ranges in this payload, independently of retained payload memory.
    fn receive_data(
        &mut self,
        _ssn: u32,
        _tcp_ack: u32,
        _data: &[u8],
    ) -> Vec<std::ops::Range<usize>> {
        Vec::new()
    }
    fn receipt_advanced(&mut self, _ssn: u32) {}
    fn reset_requested(&self) -> bool {
        false
    }
    /// The options carried by the RST that `reset_requested` makes due (a multiple of 4
    /// octets, at most 16).
    fn reset_option(&self) -> Option<Vec<u8>> {
        None
    }
    /// An acceptable RST, SYN-SENT included, before the TCB is torn down.
    fn on_reset(&mut self, _seg: &crate::wire::packet::Segment<'_>) {}

    /// Protocol options first; return a word-aligned length, using NOP padding.
    /// The remaining option space is available for TCP SACK blocks.
    fn options_for(&mut self, _flags: crate::wire::packet::TcpFlags, _out: &mut [u8]) -> usize {
        0
    }

    /// Signals for an ACK-only segment, after `options_for`'s options and before SACK blocks:
    /// at most `room` octets into `out`. Called only for an ACK about to go out, never for a
    /// data segment, probe or RST; nothing is consumed until `ack_emitted`.
    fn ack_signals(&mut self, _purpose: AckPurpose, _room: usize, _out: &mut [u8]) -> usize {
        0
    }
    /// The ACK the last `ack_signals` filled went out.
    fn ack_emitted(&mut self) {}

    /// Reserved data layout, including padding (may exceed the initial wire layout).
    fn data_option_len(&self) -> usize {
        0
    }
    fn data_options_for(&mut self, _ssn: u32, out: &mut [u8]) -> usize {
        self.options_for(crate::wire::packet::TcpFlags::ACK, out)
    }
    /// Connection receive-window override and commit, called only for transmitted segments.
    fn window_offer(&self, _scale: u8, _mss: u16) -> Option<u16> {
        None
    }
    fn window_sent(&mut self, _field: u16, _scale: u8) {}
    fn window_update_due(&self, _scale: u8, _mss: u16) -> bool {
        false
    }
    fn duplicate_ack_allowed(&self, _seg: &crate::wire::packet::Segment<'_>) -> bool {
        true
    }

    /// New octets starting at `rel_ssn` (the first data octet is 1). Each octet is handed over
    /// once, so the pieces held out of order tile the sequence space: a piece that extends the
    /// in-order data ends where the next held piece starts, if it touches one.
    fn accept_payload(&mut self, rel_ssn: u32, data: &[u8]);
    /// Free receive space in octets, before window scaling.
    fn recv_window(&self) -> u32;
}

pub trait Hooks: SendBuf + SegmentHooks {}
impl<T: SendBuf + SegmentHooks> Hooks for T {}

/// Plain TCP: one contiguous send buffer, one in-order receive buffer and the out-of-order
/// pieces waiting for it.
pub struct PlainHooks {
    send: VecDeque<u8>,
    /// Relative SSN of `send[0]`.
    send_una: u32,
    send_buffer: usize,
    recv: VecDeque<u8>,
    /// Relative SSN one past the last in-order octet stored.
    recv_end: u32,
    /// Out-of-order pieces by relative SSN, and their total length.
    ooo: BTreeMap<u32, VecDeque<u8>>,
    ooo_len: usize,
    recv_buffer: usize,
}

impl PlainHooks {
    pub fn new(cfg: &ConnectConfig) -> Self {
        Self {
            send: VecDeque::new(),
            send_una: 1,
            send_buffer: cfg.send_buffer as usize,
            recv: VecDeque::new(),
            recv_end: 1,
            ooo: BTreeMap::new(),
            ooo_len: 0,
            recv_buffer: cfg.recv_buffer as usize,
        }
    }

    /// Queues as much of `data` as the send buffer has room for; returns the count queued.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let n = data
            .len()
            .min(self.send_buffer.saturating_sub(self.send.len()));
        self.send.extend(&data[..n]);
        n
    }

    #[cfg(test)]
    fn ooo_pieces(&self) -> usize {
        self.ooo.len()
    }

    /// Whether received in-order bytes are waiting to be read.
    pub fn has_unread(&self) -> bool {
        !self.recv.is_empty()
    }

    /// Moves received in-order bytes into `buf`; returns the count moved.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.recv.len());
        for (dst, src) in buf.iter_mut().zip(self.recv.drain(..n)) {
            *dst = src;
        }
        n
    }
}

impl SendBuf for PlainHooks {
    fn peek_with<R>(&self, rel_ssn: u32, max: usize, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        // Below `send_una` wraps to a huge offset and is rejected too.
        let off = rel_ssn.wrapping_sub(self.send_una) as usize;
        if off >= self.send.len() {
            return None;
        }
        let (a, b) = self.send.as_slices();
        let run = if off < a.len() {
            &a[off..]
        } else {
            &b[off - a.len()..]
        };
        Some(f(&run[..run.len().min(max)]))
    }

    fn assigned_end(&self) -> u32 {
        self.send_una.wrapping_add(self.send.len() as u32)
    }

    fn mark_acked(&mut self, rel_ssn_una: u32) {
        let d = rel_ssn_una.wrapping_sub(self.send_una) as i32;
        if d <= 0 {
            return;
        }
        let n = (d as usize).min(self.send.len());
        self.send.drain(..n);
        self.send_una = self.send_una.wrapping_add(n as u32);
    }
}

impl SegmentHooks for PlainHooks {
    fn accept_payload(&mut self, rel_ssn: u32, data: &[u8]) {
        if rel_ssn != self.recv_end {
            self.ooo_len += data.len();
            // Merge into touching neighbours so the entry count follows the Tcb's receipt ranges,
            // not the number of segments the peer sent. The smaller of the two neighbours is
            // copied into the larger (a deque takes pieces at both ends), so every octet is
            // copied O(log n) times, not once per later segment.
            let end = rel_ssn.wrapping_add(data.len() as u32);
            let prev = self
                .ooo
                .range(..rel_ssn)
                .next_back()
                .filter(|(k, v)| k.wrapping_add(v.len() as u32) == rel_ssn)
                .map(|(k, _)| *k)
                .and_then(|k| self.ooo.remove(&k).map(|v| (k, v)));
            let next = self.ooo.remove(&end);
            let (key, piece) = match (prev, next) {
                (None, None) => (rel_ssn, VecDeque::from(data.to_vec())),
                (Some((k, mut p)), None) => {
                    p.extend(data);
                    (k, p)
                }
                (None, Some(mut n)) => {
                    for &b in data.iter().rev() {
                        n.push_front(b);
                    }
                    (rel_ssn, n)
                }
                (Some((k, mut p)), Some(mut n)) => {
                    if p.len() >= n.len() {
                        p.extend(data);
                        p.append(&mut n);
                        (k, p)
                    } else {
                        for &b in data.iter().rev() {
                            n.push_front(b);
                        }
                        while let Some(b) = p.pop_back() {
                            n.push_front(b);
                        }
                        (k, n)
                    }
                }
            };
            let old = self.ooo.insert(key, piece);
            debug_assert!(old.is_none(), "the Tcb hands each octet over once");
            return;
        }
        self.recv.extend(data);
        self.recv_end = self.recv_end.wrapping_add(data.len() as u32);
        // Pieces tile the sequence space, so the next in-order one starts exactly here.
        while let Some(mut next) = self.ooo.remove(&self.recv_end) {
            self.ooo_len -= next.len();
            self.recv_end = self.recv_end.wrapping_add(next.len() as u32);
            self.recv.append(&mut next);
        }
    }

    fn recv_window(&self) -> u32 {
        self.recv_buffer
            .saturating_sub(self.recv.len() + self.ooo_len) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hooks(send: u32, recv: u32) -> PlainHooks {
        PlainHooks::new(&ConnectConfig {
            send_buffer: send,
            recv_buffer: recv,
            ..ConnectConfig::default()
        })
    }

    #[test]
    fn send_buffer_bounded_peek_and_ack() {
        let mut h = hooks(8, 8);
        assert_eq!(h.assigned_end(), 1);
        assert_eq!(h.write(b"abcdef"), 6);
        assert_eq!(h.write(b"ghij"), 2);
        assert_eq!(h.write(b"k"), 0);
        assert_eq!(h.assigned_end(), 9);
        assert_eq!(h.peek_with(1, 3, |d| d.to_vec()), Some(b"abc".to_vec()));
        assert_eq!(h.peek_with(7, 100, |d| d.to_vec()), Some(b"gh".to_vec()));
        assert_eq!(h.peek_with(9, 1, |d| d.len()), None);
        h.mark_acked(5);
        assert_eq!(h.peek_with(4, 1, |d| d.len()), None);
        assert_eq!(h.peek_with(5, 2, |d| d.to_vec()), Some(b"ef".to_vec()));
        h.mark_acked(3); // stale: no effect
        assert_eq!(h.peek_with(5, 1, |d| d.to_vec()), Some(b"e".to_vec()));
        assert_eq!(h.write(b"klmnop"), 4);
        assert_eq!(h.assigned_end(), 13);
    }

    #[test]
    fn peek_run_ends_at_buffer_wrap() {
        let mut h = hooks(8, 8);
        // Fill, ack, refill so the deque wraps; peeks must still return the right bytes in order.
        let mut out = Vec::new();
        let mut next = 1u32;
        for chunk in [b"abcdefgh".as_slice(), b"ijkl", b"mnop"] {
            h.write(chunk);
            while let Some(run) = h.peek_with(next, 100, |d| d.to_vec()) {
                assert!(!run.is_empty());
                next += run.len() as u32;
                out.extend(run);
            }
            h.mark_acked(next);
        }
        assert_eq!(out, b"abcdefghijklmnop");
    }

    #[test]
    fn recv_in_order_read_and_window() {
        let mut h = hooks(8, 8);
        assert_eq!(h.recv_window(), 8);
        h.accept_payload(1, b"ab");
        h.accept_payload(3, b"cde");
        assert_eq!(h.recv_window(), 3);
        let mut buf = [0u8; 4];
        assert_eq!(h.read(&mut buf), 4);
        assert_eq!(&buf, b"abcd");
        assert_eq!(h.read(&mut []), 0);
        assert_eq!(h.read(&mut buf), 1);
        assert_eq!(buf[0], b'e');
        assert_eq!(h.read(&mut buf), 0);
        assert_eq!(h.recv_window(), 8);
    }

    #[test]
    fn recv_adjacent_out_of_order_pieces_coalesce() {
        let mut h = hooks(8, 1 << 20);
        for i in 2..5002u32 {
            h.accept_payload(i, &[(i % 251) as u8]);
        }
        assert!(h.ooo_pieces() <= 64, "{} pieces", h.ooo_pieces());
        // fill from the back and the middle too: still one run
        h.accept_payload(5003, b"z");
        h.accept_payload(5002, &[(5002 % 251) as u8]);
        assert_eq!(h.ooo_pieces(), 1);
        h.accept_payload(1, &[1]);
        let mut buf = vec![0u8; 6000];
        assert_eq!(h.read(&mut buf), 5003);
        for i in 1..5003usize {
            assert_eq!(buf[i - 1], (i % 251) as u8);
        }
        assert_eq!(buf[5002], b'z');
        assert_eq!(h.recv_window(), 1 << 20);
    }

    #[test]
    fn recv_descending_adjacent_pieces_stay_cheap() {
        // Descending one-byte segments: copying the whole accumulated piece each time would be
        // quadratic (~1 TB moved at this size), far beyond any test runtime.
        const N: u32 = 1 << 21;
        let mut h = hooks(8, N + 8);
        for i in (2..=N).rev() {
            h.accept_payload(i, &[(i % 251) as u8]);
        }
        assert_eq!(h.ooo_pieces(), 1);
        h.accept_payload(1, &[1]);
        let mut buf = vec![0u8; N as usize + 1];
        assert_eq!(h.read(&mut buf), N as usize);
        assert!((1..=N as usize).all(|i| buf[i - 1] == (i % 251) as u8));
        // Interleaved arrival also merges into one piece.
        let mut h = hooks(8, N + 8);
        for i in (2..=4096u32).step_by(2).chain((3..=4096).step_by(2)) {
            h.accept_payload(i, &[(i % 251) as u8]);
        }
        assert_eq!(h.ooo_pieces(), 1);
    }

    #[test]
    fn recv_out_of_order_drained_when_contiguous() {
        let mut h = hooks(8, 8);
        h.accept_payload(6, b"fg");
        h.accept_payload(4, b"de");
        assert_eq!(h.recv_window(), 4);
        assert_eq!(h.read(&mut [0u8; 8]), 0);
        h.accept_payload(1, b"abc");
        assert_eq!(h.recv_window(), 1);
        let mut buf = [0u8; 8];
        assert_eq!(h.read(&mut buf), 7);
        assert_eq!(&buf[..7], b"abcdefg");
        assert_eq!(h.recv_window(), 8);
    }
}
