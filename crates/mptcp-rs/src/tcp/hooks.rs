//! Hook traits through which the `Tcb` reaches the send and receive buffers (spec §3), and
//! `PlainHooks`, their plain-TCP implementation with real buffers.

use std::collections::{BTreeMap, VecDeque};

use super::tcb::ConnectConfig;

/// Send-side data source. Relative SSN: the first data octet is 1 (spec §5.3).
pub trait SendBuf {
    /// Calls `f` with the contiguous run of buffered bytes starting at `rel_ssn`, at most `max`
    /// long. The run may be shorter than `max` and than what is buffered (it ends at an internal
    /// buffer boundary). `None` if no byte at `rel_ssn` is buffered.
    fn peek_with<R>(&self, rel_ssn: u32, max: usize, f: impl FnOnce(&[u8]) -> R) -> Option<R>;
    /// Relative SSN one past the last assigned octet.
    fn assigned_end(&self) -> u32;
    /// Releases every octet below `rel_ssn_una`.
    fn mark_acked(&mut self, rel_ssn_una: u32);
}

/// Receive-side sink. The `Tcb` drops duplicates and trims every segment to what the hooks can
/// store before calling `accept_payload`, so the call cannot fail.
pub trait SegmentHooks {
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
    ooo: BTreeMap<u32, Vec<u8>>,
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
            // not the number of segments the peer sent.
            let end = rel_ssn.wrapping_add(data.len() as u32);
            let prev = self
                .ooo
                .range(..rel_ssn)
                .next_back()
                .filter(|(k, v)| k.wrapping_add(v.len() as u32) == rel_ssn)
                .map(|(k, _)| *k);
            let (key, mut piece) = match prev {
                Some(k) => (k, self.ooo.remove(&k).unwrap_or_default()),
                None => (rel_ssn, Vec::with_capacity(data.len())),
            };
            piece.extend_from_slice(data);
            if let Some(next) = self.ooo.remove(&end) {
                piece.extend(next);
            }
            let old = self.ooo.insert(key, piece);
            debug_assert!(old.is_none(), "the Tcb hands each octet over once");
            return;
        }
        self.recv.extend(data);
        self.recv_end = self.recv_end.wrapping_add(data.len() as u32);
        // Pieces tile the sequence space, so the next in-order one starts exactly here.
        while let Some(next) = self.ooo.remove(&self.recv_end) {
            self.ooo_len -= next.len();
            self.recv_end = self.recv_end.wrapping_add(next.len() as u32);
            self.recv.extend(next);
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
