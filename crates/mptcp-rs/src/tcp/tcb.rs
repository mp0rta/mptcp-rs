//! Pure TCP state machine (RFC 9293), driven by segments, time and hooks (spec §3, §3.1).

use std::net::SocketAddr;
use std::time::Duration;

use super::hooks::Hooks;
use crate::seq::SeqNum;
use crate::time::Instant;
use crate::wire::packet::{Segment, TcpFlags};
use crate::wire::tcp_options::{self, TcpOpt};

const INITIAL_RTO: Duration = Duration::from_secs(1);
const MAX_RTO: Duration = Duration::from_secs(60);
/// RFC 9293 MUST-23: R2 for a SYN is at least 3 minutes.
const MIN_R2_SYN: Duration = Duration::from_secs(180);
const MAX_WS_SHIFT: u8 = 14;

/// Per-connection settings (spec §3; R2 is settable per connection, RFC 9293 MUST-21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectConfig {
    pub mtu: u16,
    pub recv_buffer: u32,
    pub send_buffer: u32,
    pub r2_data: Duration,
    /// Used as at least 180 s (RFC 9293 MUST-23).
    pub r2_syn: Duration,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            mtu: 1500,
            recv_buffer: 4 << 20,
            send_buffer: 4 << 20,
            r2_data: Duration::from_secs(100),
            r2_syn: Duration::from_secs(180),
        }
    }
}

/// RFC 9293 connection states (a client never uses LISTEN or SYN-RECEIVED).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Normal,
    Reset,
    Timeout,
}

/// What the caller must report after an input. Every `Closed(_)` is returned exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    None,
    Established,
    Closed(CloseReason),
}

/// The segment `poll_send` just wrote into the `SegmentWriter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SentMeta {
    pub seq: SeqNum,
    pub len: u32,
    pub flags: TcpFlags,
}

/// TCP header fields and payload of one outgoing segment; the Endpoint adds the addresses and
/// builds the IP packet with `wire::packet::build`.
#[derive(Debug)]
pub struct SegmentWriter {
    pub seq: SeqNum,
    pub ack: SeqNum,
    pub flags: TcpFlags,
    pub wnd: u16,
    pub options: [u8; 40],
    pub options_len: usize,
    /// Reused across segments.
    pub payload: Vec<u8>,
}

impl Default for SegmentWriter {
    fn default() -> Self {
        Self {
            seq: SeqNum(0),
            ack: SeqNum(0),
            flags: TcpFlags::default(),
            wnd: 0,
            options: [0; 40],
            options_len: 0,
            payload: Vec::new(),
        }
    }
}

impl SegmentWriter {
    pub fn options(&self) -> &[u8] {
        &self.options[..self.options_len]
    }

    /// Starts a segment with no options and no payload.
    fn start(&mut self, seq: SeqNum, ack: SeqNum, flags: TcpFlags, wnd: u16) -> SentMeta {
        self.seq = seq;
        self.ack = ack;
        self.flags = flags;
        self.wnd = wnd;
        self.options_len = 0;
        self.payload.clear();
        SentMeta { seq, len: 0, flags }
    }
}

#[derive(Debug)]
pub struct Tcb {
    cfg: ConnectConfig,
    v6: bool,
    state: TcpState,
    nodelay: bool,

    // Send sequence space (RFC 9293 §3.3.1).
    iss: SeqNum,
    snd_una: SeqNum,
    snd_nxt: SeqNum,
    /// Peer's window in octets, already scaled.
    snd_wnd: u32,
    /// Shift applied to the peer's window fields (RFC 7323 Snd.Wind.Shift).
    snd_shift: u8,
    /// Effective send MSS (spec §3); final once ESTABLISHED.
    eff_mss: u16,

    // Receive sequence space.
    rcv_nxt: SeqNum,
    /// Shift applied to our window fields (RFC 7323 Rcv.Wind.Shift). Holds our offer until the
    /// SYN/ACK; 0 if the peer did not offer.
    rcv_shift: u8,

    // Timers.
    rto: Duration,
    rto_at: Option<Instant>,
    /// First SYN transmission; R2 for the SYN counts from here.
    first_syn_at: Option<Instant>,
    closed_at: Option<Instant>,

    // Segments due at the next `poll_send`.
    syn_due: bool,
    ack_due: bool,
    /// RST answering an unacceptable ACK, `<SEQ=SEG.ACK><CTL=RST>`.
    rst_due: Option<SeqNum>,
}

impl Tcb {
    pub fn new_active(
        cfg: &ConnectConfig,
        _local: SocketAddr,
        remote: SocketAddr,
        isn: SeqNum,
        _now: Instant,
    ) -> Tcb {
        let mut tcb = Tcb {
            cfg: cfg.clone(),
            v6: remote.is_ipv6(),
            state: TcpState::SynSent,
            nodelay: false,
            iss: isn,
            snd_una: isn,
            // Becomes ISS + 1 when the SYN is sent; until then no ACK is acceptable.
            snd_nxt: isn,
            snd_wnd: 0,
            snd_shift: 0,
            eff_mss: 0,
            rcv_nxt: SeqNum(0),
            rcv_shift: ws_shift(cfg.recv_buffer),
            rto: INITIAL_RTO,
            rto_at: None,
            first_syn_at: None,
            closed_at: None,
            syn_due: true,
            ack_due: false,
            rst_due: None,
        };
        tcb.eff_mss = tcb.eff_mss_for(None);
        tcb
    }

    pub fn state(&self) -> TcpState {
        self.state
    }

    /// Switches Nagle off (`true`) or on (`false`, the default).
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
    }

    pub fn on_segment(&mut self, seg: &Segment, now: Instant, _h: &mut impl Hooks) -> Reaction {
        match self.state {
            TcpState::SynSent => self.on_segment_syn_sent(seg, now),
            _ => Reaction::None,
        }
    }

    /// Processes every timer expiry due at `now` (spec §3.1).
    pub fn on_timeout(&mut self, now: Instant, _h: &mut impl Hooks) -> Reaction {
        match self.state {
            TcpState::SynSent => self.on_timeout_syn_sent(now),
            _ => Reaction::None,
        }
    }

    pub fn poll_send(
        &mut self,
        now: Instant,
        h: &mut impl Hooks,
        out: &mut SegmentWriter,
    ) -> Option<SentMeta> {
        if self.state == TcpState::Closed {
            return None;
        }
        if let Some(seq) = self.rst_due.take() {
            return Some(out.start(seq, SeqNum(0), TcpFlags::RST, 0));
        }
        if self.syn_due {
            self.syn_due = false;
            self.first_syn_at.get_or_insert(now);
            self.rto_at = Some(now + self.rto);
            self.snd_nxt = self.iss.wrapping_add(1);
            // RFC 7323 §2.2: the window field of a SYN is never scaled.
            let wnd = self.cfg.recv_buffer.min(65535) as u16;
            let meta = out.start(self.iss, SeqNum(0), TcpFlags::SYN, wnd);
            let n = tcp_options::write_mss(&mut out.options, self.mss_option());
            out.options_len = n + tcp_options::write_ws(&mut out.options[n..], self.rcv_shift);
            return Some(meta);
        }
        if self.ack_due {
            self.ack_due = false;
            let wnd = (h.recv_window() >> self.rcv_shift).min(65535) as u16;
            return Some(out.start(self.snd_nxt, self.rcv_nxt, TcpFlags::ACK, wnd));
        }
        None
    }

    /// The next timer deadline; `closed_at` once `Closed`. Segments made due by an input are
    /// not reported here: the driver calls `poll_send` after every input.
    pub fn poll_send_at(&self) -> Option<Instant> {
        match self.state {
            TcpState::Closed => self.closed_at,
            TcpState::SynSent => {
                let r2 = self.first_syn_at.map(|t| t + self.r2_syn());
                [self.rto_at, r2].into_iter().flatten().min()
            }
            _ => None,
        }
    }

    /// RFC 9293 §3.10.7.3. A segment without ACK is dropped: a RST without ACK by the RFC's
    /// rule, a bare SYN because this client does not support simultaneous open.
    fn on_segment_syn_sent(&mut self, seg: &Segment, now: Instant) -> Reaction {
        let rst = seg.flags.contains(TcpFlags::RST);
        if !seg.flags.contains(TcpFlags::ACK) {
            return Reaction::None;
        }
        // Acceptable iff SND.UNA (= ISS here) < SEG.ACK =< SND.NXT.
        if seg.ack.le(self.iss) || seg.ack.gt(self.snd_nxt) {
            if !rst {
                self.rst_due = Some(seg.ack);
            }
            return Reaction::None;
        }
        if rst {
            return self.close(CloseReason::Reset, now);
        }
        if !seg.flags.contains(TcpFlags::SYN) {
            return Reaction::None;
        }

        let (mut mss, mut ws) = (None, None);
        for opt in tcp_options::walk(seg.options).map_while(Result::ok) {
            match opt {
                TcpOpt::Mss(m) => mss = Some(m),
                TcpOpt::WindowScale(s) => ws = Some(s),
                _ => {}
            }
        }
        self.eff_mss = self.eff_mss_for(mss);
        // RFC 7323 §2.3: scaling only if both SYNs carry WS; a shift above 14 is used as 14.
        match ws {
            Some(s) => self.snd_shift = s.min(MAX_WS_SHIFT),
            None => self.rcv_shift = 0,
        }
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.snd_una = seg.ack;
        self.snd_wnd = u32::from(seg.wnd);
        // A SYN retransmission made due by an RTO that fired just before is now moot.
        self.syn_due = false;
        self.rto_at = None;
        self.ack_due = true;
        self.state = TcpState::Established;
        Reaction::Established
    }

    fn on_timeout_syn_sent(&mut self, now: Instant) -> Reaction {
        if self.first_syn_at.is_some_and(|t| now >= t + self.r2_syn()) {
            return self.close(CloseReason::Timeout, now);
        }
        if self.rto_at.is_some_and(|t| now >= t) {
            self.rto_at = None;
            self.rto = (self.rto * 2).min(MAX_RTO);
            self.syn_due = true;
        }
        Reaction::None
    }

    fn close(&mut self, reason: CloseReason, now: Instant) -> Reaction {
        self.state = TcpState::Closed;
        self.closed_at = Some(now);
        Reaction::Closed(reason)
    }

    fn r2_syn(&self) -> Duration {
        self.cfg.r2_syn.max(MIN_R2_SYN)
    }

    /// Our SYN's MSS option: MTU minus the IP and TCP headers (RFC 9293 §3.7.1).
    fn mss_option(&self) -> u16 {
        self.cfg.mtu.saturating_sub(if self.v6 { 60 } else { 40 })
    }

    /// Spec §3: min(peer's MSS option, or 536 / 1220 when absent; our MTU-derived MSS). No TCP
    /// options are in use on data segments in M0.
    fn eff_mss_for(&self, peer: Option<u16>) -> u16 {
        let peer = peer.unwrap_or(if self.v6 { 1220 } else { 536 });
        // ponytail: a peer MSS of 0 would stall the send path; used as 1.
        peer.min(self.mss_option()).max(1)
    }
}

/// Smallest shift `s` with `buffer >> s <= 65535`, at most 14 (RFC 7323 §2.3).
fn ws_shift(buffer: u32) -> u8 {
    (0..MAX_WS_SHIFT)
        .find(|&s| buffer >> s <= 65535)
        .unwrap_or(MAX_WS_SHIFT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::PlainHooks;

    const ISN: SeqNum = SeqNum(0x1000);
    const PEER_ISN: SeqNum = SeqNum(0xFFFF_FFF0);

    fn v4() -> (SocketAddr, SocketAddr) {
        (
            "10.0.0.1:50000".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
        )
    }
    fn v6() -> (SocketAddr, SocketAddr) {
        (
            "[fd00::1]:50000".parse().unwrap(),
            "[fd00::2]:80".parse().unwrap(),
        )
    }
    fn t(secs: u64) -> Instant {
        Instant::from_nanos(1_000_000_000) + Duration::from_secs(secs)
    }

    struct Fixture {
        tcb: Tcb,
        h: PlainHooks,
        out: SegmentWriter,
        addrs: (SocketAddr, SocketAddr),
    }

    impl Fixture {
        fn new(cfg: ConnectConfig, addrs: (SocketAddr, SocketAddr)) -> Self {
            Self {
                tcb: Tcb::new_active(&cfg, addrs.0, addrs.1, ISN, t(0)),
                h: PlainHooks::new(&cfg),
                out: SegmentWriter::default(),
                addrs,
            }
        }
        fn send(&mut self, now: Instant) -> Option<SentMeta> {
            self.tcb.poll_send(now, &mut self.h, &mut self.out)
        }
        fn timeout(&mut self, now: Instant) -> Reaction {
            self.tcb.on_timeout(now, &mut self.h)
        }
        fn recv(&mut self, flags: TcpFlags, ack: SeqNum, wnd: u16, opts: &[u8]) -> Reaction {
            let seg = Segment {
                src: self.addrs.1,
                dst: self.addrs.0,
                seq: PEER_ISN,
                ack,
                flags,
                wnd,
                options: opts,
                payload: &[],
            };
            self.tcb.on_segment(&seg, t(0), &mut self.h)
        }
        /// SYN sent at t(0), then a SYN/ACK acknowledging it.
        fn synack(&mut self, wnd: u16, opts: &[u8]) -> Reaction {
            self.send(t(0)).unwrap();
            self.recv(
                TcpFlags::SYN | TcpFlags::ACK,
                ISN.wrapping_add(1),
                wnd,
                opts,
            )
        }
    }

    fn opts(mss: Option<u16>, ws: Option<u8>) -> Vec<u8> {
        let mut b = [0u8; 8];
        let mut n = 0;
        if let Some(m) = mss {
            n += tcp_options::write_mss(&mut b[n..], m);
        }
        if let Some(s) = ws {
            n += tcp_options::write_ws(&mut b[n..], s);
        }
        b[..n].to_vec()
    }

    fn parsed(raw: &[u8]) -> Vec<TcpOpt<'_>> {
        tcp_options::walk(raw).map(Result::unwrap).collect()
    }

    #[test]
    fn syn_carries_mss_and_ws() {
        for (addrs, mss) in [(v4(), 1460), (v6(), 1440)] {
            let mut f = Fixture::new(ConnectConfig::default(), addrs);
            assert_eq!(f.tcb.state(), TcpState::SynSent);
            let meta = f.send(t(0)).unwrap();
            assert_eq!(
                meta,
                SentMeta {
                    seq: ISN,
                    len: 0,
                    flags: TcpFlags::SYN
                }
            );
            assert_eq!(f.out.seq, ISN);
            assert_eq!(f.out.flags, TcpFlags::SYN);
            assert_eq!(f.out.wnd, 65535);
            assert!(f.out.payload.is_empty());
            // Only MSS and WS: no SACK-permitted, no timestamps.
            assert_eq!(
                parsed(f.out.options()),
                vec![TcpOpt::Mss(mss), TcpOpt::WindowScale(7)]
            );
            assert_eq!(f.send(t(0)), None);
        }
    }

    #[test]
    fn syn_window_is_buffer_when_small() {
        let cfg = ConnectConfig {
            recv_buffer: 1000,
            ..ConnectConfig::default()
        };
        let mut f = Fixture::new(cfg, v4());
        f.send(t(0)).unwrap();
        assert_eq!(f.out.wnd, 1000);
        assert_eq!(
            parsed(f.out.options()),
            vec![TcpOpt::Mss(1460), TcpOpt::WindowScale(0)]
        );
    }

    #[test]
    fn synack_establishes_and_acks() {
        let mut f = Fixture::new(ConnectConfig::default(), v4());
        assert_eq!(
            f.synack(5000, &opts(Some(1400), Some(8))),
            Reaction::Established
        );
        assert_eq!(f.tcb.state(), TcpState::Established);
        assert_eq!(f.tcb.eff_mss, 1400);
        let meta = f.send(t(0)).unwrap();
        assert_eq!(meta.flags, TcpFlags::ACK);
        assert_eq!(meta.len, 0);
        assert_eq!(f.out.seq, ISN.wrapping_add(1));
        assert_eq!(f.out.ack, PEER_ISN.wrapping_add(1));
        // 4 MiB receive buffer advertised with our shift 7.
        assert_eq!(f.out.wnd, 32768);
        assert!(f.out.options().is_empty());
        assert_eq!(f.send(t(0)), None);
        // Timers stop once established.
        assert_eq!(f.tcb.poll_send_at(), None);
    }

    #[test]
    fn eff_mss_rules() {
        for (addrs, absent, cap) in [(v4(), 536, 1460), (v6(), 1220, 1440)] {
            for (peer, want) in [(None, absent), (Some(64), 64), (Some(9000), cap)] {
                let mut f = Fixture::new(ConnectConfig::default(), addrs);
                assert_eq!(f.synack(5000, &opts(peer, Some(7))), Reaction::Established);
                assert_eq!(f.tcb.eff_mss, want, "{addrs:?} peer {peer:?}");
            }
        }
    }

    #[test]
    fn malformed_peer_mss_treated_as_absent() {
        let mut f = Fixture::new(ConnectConfig::default(), v4());
        // MSS kind with length 3: the walker reports it as Unknown.
        assert_eq!(f.synack(5000, &[2, 3, 5, 0]), Reaction::Established);
        assert_eq!(f.tcb.eff_mss, 536);
    }

    #[test]
    fn peer_ws_above_14_clamped() {
        let mut f = Fixture::new(ConnectConfig::default(), v4());
        assert_eq!(
            f.synack(5000, &opts(Some(1460), Some(15))),
            Reaction::Established
        );
        assert_eq!(f.tcb.snd_shift, 14);
        assert_eq!(f.tcb.rcv_shift, 7);
    }

    #[test]
    fn synack_window_taken_unscaled() {
        let mut f = Fixture::new(ConnectConfig::default(), v4());
        assert_eq!(
            f.synack(1000, &opts(Some(1460), Some(8))),
            Reaction::Established
        );
        assert_eq!(f.tcb.snd_shift, 8);
        assert_eq!(f.tcb.snd_wnd, 1000);
    }

    /// Drives a SYN that is never answered; returns the SYN send times (s after t(0)) and the
    /// time of `Closed(Timeout)`.
    fn run_unanswered(cfg: ConnectConfig) -> (Vec<u64>, u64, Fixture) {
        let mut f = Fixture::new(cfg, v4());
        let mut sends = Vec::new();
        assert!(f.send(t(0)).is_some());
        loop {
            let at = f.tcb.poll_send_at().expect("a deadline while SYN-SENT");
            let secs = (at - t(0)).as_secs();
            assert_eq!(at, t(secs), "deadlines are whole seconds here");
            match f.timeout(at) {
                Reaction::None => {}
                Reaction::Closed(CloseReason::Timeout) => return (sends, secs, f),
                r => panic!("unexpected {r:?}"),
            }
            let meta = f.send(at).expect("SYN retransmitted after RTO");
            assert_eq!(meta.flags, TcpFlags::SYN);
            assert_eq!(f.out.seq, ISN);
            sends.push(secs);
            assert_eq!(f.send(at), None);
        }
    }

    #[test]
    fn syn_retransmits_with_backoff_until_r2() {
        let (sends, closed, mut f) = run_unanswered(ConnectConfig::default());
        // RTO 1, 2, 4, ... 32, then capped at 60 s.
        assert_eq!(sends, vec![1, 3, 7, 15, 31, 63, 123]);
        assert_eq!(closed, 180);
        assert_eq!(f.tcb.state(), TcpState::Closed);
        assert_eq!(f.tcb.poll_send_at(), Some(t(180)));
        // Exactly once.
        assert_eq!(f.timeout(t(500)), Reaction::None);
        assert_eq!(f.send(t(500)), None);
        assert_eq!(f.tcb.poll_send_at(), Some(t(180)));
    }

    #[test]
    fn early_timeout_call_does_not_retransmit() {
        let mut f = Fixture::new(ConnectConfig::default(), v4());
        f.send(t(0)).unwrap();
        assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
        assert_eq!(f.timeout(t(0) + Duration::from_millis(999)), Reaction::None);
        assert_eq!(f.send(t(0) + Duration::from_millis(999)), None);
    }

    #[test]
    fn r2_syn_clamped_to_180s() {
        let cfg = ConnectConfig {
            r2_syn: Duration::from_secs(10),
            ..ConnectConfig::default()
        };
        let (sends, closed, _) = run_unanswered(cfg);
        assert_eq!(sends, vec![1, 3, 7, 15, 31, 63, 123]);
        assert_eq!(closed, 180);
        // A longer R2 is honoured.
        let cfg = ConnectConfig {
            r2_syn: Duration::from_secs(200),
            ..ConnectConfig::default()
        };
        let (sends, closed, _) = run_unanswered(cfg);
        assert_eq!(sends, vec![1, 3, 7, 15, 31, 63, 123, 183]);
        assert_eq!(closed, 200);
    }

    #[test]
    fn rst_in_syn_sent_with_acceptable_ack_resets() {
        let rst_ack = TcpFlags::RST | TcpFlags::ACK;
        let mut f = Fixture::new(ConnectConfig::default(), v4());
        f.send(t(0)).unwrap();
        // Wrong ACK (not our SYN), or no ACK at all: dropped, no reply.
        assert_eq!(f.recv(rst_ack, ISN, 0, &[]), Reaction::None);
        assert_eq!(f.recv(rst_ack, ISN.wrapping_add(2), 0, &[]), Reaction::None);
        assert_eq!(f.recv(TcpFlags::RST, SeqNum(0), 0, &[]), Reaction::None);
        assert_eq!(f.tcb.state(), TcpState::SynSent);
        assert_eq!(f.send(t(0)), None);

        assert_eq!(
            f.recv(rst_ack, ISN.wrapping_add(1), 0, &[]),
            Reaction::Closed(CloseReason::Reset)
        );
        assert_eq!(f.tcb.state(), TcpState::Closed);
        assert_eq!(f.tcb.poll_send_at(), Some(t(0)));
        // Exactly once.
        assert_eq!(f.recv(rst_ack, ISN.wrapping_add(1), 0, &[]), Reaction::None);
        assert_eq!(f.timeout(t(500)), Reaction::None);
        assert_eq!(f.send(t(0)), None);
    }

    #[test]
    fn unacceptable_ack_in_syn_sent_answered_with_rst() {
        let mut f = Fixture::new(ConnectConfig::default(), v4());
        f.send(t(0)).unwrap();
        let bad = ISN.wrapping_add(5);
        assert_eq!(
            f.recv(TcpFlags::SYN | TcpFlags::ACK, bad, 5000, &[]),
            Reaction::None
        );
        assert_eq!(f.tcb.state(), TcpState::SynSent);
        let meta = f.send(t(0)).unwrap();
        assert_eq!(meta.flags, TcpFlags::RST);
        assert_eq!(f.out.seq, bad);
        assert!(f.out.options().is_empty());
        assert_eq!(f.send(t(0)), None);
        // The SYN timer still runs.
        assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
    }

    #[test]
    fn segment_without_ack_ignored_in_syn_sent() {
        let mut f = Fixture::new(ConnectConfig::default(), v4());
        f.send(t(0)).unwrap();
        // A bare SYN (simultaneous open) is not supported by this client; dropped.
        assert_eq!(f.recv(TcpFlags::SYN, SeqNum(0), 5000, &[]), Reaction::None);
        // ACK without SYN: dropped (RFC 9293 §3.10.7.3 fifth step).
        assert_eq!(
            f.recv(TcpFlags::ACK, ISN.wrapping_add(1), 5000, &[]),
            Reaction::None
        );
        assert_eq!(f.tcb.state(), TcpState::SynSent);
        assert_eq!(f.send(t(0)), None);
    }

    #[test]
    fn synack_after_rto_fired_sends_only_ack() {
        let mut f = Fixture::new(ConnectConfig::default(), v4());
        f.send(t(0)).unwrap();
        // The SYN RTO fires, then the SYN/ACK arrives before the retransmission is polled.
        assert_eq!(f.timeout(t(1)), Reaction::None);
        assert_eq!(
            f.recv(
                TcpFlags::SYN | TcpFlags::ACK,
                ISN.wrapping_add(1),
                5000,
                &opts(Some(1460), Some(7))
            ),
            Reaction::Established
        );
        let meta = f.send(t(1)).unwrap();
        assert_eq!(meta.flags, TcpFlags::ACK);
        assert_eq!(f.out.seq, ISN.wrapping_add(1));
        assert_eq!(f.send(t(1)), None);
        assert_eq!(f.tcb.snd_nxt, ISN.wrapping_add(1));
        assert_eq!(f.tcb.rto_at, None);
        assert_eq!(f.tcb.poll_send_at(), None);
    }

    #[test]
    fn synack_without_ws_disables_scaling_both_ways() {
        for addrs in [v4(), v6()] {
            let mut f = Fixture::new(ConnectConfig::default(), addrs);
            assert_eq!(
                f.synack(5000, &opts(Some(1460), None)),
                Reaction::Established
            );
            assert_eq!((f.tcb.snd_shift, f.tcb.rcv_shift), (0, 0));
            assert_eq!(f.tcb.snd_wnd, 5000);
            f.send(t(0)).unwrap();
            // 4 MiB free, unscaled: capped at 65535.
            assert_eq!(f.out.wnd, 65535);
        }
    }
}
