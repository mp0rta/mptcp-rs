//! Pure TCP state machine (RFC 9293), driven by segments, time and hooks (spec §3, §3.1).

use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::time::Duration;

use rangemap::RangeSet;

use super::cc::{CongestionControl, CongestionEvent, Unbounded};
use super::hooks::Hooks;
use super::rtt::{INITIAL_RTO, RttEstimator};
use crate::seq::SeqNum;
use crate::time::Instant;
use crate::wire::packet::{Segment, TcpFlags};
use crate::wire::tcp_options::{self, TcpOpt};

/// RFC 9293 MUST-23: R2 for a SYN is at least 3 minutes.
const MIN_R2_SYN: Duration = Duration::from_secs(180);
const MAX_WS_SHIFT: u8 = 14;
/// Persist interval cap (RFC 9293 SHLD-30 leaves it open; same as the RTO cap).
const MAX_PERSIST: Duration = Duration::from_secs(60);
/// Sender SWS override timeout (RFC 9293 §3.8.6.2.1 rule 4).
const SWS_OVERRIDE: Duration = Duration::from_millis(500);
/// Delayed ACK bound (RFC 9293 MUST-40: less than 0.5 s).
const DELAYED_ACK: Duration = Duration::from_millis(200);
/// Out-of-order receipt ranges kept at most; a segment that would add one more is dropped.
const MAX_OOO_RANGES: usize = 64;

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
    /// SEG.SEQ / SEG.ACK of the segment that last updated `snd_wnd`.
    snd_wl1: SeqNum,
    snd_wl2: SeqNum,
    /// Max(SND.WND), the sender SWS estimate of the peer's buffer (RFC 9293 §3.8.6.2.1).
    max_snd_wnd: u32,
    /// Effective send MSS (spec §3); final once ESTABLISHED.
    eff_mss: u16,

    // Receive sequence space.
    rcv_nxt: SeqNum,
    /// Relative SSN of RCV.NXT, not wrapped (IRS + 1 is 1); keys `rcv_ooo`.
    rcv_ssn: u64,
    /// Shift applied to our window fields (RFC 7323 Rcv.Wind.Shift). Holds our offer until the
    /// SYN/ACK; 0 if the peer did not offer.
    rcv_shift: u8,
    /// Largest right window edge ever advertised (never moves left, RFC 9293 SHLD-14).
    rcv_right_edge: SeqNum,
    /// Out-of-order receipt ranges (headers only, spec §2 step 4), in unwrapped relative SSN.
    /// Exactly the octets the hooks hold out of order.
    rcv_ooo: RangeSet<u64>,
    /// In-order data segments received since our last ACK.
    rcv_unacked: u8,

    cc: Box<dyn CongestionControl>,

    // Timers.
    rtt: RttEstimator,
    /// Retransmission timer (SYN, then data at SND.UNA).
    rto_at: Option<Instant>,
    /// The one timed segment (Karn): its end and send time; cleared by any RTO.
    rtt_timed: Option<(SeqNum, Instant)>,
    /// R2 base for data: first transmission of the segment at SND.UNA, restarted when SND.UNA
    /// advances; or the first unanswered zero-window probe. `None` when nothing is pending.
    r2_since: Option<Instant>,
    /// Persist timer and its current interval (first = RTO, ×2 per probe, cap 60 s).
    persist_at: Option<Instant>,
    persist_ivl: Duration,
    /// Sender SWS override timer (RFC 9293 §3.8.6.2.1 rule 4).
    sws_at: Option<Instant>,
    /// Delayed-ACK deadline.
    ack_at: Option<Instant>,
    /// First SYN transmission; R2 for the SYN counts from here.
    first_syn_at: Option<Instant>,
    closed_at: Option<Instant>,

    // Segments due at the next `poll_send`.
    syn_due: bool,
    ack_due: bool,
    /// RST answering an unacceptable ACK, `<SEQ=SEG.ACK><CTL=RST>`.
    rst_due: Option<SeqNum>,
    /// RTO expired: resend one segment at SND.UNA.
    retransmit_due: bool,
    probe_due: bool,
    /// SWS override timer expired: send what the window allows.
    sws_override: bool,
}

impl Tcb {
    pub fn new_active(
        cfg: &ConnectConfig,
        local: SocketAddr,
        remote: SocketAddr,
        isn: SeqNum,
        now: Instant,
    ) -> Tcb {
        Self::with_cc(cfg, local, remote, isn, now, Box::new(Unbounded))
    }

    pub(crate) fn with_cc(
        cfg: &ConnectConfig,
        _local: SocketAddr,
        remote: SocketAddr,
        isn: SeqNum,
        _now: Instant,
        cc: Box<dyn CongestionControl>,
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
            snd_wl1: SeqNum(0),
            snd_wl2: SeqNum(0),
            max_snd_wnd: 0,
            eff_mss: 0,
            rcv_nxt: SeqNum(0),
            rcv_ssn: 0,
            rcv_shift: ws_shift(cfg.recv_buffer),
            rcv_right_edge: SeqNum(0),
            rcv_ooo: RangeSet::new(),
            rcv_unacked: 0,
            cc,
            rtt: RttEstimator::new(),
            rto_at: None,
            rtt_timed: None,
            r2_since: None,
            persist_at: None,
            persist_ivl: Duration::ZERO,
            sws_at: None,
            ack_at: None,
            first_syn_at: None,
            closed_at: None,
            syn_due: true,
            ack_due: false,
            rst_due: None,
            retransmit_due: false,
            probe_due: false,
            sws_override: false,
        };
        tcb.eff_mss = tcb.eff_mss_for(None);
        tcb
    }

    /// ESTABLISHED as if our SYN had been answered by a SYN/ACK carrying `peer_mss` and
    /// `peer_ws` (window 65535) at `now`; the handshake ACK is due. `cc::Unbounded`.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_established(
        cfg: &ConnectConfig,
        local: SocketAddr,
        remote: SocketAddr,
        isn: SeqNum,
        peer_isn: SeqNum,
        peer_mss: Option<u16>,
        peer_ws: Option<u8>,
        now: Instant,
    ) -> Tcb {
        let mut tcb = Self::with_cc(cfg, local, remote, isn, now, Box::new(Unbounded));
        tcb.syn_due = false;
        tcb.snd_nxt = isn.wrapping_add(1);
        let mut opts = [0u8; 8];
        let mut n = 0;
        if let Some(m) = peer_mss {
            n += tcp_options::write_mss(&mut opts[n..], m);
        }
        if let Some(s) = peer_ws {
            n += tcp_options::write_ws(&mut opts[n..], s);
        }
        let synack = Segment {
            src: remote,
            dst: local,
            seq: peer_isn,
            ack: tcb.snd_nxt,
            flags: TcpFlags::SYN | TcpFlags::ACK,
            wnd: 65535,
            options: &opts[..n],
            payload: &[],
        };
        assert_eq!(tcb.on_segment_syn_sent(&synack, now), Reaction::Established);
        tcb
    }

    pub fn state(&self) -> TcpState {
        self.state
    }

    /// Switches Nagle off (`true`) or on (`false`, the default).
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
    }

    pub fn on_segment(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) -> Reaction {
        match self.state {
            TcpState::SynSent => self.on_segment_syn_sent(seg, now),
            TcpState::Established => self.on_segment_sync(seg, now, h),
            _ => Reaction::None,
        }
    }

    /// Processes every timer expiry due at `now` (spec §3.1).
    pub fn on_timeout(&mut self, now: Instant, _h: &mut impl Hooks) -> Reaction {
        match self.state {
            TcpState::SynSent => self.on_timeout_syn_sent(now),
            TcpState::Established => self.on_timeout_data(now),
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
            self.rto_at = Some(now + self.rtt.rto());
            self.snd_nxt = self.iss.wrapping_add(1);
            // RFC 7323 §2.2: the window field of a SYN is never scaled.
            let wnd = self.cfg.recv_buffer.min(65535) as u16;
            let meta = out.start(self.iss, SeqNum(0), TcpFlags::SYN, wnd);
            let n = tcp_options::write_mss(&mut out.options, self.mss_option());
            out.options_len = n + tcp_options::write_ws(&mut out.options[n..], self.rcv_shift);
            return Some(meta);
        }
        if self.state == TcpState::Established {
            if let Some(meta) = self.poll_data(now, h, out) {
                // Every data segment and probe carries the current ACK.
                self.ack_sent();
                return Some(meta);
            }
            // A read that let the window edge move is announced (RFC 9293 §3.8.6.2.2).
            if !self.ack_due && self.window_update_due(h) {
                self.ack_due = true;
            }
        }
        if self.ack_due {
            self.ack_sent();
            let wnd = self.wnd_field(h);
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
            TcpState::Established => {
                let r2 = self.r2_since.map(|t| t + self.cfg.r2_data);
                [self.rto_at, r2, self.persist_at, self.sws_at, self.ack_at]
                    .into_iter()
                    .flatten()
                    .min()
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
        self.rcv_ssn = 1;
        // The window field of our SYN (unscaled) is the first edge advertised.
        self.rcv_right_edge = self.rcv_nxt.wrapping_add(self.cfg.recv_buffer.min(65535));
        self.snd_una = seg.ack;
        self.snd_wnd = u32::from(seg.wnd);
        self.max_snd_wnd = self.snd_wnd;
        self.snd_wl1 = seg.seq;
        self.snd_wl2 = seg.ack;
        // RFC 6298 §5.7: the timer expired awaiting the SYN's ACK (only then is RTO above 1 s).
        if self.rtt.rto() > INITIAL_RTO {
            self.rtt.reinit_after_syn_retransmission();
        }
        self.cc.init(u32::from(self.eff_mss));
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
            self.rtt.backoff();
            self.syn_due = true;
        }
        Reaction::None
    }

    /// RFC 9293 §3.10.7.4 in a synchronized state (ESTABLISHED so far). RST is not acted on
    /// yet and FIN is ignored: an acceptable RST or FIN is dropped.
    fn on_segment_sync(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) -> Reaction {
        let rst = seg.flags.contains(TcpFlags::RST);
        // First: an unacceptable segment draws an ACK, unless it is a RST, and is dropped.
        if !self.acceptable(seg) {
            self.ack_due |= !rst;
            // "If the RCV.WND is zero, ... special allowance should be made to accept valid
            // ACKs, URGs, and RSTs": with our window closed, the ACK field of a segment at or
            // beyond RCV.NXT is still processed; its text is not. (An RST allowance would go
            // here too; RST is not acted on yet.)
            let ack_only =
                seg.flags.contains(TcpFlags::ACK) && !rst && !seg.flags.contains(TcpFlags::SYN);
            if ack_only && self.rcv_nxt.le(seg.seq) && self.window_offer(h).0 == 0 {
                if let ControlFlow::Break(r) = self.on_ack(seg, now, h) {
                    return r;
                }
            }
            return Reaction::None;
        }
        if rst {
            return Reaction::None;
        }
        // Fourth: a SYN (e.g. a retransmitted SYN/ACK) draws a challenge ACK (RFC 5961 §4).
        if seg.flags.contains(TcpFlags::SYN) {
            self.ack_due = true;
            return Reaction::None;
        }
        // Fifth.
        if !seg.flags.contains(TcpFlags::ACK) {
            return Reaction::None;
        }
        if let ControlFlow::Break(r) = self.on_ack(seg, now, h) {
            return r;
        }
        // Seventh (URG is not processed: urgent data is delivered inline, RFC 6093).
        self.on_text(seg, now, h);
        Reaction::None
    }

    /// RFC 9293 Table 6, against the largest window advertised (RFC 7323 §2.4 rule 1).
    fn acceptable(&self, seg: &Segment) -> bool {
        let wnd = i64::from(self.rcv_wnd());
        let len = seg.payload.len() as i64
            + i64::from(seg.flags.contains(TcpFlags::SYN))
            + i64::from(seg.flags.contains(TcpFlags::FIN));
        let off = i64::from(self.rcv_nxt.distance(seg.seq));
        let in_wnd = |o: i64| 0 <= o && o < wnd;
        match (len, wnd) {
            (0, 0) => off == 0,
            (0, _) => in_wnd(off),
            (_, 0) => false,
            _ => in_wnd(off) || in_wnd(off + len - 1),
        }
    }

    /// Seventh step for an acceptable segment: hands the octets that are new, inside the window
    /// and fit the memory to the hooks once each, in order of SSN, and decides when to ACK
    /// (RFC 5681 §4.2, RFC 9293 §3.8.6.3). Octets cut off are neither recorded nor ACKed.
    fn on_text(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) {
        if seg.payload.is_empty() {
            return;
        }
        let off = i64::from(self.rcv_nxt.distance(seg.seq));
        let end = off + seg.payload.len() as i64;
        // Free memory counts from RCV.NXT with the held out-of-order octets inside it, so the
        // octets at RCV.NXT always fit.
        let held: u64 = self.rcv_ooo.iter().map(|r| r.end - r.start).sum();
        let room = u64::from(self.rcv_wnd()).min(u64::from(h.recv_window()) + held);
        let (lo, hi) = (off.max(0), end.min(room as i64));
        let was_ooo = !self.rcv_ooo.is_empty();
        if lo < hi {
            let (s, e) = (self.rcv_ssn + lo as u64, self.rcv_ssn + hi as u64);
            let new_range = lo > 0 && !self.rcv_ooo.overlaps(&(s - 1..e + 1));
            if new_range && self.rcv_ooo.len() >= MAX_OOO_RANGES {
                return;
            }
            for gap in self.rcv_ooo.gaps(&(s..e)) {
                let at = |ssn: u64| ((ssn - self.rcv_ssn) as i64 - off) as usize;
                h.accept_payload(gap.start as u32, &seg.payload[at(gap.start)..at(gap.end)]);
            }
            self.rcv_ooo.insert(s..e);
            if let Some(r) = self
                .rcv_ooo
                .first()
                .cloned()
                .filter(|r| r.start == self.rcv_ssn)
            {
                self.rcv_nxt = self.rcv_nxt.wrapping_add((r.end - r.start) as u32);
                self.rcv_ssn = r.end;
                self.rcv_ooo.remove(r);
            }
        }
        // Out of order, filling a gap, or cut short by the window or the memory: ACK now.
        if was_ooo || !self.rcv_ooo.is_empty() || hi < end {
            self.ack_due = true;
        } else {
            // Every second segment, else within DELAYED_ACK (RFC 5681 §4.2: "at least every
            // second segment, regardless of size").
            self.rcv_unacked = self.rcv_unacked.saturating_add(1);
            if self.rcv_unacked >= 2 {
                self.ack_due = true;
            } else {
                self.ack_at.get_or_insert(now + DELAYED_ACK);
            }
        }
    }

    /// RFC 9293 §3.10.7.4 fifth step, send side: SND.UNA, the send buffer, RTT, CC and SND.WND.
    /// `Break` means drop the segment and return.
    fn on_ack(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) -> ControlFlow<Reaction> {
        if seg.ack.lt(self.snd_una) {
            // An old duplicate ACK: ignored, the segment is processed further.
            return ControlFlow::Continue(());
        }
        if seg.ack.gt(self.snd_nxt) {
            self.ack_due = true;
            return ControlFlow::Break(Reaction::None);
        }
        if seg.ack.gt(self.snd_una) {
            let acked = self.snd_una.distance(seg.ack) as u32;
            self.snd_una = seg.ack;
            h.mark_acked(self.rel(seg.ack));
            let rtt = match self.rtt_timed {
                Some((end, sent)) if end.le(seg.ack) => {
                    self.rtt_timed = None;
                    self.rtt.sample(now - sent);
                    Some(now - sent)
                }
                _ => None,
            };
            let in_flight = self.in_flight();
            self.cc.on_ack(acked, rtt, in_flight, now);
            // RFC 6298 §5.2 / §5.3; R2 restarts with SND.UNA (ruling R8).
            let restart = (in_flight > 0).then_some(now);
            self.rto_at = restart.map(|t| t + self.rtt.rto());
            self.r2_since = restart;
        }
        if self.snd_wl1.lt(seg.seq) || (self.snd_wl1 == seg.seq && self.snd_wl2.le(seg.ack)) {
            self.snd_wnd = u32::from(seg.wnd) << self.snd_shift;
            self.max_snd_wnd = self.max_snd_wnd.max(self.snd_wnd);
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = seg.ack;
        }
        // An acceptable ACK with nothing outstanding or a zero window answers the probe (the
        // zero-length one, or the retransmission that probes while data is unacknowledged):
        // answered probes do not count toward R2 (MUST-37).
        if self.in_flight() == 0 || self.snd_wnd == 0 {
            self.r2_since = (self.in_flight() > 0).then_some(now);
        }
        ControlFlow::Continue(())
    }

    fn on_timeout_data(&mut self, now: Instant) -> Reaction {
        if self.r2_since.is_some_and(|t| now >= t + self.cfg.r2_data) {
            return self.close(CloseReason::Timeout, now);
        }
        if self.rto_at.is_some_and(|t| now >= t) {
            // RFC 6298 §5.4–5.6: the retransmission restarts the timer when it is sent.
            self.rto_at = None;
            self.rtt.backoff();
            // Karn: nothing in flight now is timed.
            self.rtt_timed = None;
            self.retransmit_due = true;
            self.cc
                .on_congestion(CongestionEvent::Rto, self.in_flight(), now);
        }
        if self.persist_at.is_some_and(|t| now >= t) {
            self.probe_due = true;
            self.persist_ivl = (self.persist_ivl * 2).min(MAX_PERSIST);
            self.persist_at = Some(now + self.persist_ivl);
        }
        if self.sws_at.is_some_and(|t| now >= t) {
            self.sws_at = None;
            self.sws_override = true;
        }
        if self.ack_at.is_some_and(|t| now >= t) {
            self.ack_at = None;
            self.ack_due = true;
        }
        Reaction::None
    }

    /// The retransmission, zero-window probe or new data segment due now, if any; also arms
    /// and disarms the persist and SWS override timers.
    fn poll_data(
        &mut self,
        now: Instant,
        h: &mut impl Hooks,
        out: &mut SegmentWriter,
    ) -> Option<SentMeta> {
        let in_flight = self.in_flight();
        if std::mem::take(&mut self.retransmit_due) && in_flight > 0 {
            // Sent even into a zero window: it is the probe then (spec §3).
            let len = in_flight.min(u32::from(self.eff_mss));
            return self.write_data(self.snd_una, len, now, h, out);
        }
        let queued = h.assigned_end().wrapping_sub(self.rel(self.snd_nxt));
        let idle = in_flight == 0;

        // RFC 9293 §3.8.6.1; never armed while data is unacknowledged.
        if idle && queued > 0 && self.snd_wnd == 0 {
            // Persist replaces the SWS override for this zero-window episode.
            self.sws_at = None;
            self.sws_override = false;
            if self.persist_at.is_none() {
                self.persist_ivl = self.rtt.rto();
                self.persist_at = Some(now + self.persist_ivl);
            }
            if !std::mem::take(&mut self.probe_due) {
                return None;
            }
            // Zero-length at SND.UNA − 1 (spec §3, I3). Unanswered probes count toward R2.
            self.r2_since.get_or_insert(now);
            let wnd = self.wnd_field(h);
            let seq = self.snd_una.wrapping_add(u32::MAX);
            return Some(out.start(seq, self.rcv_nxt, TcpFlags::ACK, wnd));
        }
        self.persist_at = None;
        self.probe_due = false;

        let sws_override = std::mem::take(&mut self.sws_override);
        let usable = self.snd_wnd.min(self.cc.cwnd()).saturating_sub(in_flight);
        let len = queued.min(usable).min(u32::from(self.eff_mss));
        if len == 0 {
            self.sws_at = None;
            return None;
        }
        // RFC 9293 §3.8.6.2.1 rules (1)–(4), Fs = 1/2; the bracketed SND.NXT = SND.UNA is
        // Nagle's (§3.7.4) and dropped by `set_nodelay(true)`. Every write counts as pushed.
        let nagle_ok = idle || self.nodelay;
        let send = len == u32::from(self.eff_mss)
            || (nagle_ok && queued <= usable)
            || (nagle_ok && len >= self.max_snd_wnd / 2)
            || sws_override;
        if !send {
            // Only an idle sender can stall here; otherwise the next ACK re-evaluates.
            if idle {
                self.sws_at.get_or_insert(now + SWS_OVERRIDE);
            } else {
                self.sws_at = None;
            }
            return None;
        }
        self.sws_at = None;
        let meta = self.write_data(self.snd_nxt, len, now, h, out)?;
        self.snd_nxt = self.snd_nxt.wrapping_add(meta.len);
        self.rtt_timed.get_or_insert((self.snd_nxt, now));
        Some(meta)
    }

    /// Writes up to `len` octets from SEQ `seq` (PSH if it ends at `assigned_end`) and starts
    /// the RTO and R2 clocks if they are not running (RFC 6298 §5.1).
    fn write_data(
        &mut self,
        seq: SeqNum,
        len: u32,
        now: Instant,
        h: &mut impl Hooks,
        out: &mut SegmentWriter,
    ) -> Option<SentMeta> {
        let wnd = self.wnd_field(h);
        let mut meta = out.start(seq, self.rcv_nxt, TcpFlags::ACK, wnd);
        let start = self.rel(seq);
        let mut got = 0u32;
        // A run may end early at a buffer boundary; an empty run is not progress.
        while got < len {
            let run = h.peek_with(start.wrapping_add(got), (len - got) as usize, |d| {
                out.payload.extend_from_slice(d);
                d.len() as u32
            });
            match run {
                Some(n) if n > 0 => got += n,
                _ => break,
            }
        }
        if got == 0 {
            return None;
        }
        if start.wrapping_add(got) == h.assigned_end() {
            out.flags = TcpFlags::PSH | TcpFlags::ACK;
        }
        meta.flags = out.flags;
        meta.len = got;
        self.rto_at.get_or_insert(now + self.rtt.rto());
        self.r2_since.get_or_insert(now);
        Some(meta)
    }

    fn in_flight(&self) -> u32 {
        self.snd_una.distance(self.snd_nxt) as u32
    }

    /// Relative SSN of `seq`: ISS + 1 is SSN 1 (spec §5.3).
    fn rel(&self, seq: SeqNum) -> u32 {
        seq.0.wrapping_sub(self.iss.0)
    }

    /// Window field of a non-SYN segment; records the right edge it advertises if it is the
    /// largest so far (only a zero window retracts it, and acceptability keeps the largest).
    fn wnd_field(&mut self, h: &impl Hooks) -> u16 {
        let (field, edge) = self.window_offer(h);
        if edge.gt(self.rcv_right_edge) {
            self.rcv_right_edge = edge;
        }
        field
    }

    /// The window field to send now and the right edge it advertises (spec §5.4 applied to
    /// plain TCP): the edge moves to RCV.NXT + free memory only in steps of the receiver SWS
    /// threshold (RFC 9293 §3.8.6.2.2), otherwise the current edge is re-advertised; it never
    /// moves left (SHLD-14), rounding up to the scale granularity only when needed. With no
    /// free memory the window is 0: the edge retracts by less than 2^scale (RFC 7323 §2.4),
    /// rather than promising octets that could never be stored.
    fn window_offer(&self, h: &impl Hooks) -> (u16, SeqNum) {
        let offered = self.rcv_wnd();
        let free = h.recv_window();
        if free == 0 {
            return (0, self.rcv_nxt);
        }
        let target = if self.sws_moves(free) { free } else { 0 };
        let mut field = (target >> self.rcv_shift).min(65535);
        if field << self.rcv_shift < offered {
            // At most 65535: `offered` came from a field of at most 65535.
            field = offered.div_ceil(1 << self.rcv_shift);
        }
        (
            field as u16,
            self.rcv_nxt.wrapping_add(field << self.rcv_shift),
        )
    }

    /// Receiver SWS (RFC 9293 §3.8.6.2.2): `buffer_edge − right_edge >= min(buffer/2, eff_mss)`.
    fn sws_moves(&self, free: u32) -> bool {
        let sws = (self.cfg.recv_buffer / 2).min(u32::from(self.eff_mss));
        free.saturating_sub(self.rcv_wnd()) >= sws
    }

    /// After a read, an update is sent only if the SWS rule moves the edge by at least the
    /// window the peer still has (ruling R15): a closed window reopens at once, while reads
    /// during a transfer ride on the ACKs the data draws anyway, and neither the creep of a
    /// rounded-up edge nor a field capped at 65535 draws an extra ACK per segment.
    fn window_update_due(&self, h: &impl Hooks) -> bool {
        let free = h.recv_window();
        let grow = self.rcv_right_edge.distance(self.window_offer(h).1);
        self.sws_moves(free) && grow > 0 && grow as u32 >= self.rcv_wnd()
    }

    /// RCV.WND: from RCV.NXT to the largest edge advertised.
    fn rcv_wnd(&self) -> u32 {
        self.rcv_nxt.distance(self.rcv_right_edge).max(0) as u32
    }

    /// Our ACK is going out: the delayed ACK is done.
    fn ack_sent(&mut self) {
        self.ack_due = false;
        self.ack_at = None;
        self.rcv_unacked = 0;
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
mod tests;
