//! Pure TCP state machine (RFC 9293), driven by segments, time and hooks (spec §3, §3.1).

use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::time::Duration;

use rangemap::RangeSet;

use super::cc::{CongestionControl, CongestionEvent, RecoveryAck, Reno};
use super::hooks::Hooks;
use super::recovery::{DupAck, NewAck, NewReno};
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
/// Maximum segment lifetime: 60 s, below RFC 9293's "arbitrarily 2 minutes" as common stacks
/// do; TIME-WAIT lasts 2·MSL (MUST-13).
const MSL: Duration = Duration::from_secs(60);

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
    /// Next sequence number to send; pulled back to SND.UNA by an RTO (go-back).
    snd_nxt: SeqNum,
    /// One past the highest sequence number sent (SND.MAX). ACKs up to it are acceptable and
    /// SND.MAX − SND.UNA is what is outstanding (FlightSize).
    snd_max: SeqNum,
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
    /// Relative SSN of our FIN: the end of the data queued at the first `poll_send` after
    /// `close`. Nothing queued later is sent.
    fin_rel: Option<u32>,

    // Receive sequence space.
    rcv_nxt: SeqNum,
    /// Relative SSN of RCV.NXT, not wrapped (IRS + 1 is 1); keys `rcv_ooo`.
    rcv_ssn: u64,
    /// Shift applied to our window fields (RFC 7323 Rcv.Wind.Shift). Holds our offer until the
    /// SYN/ACK; 0 if the peer did not offer.
    rcv_shift: u8,
    /// Largest right window edge ever advertised (never moves left, RFC 9293 SHLD-14).
    rcv_right_edge: SeqNum,
    /// The edge the receiver SWS rule last set; every window is rounded up from it. It never
    /// passes the memory's edge (RCV.NXT + free + held out of order), which only moves right.
    rcv_sws_edge: SeqNum,
    /// Out-of-order receipt ranges (headers only, spec §2 step 4), in unwrapped relative SSN.
    /// Exactly the octets the hooks hold out of order.
    rcv_ooo: RangeSet<u64>,
    /// Peer offered SACK-Permitted in its SYN; our sender still uses NewReno.
    sack_permitted: bool,
    /// Points in the most recently received out-of-order blocks, newest first.
    sack_recent: Vec<u64>,
    /// Duplicate data from the latest input, reported once (RFC 2883).
    dsack: Option<(SeqNum, SeqNum)>,
    /// In-order data segments received since our last ACK.
    rcv_unacked: u8,
    /// The peer's FIN is received (RCV.NXT is past it).
    fin_received: bool,

    cc: Box<dyn CongestionControl>,
    recovery: NewReno,

    // Timers.
    rtt: RttEstimator,
    /// Retransmission timer (SYN, then data at SND.UNA).
    rto_at: Option<Instant>,
    /// End of the last retransmission at SND.UNA and its earliest permitted RTO expiry
    /// (RFC 6298 §5). Cleared once all of that segment, including any FIN, is acknowledged.
    rto_not_before: Option<(SeqNum, Instant)>,
    /// The one timed segment (Karn): its end and send time; cleared by any RTO.
    rtt_timed: Option<(SeqNum, Instant)>,
    /// When data octets last went out (RFC 5681 §4.1 idle detection).
    last_data_sent: Option<Instant>,
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
    /// End of TIME-WAIT.
    time_wait_at: Option<Instant>,
    /// `None` in `Closed` only after a `close` in SYN-SENT that `on_timeout` has not reported.
    closed_at: Option<Instant>,

    // Segments due at the next `poll_send`.
    syn_due: bool,
    ack_due: bool,
    /// RST answering an unacceptable ACK, `<SEQ=SEG.ACK><CTL=RST>`.
    rst_due: Option<SeqNum>,
    /// Resend one segment at SND.UNA (RTO, fast retransmit, partial ACK).
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
        Self::with_cc(cfg, local, remote, isn, now, Box::new(Reno::new()))
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
            snd_max: isn,
            snd_wnd: 0,
            snd_shift: 0,
            snd_wl1: SeqNum(0),
            snd_wl2: SeqNum(0),
            max_snd_wnd: 0,
            eff_mss: 0,
            fin_rel: None,
            rcv_nxt: SeqNum(0),
            rcv_ssn: 0,
            rcv_shift: ws_shift(cfg.recv_buffer),
            rcv_right_edge: SeqNum(0),
            rcv_sws_edge: SeqNum(0),
            rcv_ooo: RangeSet::new(),
            sack_permitted: false,
            sack_recent: Vec::new(),
            dsack: None,
            rcv_unacked: 0,
            fin_received: false,
            cc,
            recovery: NewReno::new(isn),
            rtt: RttEstimator::new(),
            rto_at: None,
            rto_not_before: None,
            rtt_timed: None,
            last_data_sent: None,
            r2_since: None,
            persist_at: None,
            persist_ivl: Duration::ZERO,
            sws_at: None,
            ack_at: None,
            first_syn_at: None,
            time_wait_at: None,
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
    /// `peer_ws` (window 65535) at `now`; the handshake ACK is due. `cc::Reno`.
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
        let mut tcb = Self::with_cc(cfg, local, remote, isn, now, Box::new(Reno::new()));
        tcb.syn_due = false;
        tcb.snd_nxt = isn.wrapping_add(1);
        tcb.snd_max = tcb.snd_nxt;
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

    /// RFC 9293 §3.10.4 CLOSE; idempotent. ESTABLISHED → FIN-WAIT-1 and CLOSE-WAIT →
    /// LAST-ACK at once; the FIN follows the data queued at the next `poll_send`, and nothing
    /// queued after that is sent (the Connection rejects writes after `close` before they
    /// reach the hooks).
    ///
    /// SYN-SENT: the TCB is deleted. `state()` is `Closed` at once and nothing more is sent or
    /// accepted; `poll_send_at` reports a deadline that is already due, and the next
    /// `on_timeout` returns `Closed(Normal)`, once, and sets `closed_at`.
    pub fn close(&mut self) {
        self.state = match self.state {
            TcpState::SynSent => TcpState::Closed,
            TcpState::Established => TcpState::FinWait1,
            TcpState::CloseWait => TcpState::LastAck,
            s => s,
        };
    }

    #[cfg(test)]
    pub(crate) fn mtu(&self) -> usize {
        usize::from(self.cfg.mtu)
    }

    /// The peer's FIN has been received. Every data octet before it was handed to the hooks
    /// first, so once they hold no more data the application's read is at EOF.
    pub fn fin_received(&self) -> bool {
        self.fin_received
    }

    /// Switches Nagle off (`true`) or on (`false`, the default).
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
    }

    pub fn on_segment(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) -> Reaction {
        match self.state {
            TcpState::Closed => Reaction::None,
            TcpState::SynSent => {
                let r = self.on_segment_syn_sent(seg, now);
                if r == Reaction::Established {
                    h.on_valid_segment(seg);
                    // §3.10.7.3: text and FIN on the SYN/ACK are processed once ESTABLISHED,
                    // from the sequence number after the SYN. The FIN's CLOSE-WAIT move
                    // emits no `Closed`, so the reaction stays `Established`.
                    let text = Segment {
                        seq: seg.seq.wrapping_add(1),
                        ..seg.clone()
                    };
                    self.on_text_and_fin(&text, now, h);
                }
                r
            }
            _ => self.on_segment_sync(seg, now, h),
        }
    }

    /// Processes every timer expiry due at `now` (spec §3.1).
    pub fn on_timeout(&mut self, now: Instant, _h: &mut impl Hooks) -> Reaction {
        match self.state {
            TcpState::SynSent => self.on_timeout_syn_sent(now),
            // A `close` in SYN-SENT, reported once.
            TcpState::Closed if self.closed_at.is_none() => {
                self.closed_at = Some(now);
                Reaction::Closed(CloseReason::Normal)
            }
            TcpState::Closed => Reaction::None,
            TcpState::TimeWait => {
                if self.time_wait_at.is_some_and(|t| now >= t) {
                    // `Closed(Normal)` was returned on entering TIME-WAIT.
                    self.terminate(CloseReason::Normal, now);
                }
                Reaction::None
            }
            _ => self.on_timeout_data(now),
        }
    }

    pub fn poll_send(
        &mut self,
        now: Instant,
        h: &mut impl Hooks,
        out: &mut SegmentWriter,
    ) -> Option<SentMeta> {
        if let Some(seq) = self.rst_due.take() {
            return Some(out.start(seq, SeqNum(0), TcpFlags::RST, 0));
        }
        if self.state == TcpState::Closed {
            return None;
        }
        if self.syn_due {
            self.syn_due = false;
            self.first_syn_at.get_or_insert(now);
            self.rto_at = Some(now + self.rtt.rto());
            self.snd_nxt = self.iss.wrapping_add(1);
            self.snd_max = self.snd_nxt;
            // RFC 7323 §2.2: the window field of a SYN is never scaled.
            let wnd = self.cfg.recv_buffer.min(65535) as u16;
            let meta = out.start(self.iss, SeqNum(0), TcpFlags::SYN, wnd);
            let n = h.options_for(TcpFlags::SYN, &mut out.options);
            let n = n + tcp_options::write_mss(&mut out.options[n..], self.mss_option());
            let n = n + tcp_options::write_ws(&mut out.options[n..], self.rcv_shift);
            out.options_len = n + tcp_options::write_sack_permitted(&mut out.options[n..]);
            return Some(meta);
        }
        if !matches!(self.state, TcpState::SynSent | TcpState::TimeWait) {
            let fin_unsent = matches!(
                self.state,
                TcpState::FinWait1 | TcpState::Closing | TcpState::LastAck
            );
            if fin_unsent && self.fin_rel.is_none() {
                self.fin_rel = Some(h.assigned_end());
            }
            let mut options = [0u8; 40];
            let limit = usize::from(self.eff_mss.saturating_sub(1)).min(options.len());
            let n = h.options_for(TcpFlags::ACK, &mut options);
            let n = n + self.write_sacks(&mut options[n..limit.max(n)]);
            if n < usize::from(self.eff_mss) {
                if let Some(meta) = self.poll_data(now, h, out, n as u16) {
                    out.options[..n].copy_from_slice(&options[..n]);
                    out.options_len = n;
                    // Every data segment, FIN and probe carries the current ACK.
                    self.ack_sent();
                    return Some(meta);
                }
            }
            // A read that let the window edge move is announced (RFC 9293 §3.8.6.2.2), while
            // data can still arrive.
            if !self.ack_due && !self.fin_received && self.window_update_due(h) {
                self.ack_due = true;
            }
        }
        if self.ack_due {
            let wnd = self.wnd_field(h);
            // SND.MAX, not a pulled-back SND.NXT: a SEQ below the peer's RCV.NXT would make
            // the ACK unacceptable to it (RFC 9293 Table 6).
            let meta = out.start(self.snd_max, self.rcv_nxt, TcpFlags::ACK, wnd);
            let limit = usize::from(self.mss_option()).min(out.options.len());
            let n = h.options_for(TcpFlags::ACK, &mut out.options);
            out.options_len = n + self.write_sacks(&mut out.options[n..limit.max(n)]);
            self.ack_sent();
            return Some(meta);
        }
        None
    }

    /// The next timer deadline; `closed_at` once `Closed`. Segments made due by an input are
    /// not reported here: the driver calls `poll_send` after every input.
    pub fn poll_send_at(&self) -> Option<Instant> {
        match self.state {
            // Due at once after a `close` in SYN-SENT.
            TcpState::Closed => Some(self.closed_at.unwrap_or(Instant::from_nanos(0))),
            TcpState::SynSent => {
                let r2 = self.first_syn_at.map(|t| t + self.r2_syn());
                [self.rto_at, r2].into_iter().flatten().min()
            }
            TcpState::TimeWait => self.time_wait_at,
            _ => {
                let r2 = self.r2_since.map(|t| t + self.cfg.r2_data);
                [
                    self.rto_deadline(),
                    r2,
                    self.persist_at,
                    self.sws_at,
                    self.ack_at,
                ]
                .into_iter()
                .flatten()
                .min()
            }
        }
    }

    /// Preserve NewReno's nominal timer (only the first partial ACK restarts it), while
    /// preventing a timer-based retry less than one RTO after the last retransmission.
    fn rto_deadline(&self) -> Option<Instant> {
        self.rto_at.map(|at| {
            self.rto_not_before
                .map_or(at, |(_, earliest)| at.max(earliest))
        })
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
            return self.terminate(CloseReason::Reset, now);
        }
        if !seg.flags.contains(TcpFlags::SYN) {
            return Reaction::None;
        }

        let (mut mss, mut ws) = (None, None);
        for opt in tcp_options::walk(seg.options).map_while(Result::ok) {
            match opt {
                TcpOpt::Mss(m) => mss = Some(m),
                TcpOpt::WindowScale(s) => ws = Some(s),
                TcpOpt::SackPermitted => self.sack_permitted = true,
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
        self.rcv_sws_edge = self.rcv_right_edge;
        self.snd_una = seg.ack;
        self.snd_wnd = u32::from(seg.wnd);
        self.max_snd_wnd = self.snd_wnd;
        self.snd_wl1 = seg.seq;
        self.snd_wl2 = seg.ack;
        self.recovery.last_wnd = self.snd_wnd;
        // RFC 6298 §5.7: the timer expired awaiting the SYN's ACK (only then is RTO above 1 s).
        let syn_lost = self.rtt.rto() > INITIAL_RTO;
        if syn_lost {
            self.rtt.reinit_after_syn_retransmission();
        }
        self.cc.init(u32::from(self.eff_mss), syn_lost);
        // A SYN retransmission made due by an RTO that fired just before is now moot.
        self.syn_due = false;
        self.rto_at = None;
        self.ack_due = true;
        self.state = TcpState::Established;
        Reaction::Established
    }

    fn on_timeout_syn_sent(&mut self, now: Instant) -> Reaction {
        if self.first_syn_at.is_some_and(|t| now >= t + self.r2_syn()) {
            return self.terminate(CloseReason::Timeout, now);
        }
        if self.rto_at.is_some_and(|t| now >= t) {
            self.rto_at = None;
            self.rtt.backoff();
            self.syn_due = true;
        }
        Reaction::None
    }

    /// RFC 9293 §3.10.7.4 in the synchronized states.
    fn on_segment_sync(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) -> Reaction {
        let fin = seg.flags.contains(TcpFlags::FIN);
        // Second step, on SEG.SEQ alone (RFC 5961 §3 as RFC 9293 gives it): RCV.NXT exactly
        // resets, elsewhere in the window draws a challenge ACK, outside it the RST is dropped
        // silently. This also covers the first step for RSTs and, with the window empty, the
        // "special allowance" for them (a RST with text at RCV.NXT still resets). No RFC 5961
        // challenge-ACK rate limit.
        if seg.flags.contains(TcpFlags::RST) {
            let off = self.rcv_nxt.distance(seg.seq);
            if off == 0 {
                h.on_valid_segment(seg);
                return self.on_reset(now);
            }
            self.ack_due |= off > 0 && (off as u32) < self.rcv_wnd();
            return Reaction::None;
        }
        // TIME-WAIT: a retransmitted FIN ends at RCV.NXT, below the window, so it is ACKed and
        // restarts 2·MSL here rather than in the fifth and eighth steps it cannot reach.
        let seg_end = seg.seq.wrapping_add(seg.payload.len() as u32);
        if self.state == TcpState::TimeWait && fin && seg_end.wrapping_add(1) == self.rcv_nxt {
            self.time_wait_at = Some(now + 2 * MSL);
            self.ack_due = true;
            return Reaction::None;
        }
        // First: an unacceptable segment draws an ACK and is dropped.
        let delegated =
            h.delegates_data() && !seg.payload.is_empty() && !seg.flags.contains(TcpFlags::SYN);
        if !delegated && !self.acceptable(seg) {
            self.ack_due = true;
            if seg.flags.contains(TcpFlags::ACK)
                && !seg.flags.contains(TcpFlags::SYN)
                && !seg.ack.gt(self.snd_max)
            {
                self.record_dsack(seg);
            }
            // "If the RCV.WND is zero, ... special allowance should be made to accept valid
            // ACKs": with our window closed, the ACK field of a segment from RCV.NXT up to one
            // past the largest edge is still processed; its text is not. One past: a one-octet
            // probe into the closed window (RFC 9293 §3.8.6.1) moves the peer's SND.NXT there.
            let ack_only = seg.flags.contains(TcpFlags::ACK) && !seg.flags.contains(TcpFlags::SYN);
            let edge = self.rcv_right_edge.wrapping_add(1);
            if ack_only
                && self.rcv_nxt.le(seg.seq)
                && seg.seq.le(edge)
                && self.window_offer(h).0 == 0
            {
                if let ControlFlow::Break(r) = self.on_ack(seg, now, h) {
                    return r;
                }
            }
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
        self.on_text_and_fin(seg, now, h)
    }

    /// Seventh and eighth steps. Seventh, until the peer's FIN (URG is not processed: urgent
    /// data is delivered inline, RFC 6093); text after the FIN is ignored. Eighth: a FIN right
    /// after all the text before it.
    fn on_text_and_fin(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) -> Reaction {
        if !h.reset_requested() && !self.fin_received {
            self.on_text(seg, now, h);
        }
        if h.reset_requested() {
            self.rst_due = Some(self.snd_max);
            return self.terminate(CloseReason::Reset, now);
        }
        let seg_end = seg.seq.wrapping_add(seg.payload.len() as u32);
        // Trim sequence-space controls to the receive window too (RFC 9293 §3.10.7.4).
        // Text may consume the whole window, leaving the following FIN outside it.
        if seg.flags.contains(TcpFlags::FIN) {
            if !seg_end.lt(self.rcv_right_edge) {
                self.ack_due = true;
            } else if seg_end == self.rcv_nxt {
                return self.on_fin(now);
            }
        }
        Reaction::None
    }

    /// Eighth step for a FIN at RCV.NXT: ACK it at once, CLOSE-WAIT / CLOSING / TIME-WAIT.
    fn on_fin(&mut self, now: Instant) -> Reaction {
        self.ack_due = true;
        if self.fin_received {
            // A second FIN where the first one ended: only ACKed.
            return Reaction::None;
        }
        self.fin_received = true;
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        match self.state {
            TcpState::Established => self.state = TcpState::CloseWait,
            // Our FIN is not ACKed yet: `on_ack` moves FIN-WAIT-1 to FIN-WAIT-2 when it is.
            TcpState::FinWait1 => self.state = TcpState::Closing,
            TcpState::FinWait2 => return self.enter_time_wait(now),
            _ => {}
        }
        Reaction::None
    }

    /// The only entry into TIME-WAIT: start 2·MSL, stop the other timers, `Closed(Normal)`.
    fn enter_time_wait(&mut self, now: Instant) -> Reaction {
        self.state = TcpState::TimeWait;
        self.time_wait_at = Some(now + 2 * MSL);
        self.rto_at = None;
        self.rto_not_before = None;
        self.r2_since = None;
        self.persist_at = None;
        self.sws_at = None;
        self.ack_at = None;
        Reaction::Closed(CloseReason::Normal)
    }

    /// An acceptable RST (second step): CLOSED. In TIME-WAIT, `Closed(Normal)` was already
    /// returned, so nothing more is.
    fn on_reset(&mut self, now: Instant) -> Reaction {
        if self.state == TcpState::TimeWait {
            self.terminate(CloseReason::Normal, now);
            return Reaction::None;
        }
        self.terminate(CloseReason::Reset, now)
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
        self.record_dsack(seg);
        if h.delegates_data() {
            self.on_delegated_text(seg, h);
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
            if self.sack_permitted && lo > 0 {
                // Retain only points in other held blocks; insertion may have coalesced them.
                self.sack_recent.retain(|point| {
                    self.rcv_ooo
                        .get(point)
                        .is_some_and(|r| !r.contains(&(e - 1)))
                });
                self.sack_recent.insert(0, e - 1);
                self.sack_recent.truncate(4);
            }
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

    /// MPTCP receipts are headers only, independent of DSN retention and eviction.
    fn on_delegated_text(&mut self, seg: &Segment, h: &mut impl Hooks) {
        let off = i64::from(self.rcv_nxt.distance(seg.seq));
        let ssn = (self.rcv_ssn as u32).wrapping_add_signed(off as i32);
        for range in h.receive_data(ssn, self.rcv_ssn as u32, seg.payload) {
            let lo = (off + range.start as i64).max(0);
            let hi = off + range.end as i64;
            if lo >= hi {
                continue;
            }
            let (s, e) = (self.rcv_ssn + lo as u64, self.rcv_ssn + hi as u64);
            if lo > 0
                && !self.rcv_ooo.overlaps(&(s - 1..e + 1))
                && self.rcv_ooo.len() >= MAX_OOO_RANGES
            {
                continue;
            }
            self.rcv_ooo.insert(s..e);
            if self.sack_permitted && lo > 0 {
                self.sack_recent.retain(|point| {
                    self.rcv_ooo
                        .get(point)
                        .is_some_and(|r| !r.contains(&(e - 1)))
                });
                self.sack_recent.insert(0, e - 1);
                self.sack_recent.truncate(4);
            }
        }
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
        h.receipt_advanced(self.rcv_ssn as u32);
        self.ack_due = true;
    }

    /// RFC 9293 §3.10.7.4 fifth step, send side: SND.UNA, the send buffer, RTT, loss recovery,
    /// CC and SND.WND. `Break` means drop the segment and return.
    fn on_ack(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) -> ControlFlow<Reaction> {
        if seg.ack.lt(self.snd_una) {
            // An old duplicate ACK: ignored, the segment is processed further.
            h.on_valid_segment(seg);
            return ControlFlow::Continue(());
        }
        if seg.ack.gt(self.snd_max) {
            self.ack_due = true;
            return ControlFlow::Break(Reaction::None);
        }
        h.on_valid_segment(seg);
        // Duplicate ACK (RFC 5681 §2), judged before this segment updates SND.WND.
        let wnd = u32::from(seg.wnd) << self.snd_shift;
        let abcd = self.in_flight() > 0
            && seg.payload.is_empty()
            && !seg.flags.contains(TcpFlags::SYN)
            && !seg.flags.contains(TcpFlags::FIN)
            && seg.ack == self.snd_una;
        if self.recovery.is_duplicate(abcd, wnd) {
            match self.recovery.on_dup_ack(seg.ack, self.snd_max) {
                DupAck::Ignore => {}
                DupAck::FastRetransmit => {
                    let flight = self.in_flight();
                    self.cc
                        .on_congestion(CongestionEvent::FastRetransmit, flight, now);
                    self.retransmit_due = true;
                }
                DupAck::Inflate => self.cc.on_recovery_ack(RecoveryAck::Duplicate),
            }
        }
        if seg.ack.gt(self.snd_una) {
            let acked = self.snd_una.distance(seg.ack) as u32;
            self.snd_una = seg.ack;
            if self.rto_not_before.is_some_and(|(end, _)| end.le(seg.ack)) {
                self.rto_not_before = None;
            }
            // An ACK past a pulled-back SND.NXT: those octets need no resend.
            if self.snd_nxt.lt(self.snd_una) {
                self.snd_nxt = self.snd_una;
            }
            // The FIN is not in the send buffer.
            let data_una = self.fin_seq().filter(|f| f.lt(seg.ack)).unwrap_or(seg.ack);
            h.mark_acked(self.rel(data_una));
            let rtt = match self.rtt_timed {
                Some((end, sent)) if end.le(seg.ack) => {
                    self.rtt_timed = None;
                    self.rtt.sample(now - sent);
                    Some(now - sent)
                }
                _ => None,
            };
            let in_flight = self.in_flight();
            // RFC 6298 §5.2 / §5.3, except that only the first partial ACK of a fast recovery
            // restarts the timer (RFC 6582 §3.2 step 3); R2 restarts with SND.UNA (ruling R8).
            let mut restart_rto = true;
            match self.recovery.on_new_ack(seg.ack) {
                NewAck::Normal => self.cc.on_ack(acked, rtt, in_flight, now),
                NewAck::Partial { first } => {
                    self.cc.on_recovery_ack(RecoveryAck::Partial { acked });
                    self.retransmit_due = true;
                    restart_rto = first;
                }
                NewAck::Full => self.cc.on_recovery_ack(RecoveryAck::Full { in_flight }),
            }
            let restart = (in_flight > 0).then_some(now);
            if restart_rto {
                self.rto_at = restart.map(|t| t + self.rtt.rto());
            }
            self.r2_since = restart;
        }
        if self.snd_wl1.lt(seg.seq) || (self.snd_wl1 == seg.seq && self.snd_wl2.le(seg.ack)) {
            self.snd_wnd = wnd;
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
        if self.fin_seq().is_some_and(|f| f.lt(self.snd_una)) {
            // Our FIN is acknowledged.
            match self.state {
                TcpState::FinWait1 => self.state = TcpState::FinWait2,
                TcpState::Closing => return ControlFlow::Break(self.enter_time_wait(now)),
                TcpState::LastAck => {
                    return ControlFlow::Break(self.terminate(CloseReason::Normal, now));
                }
                _ => {}
            }
        }
        ControlFlow::Continue(())
    }

    fn on_timeout_data(&mut self, now: Instant) -> Reaction {
        if self.r2_since.is_some_and(|t| now >= t + self.cfg.r2_data) {
            return self.terminate(CloseReason::Timeout, now);
        }
        if self.rto_deadline().is_some_and(|t| now >= t) {
            // RFC 6298 §5.4–5.6: the retransmission restarts the timer when it is sent.
            self.rto_at = None;
            self.rto_not_before = None;
            self.rtt.backoff();
            // Karn: nothing in flight now is timed.
            self.rtt_timed = None;
            self.cc
                .on_congestion(CongestionEvent::Rto, self.in_flight(), now);
            self.recovery.on_rto(self.snd_max);
            // Go back (RFC 5681 §3.1, RFC 6298 §5.4): SND.UNA's segment now, the rest of the
            // window under slow start as ACKs return.
            self.snd_nxt = self.snd_una;
            self.retransmit_due = true;
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
        options_len: u16,
    ) -> Option<SentMeta> {
        let mss = u32::from(self.eff_mss - options_len);
        let in_flight = self.in_flight();
        if std::mem::take(&mut self.retransmit_due) && in_flight > 0 {
            // The segment at SND.UNA (RTO, fast retransmit, partial ACK): sent regardless of
            // cwnd, Nagle and SWS, even into a zero window, where it is the probe (spec §3).
            // Karn: no RTT sample from anything now in flight.
            self.rtt_timed = None;
            let len = self.data_len(self.snd_una, self.snd_max).min(mss);
            let fin = self.fin_sent();
            let meta = self.write_data(self.snd_una, len, fin, now, h, out)?;
            let end = self.snd_una.wrapping_add(seq_len(&meta));
            self.rto_not_before = Some((end, now + self.rtt.rto()));
            if end.gt(self.snd_nxt) {
                self.snd_nxt = end;
            }
            return Some(meta);
        }
        let queued = self.data_len(self.snd_nxt, self.iss.wrapping_add(h.assigned_end()));
        let fin_pending = self.fin_rel.is_some() && !self.fin_sent();
        let idle = in_flight == 0;

        // RFC 9293 §3.8.6.1 (a FIN waits for the window like data); never armed while data is
        // unacknowledged.
        if idle && (queued > 0 || fin_pending) && self.snd_wnd == 0 {
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

        // RFC 5681 §4.1: "a TCP SHOULD set cwnd to no more than RW before beginning
        // transmission if the TCP has not sent data in an interval exceeding the
        // retransmission timeout" (the SHOULD, not the receive-side wording of the prose
        // above it). Idempotent, so a send held back by Nagle may repeat it.
        if idle
            && queued > 0
            && self
                .last_data_sent
                .is_some_and(|t| now > t + self.rtt.rto())
        {
            self.cc.on_idle_restart();
        }

        // RFC 5681 §2: nothing beyond SND.UNA + min(cwnd, rwnd); after a go-back the octets
        // between SND.NXT and SND.MAX count as lost.
        let sent = self.snd_una.distance(self.snd_nxt) as u32;
        let usable = self.snd_wnd.min(self.cc.cwnd()).saturating_sub(sent);
        let resend = self.snd_nxt.distance(self.snd_max) as u32;
        if resend > 0 {
            // Go-back: resends stop at SND.MAX and skip Nagle and SWS; they are not timed. The
            // FIN goes again if the window has room behind the data.
            let len = self
                .data_len(self.snd_nxt, self.snd_max)
                .min(usable)
                .min(mss);
            let fin = self.fin_sent() && usable > len;
            let meta = self.write_data(self.snd_nxt, len, fin, now, h, out)?;
            self.snd_nxt = self.snd_nxt.wrapping_add(seq_len(&meta));
            return Some(meta);
        }
        let sws_override = std::mem::take(&mut self.sws_override);
        let len = queued.min(usable).min(mss);
        // The FIN takes one sequence number of the window, behind the last data octet.
        let fin = fin_pending && usable > len;
        if len == 0 && !fin {
            self.sws_at = None;
            return None;
        }
        // RFC 9293 §3.8.6.2.1 rules (1)–(4), Fs = 1/2; the bracketed SND.NXT = SND.UNA is
        // Nagle's (§3.7.4) and dropped by `set_nodelay(true)`. Every write counts as pushed.
        // A FIN alone is sent at once.
        let nagle_ok = idle || self.nodelay;
        let send = len == 0
            || len == mss
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
        let meta = self.write_data(self.snd_nxt, len, fin, now, h, out)?;
        self.snd_nxt = self.snd_nxt.wrapping_add(seq_len(&meta));
        self.snd_max = self.snd_nxt;
        // New data only (SEQ = SND.MAX): resends never get here (Karn).
        self.rtt_timed.get_or_insert((self.snd_nxt, now));
        Some(meta)
    }

    /// Writes up to `len` data octets from SEQ `seq`, PSH if they end at the last queued octet,
    /// and the FIN if `fin` and they end where it sits; `None` if neither data nor FIN goes.
    /// Starts the RTO and R2 clocks if they are not running (RFC 6298 §5.1).
    fn write_data(
        &mut self,
        seq: SeqNum,
        len: u32,
        fin: bool,
        now: Instant,
        h: &mut impl Hooks,
        out: &mut SegmentWriter,
    ) -> Option<SentMeta> {
        let (wnd, edge, sws_edge) = self.window_offer(h);
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
        let end = start.wrapping_add(got);
        let fin = fin && self.fin_rel == Some(end);
        if got == 0 && !fin {
            return None;
        }
        if got > 0 && end == self.fin_rel.unwrap_or(h.assigned_end()) {
            out.flags = out.flags | TcpFlags::PSH;
        }
        if fin {
            out.flags = out.flags | TcpFlags::FIN;
        }
        meta.flags = out.flags;
        meta.len = got;
        self.record_offer(edge, sws_edge);
        if got > 0 {
            self.last_data_sent = Some(now);
        }
        self.rto_at.get_or_insert(now + self.rtt.rto());
        self.r2_since.get_or_insert(now);
        Some(meta)
    }

    /// Octets outstanding: SND.MAX − SND.UNA (FlightSize).
    fn in_flight(&self) -> u32 {
        self.snd_una.distance(self.snd_max) as u32
    }

    /// SEQ of our FIN, once fixed.
    fn fin_seq(&self) -> Option<SeqNum> {
        self.fin_rel.map(|r| self.iss.wrapping_add(r))
    }

    fn fin_sent(&self) -> bool {
        self.fin_seq().is_some_and(|f| f.lt(self.snd_max))
    }

    /// Data octets from `seq` to `end`, stopping at the FIN; 0 if `seq` is past either.
    fn data_len(&self, seq: SeqNum, end: SeqNum) -> u32 {
        let end = self.fin_seq().filter(|f| f.lt(end)).unwrap_or(end);
        seq.distance(end).max(0) as u32
    }

    /// Relative SSN of `seq`: ISS + 1 is SSN 1 (spec §5.3).
    fn rel(&self, seq: SeqNum) -> u32 {
        seq.0.wrapping_sub(self.iss.0)
    }

    /// Window field of a non-SYN segment. Records the SWS edge, and the advertised edge if it
    /// is the largest so far (acceptability keeps the largest).
    fn wnd_field(&mut self, h: &impl Hooks) -> u16 {
        let (field, edge, sws_edge) = self.window_offer(h);
        self.record_offer(edge, sws_edge);
        field
    }

    /// Records an advertised window. Only for a segment that is really going out.
    fn record_offer(&mut self, edge: SeqNum, sws_edge: SeqNum) {
        self.rcv_sws_edge = sws_edge;
        if edge.gt(self.rcv_right_edge) {
            self.rcv_right_edge = edge;
        }
    }

    /// The window field to send now, the edge it advertises and the SWS edge behind it
    /// (spec §5.4 applied to plain TCP, ruling R16).
    ///
    /// The SWS edge moves to the scale-aligned RCV.NXT + free memory only when the receiver
    /// SWS rule allows (RFC 9293 §3.8.6.2.2) and never moves left; the field is the SWS edge
    /// rounded up to the scale unit, so it rounds only when the edge is re-advertised from an
    /// older RCV.NXT.
    ///
    /// Invariant: the SWS edge never passes the memory's edge, so the advertised edge is less
    /// than 2^scale beyond it, and no advertisement retracts the largest edge by 2^scale or
    /// more (RFC 7323 §2.4). With no free memory nothing is held out of order (a hole below it
    /// would be free), the SWS edge is at or before RCV.NXT and the field is 0 (ruling R14).
    fn window_offer(&self, h: &impl Hooks) -> (u16, SeqNum, SeqNum) {
        let free = h.recv_window();
        let mut sws_edge = self.rcv_sws_edge;
        if self.sws_moves(free) {
            let aligned = (free >> self.rcv_shift).min(65535) << self.rcv_shift;
            let edge = self.rcv_nxt.wrapping_add(aligned);
            if edge.gt(sws_edge) {
                sws_edge = edge;
            }
        }
        // At most 65535: the SWS edge was set by a field of at most 65535 from an RCV.NXT at
        // or before the current one.
        let wnd = self.rcv_nxt.distance(sws_edge).max(0) as u32;
        let field = wnd.div_ceil(1 << self.rcv_shift).min(65535);
        debug_assert!(free > 0 || field == 0, "a window without memory");
        let edge = self.rcv_nxt.wrapping_add(field << self.rcv_shift);
        (field as u16, edge, sws_edge)
    }

    /// Receiver SWS (RFC 9293 §3.8.6.2.2): `buffer_edge − sws_edge >= min(buffer/2, eff_mss)`.
    fn sws_moves(&self, free: u32) -> bool {
        let sws = (self.cfg.recv_buffer / 2).min(u32::from(self.eff_mss));
        let buffer_edge = self.rcv_nxt.wrapping_add(free);
        i64::from(self.rcv_sws_edge.distance(buffer_edge)) >= i64::from(sws)
    }

    /// After a read, an update is sent only if the SWS rule moves the edge by at least the
    /// window the peer still has (ruling R15): a closed window reopens at once, while reads
    /// during a transfer ride on the ACKs the data draws anyway, and a field capped at 65535
    /// draws no extra ACK per segment.
    fn window_update_due(&self, h: &impl Hooks) -> bool {
        let (_, edge, sws_edge) = self.window_offer(h);
        let grow = self.rcv_right_edge.distance(edge);
        sws_edge != self.rcv_sws_edge && grow > 0 && grow as u32 >= self.rcv_wnd()
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
        self.dsack = None;
    }

    /// Reports only bytes actually received, including a prefix below the cumulative ACK.
    fn record_dsack(&mut self, seg: &Segment) {
        self.dsack = None;
        if !self.sack_permitted || seg.payload.is_empty() {
            return;
        }
        let next = self
            .rcv_nxt
            .wrapping_add(0u32.wrapping_sub(u32::from(self.fin_received)));
        let off = i64::from(next.distance(seg.seq));
        let end = off + seg.payload.len() as i64;
        let lo = off.max(1 - self.rcv_ssn as i64);
        let hi = end.min(0);
        if lo < hi {
            self.dsack = Some((next.wrapping_add(lo as u32), next.wrapping_add(hi as u32)));
        } else if end > 0 {
            let start = self.rcv_ssn + off.max(0) as u64;
            let end = self.rcv_ssn + end as u64;
            if let Some(r) = self.rcv_ooo.iter().find(|r| r.start < end && r.end > start) {
                let left = r.start.max(start);
                let right = r.end.min(end);
                self.dsack = Some((
                    next.wrapping_add((left - self.rcv_ssn) as u32),
                    next.wrapping_add((right - self.rcv_ssn) as u32),
                ));
            }
        }
    }

    /// DSACK first, its containing block second, then held blocks in reception order.
    fn write_sacks(&self, out: &mut [u8]) -> usize {
        if !self.sack_permitted {
            return 0;
        }
        let mut blocks = [(0, 0); 4];
        let mut count = 0;
        let duplicate = self
            .dsack
            .filter(|(left, _)| !left.lt(self.rcv_nxt))
            .map(|(left, _)| self.rcv_ssn + self.rcv_nxt.distance(left) as u64);
        // A DSACK above ACK requires its containing block too (RFC 2883 §4).
        let dsack = self
            .dsack
            .filter(|_| duplicate.is_none() || out.len() >= 20);
        if let Some((left, right)) = dsack {
            blocks[0] = (left.0, right.0);
            count = 1;
        }
        for point in duplicate
            .into_iter()
            .chain(self.sack_recent.iter().copied())
            .chain(self.rcv_ooo.iter().rev().map(|r| r.end - 1))
        {
            if let Some(r) = self.rcv_ooo.get(&point) {
                let block = (
                    self.rcv_nxt.wrapping_add((r.start - self.rcv_ssn) as u32).0,
                    self.rcv_nxt.wrapping_add((r.end - self.rcv_ssn) as u32).0,
                );
                // A full duplicate above ACK needs the same block again to identify DSACK.
                let first = usize::from(dsack.is_some());
                if count < blocks.len() && !blocks[first..count].contains(&block) {
                    blocks[count] = block;
                    count += 1;
                }
            }
        }
        tcp_options::write_sack(out, &blocks[..count])
    }

    fn terminate(&mut self, reason: CloseReason, now: Instant) -> Reaction {
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

    /// Spec §3: min(peer's MSS option, or 536 / 1220 when absent; our MTU-derived MSS). TCP
    /// option bytes are subtracted by `poll_data` when SACK accompanies data.
    fn eff_mss_for(&self, peer: Option<u16>) -> u16 {
        let peer = peer.unwrap_or(if self.v6 { 1220 } else { 536 });
        // ponytail: a peer MSS of 0 would stall the send path; used as 1.
        peer.min(self.mss_option()).max(1)
    }
}

/// Sequence numbers a segment we sent occupies: its data and the FIN.
fn seq_len(m: &SentMeta) -> u32 {
    m.len + u32::from(m.flags.contains(TcpFlags::FIN))
}

/// Smallest shift `s` with `buffer >> s <= 65535`, at most 14 (RFC 7323 §2.3).
fn ws_shift(buffer: u32) -> u8 {
    (0..MAX_WS_SHIFT)
        .find(|&s| buffer >> s <= 65535)
        .unwrap_or(MAX_WS_SHIFT)
}

#[cfg(test)]
mod tests;
