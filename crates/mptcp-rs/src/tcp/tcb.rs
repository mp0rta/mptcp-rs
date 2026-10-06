//! Pure TCP state machine (RFC 9293), driven by segments, time and hooks (spec §3, §3.1).

use std::net::SocketAddr;
use std::time::Duration;

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
    /// Shift applied to our window fields (RFC 7323 Rcv.Wind.Shift). Holds our offer until the
    /// SYN/ACK; 0 if the peer did not offer.
    rcv_shift: u8,

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
            rcv_shift: ws_shift(cfg.recv_buffer),
            cc,
            rtt: RttEstimator::new(),
            rto_at: None,
            rtt_timed: None,
            r2_since: None,
            persist_at: None,
            persist_ivl: Duration::ZERO,
            sws_at: None,
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
            TcpState::Established => self.on_ack(seg, now, h),
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
                self.ack_due = false;
                return Some(meta);
            }
        }
        if self.ack_due {
            self.ack_due = false;
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
                [self.rto_at, r2, self.persist_at, self.sws_at]
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

    /// RFC 9293 §3.10.7.4 fifth step, send side: SND.UNA, the send buffer, RTT, CC and SND.WND.
    /// Segment acceptability, RST/SYN checks and payload are not handled here.
    fn on_ack(&mut self, seg: &Segment, now: Instant, h: &mut impl Hooks) -> Reaction {
        if !seg.flags.contains(TcpFlags::ACK) || seg.ack.lt(self.snd_una) {
            return Reaction::None;
        }
        if seg.ack.gt(self.snd_nxt) {
            self.ack_due = true;
            return Reaction::None;
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
        Reaction::None
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

    /// Window field of a non-SYN segment.
    fn wnd_field(&self, h: &impl Hooks) -> u16 {
        (h.recv_window() >> self.rcv_shift).min(65535) as u16
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
    use crate::tcp::cc::CongestionEvent;
    use crate::tcp::{PlainHooks, SegmentHooks, SendBuf};
    use std::cell::RefCell;
    use std::rc::Rc;

    const ISN: SeqNum = SeqNum(0x1000);
    const PEER_ISN: SeqNum = SeqNum(0xFFFF_FFF0);
    /// Peer MSS in the send-path tests.
    const MSS: u16 = 1000;

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
    fn tm(ms: u64) -> Instant {
        t(0) + Duration::from_millis(ms)
    }
    /// Sequence number of data octet `n` (0-based).
    fn data(n: u32) -> SeqNum {
        ISN.wrapping_add(1 + n)
    }
    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    struct Fixture<H = PlainHooks> {
        tcb: Tcb,
        h: H,
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
        /// IPv4, `cc::Unbounded` passed explicitly (send-path tests must not depend on the
        /// default CC).
        fn unbounded(cfg: ConnectConfig) -> Self {
            let h = PlainHooks::new(&cfg);
            Fixture::with(cfg, Box::new(Unbounded), h)
        }
        /// ESTABLISHED at t(0): eff_mss = MSS, peer shift 0, peer window `wnd`, handshake ACK
        /// already sent.
        fn established(cfg: ConnectConfig, wnd: u16) -> Self {
            let mut f = Fixture::unbounded(cfg);
            f.establish(wnd);
            f
        }
        fn write(&mut self, data: &[u8]) {
            assert_eq!(self.h.write(data), data.len());
        }
    }

    impl<H: Hooks> Fixture<H> {
        fn with(cfg: ConnectConfig, cc: Box<dyn CongestionControl>, h: H) -> Self {
            let addrs = v4();
            Self {
                tcb: Tcb::with_cc(&cfg, addrs.0, addrs.1, ISN, t(0), cc),
                h,
                out: SegmentWriter::default(),
                addrs,
            }
        }
        fn establish(&mut self, wnd: u16) {
            assert_eq!(
                self.synack(wnd, &opts(Some(MSS), Some(0))),
                Reaction::Established
            );
            assert_eq!(self.send(t(0)).unwrap().flags, TcpFlags::ACK);
            assert_eq!(self.send(t(0)), None);
        }
        /// An ACK-only segment from the peer.
        fn ack_seq(&mut self, now: Instant, seq: SeqNum, ack: SeqNum, wnd: u16) -> Reaction {
            let seg = Segment {
                src: self.addrs.1,
                dst: self.addrs.0,
                seq,
                ack,
                flags: TcpFlags::ACK,
                wnd,
                options: &[],
                payload: &[],
            };
            self.tcb.on_segment(&seg, now, &mut self.h)
        }
        fn ack(&mut self, now: Instant, ack: SeqNum, wnd: u16) -> Reaction {
            self.ack_seq(now, PEER_ISN.wrapping_add(1), ack, wnd)
        }
        /// Every segment `poll_send` emits at `now`, with its payload.
        fn drain(&mut self, now: Instant) -> Vec<(SentMeta, Vec<u8>)> {
            let mut v = Vec::new();
            while let Some(m) = self.send(now) {
                v.push((m, self.out.payload.clone()));
                assert!(v.len() < 1000, "poll_send does not stop");
            }
            v
        }
        /// Fires every deadline until `Closed`; returns the send times and the close time.
        fn run_until_closed(&mut self) -> (Vec<Instant>, Instant) {
            let mut sends = Vec::new();
            loop {
                let at = self.tcb.poll_send_at().expect("a deadline");
                match self.timeout(at) {
                    Reaction::None => {}
                    Reaction::Closed(CloseReason::Timeout) => return (sends, at),
                    r => panic!("unexpected {r:?}"),
                }
                let segs = self.drain(at);
                assert_eq!(segs.len(), 1, "one segment per expiry at {at:?}");
                sends.push(at);
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

    // ---- Send path (Task 7) ----

    const PSH_ACK: TcpFlags = TcpFlags(TcpFlags::PSH.0 | TcpFlags::ACK.0);

    #[test]
    fn sends_full_segments_up_to_window() {
        let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
        let bytes = pattern(25 * MSS as usize);
        f.write(&bytes);
        let segs = f.drain(t(0));
        assert_eq!(segs.len(), 10);
        for (i, (meta, payload)) in segs.iter().enumerate() {
            let off = i * MSS as usize;
            assert_eq!(meta.seq, data(off as u32));
            assert_eq!(meta.len, u32::from(MSS));
            assert_eq!(meta.flags, TcpFlags::ACK, "segment {i}: no PSH");
            assert_eq!(payload[..], bytes[off..off + MSS as usize]);
        }
        assert_eq!(f.out.ack, PEER_ISN.wrapping_add(1));
        // Window full, data in flight: only the RTO is pending.
        assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
    }

    #[test]
    fn psh_on_last_segment_of_written_data() {
        let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
        f.tcb.set_nodelay(true);
        f.write(&pattern(3 * MSS as usize / 2));
        let segs = f.drain(t(0));
        let got: Vec<_> = segs.iter().map(|(m, _)| (m.seq, m.len, m.flags)).collect();
        assert_eq!(
            got,
            vec![
                (data(0), u32::from(MSS), TcpFlags::ACK),
                (data(u32::from(MSS)), u32::from(MSS) / 2, PSH_ACK),
            ]
        );
    }

    #[test]
    fn nagle_holds_small_segment_while_unacked() {
        let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
        f.write(&[1; 100]);
        let segs = f.drain(t(0));
        assert_eq!(segs.len(), 1);
        assert_eq!((segs[0].0.seq, segs[0].0.len), (data(0), 100));
        assert_eq!(segs[0].0.flags, PSH_ACK);
        f.write(&[2; 100]);
        assert!(
            f.drain(tm(10)).is_empty(),
            "held while 100 B unacknowledged"
        );
        // No SWS override while data is in flight: only the RTO is pending.
        assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
        assert_eq!(f.ack(tm(50), data(100), 10 * MSS), Reaction::None);
        let segs = f.drain(tm(50));
        assert_eq!(segs.len(), 1);
        assert_eq!((segs[0].0.seq, segs[0].0.len), (data(100), 100));
        assert_eq!(segs[0].1, vec![2; 100]);
    }

    #[test]
    fn rto_retransmits_with_backoff_and_karn() {
        let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
        let bytes = pattern(500);
        f.write(&bytes);
        assert_eq!(f.drain(t(0)).len(), 1);
        assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
        assert_eq!(f.timeout(tm(999)), Reaction::None);
        assert!(f.drain(tm(999)).is_empty());
        for (at, next) in [(1, 3), (3, 7)] {
            assert_eq!(f.timeout(t(at)), Reaction::None);
            let segs = f.drain(t(at));
            assert_eq!(segs.len(), 1, "retransmission at {at} s");
            assert_eq!((segs[0].0.seq, segs[0].0.len), (data(0), 500));
            assert_eq!(segs[0].1, bytes);
            assert_eq!(f.tcb.poll_send_at(), Some(t(next)));
        }
        // The ACK covers a retransmitted segment: no RTT sample, RTO stays backed off.
        assert_eq!(f.ack(tm(3100), data(500), 10 * MSS), Reaction::None);
        assert_eq!(f.tcb.rtt.srtt(), None);
        assert_eq!(f.tcb.rtt.rto(), Duration::from_secs(4));
        assert_eq!(f.tcb.poll_send_at(), None);
        // A fresh segment is timed and its ACK yields a sample, collapsing the RTO.
        f.write(&[7; 100]);
        assert_eq!(f.drain(tm(3200)).len(), 1);
        assert_eq!(f.tcb.poll_send_at(), Some(tm(7200)));
        assert_eq!(f.ack(tm(3400), data(600), 10 * MSS), Reaction::None);
        assert_eq!(f.tcb.rtt.srtt(), Some(Duration::from_millis(200)));
        assert_eq!(f.tcb.rtt.rto(), Duration::from_secs(1));
    }

    #[test]
    fn rto_reinit_3s_after_syn_retransmission() {
        let mut f = Fixture::unbounded(ConnectConfig::default());
        f.send(t(0)).unwrap();
        assert_eq!(f.timeout(t(1)), Reaction::None);
        assert_eq!(f.send(t(1)).unwrap().flags, TcpFlags::SYN);
        assert_eq!(
            f.recv(
                TcpFlags::SYN | TcpFlags::ACK,
                ISN.wrapping_add(1),
                10 * MSS,
                &opts(Some(MSS), Some(0))
            ),
            Reaction::Established
        );
        f.write(&[1; 100]);
        let segs = f.drain(t(1));
        assert_eq!(segs.len(), 1, "data carries the handshake ACK");
        assert_eq!(segs[0].0.len, 100);
        assert_eq!(f.tcb.poll_send_at(), Some(t(4)));
    }

    #[test]
    fn r2_data_closes() {
        let cfg = ConnectConfig {
            r2_data: Duration::from_secs(100),
            ..ConnectConfig::default()
        };
        let mut f = Fixture::established(cfg, 10 * MSS);
        f.write(&[1; 500]);
        assert_eq!(f.drain(t(0)).len(), 1);
        let (sends, closed) = f.run_until_closed();
        assert_eq!(sends, [1, 3, 7, 15, 31, 63].map(t));
        assert_eq!(closed, t(100));
        assert_eq!(f.tcb.state(), TcpState::Closed);
        assert_eq!(f.tcb.poll_send_at(), Some(t(100)));
        // Exactly once.
        assert_eq!(f.timeout(t(500)), Reaction::None);
        assert_eq!(f.send(t(500)), None);
    }

    #[test]
    fn r2_restarts_when_snd_una_advances() {
        let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
        f.write(&[1; 2000]);
        assert_eq!(f.drain(t(0)).len(), 2);
        // The first segment is acknowledged at 0.1 s; R2 now counts from there.
        assert_eq!(f.ack(tm(100), data(1000), 10 * MSS), Reaction::None);
        let (sends, closed) = f.run_until_closed();
        assert_eq!(sends[0], tm(1100));
        assert_eq!(closed, tm(100_100));
    }

    #[test]
    fn sender_sws_override_after_500ms() {
        let mut f = Fixture::unbounded(ConnectConfig::default());
        assert_eq!(
            f.synack(8192, &opts(Some(1460), Some(0))),
            Reaction::Established
        );
        assert_eq!(f.drain(t(0)).len(), 1); // handshake ACK
        assert_eq!(f.ack(t(0), ISN.wrapping_add(1), 300), Reaction::None);
        assert_eq!(f.tcb.snd_wnd, 300);
        f.write(&pattern(1000));
        // (1) 300 < 1460, (2) D = 1000 > U = 300, (3) 300 < 8192 / 2: nothing sent.
        assert!(f.drain(t(0)).is_empty());
        assert_eq!(f.tcb.poll_send_at(), Some(tm(500)));
        assert_eq!(f.timeout(tm(499)), Reaction::None);
        assert!(f.drain(tm(499)).is_empty());
        assert_eq!(f.timeout(tm(500)), Reaction::None);
        let segs = f.drain(tm(500));
        assert_eq!(segs.len(), 1);
        assert_eq!((segs[0].0.seq, segs[0].0.len), (data(0), 300));
        assert_eq!(segs[0].0.flags, TcpFlags::ACK);
        assert_eq!(segs[0].1, pattern(300));
    }

    #[test]
    fn zero_window_probe_is_zero_length_at_una_minus_1() {
        let mut f = Fixture::established(ConnectConfig::default(), 0);
        f.write(&pattern(500));
        assert!(f.drain(t(0)).is_empty());
        assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
        for (at, next) in [(1, 3), (3, 7)] {
            assert_eq!(f.timeout(t(at)), Reaction::None);
            let segs = f.drain(t(at));
            assert_eq!(segs.len(), 1, "probe at {at} s");
            let (meta, payload) = &segs[0];
            assert_eq!(meta.seq, ISN); // SND.UNA − 1
            assert_eq!((meta.len, meta.flags), (0, TcpFlags::ACK));
            assert!(payload.is_empty());
            assert_eq!(f.out.ack, PEER_ISN.wrapping_add(1));
            assert_eq!(f.tcb.poll_send_at(), Some(t(next)));
        }
        // The window opens: data flows and persist stops.
        assert_eq!(f.ack(t(4), data(0), 10 * MSS), Reaction::None);
        let segs = f.drain(t(4));
        assert_eq!(segs.len(), 1);
        assert_eq!((segs[0].0.seq, segs[0].0.len), (data(0), 500));
        assert_eq!(f.tcb.persist_at, None);
        assert_eq!(f.tcb.poll_send_at(), Some(t(5)));
    }

    #[test]
    fn persist_not_armed_while_unacked() {
        let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
        f.write(&pattern(500));
        assert_eq!(f.drain(t(0)).len(), 1);
        // Window closes with the data still unacknowledged.
        assert_eq!(f.ack(tm(100), data(0), 0), Reaction::None);
        assert_eq!(f.tcb.snd_wnd, 0);
        assert!(f.drain(tm(100)).is_empty());
        assert_eq!(f.tcb.persist_at, None);
        assert_eq!(f.tcb.poll_send_at(), Some(t(1)));
        assert_eq!(f.timeout(t(1)), Reaction::None);
        let segs = f.drain(t(1));
        assert_eq!(segs.len(), 1);
        assert_eq!((segs[0].0.seq, segs[0].0.len), (data(0), 500));
        assert_eq!(f.tcb.persist_at, None);
    }

    #[test]
    fn answered_probes_do_not_hit_r2() {
        let mut f = Fixture::established(ConnectConfig::default(), 0);
        f.write(&pattern(500));
        assert!(f.drain(t(0)).is_empty());
        let mut probes = Vec::new();
        loop {
            let at = f.tcb.poll_send_at().unwrap();
            if at > t(300) {
                break;
            }
            assert_eq!(f.timeout(at), Reaction::None);
            let segs = f.drain(at);
            assert_eq!(segs.len(), 1);
            assert_eq!((segs[0].0.seq, segs[0].0.len), (ISN, 0));
            probes.push(at);
            assert_eq!(f.ack(at, data(0), 0), Reaction::None);
        }
        // ×2 per probe, capped at 60 s.
        assert_eq!(probes, [1, 3, 7, 15, 31, 63, 123, 183, 243].map(t));
        assert_eq!(f.tcb.state(), TcpState::Established);
    }

    #[test]
    fn unanswered_probes_close_at_r2() {
        let mut f = Fixture::established(ConnectConfig::default(), 0);
        f.write(&pattern(500));
        assert!(f.drain(t(0)).is_empty());
        let (probes, closed) = f.run_until_closed();
        assert_eq!(probes, [1, 3, 7, 15, 31, 63].map(t));
        // R2 (100 s) counts from the first unanswered probe.
        assert_eq!(closed, t(101));
    }

    #[test]
    fn ack_processing_rules() {
        let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
        f.write(&pattern(1000));
        assert_eq!(f.drain(t(0)).len(), 1);
        // ACK of data not yet sent: answered with an ACK, otherwise ignored.
        assert_eq!(f.ack(tm(10), data(5000), 20000), Reaction::None);
        let segs = f.drain(tm(10));
        assert_eq!(segs.len(), 1);
        assert_eq!((segs[0].0.seq, segs[0].0.len), (data(1000), 0));
        assert_eq!(segs[0].0.flags, TcpFlags::ACK);
        assert_eq!((f.tcb.snd_una, f.tcb.snd_wnd), (data(0), 10000));
        // Window update from a later segment, then an older one (SEG.SEQ < SND.WL1) is ignored.
        let peer = PEER_ISN.wrapping_add(1);
        assert_eq!(
            f.ack_seq(tm(20), peer.wrapping_add(4), data(1000), 20000),
            Reaction::None
        );
        assert_eq!((f.tcb.snd_una, f.tcb.snd_wnd), (data(1000), 20000));
        assert_eq!(f.ack_seq(tm(30), peer, data(1000), 0), Reaction::None);
        assert_eq!(f.tcb.snd_wnd, 20000);
        // A peer window field is scaled by the shift from its SYN/ACK.
        let mut f = Fixture::unbounded(ConnectConfig::default());
        f.synack(100, &opts(Some(MSS), Some(3)));
        assert_eq!(f.tcb.snd_wnd, 100, "SYN/ACK window unscaled");
        assert_eq!(f.ack(t(0), ISN.wrapping_add(1), 100), Reaction::None);
        assert_eq!(f.tcb.snd_wnd, 800);
        assert_eq!(f.tcb.max_snd_wnd, 800);
    }

    #[derive(Default)]
    struct CcLog {
        init: Option<u32>,
        acks: Vec<(u32, Option<Duration>, u32)>,
        events: Vec<(CongestionEvent, u32)>,
    }

    /// Fixed 2-segment window that records what the `Tcb` reports.
    struct Recording(Rc<RefCell<CcLog>>);

    impl CongestionControl for Recording {
        fn init(&mut self, smss: u32) {
            self.0.borrow_mut().init = Some(smss);
        }
        fn on_ack(&mut self, acked: u32, rtt: Option<Duration>, in_flight: u32, _: Instant) {
            self.0.borrow_mut().acks.push((acked, rtt, in_flight));
        }
        fn on_congestion(&mut self, ev: CongestionEvent, in_flight: u32, _: Instant) {
            self.0.borrow_mut().events.push((ev, in_flight));
        }
        fn cwnd(&self) -> u32 {
            2 * u32::from(MSS)
        }
    }

    #[test]
    fn cc_gates_sending_and_sees_acks_and_rto() {
        let log = Rc::new(RefCell::new(CcLog::default()));
        let cfg = ConnectConfig::default();
        let h = PlainHooks::new(&cfg);
        let mut f = Fixture::with(cfg, Box::new(Recording(log.clone())), h);
        f.establish(10 * MSS);
        assert_eq!(log.borrow().init, Some(u32::from(MSS)));
        f.write(&pattern(5000));
        let segs = f.drain(t(0));
        assert_eq!(segs.len(), 2, "cwnd = 2 segments");
        assert_eq!(f.ack(tm(100), data(1000), 10 * MSS), Reaction::None);
        assert_eq!(
            log.borrow().acks,
            vec![(1000, Some(Duration::from_millis(100)), 1000)]
        );
        let segs = f.drain(tm(100));
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].0.seq, data(2000));
        // RTO restarted by the ACK at 0.1 s.
        assert_eq!(f.tcb.poll_send_at(), Some(tm(1100)));
        assert_eq!(f.timeout(tm(1100)), Reaction::None);
        // FlightSize at the RTO: data(1000)..data(3000).
        assert_eq!(log.borrow().events, vec![(CongestionEvent::Rto, 2000)]);
        let segs = f.drain(tm(1100));
        assert_eq!(segs.len(), 1);
        assert_eq!((segs[0].0.seq, segs[0].0.len), (data(1000), 1000));
    }

    /// A send buffer whose runs are at most 7 octets, as at many internal buffer boundaries.
    struct ShortRuns(PlainHooks);

    impl SendBuf for ShortRuns {
        fn peek_with<R>(&self, rel_ssn: u32, max: usize, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
            self.0.peek_with(rel_ssn, max.min(7), f)
        }
        fn assigned_end(&self) -> u32 {
            self.0.assigned_end()
        }
        fn mark_acked(&mut self, rel_ssn_una: u32) {
            self.0.mark_acked(rel_ssn_una)
        }
    }

    impl SegmentHooks for ShortRuns {
        fn accept_payload(&mut self, rel_ssn: u32, data: &[u8]) {
            self.0.accept_payload(rel_ssn, data)
        }
        fn recv_window(&self) -> u32 {
            self.0.recv_window()
        }
    }

    #[test]
    fn segment_filled_across_short_runs() {
        let cfg = ConnectConfig::default();
        let h = ShortRuns(PlainHooks::new(&cfg));
        let mut f = Fixture::with(cfg, Box::new(Unbounded), h);
        f.establish(10 * MSS);
        f.tcb.set_nodelay(true);
        let bytes = pattern(2500);
        assert_eq!(f.h.0.write(&bytes), 2500);
        let segs = f.drain(t(0));
        let lens: Vec<_> = segs.iter().map(|(m, _)| m.len).collect();
        assert_eq!(lens, [1000, 1000, 500]);
        let sent: Vec<u8> = segs.into_iter().flat_map(|(_, p)| p).collect();
        assert_eq!(sent, bytes);
    }

    #[test]
    fn answered_retransmission_probes_do_not_hit_r2() {
        let mut f = Fixture::established(ConnectConfig::default(), 10 * MSS);
        f.write(&pattern(500));
        assert_eq!(f.drain(t(0)).len(), 1);
        // The window closes with the data unacknowledged: each RTO retransmission is the probe.
        assert_eq!(f.ack(tm(100), data(0), 0), Reaction::None);
        let mut sends = Vec::new();
        loop {
            let at = f.tcb.poll_send_at().unwrap();
            if at > t(300) {
                break;
            }
            assert_eq!(f.timeout(at), Reaction::None);
            let segs = f.drain(at);
            assert_eq!(segs.len(), 1);
            assert_eq!((segs[0].0.seq, segs[0].0.len), (data(0), 500));
            sends.push(at);
            assert_eq!(f.ack(at, data(0), 0), Reaction::None);
        }
        assert_eq!(sends, [1, 3, 7, 15, 31, 63, 123, 183, 243].map(t));
        assert_eq!(f.tcb.state(), TcpState::Established);
    }

    #[test]
    fn zero_window_discards_pending_sws_override() {
        let mut f = Fixture::unbounded(ConnectConfig::default());
        f.synack(8192, &opts(Some(1460), Some(0)));
        f.drain(t(0));
        f.ack(t(0), ISN.wrapping_add(1), 300);
        f.write(&pattern(1000));
        assert!(f.drain(t(0)).is_empty());
        // The override fires, but the window closes before the next poll.
        assert_eq!(f.timeout(tm(500)), Reaction::None);
        f.ack(tm(500), ISN.wrapping_add(1), 0);
        assert!(f.drain(tm(500)).is_empty());
        assert_eq!(f.tcb.poll_send_at(), Some(tm(1500)), "persist only");
        // Reopened to a sub-SWS window: a fresh 500 ms override, not the stale one.
        f.ack(tm(600), ISN.wrapping_add(1), 300);
        assert!(f.drain(tm(600)).is_empty());
        assert_eq!(f.tcb.poll_send_at(), Some(tm(1100)));
    }
}
