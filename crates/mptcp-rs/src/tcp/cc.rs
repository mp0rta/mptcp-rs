//! Congestion control: the one swappable trait in M0–M2 (spec §3).

use std::fmt;
use std::time::Duration;

use crate::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionEvent {
    FastRetransmit,
    Rto,
}

/// An ACK during fast recovery (RFC 6582 §3.2); the recovery module classifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAck {
    /// A further duplicate ACK (RFC 5681 §3.2 step 4).
    Duplicate,
    /// A partial ACK newly acknowledging `acked` octets.
    Partial { acked: u32 },
    /// A full ACK, which ends recovery; `in_flight` is SND.MAX − SND.UNA after it.
    Full { in_flight: u32 },
}

pub trait CongestionControl: Send {
    /// Called once when the connection reaches ESTABLISHED, with the effective send MSS;
    /// `syn_lost` is true if our SYN was retransmitted (RFC 5681 §3.1: IW is then one segment).
    fn init(&mut self, _smss: u32, _syn_lost: bool) {}
    /// Called when an ACK advances SND.UNA outside fast recovery. `acked` is the number of
    /// octets newly acknowledged; `rtt` is the RTT sample this ACK produced, if any;
    /// `in_flight` is SND.MAX − SND.UNA *after* this ACK moved SND.UNA (octets still
    /// outstanding).
    fn on_ack(&mut self, acked: u32, rtt: Option<Duration>, in_flight: u32, now: Instant);
    /// `in_flight` is FlightSize (RFC 5681): SND.MAX − SND.UNA at the event, before any
    /// retransmission it triggers. `FastRetransmit` starts fast recovery.
    fn on_congestion(&mut self, ev: CongestionEvent, in_flight: u32, now: Instant);
    /// Called in place of `on_ack` for every ACK between `on_congestion(FastRetransmit)` and
    /// the full ACK (or an RTO) that ends fast recovery: the window inflation and deflation of
    /// RFC 5681 §3.2 / RFC 6582 §3.2 belong to the controller.
    fn on_recovery_ack(&mut self, ack: RecoveryAck);
    /// Called before new data goes out after the sender sat idle for more than one RTO with
    /// nothing outstanding (RFC 5681 §4.1): cwnd is set to no more than the restart window.
    fn on_idle_restart(&mut self) {}
    /// Octets that may be outstanding.
    fn cwnd(&self) -> u32;
}

impl fmt::Debug for dyn CongestionControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CongestionControl")
            .field("cwnd", &self.cwnd())
            .finish()
    }
}

/// No congestion limit: the send path is bounded by the peer's window only. Lets tests of
/// other behaviour run without depending on the default CC.
#[cfg(test)]
pub(crate) struct Unbounded;

#[cfg(test)]
impl CongestionControl for Unbounded {
    fn on_ack(&mut self, _: u32, _: Option<Duration>, _: u32, _: Instant) {}
    fn on_congestion(&mut self, _: CongestionEvent, _: u32, _: Instant) {}
    fn on_recovery_ack(&mut self, _: RecoveryAck) {}
    fn cwnd(&self) -> u32 {
        u32::MAX
    }
}

/// Reno (RFC 5681 §3.1–3.2) with the NewReno window rules of RFC 6582 §3.2.
#[derive(Debug)]
pub(crate) struct Reno {
    smss: u32,
    /// The initial window, from `init`; the restart window of RFC 5681 §4.1 is min(iw, cwnd).
    iw: u32,
    cwnd: u32,
    ssthresh: u32,
    /// Octets acknowledged in congestion avoidance since cwnd last grew (byte counting).
    ca_acked: u32,
}

impl Reno {
    pub(crate) fn new() -> Self {
        Self {
            smss: 0,
            iw: 0,
            cwnd: 0,
            // RFC 5681 §3.1: "arbitrarily high".
            ssthresh: u32::MAX,
            ca_acked: 0,
        }
    }

    /// RFC 5681 eq. 4.
    fn reduce(&mut self, flight_size: u32) {
        self.ssthresh = (flight_size / 2).max(2 * self.smss);
        self.ca_acked = 0;
    }
}

impl CongestionControl for Reno {
    /// IW per RFC 5681 §3.1, or one segment after a lost SYN.
    fn init(&mut self, smss: u32, syn_lost: bool) {
        self.smss = smss;
        let segs = match smss {
            _ if syn_lost => 1,
            0..=1095 => 4,
            1096..=2190 => 3,
            _ => 2,
        };
        self.iw = segs * smss;
        self.cwnd = self.iw;
    }

    /// RW = min(IW, cwnd); ssthresh is kept (RFC 5681 §4.1).
    fn on_idle_restart(&mut self) {
        self.cwnd = self.cwnd.min(self.iw);
    }

    /// Slow start below ssthresh (eq. 2); congestion avoidance by byte counting otherwise,
    /// the RECOMMENDED method: + SMSS once a cwnd of octets has been acknowledged.
    fn on_ack(&mut self, acked: u32, _: Option<Duration>, _: u32, _: Instant) {
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(acked.min(self.smss));
            return;
        }
        self.ca_acked = self.ca_acked.saturating_add(acked);
        if self.ca_acked >= self.cwnd {
            // The remainder is dropped, so a stretch ACK still adds one SMSS at most.
            self.ca_acked = 0;
            self.cwnd = self.cwnd.saturating_add(self.smss);
        }
    }

    /// RTO: cwnd = LW = 1 SMSS. Fast retransmit: cwnd = ssthresh + 3·SMSS (RFC 5681 §3.2
    /// step 3). A repeated RTO with SND.UNA unmoved sees the same FlightSize (SND.MAX −
    /// SND.UNA), so ssthresh is held as §3.1 requires.
    fn on_congestion(&mut self, ev: CongestionEvent, in_flight: u32, _: Instant) {
        self.reduce(in_flight);
        self.cwnd = match ev {
            CongestionEvent::Rto => self.smss,
            CongestionEvent::FastRetransmit => self.ssthresh.saturating_add(3 * self.smss),
        };
    }

    /// RFC 5681 §3.2 step 4 and RFC 6582 §3.2 step 3; the full ACK takes option (1),
    /// min(ssthresh, max(FlightSize, SMSS) + SMSS), which needs no burst mitigation.
    fn on_recovery_ack(&mut self, ack: RecoveryAck) {
        self.cwnd = match ack {
            RecoveryAck::Duplicate => self.cwnd.saturating_add(self.smss),
            RecoveryAck::Partial { acked } => {
                let back = if acked >= self.smss { self.smss } else { 0 };
                self.cwnd.saturating_sub(acked) + back
            }
            RecoveryAck::Full { in_flight } => self
                .ssthresh
                .min(in_flight.max(self.smss).saturating_add(self.smss)),
        };
    }

    fn cwnd(&self) -> u32 {
        self.cwnd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMSS: u32 = 1000;
    const T0: Instant = Instant::from_nanos(0);

    fn reno() -> Reno {
        let mut r = Reno::new();
        r.init(SMSS, false);
        r
    }

    #[test]
    fn reno_idle_restart_window_is_min_iw_cwnd() {
        let mut r = reno();
        r.on_idle_restart();
        assert_eq!(r.cwnd(), 4 * SMSS, "cwnd at IW stays");
        for _ in 0..10 {
            r.on_ack(SMSS, None, 0, T0);
        }
        assert_eq!(r.cwnd(), 14 * SMSS);
        r.on_idle_restart();
        assert_eq!(r.cwnd(), 4 * SMSS);
        // A cwnd below IW (after an RTO) is not raised; ssthresh is kept.
        r.on_congestion(CongestionEvent::Rto, 8 * SMSS, T0);
        r.on_idle_restart();
        assert_eq!(r.cwnd(), SMSS);
        assert_eq!(r.ssthresh, 4 * SMSS);
    }

    #[test]
    fn reno_initial_window_by_smss() {
        // RFC 5681 §3.1: 4 / 3 / 2 segments at the 1095 and 2190 boundaries.
        for (smss, iw) in [
            (536, 2144),
            (1095, 4380),
            (1096, 3288),
            (1460, 4380),
            (2190, 6570),
            (2191, 4382),
        ] {
            let mut r = Reno::new();
            r.init(smss, false);
            assert_eq!(r.cwnd(), iw, "SMSS {smss}");
            assert_eq!(r.ssthresh, u32::MAX, "arbitrarily high");
        }
        // The SYN (or SYN/ACK) was lost: one segment.
        let mut r = Reno::new();
        r.init(1460, true);
        assert_eq!(r.cwnd(), 1460);
    }

    #[test]
    fn reno_slow_start_then_ca() {
        let mut r = reno();
        assert_eq!(r.cwnd(), 4 * SMSS);
        // Slow start: cwnd += min(N, SMSS) per ACK (eq. 2).
        r.on_ack(1000, None, 0, T0);
        assert_eq!(r.cwnd(), 5000);
        r.on_ack(400, None, 0, T0);
        assert_eq!(r.cwnd(), 5400);
        r.on_ack(3000, None, 0, T0);
        assert_eq!(r.cwnd(), 6400);
        // ssthresh = max(FlightSize / 2, 2·SMSS) = 8000, cwnd = 1 SMSS.
        r.on_congestion(CongestionEvent::Rto, 16_000, T0);
        assert_eq!((r.cwnd(), r.ssthresh), (1000, 8000));
        for segs in 2..=8 {
            r.on_ack(1000, None, 0, T0);
            assert_eq!(r.cwnd(), segs * SMSS, "slow start up to ssthresh");
        }
        // Congestion avoidance by byte counting: + SMSS once a cwnd of octets is acknowledged,
        // i.e. one SMSS per RTT.
        for _ in 0..7 {
            r.on_ack(1000, None, 0, T0);
            assert_eq!(r.cwnd(), 8000);
        }
        r.on_ack(1000, None, 0, T0);
        assert_eq!(r.cwnd(), 9000);
        // Delayed ACKs (2 SMSS each) still grow it by one SMSS per window, not per ACK.
        for _ in 0..4 {
            r.on_ack(2000, None, 0, T0);
            assert_eq!(r.cwnd(), 9000);
        }
        r.on_ack(2000, None, 0, T0);
        assert_eq!(r.cwnd(), 10_000);
        // A stretch ACK of three windows still adds at most one SMSS.
        r.on_ack(30_000, None, 0, T0);
        assert_eq!(r.cwnd(), 11_000);
        r.on_ack(1000, None, 0, T0);
        assert_eq!(r.cwnd(), 11_000);
    }

    #[test]
    fn reno_rto_resets_cwnd() {
        let mut r = reno();
        r.on_congestion(CongestionEvent::Rto, 3000, T0);
        // The loss window is one SMSS; ssthresh is at least 2·SMSS.
        assert_eq!((r.cwnd(), r.ssthresh), (SMSS, 2 * SMSS));
        // Repeated RTO with nothing acknowledged: same FlightSize, ssthresh held.
        let mut r = reno();
        r.on_congestion(CongestionEvent::Rto, 20_000, T0);
        r.on_congestion(CongestionEvent::Rto, 20_000, T0);
        assert_eq!((r.cwnd(), r.ssthresh), (SMSS, 10_000));
    }

    #[test]
    fn reno_fast_recovery_window() {
        let mut r = reno();
        // RFC 5681 §3.2 steps 2–3: ssthresh = FlightSize / 2, cwnd = ssthresh + 3·SMSS.
        r.on_congestion(CongestionEvent::FastRetransmit, 10_000, T0);
        assert_eq!((r.cwnd(), r.ssthresh), (8000, 5000));
        // Step 4: + SMSS per further duplicate ACK.
        r.on_recovery_ack(RecoveryAck::Duplicate);
        assert_eq!(r.cwnd(), 9000);
        // RFC 6582 partial ACK: deflate by the amount acknowledged, add back SMSS if >= SMSS.
        r.on_recovery_ack(RecoveryAck::Partial { acked: 3000 });
        assert_eq!(r.cwnd(), 7000);
        r.on_recovery_ack(RecoveryAck::Partial { acked: 500 });
        assert_eq!(r.cwnd(), 6500);
        // Full ACK, option (1): min(ssthresh, max(FlightSize, SMSS) + SMSS).
        r.on_recovery_ack(RecoveryAck::Full { in_flight: 2000 });
        assert_eq!(r.cwnd(), 3000);
        // Back in slow start below ssthresh.
        r.on_ack(1000, None, 0, T0);
        assert_eq!(r.cwnd(), 4000);
        let mut r = reno();
        r.on_congestion(CongestionEvent::FastRetransmit, 10_000, T0);
        r.on_recovery_ack(RecoveryAck::Full { in_flight: 0 });
        assert_eq!(r.cwnd(), 2000, "nothing outstanding: SMSS + SMSS");
        r.on_congestion(CongestionEvent::FastRetransmit, 10_000, T0);
        r.on_recovery_ack(RecoveryAck::Full { in_flight: 9000 });
        assert_eq!(r.cwnd(), 5000, "capped at ssthresh");
    }
}
