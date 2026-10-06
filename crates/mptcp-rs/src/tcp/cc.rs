//! Congestion control: the one swappable trait in M0–M2 (spec §3).

use std::fmt;
use std::time::Duration;

use crate::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionEvent {
    FastRetransmit,
    Rto,
}

pub trait CongestionControl {
    /// Called once when the connection reaches ESTABLISHED, with the effective send MSS.
    fn init(&mut self, _smss: u32) {}
    /// Called when an ACK advances SND.UNA. `acked` is the number of octets newly
    /// acknowledged; `rtt` is the RTT sample this ACK produced, if any; `in_flight` is
    /// SND.NXT − SND.UNA *after* this ACK moved SND.UNA (octets still outstanding).
    fn on_ack(&mut self, acked: u32, rtt: Option<Duration>, in_flight: u32, now: Instant);
    /// `in_flight` is FlightSize (RFC 5681): SND.NXT − SND.UNA at the event, before any
    /// retransmission it triggers.
    fn on_congestion(&mut self, ev: CongestionEvent, in_flight: u32, now: Instant);
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

/// No congestion limit: the send path is bounded by the peer's window only.
pub(crate) struct Unbounded;

impl CongestionControl for Unbounded {
    fn on_ack(&mut self, _: u32, _: Option<Duration>, _: u32, _: Instant) {}
    fn on_congestion(&mut self, _: CongestionEvent, _: u32, _: Instant) {}
    fn cwnd(&self) -> u32 {
        u32::MAX
    }
}
