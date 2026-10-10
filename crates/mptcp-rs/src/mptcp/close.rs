//! Connection sequence-space closure, independent of TCP subflow state.
use super::{ConnectionHooks, SubflowHooks};
use crate::tcp::Tcb;
use crate::time::Instant;
use crate::wire::{
    mptcp::{self, MptcpOption},
    packet::Segment,
    tcp_options::{TcpOpt, walk},
};
use std::time::Duration;

pub(super) struct Close {
    pub local: Option<u64>,
    pub sent: bool,
    pub acked: bool,
    pub attached: bool,
    pub due: bool,
    pub at: Option<Instant>,
    pub interval: Duration,
    pub peer_acked: bool,
    pub no_subflow_at: Option<Instant>,
    pub closed: bool,
}
impl Default for Close {
    fn default() -> Self {
        Self {
            local: None,
            sent: false,
            acked: false,
            attached: false,
            due: false,
            at: None,
            interval: Duration::from_secs(1),
            peer_acked: false,
            no_subflow_at: None,
            closed: false,
        }
    }
}

impl ConnectionHooks {
    pub fn active(&self) -> bool {
        self.data.as_ref().is_some_and(|d| !d.fallback)
    }
    pub fn eof(&self, tcp_fin: bool) -> bool {
        if self.active() {
            self.data.as_ref().unwrap().recv.eof()
        } else {
            tcp_fin
        }
    }
    pub fn retained(&self) -> bool {
        self.data
            .as_ref()
            .is_some_and(|d| !d.fallback && !d.close.closed)
    }
    /// Our DATA_FIN is DATA_ACKed and the peer's has arrived (our DATA_ACK for it may still be
    /// due): the connection is ending, not losing a path.
    pub fn data_closed(&self) -> bool {
        (self.data.as_ref()).is_some_and(|d| d.close.acked && d.recv.eof())
    }
    /// `add_subflow` on a Confirmed connection: the join starts at once, so the no-subflow
    /// wait ends (spec §5.5).
    pub fn cancel_no_subflow_wait(&mut self) {
        if let Some(d) = &mut self.data {
            d.close.no_subflow_at = None;
        }
    }
    /// `Connection::abort`: the data level ends with no `Closed` of its own. Returns the peer's
    /// key when the RSTs carry MP_FASTCLOSE (MPTCP, not fallen back).
    pub fn abort(&mut self) -> Option<u64> {
        let d = self.data.as_mut().filter(|d| !d.fallback)?;
        d.close.closed = true;
        self.negotiation.as_ref()?.peer_key
    }
    pub fn close(&mut self) -> bool {
        if let Some(d) = self.data.as_mut().filter(|d| !d.fallback) {
            d.close.local.get_or_insert(d.send.end);
            true
        } else {
            self.data
                .as_ref()
                .is_some_and(|d| d.send.next != d.send.end)
        }
    }
}

impl SubflowHooks<'_> {
    /// `last`: no other subflow of the connection is open.
    pub fn update_close(
        &mut self,
        tcb: &Tcb,
        now: Instant,
        last: bool,
    ) -> Option<crate::tcp::CloseReason> {
        let d = self.conn.data.as_mut().filter(|d| !d.fallback)?;
        if d.close.closed {
            return None;
        }
        let reason = if self.conn.fast_closed {
            Some(crate::tcp::CloseReason::Reset)
        } else if tcb.state() == crate::tcp::TcpState::Closed {
            // `Connection::update_health` has queued its mappings for reinjection.
            if !last {
                // Another subflow is open: the connection carries on, no no-subflow wait.
                d.close.no_subflow_at = None;
                return None;
            }
            // The reinjection queue survives the wait: a subflow added during it resends at
            // once. The timers stop (nothing can carry their retries).
            d.recovery_at = None;
            d.close.at = None;
            if d.close.acked && d.close.peer_acked {
                Some(crate::tcp::CloseReason::Normal)
            } else {
                let at = d
                    .close
                    .no_subflow_at
                    .get_or_insert(now + Duration::from_secs(60));
                (now >= *at).then_some(crate::tcp::CloseReason::Timeout)
            }
        } else {
            None
        };
        if reason.is_some() {
            d.close.closed = true;
        }
        reason
    }
    pub fn on_transmitted(&mut self, seg: &Segment<'_>, now: Instant, rto: Duration) {
        self.join_transmitted(seg.flags, now, rto);
        if let Some(d) = &mut self.conn.data {
            for opt in walk(seg.options) {
                if let Ok(TcpOpt::Mptcp(raw)) = opt {
                    if let Ok(MptcpOption::Dss(v)) = mptcp::parse(raw) {
                        // Only a segment that carried the infinite mapping makes it sent.
                        if v.mapping.is_some_and(|m| m.data_len == 0) {
                            self.sf.final_mapping = None;
                        }
                        if v.data_fin {
                            d.close.sent = true;
                            d.close.due = false;
                            if d.close.at.is_none()
                                && !d.close.acked
                                && (v.mapping.is_some_and(|m| m.ssn == 0)
                                    || d.send.una == d.send.end)
                            {
                                if d.close.interval == Duration::from_secs(1) {
                                    d.close.interval = rto;
                                }
                                d.close.at = Some(now + d.close.interval);
                            }
                        }
                        if d.recv.eof() && v.data_ack == Some(mptcp::DataAck::Ack64(d.recv.next)) {
                            d.close.peer_acked = true;
                        }
                    }
                }
            }
        }
    }
}
