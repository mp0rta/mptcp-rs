//! Connection sequence-space closure, independent of TCP subflow state.
use super::{ConnectionHooks, SubflowHooks, data::TxMaps};
use crate::tcp::{SendBuf, Tcb};
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
    pub fn update_close(&mut self, tcb: &Tcb, now: Instant) -> Option<crate::tcp::CloseReason> {
        let d = self.conn.data.as_mut().filter(|d| !d.fallback)?;
        if d.close.closed {
            return None;
        }
        let reason = if self.conn.fast_closed {
            Some(crate::tcp::CloseReason::Reset)
        } else if tcb.state() == crate::tcp::TcpState::Closed {
            self.sf.tx = TxMaps::new(self.sf.tx.assigned_end(), 1024);
            d.recovery_at = None;
            d.reinject.clear();
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
        if let Some(d) = &mut self.conn.data {
            self.sf.final_mapping = None;
            for opt in walk(seg.options) {
                if let Ok(TcpOpt::Mptcp(raw)) = opt {
                    if let Ok(MptcpOption::Dss(v)) = mptcp::parse(raw) {
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
