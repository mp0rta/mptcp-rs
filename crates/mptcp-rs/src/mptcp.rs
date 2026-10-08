//! MPTCP negotiation, MP_JOIN subflows, data transfer, recovery and closure.
mod close;
pub(crate) mod data;
mod join;
pub(crate) mod sched;
mod subflow;
use crate::crypto::key_token_idsn;
use data::{RecvAssembler, SendStore, TxMaps, promote32};
pub(crate) use join::Join;
use sched::{MinRtt, Payload, Pending, Plan, ReinjectQueue, Scheduler, SubflowSnapshot};
pub use subflow::SubflowId;
pub(crate) use subflow::{Subflow, SubflowHooks, SubflowMp, SubflowState};

use crate::connection::Connection;
use crate::tcp::rtt::INITIAL_RTO;

use crate::tcp::{AppLimited, ConnectConfig, PlainHooks, SegmentHooks, SendBudget, SendBuf, Tcb};
use crate::time::Instant;
use crate::wire::packet::{Segment, TcpFlags};
use crate::wire::{
    mptcp::{self, CAP_C, CAP_H, MpCapable, MptcpOption},
    tcp_options::{TcpOpt, walk},
};
use std::time::Duration;

pub(crate) struct ConnectionHooks {
    plain: PlainHooks,
    pub negotiation: Option<Negotiation>,
    pub data: Option<DataState>,
    recv_cap: usize,
    send_cap: usize,
    pub fallback_event: bool,
    fast_closed: bool,
    /// MinRTT; tests inject others (spec §4: crate-internal, one implementation).
    pub scheduler: Box<dyn Scheduler>,
    /// Refilled every scheduling step; capacity = subflow cap, so steps never allocate.
    snapshots: Vec<SubflowSnapshot>,
    /// Plans rejected by validation (spec §4 rule 1); debug counter.
    pub rejected_plans: u64,
    /// Validated plans `SendStore::assign` refused; stays 0 by construction.
    pub assign_failures: u64,
}

/// Subflows per connection (M2: snapshot buffer capacity).
pub(crate) const SUBFLOW_CAP: usize = 8;

/// Connection-level MPTCP data state; absent for plain TCP and before MP_CAPABLE completes.
pub(crate) struct DataState {
    pub recv: RecvAssembler,
    close: close::Close,
    pub send: SendStore,
    pub sanity_failures: u64,
    recovery_head: Option<u64>,
    recovery_at: Option<Instant>,
    recovery_interval: Duration,
    /// DSN ranges awaiting reinjection, always within `[send.una, send.next)`.
    pub reinject: ReinjectQueue,
    fallback: bool,
}

impl ConnectionHooks {
    pub fn new(cfg: &ConnectConfig) -> Self {
        Self {
            plain: PlainHooks::new(cfg),
            negotiation: None,
            data: None,
            recv_cap: cfg.recv_buffer as usize,
            send_cap: cfg.send_buffer as usize,
            fallback_event: false,
            fast_closed: false,
            scheduler: Box::new(MinRtt),
            snapshots: Vec::with_capacity(SUBFLOW_CAP),
            rejected_plans: 0,
            assign_failures: 0,
        }
    }
    /// Unassigned data within the connection-level window (peer right edge).
    fn unassigned_len(&self) -> usize {
        match (&self.data, &self.negotiation) {
            (Some(d), Some(m)) => {
                (d.send.end.wrapping_sub(d.send.next) as usize).min(if d.fallback {
                    usize::MAX
                } else {
                    (m.send_right_edge.unwrap().wrapping_sub(d.send.next) as i64).max(0) as usize
                })
            }
            _ => 0,
        }
    }
    /// The New candidate: one stored run, within the DSS length limit.
    fn candidate_len(&self) -> usize {
        self.data.as_ref().map_or(0, |d| {
            d.send
                .run_len(d.send.next)
                .min(self.unassigned_len())
                .min(u16::MAX as usize - usize::from(d.close.local.is_some()))
        })
    }
    pub fn recovery_deadline(&self) -> Option<Instant> {
        self.data.as_ref().and_then(|d| {
            [d.recovery_at, d.close.at, d.close.no_subflow_at]
                .into_iter()
                .flatten()
                .min()
        })
    }
    pub fn write(&mut self, bytes: &[u8]) -> usize {
        self.data
            .as_mut()
            .map_or_else(|| self.plain.write(bytes), |d| d.send.write(bytes))
    }
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        match &mut self.data {
            Some(d) => d.recv.read(out),
            None => self.plain.read(out),
        }
    }
    pub fn has_unread(&self) -> bool {
        self.data
            .as_ref()
            .map_or_else(|| self.plain.has_unread(), |d| d.recv.has_unread())
    }
}
/// Un-subflow-ACKed mappings of the Active subflows: the copies reinjection must not duplicate.
fn active_maps(subflows: &[Subflow]) -> impl Iterator<Item = &TxMaps> + Clone {
    subflows
        .iter()
        .filter(|s| s.state == SubflowState::Active)
        .map(|s| &s.mp.tx)
}

/// Spec §4 rule 1: `k × seg_payload` with `1 <= k <= full_segments`, or at most `partial`.
fn fits(b: SendBudget, bytes: u32) -> bool {
    let n = bytes as usize;
    n > 0
        && b.seg_payload > 0
        && ((n % b.seg_payload == 0 && n / b.seg_payload <= b.full_segments) || n <= b.partial)
}

/// Validates a plan against the snapshot it was made from (boundary invariant 5): the named
/// subflow exists and is Active, `New` fits its New budget, `Reinject` is a prefix of the head
/// candidate and fits its Reinject budget. Returns the subflow's index.
pub(crate) fn accept_plan(
    plan: Plan,
    snapshots: &[SubflowSnapshot],
    head: Option<(u64, u32)>,
) -> Option<(usize, Payload)> {
    let Plan::Send { subflow, payload } = plan else {
        return None;
    };
    let i = snapshots.iter().position(|s| s.id == subflow)?;
    let s = &snapshots[i];
    let ok = s.state == SubflowState::Active
        && match payload {
            Payload::New { bytes } => fits(s.new_budget, bytes),
            Payload::Reinject { dsn, len } => {
                head.is_some_and(|(start, c)| start == dsn && len <= c)
                    && fits(s.reinject_budget, len)
            }
        };
    ok.then_some((i, payload))
}

impl Connection {
    /// The head reinjection candidate `(dsn, len)` (Hot-path rules); trims covered head parts.
    pub(crate) fn reinject_head(&mut self) -> Option<(u64, u32)> {
        let d = self
            .hooks
            .data
            .as_mut()
            .filter(|d| !d.reinject.is_empty())?;
        let fin = d.close.local.is_some();
        d.reinject.head(active_maps(&self.subflows), &d.send, fin)
    }

    /// Refills the snapshot buffer: both budgets of every subflow, read-only (`send_budget`).
    /// A subflow that may not take a mapping now (TCP state, all mapping slots taken, `buf`
    /// smaller than its MTU) reports zero budgets.
    pub(crate) fn build_snapshots(&mut self, now: Instant, head: Option<(u64, u32)>, buf: usize) {
        let mut snapshots = std::mem::take(&mut self.hooks.snapshots);
        snapshots.clear();
        for sf in &mut self.subflows {
            let hk = SubflowHooks {
                conn: &mut self.hooks,
                sf: &mut sf.mp,
            };
            let (mut new_budget, mut reinject_budget) = Default::default();
            if buf >= sf.tcb.mtu() && hk.may_assign(&sf.tcb) {
                let options = hk.data_option_len();
                let (bytes, run) = (hk.conn.unassigned_len(), hk.conn.candidate_len());
                new_budget = sf.tcb.send_budget(now, bytes, run, false, options, &hk);
                if let Some((_, c)) = head {
                    let c = c as usize;
                    reinject_budget = sf.tcb.send_budget(now, c, c, true, options, &hk);
                }
            }
            snapshots.push(SubflowSnapshot {
                id: sf.id,
                state: sf.state,
                new_budget,
                reinject_budget,
                srtt: sf.tcb.srtt().unwrap_or(INITIAL_RTO),
                app_limited: sf.tcb.app_limited(),
            });
        }
        self.hooks.snapshots = snapshots;
    }

    #[cfg(test)]
    pub(crate) fn snapshots(&self) -> &[SubflowSnapshot] {
        &self.hooks.snapshots
    }

    /// `poll_transmit` step 2 (spec §3.1): trim the reinjection head, snapshot, `plan`,
    /// validate and install the mapping. Returns the index of the subflow that got it. A step
    /// that installs no mapping ends the pass: it is an app-limited evaluation point.
    pub(crate) fn schedule(&mut self, now: Instant, buf: usize) -> Option<usize> {
        self.hooks.data.as_ref()?;
        let installed = self.schedule_step(now, buf);
        // Every subflow offered a budget and given nothing in this step is passed over.
        for (k, (sf, s)) in self
            .subflows
            .iter_mut()
            .zip(&self.hooks.snapshots)
            .enumerate()
        {
            if Some(k) == installed {
                sf.mp.offered_unused = false;
            } else if s.state == SubflowState::Active
                && (s.new_budget.bytes() > 0 || s.reinject_budget.bytes() > 0)
            {
                sf.mp.offered_unused = true;
            }
        }
        if installed.is_none() {
            self.mark_passed_over(now);
            let d = self.hooks.data.as_ref().unwrap();
            if d.send.next == d.send.end && d.reinject.is_empty() {
                for sf in &mut self.subflows {
                    if sf.state == SubflowState::Active {
                        let hk = SubflowHooks {
                            conn: &mut self.hooks,
                            sf: &mut sf.mp,
                        };
                        sf.tcb.mark_unused_opportunity(now, AppLimited::NoData, &hk);
                    }
                }
            }
        }
        installed
    }

    /// App-limited evaluation point: at the end of a pass, and before an input reaches the
    /// connection (for drivers that interleave one `poll_transmit` per input). Every subflow
    /// passed over since the last evaluation is marked `NotScheduled`, unless data is queued
    /// but the connection-level window admits none of it: receiver-limited is not app-limited
    /// (draft-ietf-ccwg-bbr-06 §4.1.1.3.1), and the flags are dropped.
    pub(crate) fn mark_passed_over(&mut self, now: Instant) {
        if !self.subflows.iter().any(|sf| sf.mp.offered_unused) {
            return;
        }
        let receiver_limited = self
            .hooks
            .data
            .as_ref()
            .is_some_and(|d| d.send.next != d.send.end && !d.fallback && d.reinject.is_empty())
            && self.hooks.unassigned_len() == 0;
        for sf in &mut self.subflows {
            if std::mem::take(&mut sf.mp.offered_unused) && !receiver_limited {
                let hk = SubflowHooks {
                    conn: &mut self.hooks,
                    sf: &mut sf.mp,
                };
                sf.tcb
                    .mark_unused_opportunity(now, AppLimited::NotScheduled, &hk);
            }
        }
    }

    fn schedule_step(&mut self, now: Instant, buf: usize) -> Option<usize> {
        let head = self.reinject_head();
        self.build_snapshots(now, head, buf);
        let hooks = &mut self.hooks;
        if !hooks.snapshots.iter().any(|s| {
            s.state == SubflowState::Active
                && (s.new_budget.bytes() > 0 || s.reinject_budget.bytes() > 0)
        }) {
            return None;
        }
        let new_bytes = hooks.unassigned_len() as u64;
        let reinject = &hooks.data.as_ref().unwrap().reinject;
        let pending = Pending {
            new_bytes,
            reinject,
        };
        let plan = hooks.scheduler.plan(now, &pending, &hooks.snapshots);
        let Some((i, payload)) = accept_plan(plan, &hooks.snapshots, head) else {
            if plan != Plan::Idle {
                hooks.rejected_plans += 1;
            }
            return None;
        };
        let sf = &mut self.subflows[i];
        let mut hk = SubflowHooks {
            conn: &mut self.hooks,
            sf: &mut sf.mp,
        };
        if !hk.install(payload) {
            hk.conn.assign_failures += 1;
            return None;
        }
        let (bytes, reinject) = match payload {
            Payload::New { bytes } => (bytes, false),
            Payload::Reinject { len, .. } => (len, true),
        };
        self.hooks.scheduler.on_assigned(sf.id, bytes, reinject);
        Some(i)
    }
}

impl SubflowHooks<'_> {
    pub fn update_recovery(&mut self, tcb: &Tcb, now: Instant) {
        let Some(d) = &mut self.conn.data else {
            return;
        };
        // A joining subflow carries no data and has no say in connection-level timers.
        if tcb.state() == crate::tcp::TcpState::Closed || self.sf.joining() {
            return;
        }
        if !d.fallback
            && d.close.sent
            && !d.close.acked
            && !d.close.due
            && d.send.una == d.send.end
            && d.close.at.is_none()
        {
            d.close.interval = tcb.retransmission_timeout();
            d.close.at = Some(now + d.close.interval);
        }
        let head = (!d.fallback && d.send.una != d.send.next).then_some(d.send.una);
        if d.recovery_head != head {
            d.recovery_head = head;
            d.recovery_at = None;
            d.recovery_interval = tcb.retransmission_timeout();
        }
        let queued = d.reinject.first().map(|(start, _)| start) == head;
        if head.is_none() || self.sf.tx.uncovered_len(d.send.una, 1) == 0 {
            d.recovery_at = None;
        } else if !queued {
            let at = d.recovery_at.get_or_insert(now + d.recovery_interval);
            if now >= *at {
                // The uncovered head run: no live copy covers any of it.
                let outstanding = d.send.next.wrapping_sub(d.send.una) as usize;
                let run = self.sf.tx.uncovered_len(d.send.una, outstanding);
                d.reinject.insert(d.send.una, run as u64);
                d.recovery_at = None;
                d.recovery_interval = (d.recovery_interval * 2).min(Duration::from_secs(60));
            }
        }
    }
    pub fn prepare_send(&mut self, tcb: &mut Tcb, now: Instant) {
        if self.sf.joining() {
            // No data, probes or DATA_FIN while joining; it still closes with the rest.
            if self.conn.data.as_ref().is_some_and(|d| d.close.acked) {
                tcb.close();
            }
            return;
        }
        self.update_recovery(tcb, now);
        // Preserve the third ACK and replies to repeated SYN/ACKs before
        // requesting a separate DATA_FIN ACK. An idle peer need not send DSS first.
        self.sf.capable_ack_due = tcb.ack_pending()
            && self
                .conn
                .negotiation
                .as_ref()
                .is_some_and(|m| m.state == State::PreConfirmed);
        if let Some(d) = self.conn.data.as_mut().filter(|d| !d.fallback) {
            if d.close.acked {
                tcb.close();
            }
            // Bare TCP FIN retires this path, but DATA_FIN+FIN leaves it available
            // for our half-close response until our own DATA_FIN is acknowledged.
            if tcb.fin_received() && !d.recv.has_fin() {
                tcb.close();
            }
            if d.close.at.is_some_and(|at| now >= at) {
                d.close.at = None;
                d.close.due = true;
                d.close.interval = (d.close.interval * 2).min(Duration::from_secs(60));
            }
            if d.close.local.is_some()
                && d.send.next == d.send.end
                && !d.close.sent
                && !d.close.attached
            {
                d.close.due = true;
            }
            if d.close.due {
                tcb.request_ack();
            }
        }
        if std::mem::take(&mut self.sf.ack_now) {
            tcb.request_ack();
        }
        if self.conn.data.is_some() && self.sf.final_mapping.is_some() {
            tcb.request_ack();
        }
        let demand = match (&self.conn.negotiation, &self.conn.data) {
            (Some(m), Some(d)) => {
                (d.send.next != d.send.end || !d.reinject.is_empty())
                    && (tcb.peer_window_closed()
                        || (!d.fallback
                            && m.send_right_edge
                                .is_some_and(|edge| edge.wrapping_sub(d.send.next) as i64 <= 0)))
            }
            _ => false,
        };
        tcb.set_probe_demand(demand);
        let reinject = self
            .conn
            .data
            .as_ref()
            .is_some_and(|d| !d.reinject.is_empty());
        tcb.pending_send(
            now,
            self.unassigned_len(),
            self.candidate_len(),
            self.data_option_len(),
            reinject,
            self,
        );
    }
    /// The subflow may take a new mapping: data can flow on it and a mapping slot is free.
    fn may_assign(&self, tcb: &Tcb) -> bool {
        let Some(d) = &self.conn.data else {
            return false;
        };
        !self.sf.tx.is_full()
            && !self.sf.joining()
            && (tcb.state() == crate::tcp::TcpState::Established
                || (tcb.state() == crate::tcp::TcpState::CloseWait
                    && (d.fallback || d.recv.has_fin())))
    }
    /// Installs a validated plan's mapping; DATA_FIN rides on the final data mapping.
    fn install(&mut self, payload: Payload) -> bool {
        let d = self.conn.data.as_mut().unwrap();
        match payload {
            Payload::Reinject { dsn, len } => {
                let len = len as usize;
                if !d.send.assign(&mut self.sf.tx, dsn, len) {
                    return false;
                }
                d.reinject.remove(dsn, len as u64);
                if d.close.local == Some(dsn.wrapping_add(len as u64)) {
                    self.sf.tx.attach_fin();
                    d.close.attached = true;
                }
            }
            Payload::New { bytes } => {
                let len = bytes as usize;
                if !d.send.assign(&mut self.sf.tx, d.send.next, len) {
                    return false;
                }
                if d.close.local == Some(d.send.next)
                    && len < u16::MAX as usize
                    && !(self.conn.negotiation.as_ref().unwrap().state == State::PreConfirmed
                        && self.sf.tx.assigned_end().wrapping_sub(len as u32) == 1)
                {
                    self.sf.tx.attach_fin();
                    d.close.attached = true;
                }
            }
        }
        true
    }
    fn candidate_len(&self) -> usize {
        self.conn.candidate_len()
    }
}
impl SendBuf for SubflowHooks<'_> {
    fn unassigned_len(&self) -> usize {
        self.conn.unassigned_len()
    }

    fn segment_limit(&self, ssn: u32) -> usize {
        if self.conn.data.is_some() {
            self.sf.tx.segment_limit(ssn)
        } else {
            usize::MAX
        }
    }
    fn is_reinjection(&self, ssn: u32) -> bool {
        self.conn.data.is_some() && self.sf.tx.is_reinjection(ssn)
    }
    fn peek_with<R>(&self, ssn: u32, max: usize, f: impl FnOnce(&[u8]) -> R) -> Option<R> {
        if self.conn.data.is_some() {
            self.sf.tx.peek_with(ssn, max, f)
        } else {
            self.conn.plain.peek_with(ssn, max, f)
        }
    }
    fn assigned_end(&self) -> u32 {
        if self.conn.data.is_some() {
            self.sf.tx.assigned_end()
        } else {
            self.conn.plain.assigned_end()
        }
    }
    fn mark_acked(&mut self, ssn: u32) {
        match &mut self.conn.data {
            Some(d) => {
                if let Some(dsn) = self.sf.tx.acked_dsn(ssn) {
                    self.sf.tcp_acked_dsn = dsn;
                    self.sf.tcp_acked_ssn = Some(ssn);
                    if !d.fallback && !self.sf.dss_confirmed {
                        match self.sf.valid_data_ack {
                            Some(true) => self.sf.dss_confirmed = true,
                            Some(false) => {
                                d.fall_back(self.sf, self.conn.negotiation.as_mut().unwrap());
                                self.conn.fallback_event = true;
                            }
                            None => {}
                        }
                    }
                }
                self.sf.tx.mark_acked(ssn);
                if d.fallback {
                    d.release(self.sf.tcp_acked_dsn);
                }
            }
            None => self.conn.plain.mark_acked(ssn),
        }
    }
}
impl SegmentHooks for SubflowHooks<'_> {
    fn data_option_len(&self) -> usize {
        if self.conn.data.as_ref().is_some_and(|d| !d.fallback) {
            28
        } else {
            0
        }
    }
    fn data_options_for(&mut self, ssn: u32, out: &mut [u8]) -> usize {
        let (Some(m), Some(d)) = (&self.conn.negotiation, &self.conn.data) else {
            return self.options_for(TcpFlags::ACK, out);
        };
        if d.fallback {
            return self.options_for(TcpFlags::ACK, out);
        }
        let mapping = self.sf.tx.mapping(ssn).expect("payload has mapping");
        let data_fin = self.sf.tx.data_fin(ssn);
        let option = if m.state == State::PreConfirmed && mapping.ssn == 1 {
            MptcpOption::Capable(MpCapable {
                version: 1,
                flags: CAP_H,
                sender_key: Some(m.local_key),
                receiver_key: m.peer_key,
                data_len: Some(mapping.data_len),
                checksum: None,
            })
        } else {
            MptcpOption::Dss(mptcp::Dss {
                data_fin,
                data_ack: Some(mptcp::DataAck::Ack64(d.recv.next)),
                mapping: Some(mapping),
            })
        };
        let n = mptcp::encode(&option, out).expect("fixed mapping layout fits");
        let padded = n.next_multiple_of(4);
        out[n..padded].fill(1);
        padded
    }
    fn window_offer(&self, scale: u8, mss: u16) -> Option<u16> {
        self.conn
            .data
            .as_ref()
            .map(|d| d.recv.window_offer(scale, mss))
    }
    fn window_sent(&mut self, field: u16, scale: u8) {
        if let Some(d) = &mut self.conn.data {
            d.recv.window_sent(field, scale);
        }
    }
    fn window_update_due(&self, scale: u8, mss: u16) -> bool {
        self.conn
            .data
            .as_ref()
            .is_some_and(|d| d.recv.window_update_due(scale, mss))
    }
    fn duplicate_ack_allowed(&self, seg: &Segment<'_>) -> bool {
        self.conn.data.is_none() || !walk(seg.options).any(|o| matches!(o, Ok(TcpOpt::Mptcp(raw)) if !matches!(mptcp::parse(raw), Ok(MptcpOption::Dss(_)))))
    }

    fn options_for(&mut self, flags: TcpFlags, out: &mut [u8]) -> usize {
        if let Some(n) = self.join_options(flags, out) {
            return n;
        }
        if let (Some(m), Some(d)) = (&self.conn.negotiation, &mut self.conn.data) {
            if let Some(mapping) = self.sf.final_mapping {
                let n = mptcp::encode(
                    &MptcpOption::Dss(mptcp::Dss {
                        data_fin: false,
                        data_ack: None,
                        mapping: Some(mapping),
                    }),
                    out,
                )
                .expect("infinite mapping fits");
                let padded = n.next_multiple_of(4);
                out[n..padded].fill(1);
                return padded;
            }
            if d.fallback {
                return 0;
            }
            if d.close.due && !self.sf.capable_ack_due && flags.contains(TcpFlags::ACK) {
                let n = mptcp::encode(
                    &MptcpOption::Dss(mptcp::Dss {
                        data_fin: true,
                        data_ack: Some(mptcp::DataAck::Ack64(d.recv.next)),
                        mapping: Some(mptcp::Mapping {
                            dsn: mptcp::Dsn::Dsn64(d.close.local.unwrap()),
                            ssn: 0,
                            data_len: 1,
                            checksum: None,
                        }),
                    }),
                    out,
                )
                .expect("DATA_FIN fits");
                let padded = n.next_multiple_of(4);
                out[n..padded].fill(1);
                return padded;
            }
            if m.state == State::Confirmed && flags.contains(TcpFlags::ACK) {
                return mptcp::encode(
                    &MptcpOption::Dss(mptcp::Dss {
                        data_fin: false,
                        data_ack: Some(mptcp::DataAck::Ack64(d.recv.next)),
                        mapping: None,
                    }),
                    out,
                )
                .expect("DSS ACK fits");
            }
        }
        self.conn
            .negotiation
            .as_mut()
            .map_or(0, |m| m.options_for(flags, out))
    }
    fn on_valid_segment(&mut self, seg: &Segment<'_>) {
        self.sf.valid_data_ack = None;
        // Validate the whole option list before mutating mapping or DATA_ACK state.
        let (mut dss, mut capable, mut fastclose) = (None, None, None);
        for opt in walk(seg.options).filter(|_| !seg.flags.contains(TcpFlags::SYN)) {
            match opt {
                Err(_) => return,
                Ok(TcpOpt::Mptcp(raw)) => match mptcp::parse(raw) {
                    Ok(MptcpOption::Dss(v)) if dss.is_none() => dss = Some(v),
                    Ok(MptcpOption::Capable(v)) if capable.is_none() => capable = Some(v),
                    Ok(MptcpOption::FastClose { receiver_key }) if fastclose.is_none() => {
                        fastclose = Some(receiver_key)
                    }
                    Ok(
                        MptcpOption::Dss(_)
                        | MptcpOption::Capable(_)
                        | MptcpOption::FastClose { .. },
                    )
                    | Err(_) => return,
                    _ => {}
                },
                _ => {}
            }
        }
        self.sf.valid_data_ack = if dss.is_some_and(|v| v.data_ack.is_some()) {
            None
        } else {
            Some(false)
        };
        // A join's SYN/ACK is its own (the handshake state and SYN window are the initial
        // subflow's); later segments find the connection Confirmed and go on as usual.
        if self.sf.join.is_some() {
            self.join_segment(seg);
            if seg.flags.contains(TcpFlags::SYN) {
                return;
            }
        }
        let Some(m) = &mut self.conn.negotiation else {
            return;
        };
        if fastclose == Some(m.local_key)
            && matches!(m.state, State::PreConfirmed | State::Confirmed)
            && (seg.flags.contains(TcpFlags::ACK) || seg.flags.contains(TcpFlags::RST))
        {
            self.conn.fast_closed = true;
            return;
        }
        m.on_valid_segment(seg, &mut self.sf.peer_scale);
        if self.conn.data.is_none() && matches!(m.state, State::PreConfirmed | State::Confirmed) {
            let mut send = SendStore::new(m.local_idsn.wrapping_add(1), self.conn.send_cap);
            // Writes during SYN-SENT were queued before knowing whether MPC succeeds.
            let mut ssn = 1;
            while let Some(n) = self
                .conn
                .plain
                .peek_with(ssn, self.conn.send_cap, |bytes| send.write(bytes))
            {
                debug_assert!(n > 0);
                ssn = ssn.wrapping_add(n as u32);
                self.conn.plain.mark_acked(ssn);
            }
            self.conn.data = Some(DataState {
                recv: RecvAssembler::new(
                    m.peer_idsn.unwrap().wrapping_add(1),
                    self.conn.recv_cap,
                    64,
                ),
                send,
                close: close::Close::default(),
                sanity_failures: 0,
                recovery_head: None,
                recovery_at: None,
                recovery_interval: Duration::from_secs(1),
                reinject: ReinjectQueue::new(m.local_idsn.wrapping_add(1)),
                fallback: false,
            });
            self.sf.tcp_acked_dsn = m.local_idsn.wrapping_add(1);
            self.sf.local_isn = seg.ack.wrapping_add(u32::MAX);
        }
        if seg.flags.contains(TcpFlags::SYN) {
            if let Some(d) = &mut self.conn.data {
                d.recv.right_edge = d
                    .recv
                    .next
                    .wrapping_add(self.conn.recv_cap.min(65535) as u64);
            }
        }
        if seg.flags.contains(TcpFlags::SYN) || seg.flags.contains(TcpFlags::RST) {
            return;
        }
        let Some(d) = &mut self.conn.data else {
            return;
        };
        if d.fallback {
            return;
        }
        if let Some(c) = capable {
            if let Some(len) = c.data_len {
                if c.sender_key != m.peer_key
                    || c.receiver_key != Some(m.local_key)
                    || !self
                        .sf
                        .rx
                        .install(1, m.peer_idsn.unwrap().wrapping_add(1), u32::from(len))
                {
                    self.sf.reset = true;
                    return;
                }
                self.sf.unmapped = 0;
            }
        }
        if let Some(v) = dss {
            if let Some(mapping) = v.mapping {
                let dsn = match mapping.dsn {
                    mptcp::Dsn::Dsn32(x) => promote32(x, d.recv.next),
                    mptcp::Dsn::Dsn64(x) => x,
                };
                if v.data_fin
                    && (mapping.data_len == 0
                        || (mapping.data_len == 1 && mapping.ssn != 0)
                        || (mapping.data_len > 1 && seg.payload.is_empty()))
                {
                    return;
                }
                if mapping.data_len == 0 {
                    d.fall_back(self.sf, m);
                    self.sf.rx_infinite = Some((mapping.ssn, dsn));
                    d.release(self.sf.tcp_acked_dsn);
                    self.conn.fallback_event = true;
                    return;
                }
                let len = u32::from(mapping.data_len).saturating_sub(u32::from(v.data_fin));
                if len > 0 && !self.sf.rx.install(mapping.ssn, dsn, len) {
                    self.sf.reset = true;
                    return;
                }
                if v.data_fin && d.recv.finish(dsn.wrapping_add(u64::from(len))) {
                    self.sf.ack_now = true;
                }
                self.sf.unmapped = 0;
            }
            if let Some(ack) = v.data_ack {
                let ack = match ack {
                    mptcp::DataAck::Ack32(x) => promote32(x, d.send.una),
                    mptcp::DataAck::Ack64(x) => x,
                };
                let fin_ack =
                    d.close.sent && d.close.local.is_some_and(|fin| ack == fin.wrapping_add(1));
                if d.release(if fin_ack { d.close.local.unwrap() } else { ack }) {
                    if fin_ack {
                        d.close.acked = true;
                        d.close.at = None;
                        d.close.due = false;
                    }
                    self.sf.valid_data_ack = Some(true);
                    // A corrected DATA_ACK can arrive after TCP has released the mapping.
                    // Keep its ACK coverage independently of the live TxMaps entries;
                    // stale/SYN-only TCP ACKs cannot confirm the data path.
                    if self
                        .sf
                        .tcp_acked_ssn
                        .is_some_and(|ssn| seg.ack.ge(self.sf.local_isn.wrapping_add(ssn)))
                    {
                        self.sf.dss_confirmed = true;
                    }
                    let edge = ack.wrapping_add(u64::from(seg.wnd) << self.sf.peer_scale);
                    if m.send_right_edge
                        .is_none_or(|old| edge.wrapping_sub(old) as i64 > 0)
                    {
                        m.send_right_edge = Some(edge);
                    }
                }
            }
        }
        // A current duplicate TCP ACK still covers our data even when an earlier
        // malformed DATA_ACK let TCP release the live mapping without confirmation.
        if !self.sf.dss_confirmed
            && self.sf.valid_data_ack == Some(false)
            && self
                .sf
                .tcp_acked_ssn
                .is_some_and(|ssn| seg.ack.ge(self.sf.local_isn.wrapping_add(ssn)))
        {
            d.fall_back(self.sf, m);
            d.release(self.sf.tcp_acked_dsn);
            self.conn.fallback_event = true;
        }
    }

    fn requires_tcp_sequence_check(&self, seg: &Segment<'_>) -> bool {
        walk(seg.options).any(|opt| matches!(opt,
            Ok(TcpOpt::Mptcp(raw)) if matches!(mptcp::parse(raw), Ok(MptcpOption::FastClose { .. }))))
    }
    fn delegates_data(&self) -> bool {
        self.conn.data.is_some()
    }
    fn reset_requested(&self) -> bool {
        self.conn.fast_closed || (self.conn.data.is_some() && self.sf.reset)
    }
    fn receipt_advanced(&mut self, ssn: u32) {
        if self.conn.data.is_some() {
            if let Some((base, dsn)) = &mut self.sf.rx_infinite {
                *dsn = dsn.wrapping_add_signed(ssn.wrapping_sub(*base) as i32 as i64);
                *base = ssn;
            }
            self.sf.rx.ack(ssn);
        }
    }
    fn receive_data(
        &mut self,
        ssn: u32,
        tcp_ack: u32,
        bytes: &[u8],
    ) -> Vec<std::ops::Range<usize>> {
        let d = self.conn.data.as_mut().unwrap();
        let mut accepted = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let pos = ssn.wrapping_add(at as u32);
            let translated = if d.fallback {
                self.sf.rx_infinite.map(|(ssn, dsn)| {
                    (
                        dsn.wrapping_add_signed(pos.wrapping_sub(ssn) as i32 as i64),
                        bytes.len() - at,
                    )
                })
            } else {
                self.sf.rx.translate(pos)
            };
            if let Some((dsn, len)) = translated {
                let len = len.min(bytes.len() - at);
                let dsn_offset = dsn.wrapping_sub(d.recv.next) as i64;
                if at == 0
                    && dsn_offset.saturating_add(len as i64) > 0
                    && i64::from(ssn.wrapping_sub(tcp_ack) as i32) > dsn_offset
                {
                    d.sanity_failures = d.sanity_failures.saturating_add(1);
                }
                let n = if d.fallback {
                    d.recv.accept_tcp(dsn, &bytes[at..at + len])
                } else {
                    d.recv.accept(dsn, &bytes[at..at + len]).1
                };
                if n > 0 {
                    accepted.push(at..at + n);
                }
                at += len;
            } else {
                // Unmapped bytes are never retained, but count against the reset bound.
                let len = self.sf.rx.unmapped_run(pos, bytes.len() - at);
                self.sf.unmapped = self.sf.unmapped.saturating_add(len);
                if self.sf.unmapped > self.conn.recv_cap {
                    self.sf.reset = true;
                    return Vec::new();
                }
                accepted.push(at..at + len);
                at += len;
            }
        }
        accepted
    }

    fn accept_payload(&mut self, ssn: u32, data: &[u8]) {
        self.conn.plain.accept_payload(ssn, data);
    }
    fn recv_window(&self) -> u32 {
        self.conn
            .data
            .as_ref()
            .map_or_else(|| self.conn.plain.recv_window(), |d| d.recv.free() as u32)
    }
}

impl DataState {
    /// Every DATA_ACK release: frees the store, then prunes the reinjection queue below
    /// the new `send.una`.
    fn release(&mut self, ack: u64) -> bool {
        let released = self.send.ack(ack);
        if released {
            self.reinject.ack(self.send.una);
        }
        released
    }
    fn fall_back(&mut self, sf: &mut SubflowMp, m: &mut Negotiation) {
        self.fallback = true;
        self.close = close::Close::default();
        m.state = State::FellBack;
        self.recovery_at = None;
        self.reinject.clear();
        sf.rx_infinite = Some((1, m.peer_idsn.unwrap().wrapping_add(1)));
        sf.final_mapping = Some(mptcp::Mapping {
            dsn: mptcp::Dsn::Dsn64(m.local_idsn.wrapping_add(1)),
            ssn: 1,
            data_len: 0,
            checksum: None,
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    SynSent,
    PreConfirmed,
    Confirmed,
    FellBack,
}

pub(crate) struct Negotiation {
    pub state: State,
    pub token: u32,
    pub local_key: u64,
    /// The peer's SYN/ACK MP_CAPABLE had C=1: it accepts no MP_JOIN to its source address.
    pub peer_c: bool,
    pub peer_idsn: Option<u64>,
    pub peer_key: Option<u64>,
    pub local_idsn: u64,
    pub send_right_edge: Option<u64>,
    syns_sent: u8,
    connected_pending: bool,
}

impl Negotiation {
    pub fn new(local_key: u64) -> Self {
        let (token, local_idsn) = key_token_idsn(local_key);
        Self {
            state: State::SynSent,
            token,
            local_key,
            local_idsn,
            peer_c: false,
            send_right_edge: None,
            peer_idsn: None,
            peer_key: None,
            syns_sent: 0,
            connected_pending: false,
        }
    }

    fn on_valid_segment(&mut self, seg: &Segment<'_>, peer_scale: &mut u8) {
        if !self.connected_pending
            && self.state == State::PreConfirmed
            && seg.flags.contains(TcpFlags::ACK)
            && !seg.flags.contains(TcpFlags::RST)
        {
            let mut dss = false;
            for opt in walk(seg.options) {
                match opt {
                    Err(_) => return,
                    Ok(TcpOpt::Mptcp(raw)) => match mptcp::parse(raw) {
                        Ok(MptcpOption::Dss(_)) if !dss => dss = true,
                        Ok(MptcpOption::Dss(_)) | Err(_) => return,
                        _ => {}
                    },
                    _ => {}
                }
            }
            if dss {
                self.state = State::Confirmed;
            }
        }
        if !seg.flags.contains(TcpFlags::SYN | TcpFlags::ACK) || seg.flags.contains(TcpFlags::RST) {
            return;
        }
        self.connected_pending = true;
        if self.state != State::SynSent {
            return;
        }
        // Parse the whole list: a valid prefix cannot hide a malformed or duplicate MPC.
        let mut peer_key = None;
        for opt in walk(seg.options) {
            match opt {
                Err(_) => {
                    peer_key = None;
                    break;
                }
                Ok(TcpOpt::Mptcp(raw)) => match mptcp::parse(raw) {
                    Ok(MptcpOption::Capable(c))
                        if raw.len() == 12
                            && c.version == 1
                            && c.flags & !CAP_C == CAP_H
                            && peer_key.is_none() =>
                    {
                        peer_key = c.sender_key;
                        self.peer_c = c.flags & CAP_C != 0;
                    }
                    _ => {
                        peer_key = None;
                        break;
                    }
                },
                _ => {}
            }
        }
        *peer_scale = walk(seg.options)
            .filter_map(|o| match o {
                Ok(TcpOpt::WindowScale(s)) => Some(s.min(14)),
                _ => None,
            })
            .next()
            .unwrap_or(0);
        self.peer_key = peer_key;
        self.peer_idsn = peer_key.map(|key| key_token_idsn(key).1);
        self.send_right_edge =
            peer_key.map(|_| self.local_idsn.wrapping_add(1 + u64::from(seg.wnd)));
        self.state = peer_key.map_or(State::FellBack, |_| State::PreConfirmed);
    }

    fn options_for(&mut self, flags: TcpFlags, out: &mut [u8]) -> usize {
        let keys = match self.state {
            State::SynSent if flags.contains(TcpFlags::SYN) => {
                if self.syns_sent == 3 {
                    self.state = State::FellBack;
                    return 0;
                }
                self.syns_sent += 1;
                (None, None)
            }
            State::PreConfirmed if flags.contains(TcpFlags::ACK) => {
                (Some(self.local_key), self.peer_key)
            }
            State::Confirmed if flags.contains(TcpFlags::ACK) => {
                return mptcp::encode(
                    &MptcpOption::Dss(mptcp::Dss {
                        data_fin: false,
                        data_ack: Some(mptcp::DataAck::Ack64(
                            self.peer_idsn.unwrap().wrapping_add(1),
                        )),
                        mapping: None,
                    }),
                    out,
                )
                .expect("DSS DATA_ACK fits TCP options");
            }
            _ => return 0,
        };
        mptcp::encode(
            &MptcpOption::Capable(MpCapable {
                version: 1,
                flags: CAP_H,
                sender_key: keys.0,
                receiver_key: keys.1,
                data_len: None,
                checksum: None,
            }),
            out,
        )
        .expect("MP_CAPABLE has a fixed layout fitting TCP options")
    }

    pub fn on_transmitted(&mut self, flags: TcpFlags) -> Option<bool> {
        if flags.contains(TcpFlags::ACK)
            && !flags.contains(TcpFlags::RST)
            && std::mem::take(&mut self.connected_pending)
        {
            Some(matches!(self.state, State::PreConfirmed | State::Confirmed))
        } else {
            None
        }
    }
}
