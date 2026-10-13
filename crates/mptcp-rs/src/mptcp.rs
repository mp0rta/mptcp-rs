//! MPTCP negotiation, MP_JOIN subflows, data transfer, recovery and closure.
pub(crate) mod addr;
mod close;
pub(crate) mod data;
mod join;
mod opp;
pub(crate) mod sched;
pub(crate) mod signal;
mod subflow;
use crate::crypto::{add_addr_hmac, key_token_idsn};
use data::{RecvAssembler, SendStore, TxMaps, promote32};
pub(crate) use join::{Join, JoinRole};
pub(crate) use opp::Cand;
pub use opp::DebugStats;
pub(crate) use opp::{Episode, Repair};
use sched::{
    HealthEvent, HealthVerdict, MinRtt, Payload, Pending, Plan, ReinjectQueue, Scheduler,
    SubflowSnapshot,
};
pub use subflow::SubflowId;
pub(crate) use subflow::{Subflow, SubflowHooks, SubflowMp, SubflowState};

use crate::Event;
use crate::connection::Connection;
use crate::tcp::rtt::INITIAL_RTO;

use crate::tcp::{
    AckPurpose, AppLimited, ConnectConfig, PlainHooks, SegmentHooks, SendBudget, SendBuf, Tcb,
    TcpState,
};
use crate::time::Instant;
use crate::wire::packet::{Segment, TcpFlags};
use crate::wire::{
    mptcp::{self, CAP_A, CAP_B, CAP_C, CAP_H, MpCapable, MptcpOption},
    tcp_options::{TcpOpt, walk},
};
use std::net::SocketAddr;
use std::time::Duration;

pub(crate) struct ConnectionHooks {
    plain: PlainHooks,
    pub negotiation: Option<Negotiation>,
    pub data: Option<DataState>,
    recv_cap: usize,
    send_cap: usize,
    pub fallback_event: bool,
    pub fast_closed: bool,
    /// An MP_JOIN SYN has been sent on this connection (a history, not a subflow count): from
    /// then on stripping resets its subflow and never falls back (RFC 8684 L2321–2328).
    pub joined_ever: bool,
    /// The highest `SubflowMp::dsn_end` of the subflows already freed.
    pub freed_dsn_end: Option<u64>,
    /// MinRTT; tests inject others (spec §4: crate-internal, one implementation).
    pub scheduler: Box<dyn Scheduler>,
    /// Refilled every scheduling step; capacity = subflow cap, so steps never allocate.
    snapshots: Vec<SubflowSnapshot>,
    /// Signals waiting for an ACK-only segment (M3 spec §3.2).
    pub signals: signal::Signals,
    /// Peer address ids named by REMOVE_ADDR in the current input
    /// (`Connection::peer_removed`).
    pub peer_removed: Vec<u8>,
    /// Authenticated ADD_ADDRs in the current input (`Connection::peer_announced`).
    pub peer_announced: Vec<signal::Echo>,
    /// ADD_ADDRs whose HMAC did not match (RFC 8684 L2017–2018); debug counter.
    pub add_addr_bad_hmac: u64,
    /// ADD_ADDRs naming a known id with another IP (RFC 8684 L2043–2047); debug counter.
    pub add_addr_conflicts: u64,
    /// Plans rejected by validation (spec §4 rule 1); debug counter.
    pub rejected_plans: u64,
    /// Validated plans `SendStore::assign` refused; stays 0 by construction.
    pub assign_failures: u64,
    /// Opportunistic retransmission counters (`Connection::debug_stats`).
    pub debug: DebugStats,
    /// The latest scheduling step found an opportunistic candidate.
    opp_live: bool,
    /// Receiver SWS MSS: the largest effective MSS among Active subflows (spec §5.4); 0 until
    /// the first `Connection::select_control`.
    sws_mss: u16,
}

/// MP_TCPRST option bytes for our RSTs (M3 spec §3.4).
pub(crate) fn tcprst(reason: u8, transient: bool) -> [u8; 4] {
    let mut out = [0; 4];
    let option = MptcpOption::TcpRst { transient, reason };
    mptcp::encode(&option, &mut out).expect("MP_TCPRST is 4 octets");
    out
}

/// MP_FASTCLOSE option bytes carrying the peer's `key` (M3 spec §3.5).
pub(crate) fn fastclose(key: u64) -> [u8; 12] {
    let mut out = [0; 12];
    let option = MptcpOption::FastClose { receiver_key: key };
    mptcp::encode(&option, &mut out).expect("MP_FASTCLOSE is 12 octets");
    out
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
    /// Fallback happened in the current input and `Connection::on_fallback` has not run yet:
    /// no release until it has checked the other subflows' data.
    settling: bool,
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
            joined_ever: false,
            freed_dsn_end: None,
            scheduler: Box::new(MinRtt),
            snapshots: Vec::with_capacity(SUBFLOW_CAP),
            signals: Default::default(),
            peer_removed: Vec::new(),
            peer_announced: Vec::new(),
            add_addr_bad_hmac: 0,
            add_addr_conflicts: 0,
            rejected_plans: 0,
            assign_failures: 0,
            debug: DebugStats::default(),
            opp_live: false,
            sws_mss: 0,
        }
    }
    fn sws_mss(&self, own: u16) -> u16 {
        if self.sws_mss == 0 { own } else { self.sws_mss }
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
        // None once the data level has closed (a TIME-WAIT subflow may keep the connection).
        self.data
            .as_ref()
            .filter(|d| !d.close.closed)
            .and_then(|d| {
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
        .filter(|s| s.is(SubflowState::Active))
        .map(|s| &s.mp.tx)
}

/// The later of two DSNs (`end` if there is no `old`).
pub(crate) fn later(old: Option<u64>, end: u64) -> Option<u64> {
    Some(
        old.filter(|&o| o.wrapping_sub(end) as i64 > 0)
            .unwrap_or(end),
    )
}

/// The snapshot offers a budget for some candidate.
fn offered(s: &SubflowSnapshot) -> bool {
    [s.new_budget, s.reinject_budget, s.opp_budget]
        .iter()
        .any(|b| b.bytes() > 0)
}

/// Index of the lowest-`srtt` subflow that passes `f` (the first on ties).
fn lowest_rtt(subflows: &[Subflow], f: impl Fn(&Subflow) -> bool) -> Option<usize> {
    (0..subflows.len())
        .filter(|&i| f(&subflows[i]))
        .min_by_key(|&i| subflows[i].tcb.srtt().unwrap_or(INITIAL_RTO))
}

/// The subflow may take a new mapping: data can flow on it and a mapping slot is free.
fn may_assign(conn: &ConnectionHooks, sf: &SubflowMp, tcb: &Tcb) -> bool {
    let Some(d) = &conn.data else {
        return false;
    };
    !sf.tx.is_full()
        && !sf.joining()
        && (tcb.state() == TcpState::Established
            || (tcb.state() == TcpState::CloseWait && (d.fallback || d.recv.has_fin())))
}

/// Spec §4 rule 1: `k × seg_payload` with `1 <= k <= full_segments`, or a short mapping:
/// exactly `partial` for new data (a shorter one may wait for the sender's SWS timer), at most
/// `partial` for reinjected data, which the `Tcb` sends regardless of SWS.
fn fits(b: SendBudget, bytes: u32, reinjected: bool) -> bool {
    let n = bytes as usize;
    n > 0
        && b.seg_payload > 0
        && ((n % b.seg_payload == 0 && n / b.seg_payload <= b.full_segments)
            || n == b.partial
            || (reinjected && n <= b.partial))
}

/// Validates a plan against the snapshot it was made from (boundary invariant 5): the named
/// subflow exists and is Active, `New` fits its New budget, `Reinject` is a prefix of the head
/// candidate and fits its Reinject budget, `Opportunistic` is a prefix of the opportunistic
/// candidate `opp` and fits its opportunistic budget (nonzero only on an eligible target).
/// Returns the subflow's index.
pub(crate) fn accept_plan(
    plan: Plan,
    snapshots: &[SubflowSnapshot],
    head: Option<(u64, u32)>,
    opp: Option<(u64, u32)>,
) -> Option<(usize, Payload)> {
    let Plan::Send { subflow, payload } = plan else {
        return None;
    };
    let i = snapshots.iter().position(|s| s.id == subflow)?;
    let s = &snapshots[i];
    let ok = s.state == SubflowState::Active
        && match payload {
            Payload::New { bytes } => fits(s.new_budget, bytes, false),
            Payload::Reinject { dsn, len } => {
                head.is_some_and(|(start, c)| start == dsn && len <= c)
                    && fits(s.reinject_budget, len, true)
            }
            Payload::Opportunistic { dsn, len } => {
                opp.is_some_and(|(start, c)| start == dsn && len <= c)
                    && fits(s.opp_budget, len, true)
            }
        };
    ok.then_some((i, payload))
}

impl Connection {
    /// Connection-scoped roles, set before every `poll_transmit` step 1 (spec §3, §4 rule 2,
    /// §5.4): the window update a read makes due goes on the lowest-RTT Active subflow that
    /// can still receive data, and a standalone DATA_FIN on the lowest-RTT Active subflow;
    /// with no such Active subflow, on a Stale one. A Closing subflow (bare peer FIN, closed
    /// from our side at once) carries neither. While data waits (unassigned or queued for
    /// reinjection), every Active subflow whose own peer window is zero has probe demand, and
    /// if the connection window is closed so has one more: the lowest-RTT Active one without
    /// unacknowledged data, else the lowest-RTT Active one. Every eligible target of the
    /// opportunistic candidate has demand (M3 §2.2). Also refreshes the receiver-SWS MSS.
    pub(crate) fn select_control(&mut self) {
        let opp = self.opp_candidate();
        for k in 0..self.subflows.len() {
            let t = &self.subflows[k];
            let demand = opp.is_some_and(|c| self.opp_target(t, c.dsn, c.blocking, !c.repair));
            self.subflows[k].mp.opp_demand = demand;
        }
        let (Some(d), Some(m)) = (&self.hooks.data, &self.hooks.negotiation) else {
            return;
        };
        let sfs = &self.subflows;
        let active = |sf: &Subflow| sf.is(SubflowState::Active);
        let role = |f: &dyn Fn(&Subflow) -> bool| {
            [SubflowState::Active, SubflowState::Stale]
                .into_iter()
                .find_map(|s| lowest_rtt(sfs, |sf| sf.is(s) && f(sf)))
        };
        let window = role(&|sf| !sf.tcb.fin_received());
        let fin = role(&|_| true);
        let waiting = d.send.next != d.send.end || !d.reinject.is_empty();
        let closed = !d.fallback
            && m.send_right_edge
                .is_some_and(|edge| edge.wrapping_sub(d.send.next) as i64 <= 0);
        let prober = (waiting && closed)
            .then(|| {
                lowest_rtt(sfs, |sf| active(sf) && !sf.tcb.has_unacked())
                    .or_else(|| lowest_rtt(sfs, active))
            })
            .flatten();
        // Connection-scoped signals (M3 spec §3.2): echoes on the lowest-RTT usable subflow,
        // REMOVE_ADDR on the lowest-RTT Active one not using a removed address.
        let signals = &self.hooks.signals;
        let echo = lowest_rtt(sfs, opp::usable).map(|i| sfs[i].id);
        let removed = |sf: &Subflow| {
            (self.local_addrs.id(sf.local.ip())).is_some_and(|id| signals.removing(id))
        };
        let remove = lowest_rtt(sfs, |sf| active(sf) && !removed(sf)).map(|i| sfs[i].id);
        let mut mss = 0;
        for (i, sf) in self.subflows.iter_mut().enumerate() {
            let active = sf.is(SubflowState::Active);
            sf.mp.window_owner = Some(i) == window;
            sf.mp.fin_carrier = Some(i) == fin;
            sf.mp.probe = Some(i) == prober || (waiting && active && sf.tcb.peer_window_closed());
            if active {
                mss = mss.max(sf.tcb.eff_mss());
            }
        }
        self.hooks.sws_mss = mss;
        (
            self.hooks.signals.echo_carrier,
            self.hooks.signals.remove_carrier,
        ) = (echo, remove);
    }

    /// Connection-level timers, evaluated once per input and per `poll_transmit` over all
    /// subflows (spec §4 rule 5, §5.5). Arms the DATA_FIN retry once it went out and all data
    /// is DATA_ACKed, and the data-retransmission timer while the head of the send queue is
    /// subflow-ACKed but not DATA_ACKed (no Active subflow holds a live copy covering it) and
    /// not already queued for reinjection. On
    /// expiry the uncovered head run — stopping before a live copy on any Active subflow — is
    /// queued for reinjection. With no subflow that may carry data (all Joining or closed)
    /// nothing is evaluated and the data-retransmission timer is disarmed. Timers use the largest un-backed-off RTO (RFC 6298 §2) among the
    /// Active subflows with an RTT sample, `INITIAL_RTO` when none has one: a backed-off RTO
    /// of a lossy subflow must not stretch recovery of what the healthy one carried.
    pub(crate) fn update_recovery(&mut self, now: Instant) {
        self.update_episode(now);
        self.update_repair(now);
        let Some(d) = &mut self.hooks.data else {
            return;
        };
        if !(self.subflows.iter()).any(|sf| sf.state != SubflowState::Joining && !sf.ended()) {
            // Nothing could consume an expiry (`poll_timeout` would stay in the past): disarm;
            // the head stays, so it rearms once a subflow is up. The DATA_FIN retry needs
            // nothing: `prepare_send` on `subflows[0]`, never Joining, consumes it.
            d.recovery_at = None;
            return;
        }
        // ponytail: one RTO for the connection, so recovery of data on a fast path still waits
        // for the slow path's RTO; use the head subflow's RTO if that matters.
        let rto = (self.subflows.iter())
            .filter(|sf| sf.is(SubflowState::Active))
            .filter_map(|sf| sf.tcb.base_rto())
            .max()
            .unwrap_or(INITIAL_RTO);
        // Ruling R18 (RFC 8684 L1600–1611): once both DATA_FINs are DATA_ACKed, a subflow
        // still holding TCP data holds only data that is DATA_ACKed (delivered via another
        // subflow). If it is not TCP-ACKed within one un-backed-off RTO it never needs to be,
        // so `Endpoint::handle_timeout` resets the subflow then.
        let closing = !d.fallback && d.close.acked && d.close.peer_acked;
        for sf in &mut self.subflows {
            if closing && sf.tcb.state() != TcpState::Closed && sf.tcb.unacked_data() {
                let rto = sf.tcb.base_rto().unwrap_or(INITIAL_RTO);
                sf.mp.strand_at.get_or_insert(now + rto);
            } else {
                sf.mp.strand_at = None;
            }
        }
        if !d.fallback
            && d.close.sent
            && !d.close.acked
            && !d.close.due
            && d.send.una == d.send.end
            && d.close.at.is_none()
        {
            d.close.interval = rto;
            d.close.at = Some(now + d.close.interval);
        }
        let head = (!d.fallback && d.send.una != d.send.next).then_some(d.send.una);
        if d.recovery_head != head {
            d.recovery_head = head;
            d.recovery_at = None;
            d.recovery_interval = rto;
        }
        let maps = active_maps(&self.subflows);
        // A queued head is the timer's job already done: disarm, or an expiry nothing
        // consumes keeps `poll_timeout` in the past while no subflow can take the reinjection.
        if head.is_none()
            || d.reinject.first().map(|(start, _)| start) == head
            || maps.clone().any(|m| m.covering_end(d.send.una).is_some())
        {
            d.recovery_at = None;
        } else {
            let at = d.recovery_at.get_or_insert(now + d.recovery_interval);
            if now >= *at {
                let outstanding = d.send.next.wrapping_sub(d.send.una) as usize;
                let run = maps.fold(outstanding, |n, m| m.uncovered_len(d.send.una, n));
                d.reinject.insert(d.send.una, run as u64);
                d.recovery_at = None;
                d.recovery_interval = (d.recovery_interval * 2).min(Duration::from_secs(60));
            }
        }
    }

    /// Subflow health and teardown (spec §4 rule 3), after every input or timeout on subflow
    /// `i`. A TCB that ended (R2, RST either way, MP_JOIN give-up) queues the DSN ranges of its
    /// un-subflow-ACKed mappings for reinjection, minus the parts a copy on an Active subflow
    /// covers, and drops them. A bare peer FIN makes it Closing and closes it from our side at
    /// once (spec §3; a DATA_FIN arriving later does not undo it). Otherwise a change of its
    /// `rto_streak` is a `HealthEvent` (`RtoFired` for a new nonzero value, `Progress` for a
    /// drop to 0) for `Scheduler::on_health`: Stale moves an Active subflow to Stale and
    /// queues its ranges the same way (its mappings stay: the `Tcb` keeps retransmitting
    /// them); Keep on `Progress` moves a Stale one back to Active. Nothing after fallback, nor
    /// once our FIN on the subflow is ACKed.
    pub(crate) fn update_health(&mut self, i: usize) -> Option<Event> {
        let d = self.hooks.data.as_ref().filter(|d| !d.fallback)?;
        let sf = &mut self.subflows[i];
        let subflow = sf.id;
        if sf.tcb.state() == TcpState::Closed {
            self.reinject_ranges(i);
            self.subflows[i].mp.tx.clear();
            return None;
        }
        if sf.tcb.fin_received()
            && !d.recv.has_fin()
            && matches!(sf.state, SubflowState::Active | SubflowState::Stale)
        {
            sf.state = SubflowState::Closing;
            sf.tcb.close();
        }
        // Our FIN is ACKed (FIN-WAIT-2, TIME-WAIT): it never carries data again, so no health
        // transition (a `SubflowRecovered` after its `SubflowDown`).
        if !matches!(sf.state, SubflowState::Active | SubflowState::Stale)
            || matches!(sf.tcb.state(), TcpState::FinWait2 | TcpState::TimeWait)
        {
            return None;
        }
        let n = sf.tcb.rto_streak();
        if n == std::mem::replace(&mut sf.mp.rto_seen, n) {
            return None;
        }
        let ev = if n == 0 {
            HealthEvent::Progress { subflow }
        } else {
            HealthEvent::RtoFired { subflow, n }
        };
        // The snapshots of the latest scheduling step.
        let verdict = self.hooks.scheduler.on_health(&ev, &self.hooks.snapshots);
        let sf = &mut self.subflows[i];
        match (ev, verdict, sf.state) {
            (HealthEvent::RtoFired { .. }, HealthVerdict::Stale, SubflowState::Active) => {
                sf.state = SubflowState::Stale;
                self.reinject_ranges(i);
                Some(Event::SubflowStale { subflow })
            }
            (HealthEvent::Progress { .. }, HealthVerdict::Keep, SubflowState::Stale) => {
                sf.state = SubflowState::Active;
                Some(Event::SubflowRecovered { subflow })
            }
            _ => None,
        }
    }

    /// Fallback found on subflow `i` in the current input (spec §5.2): `i` alone carries the
    /// connection from now on (RFC 8684 L2437–2440) and becomes `subflows[0]`; every other
    /// subflow is reset. Nothing is reinjected. Returns `true` when any other subflow, live or
    /// freed, ever carried data whose DSN end is above `send.una` (ruling R17: conservative,
    /// it may have been dropped after a subflow ACK, RFC 8684 L1531–1534; MP_FAIL, M4, is the
    /// precise mechanism): that data may be undeliverable, so `i` is reset too and the caller
    /// closes with `FallbackDataLoss`. The survivor's own data never counts; a Stale survivor,
    /// or one whose join completed in this input, becomes Active (no `SubflowUp`: `FellBack`).
    pub(crate) fn on_fallback(&mut self, i: usize, now: Instant) -> bool {
        let d = self.hooks.data.as_mut().unwrap();
        let others = (self.subflows.iter().enumerate())
            .filter(|&(j, _)| j != i)
            .map(|(_, sf)| sf.mp.dsn_end);
        let una = d.send.una;
        let lost = (others.chain([self.hooks.freed_dsn_end]).flatten())
            .any(|end| end.wrapping_sub(una) as i64 > 0);
        d.reinject.clear();
        d.settling = false;
        // Signals end with MPTCP (M3 spec §3.3 rev3 S4); published events stand.
        self.peer_addrs.0.clear();
        self.hooks.signals.clear_echoes();
        self.opp = None;
        self.repair = Repair::default();
        d.release(self.subflows[i].mp.tcp_acked_dsn);
        // Health no longer applies after fallback: a Stale survivor carries the data again.
        // So does one whose join this input completed: as `subflows[0]` it never reaches
        // `Endpoint::subflow_event`, which would make it Active.
        let sf = &mut self.subflows[i];
        if sf.state == SubflowState::Stale
            || (sf.state == SubflowState::Joining && !sf.mp.joining())
        {
            sf.state = SubflowState::Active;
        }
        self.abort_all(now, (!lost).then_some(i), Some(tcprst(0x01, false)));
        for (_, sf) in (self.subflows.iter_mut().enumerate()).filter(|&(j, _)| j != i) {
            sf.mp.tx.clear();
        }
        self.subflows.swap(0, i);
        lost
    }

    /// Resets every open subflow except `except` (MP_FASTCLOSE, fallback), each RST carrying
    /// `rst_option`.
    pub(crate) fn abort_all(
        &mut self,
        now: Instant,
        except: Option<usize>,
        rst_option: Option<[u8; 4]>,
    ) {
        for (j, sf) in self.subflows.iter_mut().enumerate() {
            if Some(j) == except || sf.tcb.state() == TcpState::Closed {
                continue;
            }
            // RFC 9293 §3.10.5: ABORT in SYN-SENT sends nothing (ruling R20a).
            if sf.tcb.state() == TcpState::SynSent {
                sf.tcb.delete(now);
            } else {
                sf.tcb
                    .abort_with(crate::tcp::CloseReason::Reset, rst_option, now);
            }
        }
    }

    /// REMOVE_ADDR for peer address `id` (M3 spec §3.3). An unknown id is ignored (RFC 8684
    /// L2108–2110). A known one, in the peer address table or recorded by a subflow's
    /// handshake, loses its advertised binding, and every subflow to it that can send runs the
    /// keepalive procedure; a path that answers is kept (RFC 8684 L2089–2096). Returns whether
    /// `id` was known.
    pub(crate) fn peer_removed(&mut self, id: u8) -> bool {
        let mut known = self.peer_addrs.0.remove(&id).is_some();
        for sf in &mut self.subflows {
            if sf.mp.peer_addr_id() == Some(id) {
                known = true;
                if !sf.ended() && sf.tcb.state() != TcpState::SynSent {
                    let k = subflow::Keepalive {
                        sent: 0,
                        deadline: None,
                    };
                    sf.mp.keepalive.get_or_insert(k);
                }
            }
        }
        known
    }

    /// An authenticated ADD_ADDR (M3 spec §3.3) that arrived on a subflow whose remote port is
    /// `port`: it is echoed, then binds its id in the peer address table. Returns the endpoint
    /// to announce, with the option's port or else `port` (RFC 8684 L1977–1981). Nothing when
    /// the echo queue is full (discarded entirely, so the peer's retransmission tries again,
    /// RFC 8684 L1999–2001), for a known id with another IP (L2043–2047), for an address
    /// nobody can join (unspecified, multicast, loopback) or with the table full.
    pub(crate) fn peer_announced(&mut self, e: signal::Echo, port: u16) -> Option<SocketAddr> {
        if !self.hooks.signals.echo(e) {
            return None;
        }
        let old = self.peer_addrs.0.get(&e.id).and_then(|a| a.advertised);
        if old.is_some_and(|(ip, _)| ip != e.addr) {
            self.hooks.add_addr_conflicts += 1;
            return None;
        }
        let ip = e.addr;
        let addr = SocketAddr::new(ip, e.port.unwrap_or(port));
        let usable = !(ip.is_unspecified() || ip.is_multicast() || ip.is_loopback());
        (usable && self.peer_addrs.announce(e.id, addr)).then_some(addr)
    }

    /// REMOVE_ADDR of `id` while PreConfirmed (M3 spec §3.3 rev3 S2): its staged binding is
    /// dropped, and the queued joins to that endpoint are cancelled; returns them. An id without
    /// a staged binding, id 0 included, is ignored.
    pub(crate) fn staged_removed(&mut self, id: u8) -> Vec<SubflowId> {
        let Some((ip, port)) = self.peer_addrs.0.remove(&id).and_then(|a| a.advertised) else {
            return Vec::new();
        };
        let gone = SocketAddr::new(ip, port);
        let (cancelled, kept) = (std::mem::take(&mut self.queued_joins).into_iter())
            .partition::<Vec<_>, _>(|q| q.remote == gone);
        self.queued_joins = kept;
        cancelled.into_iter().map(|q| q.id).collect()
    }

    /// Subflow `i`'s join failed before it became Active (`SubflowMp::join_failed`): its
    /// remote, if announced, is marked failed, unless the peer's RST said transient or the join
    /// was already cancelled locally: `close_subflow` (ruling R24) or `close` (M3 spec §3.3).
    pub(crate) fn note_join_failure(&mut self, i: usize) {
        let cancelled = self.closed_by_app;
        let sf = &mut self.subflows[i];
        // A responder's peer address is where the peer joined from, never one it announced.
        let initiator = (sf.mp.join.as_ref()).is_some_and(|j| j.role == JoinRole::Initiator);
        if let Some(rst) = sf.mp.join_failed.take().filter(|_| initiator) {
            let cancelled = cancelled || sf.state == SubflowState::Closing;
            if !rst.is_some_and(|r| r.transient) && !cancelled {
                self.peer_addrs.fail(sf.remote);
            }
        }
    }

    /// Queues subflow `i`'s un-subflow-ACKed DSN ranges for reinjection, except where a live
    /// copy on an Active subflow covers them (dedup at insertion; `i` itself is not Active).
    fn reinject_ranges(&mut self, i: usize) {
        let d = self.hooks.data.as_mut().unwrap();
        let maps = active_maps(&self.subflows);
        for (dsn, len) in self.subflows[i].mp.tx.ranges() {
            d.reinject.insert_uncovered(dsn, len, maps.clone());
        }
    }

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

    /// Refills the snapshot buffer: every budget of every subflow, read-only (`send_budget`).
    /// A subflow that may not take a mapping now (TCP state, all mapping slots taken, `buf`
    /// smaller than its MTU) reports zero budgets; one that is not an eligible target of the
    /// opportunistic candidate `opp` a zero opportunistic budget.
    pub(crate) fn build_snapshots(
        &mut self,
        now: Instant,
        head: Option<(u64, u32)>,
        opp: Option<Cand>,
        buf: usize,
    ) {
        // Per open subflow, in order (at most SUBFLOW_CAP: `add_subflow`): the candidate's
        // prefix that its own live mappings leave uncovered. Ended ones are never targets.
        let mut opp_lens = [0; SUBFLOW_CAP];
        if let Some(c) = opp {
            let open = self.subflows.iter().filter(|sf| !sf.ended());
            for (k, t) in open.enumerate().take(SUBFLOW_CAP) {
                if self.opp_target(t, c.dsn, c.blocking, !c.repair) {
                    opp_lens[k] = t.mp.tx.uncovered_len(c.dsn, c.len as usize);
                }
            }
        }
        let mut snapshots = std::mem::take(&mut self.hooks.snapshots);
        snapshots.clear();
        let mut k = 0;
        for sf in self.subflows.iter_mut() {
            let open_k = (!sf.ended()).then_some(k);
            k += usize::from(open_k.is_some());
            let hk = SubflowHooks {
                conn: &mut self.hooks,
                sf: &mut sf.mp,
            };
            let (mut new_budget, mut reinject_budget, mut opp_budget) = Default::default();
            if buf >= sf.tcb.mtu() && may_assign(hk.conn, hk.sf, &sf.tcb) {
                let options = hk.data_option_len();
                let (bytes, run) = (hk.conn.unassigned_len(), hk.conn.candidate_len());
                new_budget = sf.tcb.send_budget(now, bytes, run, false, options, &hk);
                if let Some((_, c)) = head {
                    let c = c as usize;
                    reinject_budget = sf.tcb.send_budget(now, c, c, true, options, &hk);
                }
                let c = open_k.and_then(|k| opp_lens.get(k)).copied().unwrap_or(0);
                if c > 0 {
                    opp_budget = sf.tcb.send_budget(now, c, c, true, options, &hk);
                }
            }
            // A dead subflow (TCB Closed, e.g. a kept `subflows[0]`) is never Active.
            let state = if sf.tcb.state() == TcpState::Closed {
                SubflowState::Closing
            } else {
                sf.state
            };
            snapshots.push(SubflowSnapshot {
                id: sf.id,
                state,
                new_budget,
                reinject_budget,
                opp_budget,
                srtt: sf.tcb.srtt().unwrap_or(INITIAL_RTO),
                app_limited: sf.tcb.app_limited(),
                backup: sf.mp.backup(),
                usable: opp::usable(sf),
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
        // A trimmed reinjection queue may leave the head to repair (§2.7 H1).
        self.update_repair(now);
        // Every subflow offered a budget and given nothing in this step is passed over.
        for (k, (sf, s)) in self
            .subflows
            .iter_mut()
            .zip(&self.hooks.snapshots)
            .enumerate()
        {
            if Some(k) == installed {
                sf.mp.offered_unused = false;
            } else if s.state == SubflowState::Active && offered(s) {
                sf.mp.offered_unused = true;
            }
        }
        if installed.is_none() {
            self.mark_passed_over(now);
            let d = self.hooks.data.as_ref().unwrap();
            if d.send.next == d.send.end && d.reinject.is_empty() && !self.hooks.opp_live {
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

    /// App-limited evaluation point, at the end of a pass only. Every subflow passed over
    /// since the last evaluation is marked `NotScheduled`, unless data is queued but the
    /// connection-level window admits none of it: receiver-limited is not app-limited
    /// (draft-ietf-ccwg-bbr-06 §4.1.1.3.1), and the flags are dropped. A pass interrupted by
    /// an input (a driver that polls once per input) is not evaluated: MinRTT fills a
    /// passed-over subflow in a later step, and marking it mid-pass froze its CUBIC cwnd
    /// (RFC 9438 §5.8 gate) for as long as a faster subflow kept getting budget.
    fn mark_passed_over(&mut self, now: Instant) {
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
        let opp = self.opp_candidate();
        if opp.is_some() && !self.hooks.opp_live {
            self.hooks.debug.opp_triggers += 1;
        }
        self.hooks.opp_live = opp.is_some();
        self.build_snapshots(now, head, opp, buf);
        let hooks = &mut self.hooks;
        if !(hooks.snapshots.iter()).any(|s| s.state == SubflowState::Active && offered(s)) {
            return None;
        }
        let new_bytes = hooks.unassigned_len() as u64;
        // A due head repair whose target has budget goes before later queued reinjections
        // (§2.7 H1); the queue itself is unchanged.
        let repair_first = opp.is_some_and(|c| c.repair)
            && (hooks.snapshots.iter()).any(|s| s.opp_budget.bytes() > 0);
        let none = ReinjectQueue::new(0);
        let (reinject, head) = if repair_first {
            (&none, None)
        } else {
            (&hooks.data.as_ref().unwrap().reinject, head)
        };
        let opportunistic = opp.map(|c| (c.dsn, c.len));
        let pending = Pending {
            new_bytes,
            reinject,
            opportunistic,
        };
        let plan = hooks.scheduler.plan(now, &pending, &hooks.snapshots);
        let Some((i, payload)) = accept_plan(plan, &hooks.snapshots, head, opportunistic) else {
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
            Payload::Reinject { len, .. } | Payload::Opportunistic { len, .. } => (len, true),
        };
        self.hooks.scheduler.on_assigned(sf.id, bytes, reinject);
        if let (Payload::Opportunistic { len, .. }, Some(c)) = (payload, opp) {
            self.opp_installed(i, c, len, now);
        }
        Some(i)
    }
}

impl SubflowHooks<'_> {
    pub fn prepare_send(&mut self, tcb: &mut Tcb, now: Instant, id: SubflowId) {
        let srtt = tcb.srtt().unwrap_or(INITIAL_RTO);
        self.sf.signal_clock = Some((id, now, srtt));
        // A signal-only ACK, once synchronized and Confirmed (M3 spec §3.2).
        let open = matches!(tcb.state(), TcpState::Established | TcpState::CloseWait);
        if (self.conn.signals).wants(id, now, srtt, open && self.signals_allowed()) {
            tcb.request_signal_ack();
        }
        if self.sf.keepalive.is_some_and(|k| k.deadline.is_none()) {
            tcb.send_keepalive_probe();
        }
        if self.sf.joining() {
            // No data, probes or DATA_FIN while joining; it still closes with the rest. CLOSE
            // leaves a join we answered in SYN-RECEIVED (`Tcb::close`): once the data level has
            // closed both ways it can carry nothing, so it is reset and its slot comes back.
            let answered = (self.sf.join.as_ref()).is_some_and(|j| j.role == JoinRole::Responder);
            if answered && tcb.state() == TcpState::SynReceived && self.conn.data_closed() {
                let rst = Some(tcprst(0x00, false));
                tcb.abort_with(crate::tcp::CloseReason::Reset, rst, now);
            } else if self.conn.data.as_ref().is_some_and(|d| d.close.acked) {
                tcb.close();
            }
            return;
        }
        // Preserve the third ACK and replies to repeated SYN/ACKs before
        // requesting a separate DATA_FIN ACK. An idle peer need not send DSS first.
        self.sf.capable_ack_due = tcb.ack_pending()
            && self
                .conn
                .negotiation
                .as_ref()
                .is_some_and(|m| m.state == State::PreConfirmed);
        if let Some(d) = self.conn.data.as_mut().filter(|d| !d.fallback) {
            // A bare TCP FIN closed its subflow at once (`Connection::update_health`);
            // DATA_FIN+FIN leaves it open for our half-close response until now.
            if d.close.acked {
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
            if d.close.due && self.sf.fin_carrier {
                tcb.request_ack();
            }
        }
        if std::mem::take(&mut self.sf.ack_now) {
            tcb.request_ack();
        }
        if self.conn.data.is_some() && self.sf.final_mapping.is_some() {
            tcb.request_ack();
        }
        tcb.set_probe_demand(self.sf.probe);
        // An opportunistic candidate this subflow may take is demand like a reinjection.
        let reinject =
            self.sf.opp_demand || (self.conn.data.as_ref()).is_some_and(|d| !d.reinject.is_empty());
        tcb.pending_send(
            now,
            self.unassigned_len(),
            self.candidate_len(),
            self.data_option_len(),
            reinject,
            self,
        );
    }
    /// Installs a validated plan's mapping; DATA_FIN rides on the final data mapping.
    fn install(&mut self, payload: Payload) -> bool {
        let d = self.conn.data.as_mut().unwrap();
        let (dsn, len) = match payload {
            Payload::Reinject { dsn, len } | Payload::Opportunistic { dsn, len } => (dsn, len),
            Payload::New { bytes } => (d.send.next, bytes),
        };
        match payload {
            Payload::Reinject { dsn, len } | Payload::Opportunistic { dsn, len } => {
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
        self.sf.dsn_end = later(self.sf.dsn_end, dsn.wrapping_add(u64::from(len)));
        true
    }
    fn candidate_len(&self) -> usize {
        self.conn.candidate_len()
    }
    /// Signals may ride this subflow's ACKs: joined, and the connection Confirmed and not
    /// fallen back (M3 spec §3.2).
    fn signals_allowed(&self) -> bool {
        !self.sf.joining()
            && self
                .conn
                .negotiation
                .as_ref()
                .is_some_and(|m| m.state == State::Confirmed)
            && self.conn.data.as_ref().is_some_and(|d| !d.fallback)
    }
}
impl SendBuf for SubflowHooks<'_> {
    fn unassigned_len(&self) -> usize {
        self.conn.unassigned_len()
    }
    fn more_app_data(&self) -> bool {
        self.conn
            .data
            .as_ref()
            .is_some_and(|d| d.send.next != d.send.end)
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
                            // A joined subflow's path strips options, or any subflow's once
                            // a join was started: it alone is reset (RFC 8684 L2313–2328,
                            // spec §5.2).
                            Some(false) if self.sf.join.is_some() || self.conn.joined_ever => {
                                self.sf.reset = true;
                                self.sf.reset_option = Some(tcprst(0x06, false));
                            }
                            Some(false) => {
                                let m = self.conn.negotiation.as_mut().unwrap();
                                d.fall_back(self.sf, m, false);
                                self.conn.fallback_event = true;
                            }
                            None => {}
                        }
                    }
                }
                self.sf.tx.mark_acked(ssn);
                if d.fallback {
                    d.release(self.sf.tcp_acked_dsn);
                    // Nothing below the infinite mapping is sent again.
                    let from = self.sf.infinite_from;
                    if from.is_some_and(|f| ssn.wrapping_sub(f) as i32 >= 0) {
                        self.sf.infinite_from = None;
                    }
                    // The peer has an octet that only ever travelled with our infinite mapping.
                    let first_new = self.sf.infinite.map(|(_, new)| new);
                    if first_new.is_some_and(|new| ssn.wrapping_sub(new) as i32 > 0) {
                        self.sf.infinite = None;
                    }
                }
            }
            None => self.conn.plain.mark_acked(ssn),
        }
    }
}
impl SubflowHooks<'_> {
    /// An ACK or RST of a TCP-valid segment carries MP_FASTCLOSE with our key (`key`) once the
    /// keys are exchanged: every subflow is torn down and the connection closes (RFC 8684
    /// L2168–2172, L2191–2196).
    fn fast_close(&mut self, key: Option<u64>, seg: &Segment<'_>) -> bool {
        let hit = self.conn.negotiation.as_ref().is_some_and(|m| {
            key == Some(m.local_key)
                && matches!(m.state, State::PreConfirmed | State::Confirmed)
                && (seg.flags.contains(TcpFlags::ACK) || seg.flags.contains(TcpFlags::RST))
        });
        self.conn.fast_closed |= hit;
        hit
    }
}

impl SegmentHooks for SubflowHooks<'_> {
    fn data_option_len(&self) -> usize {
        if self.conn.data.as_ref().is_some_and(|d| !d.fallback) {
            28
        } else if self.conn.data.is_some() && self.sf.infinite.is_some() {
            20
        } else {
            0
        }
    }
    fn data_options_for(&mut self, ssn: u32, out: &mut [u8]) -> usize {
        let (Some(m), Some(d)) = (&self.conn.negotiation, &self.conn.data) else {
            return self.options_for(TcpFlags::ACK, out);
        };
        let below_infinite = |from: u32| (ssn.wrapping_sub(from) as i32) < 0;
        if d.fallback && !self.sf.infinite_from.is_some_and(below_infinite) {
            let Some((mapping, _)) = self.sf.infinite else {
                return self.options_for(TcpFlags::ACK, out);
            };
            let dss = mptcp::Dss {
                data_fin: false,
                data_ack: None,
                mapping: Some(mapping),
            };
            let n = mptcp::encode(&MptcpOption::Dss(dss), out).expect("infinite mapping fits");
            let padded = n.next_multiple_of(4);
            out[n..padded].fill(1);
            return padded;
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
            // After fallback, data below the infinite mapping keeps its finite mapping, which
            // the peer needs to place it (RFC 8684 L1487–1494); no DATA_ACK (L2431–2435).
            MptcpOption::Dss(mptcp::Dss {
                data_fin,
                data_ack: (!d.fallback).then_some(mptcp::DataAck::Ack64(d.recv.next)),
                mapping: Some(mapping),
            })
        };
        let n = mptcp::encode(&option, out).expect("fixed mapping layout fits");
        let padded = n.next_multiple_of(4);
        out[n..padded].fill(1);
        padded
    }
    fn window_offer(&self, scale: u8, mss: u16) -> Option<u16> {
        let mss = self.conn.sws_mss(mss);
        self.conn
            .data
            .as_ref()
            .map(|d| d.recv.window_offer(scale, mss))
    }
    /// A joining subflow's ACK carries no DATA_ACK, so the peer cannot take its window at
    /// connection level (RFC 8684 §3.3.2): it is not the connection's advertisement.
    fn window_sent(&mut self, field: u16, scale: u8) {
        if let Some(d) = self.conn.data.as_mut().filter(|_| !self.sf.joining()) {
            d.recv.window_sent(field, scale);
        }
    }
    /// Only the subflow chosen to announce a read's window (`window_owner`) sends it.
    fn window_update_due(&self, scale: u8, mss: u16) -> bool {
        let mss = self.conn.sws_mss(mss);
        self.sf.window_owner
            && (self.conn.data.as_ref()).is_some_and(|d| d.recv.window_update_due(scale, mss))
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
            if d.close.due
                && self.sf.fin_carrier
                && !self.sf.capable_ack_due
                && flags.contains(TcpFlags::ACK)
            {
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
    fn ack_signals(&mut self, purpose: AckPurpose, room: usize, out: &mut [u8]) -> usize {
        self.sf.signal_take = None;
        let Some((id, now, srtt)) = self.sf.signal_clock.filter(|_| self.signals_allowed()) else {
            return 0;
        };
        let signals = &self.conn.signals;
        let (n, take) = signals.peek_ack_options(id, purpose, now, srtt, room, out);
        self.sf.signal_take = Some(take);
        n
    }
    fn ack_emitted(&mut self) {
        if let (Some(take), Some((_, now, _))) = (self.sf.signal_take.take(), self.sf.signal_clock)
        {
            self.conn.signals.commit(take, now);
        }
    }
    fn on_valid_segment(&mut self, seg: &Segment<'_>) {
        self.sf.valid_data_ack = None;
        // Any acceptable segment after the first keepalive probe: the path is alive.
        if self.sf.keepalive.is_some_and(|k| k.sent > 0) {
            self.sf.keepalive = None;
        }
        // Validate the whole option list before mutating mapping or DATA_ACK state.
        let (mut dss, mut capable, mut fastclose, mut prio) = (None, None, None, None);
        let (mut removed, mut added) = (Vec::new(), Vec::new());
        let mut bad_capable = false;
        let options_ok = 'opts: {
            for opt in walk(seg.options).filter(|_| !seg.flags.contains(TcpFlags::SYN)) {
                match opt {
                    Err(_) => break 'opts false,
                    Ok(TcpOpt::Mptcp(raw)) => match mptcp::parse(raw) {
                        Ok(MptcpOption::Dss(v)) if dss.is_none() => dss = Some(v),
                        Ok(MptcpOption::Capable(v)) if capable.is_none() => {
                            capable = Some((v, raw.len()))
                        }
                        Ok(MptcpOption::FastClose { receiver_key }) if fastclose.is_none() => {
                            fastclose = Some(receiver_key)
                        }
                        Ok(MptcpOption::Prio { backup }) => prio = Some(backup),
                        Ok(MptcpOption::RemoveAddr { ids }) => removed.extend(ids.iter()),
                        // E=1 echoes our ADD_ADDR, and we send none.
                        Ok(MptcpOption::AddAddr {
                            echo: false,
                            id,
                            addr,
                            port,
                            hmac: Some(hmac),
                        }) => added.push((signal::Echo { id, addr, port }, hmac)),
                        // A malformed signal-only option is ignored, like an unknown one.
                        Err(_) if mptcp::is_signal(raw) => {}
                        Ok(
                            MptcpOption::Dss(_)
                            | MptcpOption::Capable(_)
                            | MptcpOption::FastClose { .. },
                        )
                        | Err(_) => {
                            bad_capable = mptcp::is_capable(raw);
                            break 'opts false;
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            true
        };
        // Listener: the final ACK decides (spec G2b); a rejected option list falls back. A
        // DATA_ACK is due at once, so that an idle client is confirmed too (RFC 8684 L832–835).
        let scale = self.sf.peer_scale;
        let awaiting = |m: &&mut Negotiation| m.state == State::AwaitingKey;
        if let Some(m) = (self.conn.negotiation.as_mut()).filter(awaiting) {
            if !seg.flags.contains(TcpFlags::RST) {
                self.sf.ack_now = m.take_key(seg, capable.filter(|_| options_ok), scale);
            }
        }
        // The responder's third ACK completes or fails its join, and nothing else (spec G3),
        // unless it carries a valid MP_FASTCLOSE, which ends the whole connection.
        if self
            .sf
            .join
            .as_ref()
            .is_some_and(|j| j.role == JoinRole::Responder && j.joining())
        {
            if !(options_ok && self.fast_close(fastclose, seg)) {
                self.join_third_ack(seg, options_ok);
            }
            return;
        }
        if !options_ok {
            // A malformed MP_CAPABLE is an invalid one: past the handshake, a listener resets
            // (as below); an initiator ignores the segment's options.
            let m = self.conn.negotiation.as_ref();
            self.sf.reset |= bad_capable
                && m.is_some_and(|m| m.passive && m.state == State::Confirmed)
                && self.conn.active();
            return;
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
        if self.fast_close(fastclose, seg) {
            return;
        }
        let Some(m) = &mut self.conn.negotiation else {
            return;
        };
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
            let mut recv =
                RecvAssembler::new(m.peer_idsn.unwrap().wrapping_add(1), self.conn.recv_cap, 64);
            // The edge our SYN or SYN/ACK advertised, unscaled.
            recv.right_edge = recv.next.wrapping_add(self.conn.recv_cap.min(65535) as u64);
            self.conn.data = Some(DataState {
                recv,
                send,
                close: close::Close::default(),
                sanity_failures: 0,
                recovery_head: None,
                recovery_at: None,
                recovery_interval: Duration::from_secs(1),
                reinject: ReinjectQueue::new(m.local_idsn.wrapping_add(1)),
                fallback: false,
                settling: false,
            });
            self.sf.tcp_acked_dsn = m.local_idsn.wrapping_add(1);
            // Our ISS: the SYN/ACK's ACK (initiator) or the final ACK's (listener) is ISS + 1.
            self.sf.local_isn = seg.ack.wrapping_add(u32::MAX);
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
        // MP_PRIO: the peer's preference for the subflow it arrived on (M3 spec §3.3).
        if let Some(backup) = prio.filter(|_| m.state == State::Confirmed) {
            self.sf.peer_backup = backup;
            self.sf.peer_prio = Some(backup);
        }
        // ADD_ADDR and REMOVE_ADDR are staged while PreConfirmed (M3 spec §3.3 rev3).
        if matches!(m.state, State::PreConfirmed | State::Confirmed) {
            self.conn.peer_removed.extend(removed);
            // Key-peer ‖ Key-local: the peer sent it (RFC 8684 L1985–2016).
            for (e, hmac) in added {
                if hmac == add_addr_hmac(m.peer_key.unwrap(), m.local_key, e.id, e.addr, e.port) {
                    self.conn.peer_announced.push(e);
                } else {
                    self.conn.add_addr_bad_hmac += 1;
                }
            }
        }
        // An MP_CAPABLE after the handshake (or the one that confirmed): with data parameters it
        // is a DSS mapping of SSN 1 to the peer's IDSN + 1 (RFC 8684 L836–873). One that fails
        // `capable_ack_ok` or names another key is an invalid mapping, and at a listener so is
        // any invalid one; an initiator still ignores one without data parameters (its peer
        // sends none after the SYN/ACK).
        if let Some((c, raw_len)) = capable {
            let payload = !seg.payload.is_empty();
            let valid =
                capable_ack_ok(&c, raw_len, payload, m.local_key) && c.sender_key == m.peer_key;
            if !valid && (c.data_len.is_some() || m.passive) {
                self.sf.reset = true;
                return;
            }
            m.peer_c |= valid && c.flags & CAP_C != 0;
            if let Some(len) = c.data_len {
                let dsn = m.peer_idsn.unwrap().wrapping_add(1);
                if !self.sf.rx.install(1, dsn, u32::from(len)) {
                    self.sf.reset = true;
                    return;
                }
                m.peer_dss_seen = true;
                self.sf.unmapped = 0;
            }
        }
        if let Some(v) = dss {
            m.peer_dss_seen = true;
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
                    d.fall_back(self.sf, m, self.conn.joined_ever);
                    self.sf.rx_infinite = Some((mapping.ssn, dsn));
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
            if self.sf.join.is_some() || self.conn.joined_ever {
                self.sf.reset = true;
                self.sf.reset_option = Some(tcprst(0x06, false));
                return;
            }
            d.fall_back(self.sf, m, false);
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
    fn reset_option(&self) -> Option<[u8; 4]> {
        self.sf.reset_option.filter(|_| !self.conn.fast_closed)
    }
    fn on_reset(&mut self, seg: &Segment<'_>) {
        let rst = walk(seg.options).find_map(|o| match o {
            Ok(TcpOpt::Mptcp(raw)) => match mptcp::parse(raw) {
                Ok(MptcpOption::TcpRst { transient, reason }) => {
                    Some(crate::MpTcpRst { reason, transient })
                }
                _ => None,
            },
            _ => None,
        });
        self.sf.rst = rst;
        if self.sf.joining() {
            self.sf.join_failed = Some(rst);
        }
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
        if self.settling {
            return false;
        }
        let released = self.send.ack(ack);
        if released {
            self.reinject.ack(self.send.una);
        }
        released
    }
    /// Falls back on subflow `sf` (`Connection::on_fallback` finishes it) and makes our
    /// infinite mapping due. Before any join it starts at the send origin `(SSN 1,
    /// local_idsn + 1)`; once a join was started it is survivor-relative, `(sf`'s
    /// `assigned_end`, `send.next)`: later data follows it linearly, and `sf`'s earlier finite
    /// mappings keep covering its earlier SSNs (RFC 8684 L1496–1500).
    fn fall_back(&mut self, sf: &mut SubflowMp, m: &mut Negotiation, joined_ever: bool) {
        self.fallback = true;
        self.settling = true;
        self.close = close::Close::default();
        m.state = State::FellBack;
        self.recovery_at = None;
        sf.rx_infinite = Some((1, m.peer_idsn.unwrap().wrapping_add(1)));
        let (ssn, dsn) = if joined_ever {
            (sf.tx.assigned_end(), self.send.next)
        } else {
            (1, m.local_idsn.wrapping_add(1))
        };
        sf.infinite_from = Some(ssn);
        let mapping = mptcp::Mapping {
            dsn: mptcp::Dsn::Dsn64(dsn),
            ssn,
            data_len: 0,
            checksum: None,
        };
        sf.final_mapping = Some(mapping);
        sf.infinite = Some((mapping, sf.tx.assigned_end()));
    }
}

/// The initiator goes `SynSent → PreConfirmed → Confirmed`, the listener `AwaitingKey →
/// Confirmed`; either may end in `FellBack`. From `Confirmed` on both roles share every path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    SynSent,
    PreConfirmed,
    /// Listener only: our SYN/ACK carried our key; the segment that completes the TCP
    /// handshake brings the client's key, or makes us fall back (spec G2a, G2b).
    AwaitingKey,
    Confirmed,
    FellBack,
}

/// What a listener makes of a SYN's MP_CAPABLE (spec G2b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SynCapable {
    Plain,
    /// `peer_c`: the client set C=1 (RFC 8684 L924–932).
    V1 {
        peer_c: bool,
    },
}

/// Exactly one MP_CAPABLE, of length 4, version 1 or higher (we answer with 1, RFC 8684
/// L716–722), A=0 (no checksums until M4b, L958–970), B=0 (L906–922) and H=1, whatever D–G
/// say: only HMAC-SHA256 is supported (L942–944, L972–982). Anything else is plain TCP.
pub(crate) fn syn_capable(seg: &Segment<'_>) -> SynCapable {
    let mut found = None;
    for opt in walk(seg.options) {
        match opt {
            Err(_) => return SynCapable::Plain,
            // A second MP_CAPABLE.
            Ok(TcpOpt::Mptcp(raw)) if mptcp::is_capable(raw) && found.replace(raw).is_some() => {
                return SynCapable::Plain;
            }
            _ => {}
        }
    }
    let Some(raw) = found.filter(|raw| raw.len() == 4) else {
        return SynCapable::Plain;
    };
    match mptcp::parse(raw) {
        Ok(MptcpOption::Capable(c))
            if c.version >= 1 && c.flags & (CAP_A | CAP_B) == 0 && c.flags & CAP_H != 0 =>
        {
            SynCapable::V1 {
                peer_c: c.flags & CAP_C != 0,
            }
        }
        _ => SynCapable::Plain,
    }
}

/// The send window scale a SYN (or SYN/ACK) sets: its WS, capped at 14, 0 without one (RFC
/// 7323 §2.3).
pub(crate) fn syn_scale(seg: &Segment<'_>) -> u8 {
    walk(seg.options)
        .filter_map(|o| match o {
            Ok(TcpOpt::WindowScale(s)) => Some(s.min(14)),
            _ => None,
        })
        .next()
        .unwrap_or(0)
}

/// The one acceptance test for an MP_CAPABLE after our SYN/ACK, of `raw_len` octets on a
/// segment with or without payload: version 1, flags exactly H with C free (C=1 is allowed,
/// L924–932), the sender's key, our key echoed, and the length for the form: 20 without data,
/// 22 with a Data-Level Length and data (L751–758; 24 means checksums, not supported).
pub(crate) fn capable_ack_ok(
    c: &MpCapable,
    raw_len: usize,
    has_payload: bool,
    local_key: u64,
) -> bool {
    c.version == 1
        && c.flags & !CAP_C == CAP_H
        && c.sender_key.is_some()
        && c.receiver_key == Some(local_key)
        && match raw_len {
            20 => !has_payload,
            22 => c.data_len.is_some() && has_payload,
            _ => false,
        }
}

pub(crate) struct Negotiation {
    pub state: State,
    pub token: u32,
    pub local_key: u64,
    /// The peer's MP_CAPABLE had C=1 (the initiator: on its SYN/ACK; the listener: on its SYN
    /// or a validated confirming option): it accepts no MP_JOIN to its source address. Never
    /// cleared (RFC 8684 L924–932).
    pub peer_c: bool,
    pub peer_idsn: Option<u64>,
    pub peer_key: Option<u64>,
    pub local_idsn: u64,
    pub send_right_edge: Option<u64>,
    /// A DSS, or an MP_CAPABLE data mapping, arrived from the peer: our own joins may start
    /// (RFC 8684 L884–887). Joins we answer need only `Confirmed` (spec G2a).
    pub peer_dss_seen: bool,
    /// The listener's negotiation (`new_passive`).
    pub passive: bool,
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
            peer_dss_seen: false,
            passive: false,
            peer_idsn: None,
            peer_key: None,
            syns_sent: 0,
            connected_pending: false,
        }
    }

    /// A listener's negotiation, created with the SYN: `AwaitingKey`.
    pub fn new_passive(local_key: u64) -> Self {
        Self {
            state: State::AwaitingKey,
            passive: true,
            ..Self::new(local_key)
        }
    }

    /// Listener, on the segment that completes the TCP handshake (with or without payload):
    /// `capable`, the segment's one MP_CAPABLE with its length, from an option list that
    /// passed validation (`None` otherwise), confirms if it passes `capable_ack_ok`, taking
    /// the client's key (RFC 8684 L836–855). No MP_CAPABLE (L993–999), more than one, a
    /// rejected option list or one that fails the test (L877–883, L958–970) falls back.
    /// Returns whether it confirmed. `peer_scale`: the SYN's WS, for this segment's window.
    fn take_key(
        &mut self,
        seg: &Segment<'_>,
        capable: Option<(MpCapable, usize)>,
        peer_scale: u8,
    ) -> bool {
        let has_payload = !seg.payload.is_empty();
        let ok =
            |(c, len): &(MpCapable, usize)| capable_ack_ok(c, *len, has_payload, self.local_key);
        let Some(key) = capable.filter(ok).and_then(|(c, _)| c.sender_key) else {
            self.state = State::FellBack;
            return false;
        };
        self.peer_key = Some(key);
        self.peer_idsn = Some(key_token_idsn(key).1);
        // Not a SYN: the window is scaled (RFC 7323 §2.2).
        let wnd = u64::from(seg.wnd) << peer_scale;
        self.send_right_edge = Some(self.local_idsn.wrapping_add(1).wrapping_add(wnd));
        self.state = State::Confirmed;
        true
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
                        Err(_) if mptcp::is_signal(raw) => {}
                        Ok(MptcpOption::Dss(_)) | Err(_) => return,
                        _ => {}
                    },
                    _ => {}
                }
            }
            if dss {
                self.state = State::Confirmed;
                self.peer_dss_seen = true;
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
        *peer_scale = syn_scale(seg);
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
            // The SYN/ACK, also each repeat of it: our key, flags exactly H (RFC 8684 L753,
            // L972–982), our C=0.
            State::AwaitingKey if flags.contains(TcpFlags::SYN) => (Some(self.local_key), None),
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
