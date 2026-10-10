//! Per-subflow state: one TCP sequence space and the MPTCP state tied to it.
use std::net::SocketAddr;

use super::ConnectionHooks;
use super::data::{RxMaps, TxMaps};
use super::join::Join;
use crate::SeqNum;
use crate::tcp::Tcb;
use crate::time::Instant;
use crate::wire::mptcp;

/// Identifies a subflow within its connection: allocated in increasing order and never
/// reused. The initial subflow is `SubflowId(0)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubflowId(pub(crate) u32);

impl SubflowId {
    /// The initial subflow, the one `connect_mptcp` opens.
    pub const INITIAL: SubflowId = SubflowId(0);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubflowState {
    /// MP_JOIN not complete: no data, not usable by the scheduler.
    Joining,
    Active,
    /// `on_health` judged it Stale: no new data or reinjections, its own TCP retransmissions
    /// go on; Active again on a `Progress` judged Keep.
    Stale,
    /// Retiring, by the peer's bare FIN or `close_subflow`: no new data or reinjections.
    Closing,
}

pub(crate) struct Subflow {
    pub id: SubflowId,
    pub tcb: Tcb,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: SubflowState,
    pub mp: SubflowMp,
}

impl Subflow {
    /// In `state` and with a TCB that is not Closed (a dead subflow keeps its state until it
    /// is freed).
    pub fn is(&self, state: SubflowState) -> bool {
        self.state == state && self.tcb.state() != crate::tcp::TcpState::Closed
    }
    /// It may take over the data of a subflow `close_subflow` retires (M3 spec §4.2): Active
    /// (not Joining, Stale or retiring), not under the peer's REMOVE_ADDR keepalive, with an
    /// established TCB. A full window, cwnd, pacing or mapping slots do not matter.
    pub fn can_replace(&self) -> bool {
        self.is(SubflowState::Active)
            && self.mp.keepalive.is_none()
            && self.tcb.state() == crate::tcp::TcpState::Established
    }
}

/// MPTCP state tied to one subflow's TCP sequence space, options or window scale. The creator
/// must set `local_isn`, `tcp_acked_dsn` and (from its SYN/ACK) `peer_scale`: the MP_CAPABLE
/// path does it in `on_valid_segment`, a join in `Endpoint::start_join` and `join_segment`.
pub(crate) struct SubflowMp {
    pub tx: TxMaps,
    pub rx: RxMaps,
    pub unmapped: usize,
    pub reset: bool,
    /// The MP_TCPRST the RST that `reset` makes due carries (M3 spec §3.4).
    pub reset_option: Option<[u8; 4]>,
    pub dss_confirmed: bool,
    pub tcp_acked_dsn: u64,
    pub tcp_acked_ssn: Option<u32>,
    pub local_isn: SeqNum,
    // None: malformed/invalid; Some(false): valid options without DATA_ACK.
    // Current ACK coverage is retained after TCP releases a mapping.
    pub valid_data_ack: Option<bool>,
    pub ack_now: bool,
    pub capable_ack_due: bool,
    /// Our infinite mapping, due until a segment carries it.
    pub final_mapping: Option<mptcp::Mapping>,
    /// SSN where our infinite mapping starts; data below it keeps its finite mapping.
    pub infinite_from: Option<u32>,
    /// The highest DSN end of any mapping ever installed on this subflow (fallback data loss).
    pub dsn_end: Option<u64>,
    pub rx_infinite: Option<(u32, u64)>,
    /// Window scale this subflow's SYN/ACK negotiated; scales DATA_ACK windows it carries.
    pub peer_scale: u8,
    /// A scheduling step offered this subflow a nonzero budget and installed no mapping on
    /// it; consumed by the next app-limited evaluation (`Connection::mark_passed_over`).
    pub offered_unused: bool,
    /// MP_JOIN state; `None` on the initial subflow.
    pub join: Option<Join>,
    /// Connection-scoped roles, set before every `poll_transmit` step 1
    /// (`Connection::select_control`): this subflow sends the window update a read makes due
    /// (spec §5.4) ...
    pub window_owner: bool,
    /// ... carries the standalone DATA_FIN (spec §4 rule 2) ...
    pub fin_carrier: bool,
    /// ... and has zero-window probe demand (spec §3).
    pub probe: bool,
    /// The `Tcb::rto_streak` last turned into a `HealthEvent`.
    pub rto_seen: u32,
    /// When a penalty last applied (M3 §2.5: at most one per srtt).
    pub penalized_at: Option<Instant>,
    /// An eligible target of the opportunistic candidate: pending demand like a queued
    /// reinjection (`Connection::select_control`).
    pub opp_demand: bool,
    /// Reset deadline while both DATA_FINs are DATA_ACKed and this subflow still holds TCP
    /// data (`Connection::update_recovery`).
    pub strand_at: Option<Instant>,
    /// The MP_TCPRST of the acceptable peer RST that ended it (`None`: none, or no RST).
    pub rst: Option<crate::MpTcpRst>,
    /// A join failed while SYN-SENT or Joining: an acceptable peer RST (with its MP_TCPRST),
    /// an invalid SYN/ACK or a timeout (`None`), for the failed mark (M3 spec §3.3;
    /// `Connection::note_join_failure`).
    pub join_failed: Option<Option<crate::MpTcpRst>>,
    /// Our own transmit policy (`Endpoint::set_local_backup`).
    pub local_backup: bool,
    /// The peer's MP_JOIN SYN/ACK B bit, then its latest MP_PRIO (RFC 8684 L1849–1852).
    pub peer_backup: bool,
    /// An MP_PRIO arrived with this B bit: `Event::PeerPriority` is due.
    pub peer_prio: Option<bool>,
    /// This subflow's id, the time and its srtt at the latest `prepare_send`: the signal
    /// clock of its ACKs.
    pub signal_clock: Option<(super::SubflowId, Instant, std::time::Duration)>,
    /// The signals the ACK being built carries, until it goes out.
    pub signal_take: Option<super::signal::Take>,
    /// The peer's REMOVE_ADDR named this subflow's peer address: the keepalive procedure runs.
    pub keepalive: Option<Keepalive>,
}

/// Keepalive probes before a REMOVE_ADDR'd subflow is reset (M3 spec §3.3).
const KEEPALIVE_PROBES: u8 = 3;

/// The REMOVE_ADDR keepalive procedure (M3 spec §3.3): probes sent so far, and the last one's
/// deadline, its transmission time plus the RTO then (`None`: the next probe is due).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Keepalive {
    pub sent: u8,
    pub deadline: Option<Instant>,
}

impl SubflowMp {
    pub fn new() -> Self {
        Self {
            tx: TxMaps::new(1, 1024),
            rx: RxMaps::new(1024),
            unmapped: 0,
            reset: false,
            reset_option: None,
            dss_confirmed: false,
            tcp_acked_dsn: 0,
            tcp_acked_ssn: None,
            local_isn: SeqNum(0),
            valid_data_ack: None,
            ack_now: false,
            capable_ack_due: false,
            final_mapping: None,
            infinite_from: None,
            dsn_end: None,
            rx_infinite: None,
            peer_scale: 0,
            offered_unused: false,
            join: None,
            window_owner: false,
            fin_carrier: false,
            probe: false,
            rto_seen: 0,
            penalized_at: None,
            opp_demand: false,
            strand_at: None,
            rst: None,
            join_failed: None,
            local_backup: false,
            peer_backup: false,
            peer_prio: None,
            signal_clock: None,
            signal_take: None,
            keepalive: None,
        }
    }
    /// The effective transmit-backup: local or peer-requested (M3 spec §4.2).
    pub fn backup(&self) -> bool {
        self.local_backup || self.peer_backup
    }
    /// The keepalive procedure at `now`: true once the last probe's deadline has passed
    /// unanswered; an earlier passed deadline makes the next probe due.
    pub fn keepalive_failed(&mut self, now: Instant) -> bool {
        let Some(k) = self.keepalive.as_mut() else {
            return false;
        };
        if !k.deadline.is_some_and(|t| t <= now) {
            return false;
        }
        k.deadline = None;
        k.sent >= KEEPALIVE_PROBES
    }
    /// The keepalive probe requested at the last `prepare_send` went out at `now` (the `Tcb`
    /// no longer has it `pending`): its deadline is one `rto` later.
    pub fn keepalive_sent(&mut self, pending: bool, now: Instant, rto: std::time::Duration) {
        if let Some(k) = self.keepalive.as_mut().filter(|k| k.deadline.is_none()) {
            if !pending {
                k.sent += 1;
                k.deadline = Some(now + rto);
            }
        }
    }
    /// The peer address id this subflow's handshake carried: 0 for the initial subflow, the
    /// MP_JOIN SYN/ACK's for a joined one.
    pub fn peer_addr_id(&self) -> Option<u8> {
        self.join.as_ref().map_or(Some(0), |j| j.peer_addr_id)
    }
    /// A joined subflow whose MP_JOIN handshake is not complete.
    pub fn joining(&self) -> bool {
        self.join.as_ref().is_some_and(Join::joining)
    }
}

/// The hooks one subflow's `Tcb` runs against: a short-lived view of the connection and
/// that subflow's MPTCP state.
pub(crate) struct SubflowHooks<'a> {
    pub conn: &'a mut ConnectionHooks,
    pub sf: &'a mut SubflowMp,
}
