//! Per-subflow state: one TCP sequence space and the MPTCP state tied to it.
use std::net::SocketAddr;

use super::ConnectionHooks;
use super::data::{RxMaps, TxMaps};
use super::join::Join;
use crate::SeqNum;
use crate::tcp::Tcb;
use crate::time::Instant;
use crate::wire::mptcp;

/// Identifies a subflow within its connection. The initial subflow is `SubflowId(0)`, which
/// is also its address ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubflowId(pub(crate) u8);

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
    /// The peer retired it with a bare FIN: no new data or reinjections.
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
}

/// MPTCP state tied to one subflow's TCP sequence space, options or window scale. The creator
/// must set `local_isn`, `tcp_acked_dsn` and (from its SYN/ACK) `peer_scale`: the MP_CAPABLE
/// path does it in `on_valid_segment`, a join in `Endpoint::start_join` and `join_segment`.
pub(crate) struct SubflowMp {
    pub tx: TxMaps,
    pub rx: RxMaps,
    pub unmapped: usize,
    pub reset: bool,
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
}

impl SubflowMp {
    pub fn new() -> Self {
        Self {
            tx: TxMaps::new(1, 1024),
            rx: RxMaps::new(1024),
            unmapped: 0,
            reset: false,
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
        }
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
