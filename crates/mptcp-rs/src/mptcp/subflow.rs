//! Per-subflow state: one TCP sequence space and the MPTCP state tied to it.
use std::net::SocketAddr;

use super::ConnectionHooks;
use super::data::{RxMaps, TxMaps};
use crate::SeqNum;
use crate::tcp::Tcb;
use crate::wire::mptcp;

/// Identifies a subflow within its connection. The initial subflow is `SubflowId(0)`, which
/// is also its address ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubflowId(pub(crate) u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SubflowState {
    /// Used once MP_JOIN subflows exist (M2 MP_JOIN task).
    #[allow(dead_code)]
    Joining,
    Active,
    /// Used by stale-path detection (M2 stale/reinjection task).
    #[allow(dead_code)]
    Stale,
    /// Used by per-subflow close (M2 close/fallback task).
    #[allow(dead_code)]
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

/// MPTCP state tied to one subflow's TCP sequence space, options or window scale.
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
    pub final_mapping: Option<mptcp::Mapping>,
    pub rx_infinite: Option<(u32, u64)>,
    /// Window scale this subflow's SYN/ACK negotiated; scales DATA_ACK windows it carries.
    pub peer_scale: u8,
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
            rx_infinite: None,
            peer_scale: 0,
        }
    }
}

/// The hooks one subflow's `Tcb` runs against: a short-lived view of the connection and
/// that subflow's MPTCP state.
pub(crate) struct SubflowHooks<'a> {
    pub conn: &'a mut ConnectionHooks,
    pub sf: &'a mut SubflowMp,
}
