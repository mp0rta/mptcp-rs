//! Plain TCP engine: the pure `Tcb` state machine and the hooks it drives (spec §3).

#[cfg_attr(not(test), allow(dead_code))]
mod bbr;
pub mod cc;
mod cubic;
mod hooks;
mod rate;
mod recovery;
pub(crate) mod rtt;
mod sack;
mod tcb;

pub use cc::{
    AppLimited, Delivery, LossEvent, RateSample, RecoveryKind, RecoveryStart, Start, Transmit,
};
pub use hooks::{AckPurpose, Hooks, PlainHooks, SegmentHooks, SendBuf};
pub use tcb::{
    CloseReason, ConnectConfig, Reaction, SegmentWriter, SendBudget, SentMeta, Tcb, TcpState,
};
