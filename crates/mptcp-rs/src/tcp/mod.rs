//! Plain TCP engine: the pure `Tcb` state machine and the hooks it drives (spec §3).

pub mod cc;
mod hooks;
mod recovery;
pub(crate) mod rtt;
mod tcb;

pub use hooks::{Hooks, PlainHooks, SegmentHooks, SendBuf};
pub use tcb::{CloseReason, ConnectConfig, Reaction, SegmentWriter, SentMeta, Tcb, TcpState};
