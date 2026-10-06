//! Plain TCP engine: the pure `Tcb` state machine and the hooks it drives (spec §3).

mod hooks;
mod tcb;

pub use hooks::{Hooks, PlainHooks, SegmentHooks, SendBuf};
pub use tcb::{CloseReason, ConnectConfig, Reaction, SegmentWriter, SentMeta, Tcb, TcpState};
