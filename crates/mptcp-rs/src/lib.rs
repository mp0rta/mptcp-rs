#![forbid(unsafe_code)]

mod connection;
pub mod crypto;
mod endpoint;
// M1 staging: remove this gate with the DSS data path before enabling public MPTCP.
#[cfg(test)]
mod mptcp;
mod seq;
pub mod tcp;
mod time;
pub mod wire;

pub use connection::{Connection, ReadError, WriteError};
pub use endpoint::{ConnectError, ConnectionHandle, Endpoint, Event};
pub use seq::SeqNum;
pub use tcp::{CloseReason, ConnectConfig};
pub use time::Instant;
