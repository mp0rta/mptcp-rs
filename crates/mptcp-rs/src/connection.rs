//! One TCP or MPTCP connection as the application sees it: its subflows plus its buffers.

use std::net::{IpAddr, SocketAddr};

use crate::mptcp::{DebugStats, Episode, Repair, Subflow, SubflowId};
use crate::tcp::{ConnectConfig, TcpState};

pub(crate) type ConnectionHooks = crate::mptcp::ConnectionHooks;

/// `write` failed because the connection is closed (by `close`, a reset or a timeout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteError {
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// No data yet and no FIN from the peer.
    WouldBlock,
    /// The peer reset the connection.
    Reset,
}

pub struct Connection {
    /// The initial subflow is `subflows[0]`; after a fallback, the subflow that carries the
    /// connection as plain TCP is.
    pub(crate) subflows: Vec<Subflow>,
    pub(crate) hooks: ConnectionHooks,
    pub(crate) closed_by_app: bool,
    pub(crate) reset: bool,
    /// Closed and out of the demux table, kept only until the application has read the
    /// remaining data (no timers, no packets).
    pub(crate) detached: bool,
    /// The configuration subflows are opened with (each with its own MTU).
    pub(crate) cfg: ConnectConfig,
    /// `set_nodelay`, applied to every subflow, joined ones included.
    pub(crate) nodelay: bool,
    /// Joins waiting for the connection to be Confirmed (RFC 8684 L884–887).
    pub(crate) queued_joins: Vec<QueuedJoin>,
    /// The next subflow ID; IDs are never reused within a connection.
    pub(crate) next_subflow: u8,
    /// Local IPs by address ID: the initial one is 0 (spec §5.6).
    pub(crate) addr_ids: Vec<IpAddr>,
    /// The opportunistic retransmission episode, if one runs (M3 spec §2.3).
    pub(crate) opp: Option<Episode>,
    /// Head repair and bounded lookahead (M3 spec §2.7).
    pub(crate) repair: Repair,
}

/// An `add_subflow` made before the connection was Confirmed.
pub(crate) struct QueuedJoin {
    pub id: SubflowId,
    pub local: IpAddr,
    pub mtu: u16,
}

impl Connection {
    /// The initial subflow's local address (after a fallback: the surviving subflow's).
    pub fn local(&self) -> SocketAddr {
        self.subflows[0].local
    }

    /// The initial subflow's remote address (after a fallback: the surviving subflow's).
    pub fn remote(&self) -> SocketAddr {
        self.subflows[0].remote
    }

    /// Queues `data` for sending; may accept less than `data.len()` (send buffer full), even 0.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        let closed = self.subflows[0].tcb.state() == TcpState::Closed && !self.hooks.retained();
        if self.closed_by_app || self.reset || closed {
            return Err(WriteError::Closed);
        }
        Ok(self.hooks.write(data))
    }

    /// Reads received bytes. `Ok(0)` is EOF (TCP FIN or MPTCP DATA_FIN, all data read)
    /// or a 0-length `buf`.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.reset {
            return Err(ReadError::Reset);
        }
        let eof = self.hooks.eof(self.subflows[0].tcb.fin_received());
        match self.hooks.read(buf) {
            0 if eof => Ok(0),
            0 => Err(ReadError::WouldBlock),
            n => Ok(n),
        }
    }

    /// Half-closes: TCP FIN or MPTCP DATA_FIN follows queued data. Reading stays possible after the
    /// connection has fully closed: unread data stays readable through `Endpoint::connection`
    /// until `read` returns `Ok(0)`; the next `Endpoint::handle_timeout` then frees it.
    ///
    /// In SYN-SENT this instead deletes the connection: queued writes are discarded and
    /// `Closed { Normal }` is reported. Wait for `Event::Connected` before `close` if the
    /// queued data must be delivered.
    pub fn close(&mut self) {
        self.closed_by_app = true;
        if self.hooks.close() {
            return;
        }
        self.subflows[0].tcb.close();
    }

    /// Opportunistic retransmission counters, for test drivers; not a stable API.
    #[doc(hidden)]
    pub fn debug_stats(&self) -> DebugStats {
        self.hooks.debug
    }

    /// Switches Nagle off (`true`) or on (`false`, the default) on every subflow, including
    /// those joined later.
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
        for sf in &mut self.subflows {
            sf.tcb.set_nodelay(nodelay);
        }
    }
}
