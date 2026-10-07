//! One plain TCP connection as the application sees it: a `Tcb` plus its buffers.

use std::net::SocketAddr;

use crate::tcp::{Tcb, TcpState};

#[cfg(not(test))]
pub(crate) type ConnectionHooks = crate::tcp::PlainHooks;
#[cfg(test)]
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
    pub(crate) tcb: Tcb,
    pub(crate) hooks: ConnectionHooks,
    pub(crate) local: SocketAddr,
    pub(crate) remote: SocketAddr,
    pub(crate) closed_by_app: bool,
    pub(crate) reset: bool,
    /// Closed and out of the demux table, kept only until the application has read the
    /// remaining data (no timers, no packets).
    pub(crate) detached: bool,
}

impl Connection {
    /// Queues `data` for sending; may accept less than `data.len()` (send buffer full), even 0.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        let closed = self.tcb.state() == TcpState::Closed;
        #[cfg(test)]
        let closed = closed && !self.hooks.retained();
        if self.closed_by_app || self.reset || closed {
            return Err(WriteError::Closed);
        }
        Ok(self.hooks.write(data))
    }

    /// Reads received bytes. `Ok(0)` is EOF (the peer's FIN, all data read) or a 0-length `buf`.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.reset {
            return Err(ReadError::Reset);
        }
        let eof = self.tcb.fin_received();
        #[cfg(test)]
        let eof = self.hooks.eof(eof);
        match self.hooks.read(buf) {
            0 if eof => Ok(0),
            0 => Err(ReadError::WouldBlock),
            n => Ok(n),
        }
    }

    /// Half-closes: the FIN follows the queued data. Reading stays possible, also after the
    /// connection has fully closed: unread data stays readable through `Endpoint::connection`
    /// until `read` returns `Ok(0)`; the next `Endpoint::handle_timeout` then frees it.
    ///
    /// In SYN-SENT this instead deletes the connection: queued writes are discarded and
    /// `Closed { Normal }` is reported. Wait for `Event::Connected` before `close` if the
    /// queued data must be delivered.
    pub fn close(&mut self) {
        self.closed_by_app = true;
        #[cfg(test)]
        if self.hooks.close() {
            return;
        }
        self.tcb.close();
    }

    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.tcb.set_nodelay(nodelay);
    }
}
