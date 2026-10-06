//! One plain TCP connection as the application sees it: a `Tcb` plus its buffers.

use std::net::SocketAddr;

use crate::tcp::{PlainHooks, Tcb, TcpState};

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
    pub(crate) hooks: PlainHooks,
    pub(crate) local: SocketAddr,
    pub(crate) remote: SocketAddr,
    pub(crate) closed_by_app: bool,
    pub(crate) reset: bool,
}

impl Connection {
    /// Queues `data` for sending; may accept less than `data.len()` (send buffer full), even 0.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        if self.closed_by_app || self.reset || self.tcb.state() == TcpState::Closed {
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
        match self.hooks.read(buf) {
            0 if self.tcb.fin_received() => Ok(0),
            0 => Err(ReadError::WouldBlock),
            n => Ok(n),
        }
    }

    /// Half-closes: the FIN follows the queued data. Reading stays possible.
    pub fn close(&mut self) {
        self.closed_by_app = true;
        self.tcb.close();
    }

    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.tcb.set_nodelay(nodelay);
    }
}
