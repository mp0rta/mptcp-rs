//! The 4-tuples of subflows `Connection::abort` reset with MP_FASTCLOSE, each with the peer's
//! key until its expiry (M3 spec §3.5): segments reaching them are answered with RST and
//! MP_FASTCLOSE, and new subflows do not use them.

use std::collections::VecDeque;
use std::net::SocketAddr;

use crate::Instant;

/// Entries beyond this evict the oldest.
const CAP: usize = 64;

/// (local, remote) as in the demux table.
type Tuple = (SocketAddr, SocketAddr);

/// Oldest first.
#[derive(Default)]
pub(super) struct Aborted(VecDeque<(Tuple, u64, Instant)>);

impl Aborted {
    pub fn insert(&mut self, tuple: Tuple, key: u64, until: Instant) {
        if self.0.len() == CAP {
            self.0.pop_front();
        }
        self.0.push_back((tuple, key, until));
    }

    /// The peer key of `tuple`, while its entry is retained at `now`.
    pub fn key(&self, tuple: Tuple, now: Instant) -> Option<u64> {
        (self.0.iter()).find_map(|&(t, key, until)| (t == tuple && now < until).then_some(key))
    }

    pub fn expire(&mut self, now: Instant) {
        self.0.retain(|&(_, _, until)| now < until);
    }

    pub fn next_expiry(&self) -> Option<Instant> {
        self.0.iter().map(|&(_, _, until)| until).min()
    }
}
