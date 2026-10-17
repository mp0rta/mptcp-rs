//! The endpoint's connections, and which of them `poll_transmit` visits (issue #12): a
//! connection is ready while it may have something to send, and parked otherwise.
//!
//! Every endpoint call that reaches a connection makes it ready: a packet for it, a path call,
//! `Endpoint::connection` (which hands out `&mut Connection`), and a `handle_timeout` pass after
//! one of those. So does its timer: a parked connection wakes when its wake time passes
//! (`wake_at`: its deadline or a pacing release), which is when the passing of time alone can
//! give it a segment to send. A turn that sends nothing and leaves nothing for the next one
//! (`Visit::Idle`) parks it. The turns skipped meanwhile would change nothing, so
//! `poll_transmit` sends what the full scan sent, in the same order (`diff_tests`).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::ops::{Bound, Index};

use crate::Instant;
use crate::connection::Connection;

use super::ConnectionHandle;

/// The endpoint's bookkeeping of one connection.
#[derive(Default)]
pub(crate) struct Slot {
    /// Its wake time while parked, which `Conns::parked` holds.
    parked: Option<Instant>,
    /// Reached by an endpoint call since its last `handle_timeout` pass.
    pending: bool,
}

/// Every connection by handle. `insert`, `get_mut`, `lend` and `touch` make a connection
/// ready; the endpoint's own passes use `untracked_mut`, which leaves that to them.
#[derive(Default)]
pub(crate) struct Conns {
    map: BTreeMap<ConnectionHandle, Connection>,
    /// The connections `poll_transmit` visits, in handle order.
    ready: BTreeSet<ConnectionHandle>,
    /// Each parked connection with a wake time, at `Slot::parked`; entries that no longer match
    /// it are skipped.
    parked: BinaryHeap<Reverse<(Instant, ConnectionHandle)>>,
    /// The connections `Endpoint::connection` handed out since `aborting`.
    lent: Vec<ConnectionHandle>,
}

impl Conns {
    pub fn insert(&mut self, h: ConnectionHandle, c: Connection) {
        self.map.insert(h, c);
        self.touch(h);
    }

    pub fn remove(&mut self, h: &ConnectionHandle) -> Option<Connection> {
        self.ready.remove(h);
        self.map.remove(h)
    }

    pub fn get(&self, h: &ConnectionHandle) -> Option<&Connection> {
        self.map.get(h)
    }

    /// Makes the connection ready (`touch`).
    pub fn get_mut(&mut self, h: &ConnectionHandle) -> Option<&mut Connection> {
        let c = self.map.get_mut(h)?;
        self.ready.insert(*h);
        (c.slot.parked, c.slot.pending) = (None, true);
        Some(c)
    }

    /// For the application (`Endpoint::connection`): made ready as by `get_mut`, and listed
    /// for `aborting`.
    pub fn lend(&mut self, h: &ConnectionHandle) -> Option<&mut Connection> {
        let c = self.map.get_mut(h)?;
        self.ready.insert(*h);
        (c.slot.parked, c.slot.pending) = (None, true);
        self.lent.push(*h);
        Some(c)
    }

    /// Without making it ready.
    pub fn untracked_mut(&mut self, h: &ConnectionHandle) -> Option<&mut Connection> {
        self.map.get_mut(h)
    }

    #[cfg(test)]
    pub fn contains_key(&self, h: &ConnectionHandle) -> bool {
        self.map.contains_key(h)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ConnectionHandle, &Connection)> {
        self.map.iter()
    }

    pub fn values(&self) -> impl Iterator<Item = &Connection> {
        self.map.values()
    }

    /// Every connection, without making any ready.
    pub fn iter_untracked_mut(
        &mut self,
    ) -> impl Iterator<Item = (&ConnectionHandle, &mut Connection)> {
        self.map.iter_mut()
    }

    pub fn retain(&mut self, mut f: impl FnMut(&ConnectionHandle, &mut Connection) -> bool) {
        let ready = &mut self.ready;
        self.map.retain(|h, c| {
            let keep = f(h, c);
            if !keep {
                ready.remove(h);
            }
            keep
        });
    }

    /// An endpoint call reached `h`: it is ready, and its next `handle_timeout` pass makes it
    /// ready again (`passed`).
    pub fn touch(&mut self, h: ConnectionHandle) {
        if let Some(c) = self.map.get_mut(&h) {
            self.ready.insert(h);
            (c.slot.parked, c.slot.pending) = (None, true);
        }
    }

    /// `handle_timeout` passed over `h`, which an endpoint call had reached since the previous
    /// pass (`Slot::take_pending`): what the pass did with it may give it something to send.
    pub fn passed(&mut self, h: ConnectionHandle) {
        if let Some(c) = self.map.get_mut(&h) {
            self.ready.insert(h);
            c.slot.parked = None;
        }
    }

    /// The connections `abort` was called on since the last look, in handle order.
    pub fn aborting(&mut self) -> Vec<ConnectionHandle> {
        let mut lent = std::mem::take(&mut self.lent);
        lent.retain(|h| self.map.get(h).is_some_and(|c| c.aborting));
        lent.sort_unstable();
        lent.dedup();
        lent
    }

    /// The first ready connection in `range`.
    pub fn next_ready(
        &self,
        range: (Bound<ConnectionHandle>, Bound<ConnectionHandle>),
    ) -> Option<ConnectionHandle> {
        self.ready.range(range).next().copied()
    }

    /// `h`'s turn found nothing to do: it waits for an endpoint call or for `wake`.
    pub fn park(&mut self, h: ConnectionHandle, wake: Option<Instant>) {
        self.ready.remove(&h);
        let c = self.map.get_mut(&h).unwrap();
        c.slot.parked = wake;
        if let Some(at) = wake {
            self.parked.push(Reverse((at, h)));
        }
        // Each park adds at most one entry: rebuilding once stale ones outnumber the
        // connections keeps the heap within twice their number, at O(1) amortized per park.
        if self.parked.len() > 2 * self.map.len() + 64 {
            let live = self
                .map
                .iter()
                .filter_map(|(&h, c)| Some(Reverse((c.slot.parked?, h))));
            self.parked = live.collect();
        }
    }

    /// Makes ready every parked connection whose wake time is at or before `now`.
    pub fn wake(&mut self, now: Instant) {
        while let Some(&Reverse((at, h))) = self.parked.peek() {
            if at > now {
                break;
            }
            self.parked.pop();
            if let Some(c) = self.map.get_mut(&h).filter(|c| c.slot.parked == Some(at)) {
                c.slot.parked = None;
                self.ready.insert(h);
            }
        }
    }
}

impl Slot {
    /// Whether an endpoint call reached it since the last `handle_timeout` pass, which this is.
    pub fn take_pending(&mut self) -> bool {
        std::mem::take(&mut self.pending)
    }
}

impl Index<&ConnectionHandle> for Conns {
    type Output = Connection;

    fn index(&self, h: &ConnectionHandle) -> &Connection {
        &self.map[h]
    }
}
