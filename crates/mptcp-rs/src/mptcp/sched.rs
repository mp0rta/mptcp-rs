//! The scheduler boundary (spec §4): read-only subflow snapshots in, a `Plan` out. The
//! connection validates and installs the plan; nothing here can reach a `Tcb` or its CC.
use std::time::Duration;

use rangemap::RangeSet;

use super::data::{SendStore, TxMaps};
use super::{SubflowId, SubflowState};
use crate::tcp::{AppLimited, SendBudget};
use crate::time::Instant;

/// What one subflow could send now, computed before any segment exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SubflowSnapshot {
    pub id: SubflowId,
    pub state: SubflowState,
    /// For the New candidate (unassigned data, Nagle and sender SWS applied).
    pub new_budget: SendBudget,
    /// For the head reinjection candidate; zero when nothing is queued.
    pub reinject_budget: SendBudget,
    /// Smoothed RTT, or the initial RTO before the first sample.
    pub srtt: Duration,
    /// Why the subflow is in an app-limited interval, if it is: its ACK samples then say
    /// nothing about path capacity.
    pub app_limited: Option<AppLimited>,
}

pub(crate) struct Pending<'a> {
    /// Unassigned data within the connection-level window.
    pub new_bytes: u64,
    pub reinject: &'a ReinjectQueue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Payload {
    New { bytes: u32 },
    Reinject { dsn: u64, len: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plan {
    Send {
        subflow: SubflowId,
        payload: Payload,
    },
    Idle,
}

/// Read by stale detection (M2 stale/reinjection task).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HealthEvent {
    RtoFired { subflow: SubflowId, n: u32 },
    Progress { subflow: SubflowId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HealthVerdict {
    Keep,
    Stale,
}

/// MinRTT's `on_health` threshold (spec §4 rule 4): Stale on the first R1 event.
const R1: u32 = 3;

pub(crate) trait Scheduler: Send {
    /// Called before any segment is built, when some Active subflow has a nonzero budget.
    fn plan(&mut self, now: Instant, pending: &Pending<'_>, subflows: &[SubflowSnapshot]) -> Plan;
    /// Judges a health fact; the connection applies the verdict.
    /// Called by stale detection (M2 stale/reinjection task).
    #[allow(dead_code)]
    fn on_health(&mut self, ev: &HealthEvent, subflows: &[SubflowSnapshot]) -> HealthVerdict;
    /// The connection installed a mapping of `bytes` octets from this scheduler's plan.
    fn on_assigned(&mut self, _subflow: SubflowId, _bytes: u32, _reinject: bool) {}
}

/// Lowest `srtt` among Active subflows with budget; queued reinjection first.
pub(crate) struct MinRtt;

impl Scheduler for MinRtt {
    fn plan(&mut self, _now: Instant, pending: &Pending<'_>, subflows: &[SubflowSnapshot]) -> Plan {
        let best = |budget: fn(&SubflowSnapshot) -> SendBudget| {
            subflows
                .iter()
                .filter(|s| s.state == SubflowState::Active && budget(s).bytes() > 0)
                .min_by_key(|s| s.srtt)
                .map(|s| (s.id, budget(s).bytes() as u32))
        };
        if let Some((dsn, len)) = pending.reinject.first() {
            if let Some((subflow, bytes)) = best(|s| s.reinject_budget) {
                let len = bytes.min(len.min(u64::from(u32::MAX)) as u32);
                let payload = Payload::Reinject { dsn, len };
                return Plan::Send { subflow, payload };
            }
        }
        match best(|s| s.new_budget).filter(|_| pending.new_bytes > 0) {
            Some((subflow, bytes)) => Plan::Send {
                subflow,
                payload: Payload::New { bytes },
            },
            None => Plan::Idle,
        }
    }
    fn on_health(&mut self, ev: &HealthEvent, _: &[SubflowSnapshot]) -> HealthVerdict {
        match ev {
            HealthEvent::RtoFired { n, .. } if *n >= R1 => HealthVerdict::Stale,
            _ => HealthVerdict::Keep,
        }
    }
}

/// DSN ranges queued for reinjection, kept as offsets from the connection's send origin
/// (`local_idsn + 1`) so that ranges never wrap. Always within `[send.una, send.next)`.
pub(crate) struct ReinjectQueue {
    origin: u64,
    /// Offset of `send.una`: nothing below it is queued.
    floor: u64,
    set: RangeSet<u64>,
}

impl ReinjectQueue {
    pub fn new(origin: u64) -> Self {
        Self {
            origin,
            floor: 0,
            set: RangeSet::new(),
        }
    }
    fn off(&self, dsn: u64) -> u64 {
        dsn.wrapping_sub(self.origin)
    }
    pub fn insert(&mut self, dsn: u64, len: u64) {
        let start = self.off(dsn).max(self.floor);
        let end = self.off(dsn) + len;
        if start < end {
            self.set.insert(start..end);
        }
    }
    pub fn remove(&mut self, dsn: u64, len: u64) {
        let start = self.off(dsn);
        if len > 0 {
            self.set.remove(start..start + len);
        }
    }
    /// DATA_ACK released everything below `una`.
    pub fn ack(&mut self, una: u64) {
        let off = self.off(una);
        if off > self.floor {
            self.floor = off;
            self.set.remove(0..off);
        }
    }
    pub fn first(&self) -> Option<(u64, u64)> {
        self.set
            .iter()
            .next()
            .map(|r| (self.origin.wrapping_add(r.start), r.end - r.start))
    }
    #[cfg(test)]
    pub fn total_len(&self) -> u64 {
        self.set.iter().map(|r| r.end - r.start).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
    pub fn clear(&mut self) {
        self.set = RangeSet::new();
    }
    /// Queues the parts of `[dsn, dsn + len)` that no un-subflow-ACKed mapping in `maps` (the
    /// Active subflows') covers: a copy already in flight is not duplicated.
    /// Used at insertion points beyond rule 5's uncovered head run (M2 stale/teardown task).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn insert_uncovered<'a>(
        &mut self,
        dsn: u64,
        len: u64,
        maps: impl Iterator<Item = &'a TxMaps> + Clone,
    ) {
        let end = dsn.wrapping_add(len);
        let mut at = dsn;
        while at != end {
            let left = end.wrapping_sub(at);
            if let Some(cover) = maps.clone().find_map(|m| m.covering_end(at)) {
                at = if cover.wrapping_sub(at) >= left {
                    end
                } else {
                    cover
                };
                continue;
            }
            let n = maps
                .clone()
                .fold(usize::try_from(left).unwrap_or(usize::MAX), |n, m| {
                    m.uncovered_len(at, n)
                }) as u64;
            self.insert(at, n);
            at = at.wrapping_add(n);
        }
    }
    /// The head reinjection candidate (Hot-path rules): drops head parts a live copy on an
    /// Active subflow covers, then returns the uncovered prefix of the first run, clipped to
    /// the stored run and the DSS length limit (`65,535 − fin`).
    pub fn head<'a>(
        &mut self,
        maps: impl Iterator<Item = &'a TxMaps> + Clone,
        send: &SendStore,
        fin: bool,
    ) -> Option<(u64, u32)> {
        loop {
            let (start, run) = self.first()?;
            if let Some(end) = maps.clone().find_map(|m| m.covering_end(start)) {
                self.remove(start, end.wrapping_sub(start));
                continue;
            }
            let len = usize::try_from(run)
                .unwrap_or(usize::MAX)
                .min(send.run_len(start))
                .min(usize::from(u16::MAX) - usize::from(fin));
            let len = maps.clone().fold(len, |n, m| m.uncovered_len(start, n));
            return Some((start, len as u32));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: SendBudget = SendBudget {
        seg_payload: 0,
        full_segments: 0,
        partial: 0,
    };
    fn budget(seg_payload: usize, full_segments: usize, partial: usize) -> SendBudget {
        SendBudget {
            seg_payload,
            full_segments,
            partial,
        }
    }
    fn snap(
        id: u8,
        state: SubflowState,
        srtt_ms: u64,
        new: SendBudget,
        re: SendBudget,
    ) -> SubflowSnapshot {
        SubflowSnapshot {
            id: SubflowId(id),
            state,
            new_budget: new,
            reinject_budget: re,
            srtt: Duration::from_millis(srtt_ms),
            app_limited: None,
        }
    }
    fn plan(q: &ReinjectQueue, new_bytes: u64, subflows: &[SubflowSnapshot]) -> Plan {
        let pending = Pending {
            new_bytes,
            reinject: q,
        };
        MinRtt.plan(Instant::from_nanos(0), &pending, subflows)
    }
    fn send(id: u8, payload: Payload) -> Plan {
        Plan::Send {
            subflow: SubflowId(id),
            payload,
        }
    }
    use SubflowState::{Active, Closing, Joining, Stale};

    #[test]
    fn minrtt_picks_lowest_srtt_with_budget() {
        let q = ReinjectQueue::new(0);
        let subflows = [
            snap(0, Active, 30, budget(1000, 2, 0), budget(1000, 2, 0)),
            snap(1, Active, 10, NONE, NONE),
        ];
        assert_eq!(
            plan(&q, 5000, &subflows),
            send(0, Payload::New { bytes: 2000 })
        );
    }

    #[test]
    fn minrtt_skips_stale_joining_closing() {
        let q = ReinjectQueue::new(0);
        let b = budget(1000, 1, 0);
        let mut subflows = [
            snap(0, Stale, 1, b, b),
            snap(1, Joining, 2, b, b),
            snap(2, Closing, 3, b, b),
            snap(3, Active, 40, b, b),
        ];
        assert_eq!(
            plan(&q, 5000, &subflows),
            send(3, Payload::New { bytes: 1000 })
        );
        subflows[3].state = Stale;
        assert_eq!(plan(&q, 5000, &subflows), Plan::Idle);
    }

    #[test]
    fn minrtt_idle_without_budget() {
        let mut q = ReinjectQueue::new(0);
        q.insert(0, 100);
        let subflows = [
            snap(0, Active, 10, NONE, NONE),
            snap(1, Active, 20, budget(1000, 0, 0), budget(1000, 0, 0)),
        ];
        assert_eq!(plan(&q, 5000, &subflows), Plan::Idle);
    }

    #[test]
    fn minrtt_reinject_before_new() {
        let mut q = ReinjectQueue::new(100);
        q.insert(100, 5000);
        q.insert(9000, 10);
        let subflows = [snap(0, Active, 10, budget(1000, 3, 0), budget(1000, 2, 0))];
        assert_eq!(
            plan(&q, 5000, &subflows),
            send(
                0,
                Payload::Reinject {
                    dsn: 100,
                    len: 2000
                }
            )
        );
    }

    #[test]
    fn minrtt_reinject_only_no_new_data() {
        let mut q = ReinjectQueue::new(0);
        q.insert(0, 300);
        let subflows = [
            snap(0, Active, 10, NONE, NONE),
            snap(1, Active, 20, NONE, budget(1000, 0, 300)),
        ];
        assert_eq!(
            plan(&q, 0, &subflows),
            send(1, Payload::Reinject { dsn: 0, len: 300 })
        );
    }

    #[test]
    fn minrtt_reinject_while_new_held_by_nagle() {
        let mut q = ReinjectQueue::new(0);
        q.insert(0, 300);
        // Nagle holds the sub-MSS new tail (partial 0); a reinjection is not held.
        let subflows = [snap(
            0,
            Active,
            10,
            budget(1000, 0, 0),
            budget(1000, 0, 300),
        )];
        assert_eq!(
            plan(&q, 400, &subflows),
            send(0, Payload::Reinject { dsn: 0, len: 300 })
        );
    }

    #[test]
    fn minrtt_reinject_uses_reinject_budget_subflow() {
        let mut q = ReinjectQueue::new(0);
        q.insert(0, 3000);
        let subflows = [
            snap(0, Active, 10, budget(1000, 4, 0), NONE),
            snap(1, Active, 30, NONE, budget(1000, 1, 0)),
        ];
        assert_eq!(
            plan(&q, 4000, &subflows),
            send(1, Payload::Reinject { dsn: 0, len: 1000 })
        );
    }

    #[test]
    fn reinject_queue_across_dsn_wrap() {
        let origin = u64::MAX - 100;
        let mut q = ReinjectQueue::new(origin);
        assert!(q.is_empty());
        q.insert(u64::MAX - 50, 100); // [MAX−50, 49) spans the wrap
        assert_eq!(
            (q.first(), q.total_len()),
            (Some((u64::MAX - 50, 100)), 100)
        );
        q.remove(u64::MAX - 10, 20); // dedup: a live copy covers [MAX−10, 9)
        assert_eq!((q.first(), q.total_len()), (Some((u64::MAX - 50, 40)), 80));
        q.remove(u64::MAX - 50, 30); // a 30-octet assign
        assert_eq!((q.first(), q.total_len()), (Some((u64::MAX - 20, 10)), 50));
        q.ack(u64::MAX - 15);
        assert_eq!((q.first(), q.total_len()), (Some((u64::MAX - 15, 5)), 45));
        q.insert(u64::MAX - 40, 10); // entirely below send.una: clipped away
        assert_eq!(q.total_len(), 45);
        q.remove(u64::MAX - 15, 5);
        assert_eq!((q.first(), q.total_len()), (Some((9, 40)), 40));
        q.ack(49);
        assert!(q.is_empty());
        assert_eq!((q.first(), q.total_len()), (None, 0));
    }

    /// A store holding the given mappings' octets from DSN 0, each mapping assigned in its
    /// own `TxMaps`; a mapping is subflow-ACKed by replacing its `TxMaps` with an empty one.
    fn store(sizes: &[usize]) -> (SendStore, Vec<TxMaps>) {
        let total = sizes.iter().sum::<usize>();
        let mut send = SendStore::new(0, 1 << 20);
        assert_eq!(send.write(&vec![0; total]), total);
        let maps = sizes
            .iter()
            .map(|&n| {
                let mut tx = TxMaps::new(1, 1024);
                assert!(send.assign(&mut tx, send.next, n));
                tx
            })
            .collect();
        (send, maps)
    }
    fn acked() -> TxMaps {
        TxMaps::new(1, 1024)
    }

    #[test]
    fn reinject_head_stops_before_inner_inflight_copy() {
        let (mut send, _) = store(&[1000]); // subflow-ACKed, not DATA_ACKed
        let mut tx = acked();
        assert!(send.assign(&mut tx, 400, 200)); // an earlier reinjection, still in flight
        let mut q = ReinjectQueue::new(0);
        q.insert(0, 1000);
        assert_eq!(q.head([&tx].into_iter(), &send, false), Some((0, 400)));
        assert!(send.assign(&mut tx, 0, 400));
        q.remove(0, 400);
        assert_eq!(q.head([&tx].into_iter(), &send, false), Some((600, 400)));
        assert_eq!(q.total_len(), 400, "the covered middle left the queue");
        assert!(send.assign(&mut tx, 600, 400));
        q.remove(600, 400);
        assert_eq!(q.head([&tx].into_iter(), &send, false), None);
    }

    #[test]
    fn reinject_insert_skips_inflight_copy_and_rule5_recovers() {
        let (mut send, mut maps) = store(&[500, 500]);
        maps[0] = acked(); // U = [0,500) subflow-ACKed; V = [500,1000) still in flight
        let mut q = ReinjectQueue::new(0);
        q.insert_uncovered(0, 1000, maps.iter());
        assert_eq!((q.first(), q.total_len()), (Some((0, 500)), 500));
        maps[1] = acked(); // V's copy subflow-ACKed without DATA_ACK
        assert_eq!(q.head(maps.iter(), &send, false), Some((0, 500)));
        assert!(send.assign(&mut maps[0], 0, 500));
        q.remove(0, 500);
        assert_eq!(q.head(maps.iter(), &send, false), None, "V is not offered");
        // Rule 5 expiry queues the uncovered head run; only then is V reinjected.
        q.insert(500, 500);
        assert_eq!(q.head(maps.iter(), &send, false), Some((500, 500)));
    }

    #[test]
    fn reinject_queue_merged_runs_drain_per_chunk() {
        let (send, _) = store(&[100]);
        let tx = acked();
        let mut q = ReinjectQueue::new(0);
        q.insert(0, 40);
        q.insert(40, 60);
        assert_eq!((q.first(), q.total_len()), (Some((0, 100)), 100));
        // The stored run is contiguous (one mapping may span writes), so the budget clips:
        // 40 octets, then 60.
        for (budget_len, start) in [(40, 0), (60, 40)] {
            assert_eq!(
                q.head([&tx].into_iter(), &send, false),
                Some((start, 100 - start as u32))
            );
            let subflows = [snap(0, Active, 10, NONE, budget(1000, 0, budget_len))];
            let Plan::Send {
                payload: Payload::Reinject { dsn, len },
                ..
            } = plan(&q, 0, &subflows)
            else {
                panic!("reinjection expected");
            };
            assert_eq!((dsn, len), (start, budget_len as u32));
            q.remove(dsn, u64::from(len));
        }
        assert!(q.is_empty());
    }

    #[test]
    fn minrtt_new_bytes_obey_rule1() {
        let q = ReinjectQueue::new(0);
        for seg in [508, 1432, 8960] {
            for fin in [0, 1] {
                let max_k = (65535 - fin) / seg;
                for (full, partial) in [(1, 0), (3, 0), (max_k, 0), (0, 100), (0, seg - 1)] {
                    let b = budget(seg, full, partial);
                    let subflows = [snap(0, Active, 10, b, NONE)];
                    let Plan::Send {
                        payload: Payload::New { bytes },
                        ..
                    } = plan(&q, 1 << 20, &subflows)
                    else {
                        panic!("new data expected");
                    };
                    let bytes = bytes as usize;
                    let k = bytes / seg;
                    assert!(
                        (bytes % seg == 0 && (1..=full).contains(&k) && k <= max_k)
                            || (bytes > 0 && bytes <= partial),
                        "seg {seg} fin {fin} budget {b:?}: {bytes}"
                    );
                }
            }
        }
    }

    #[test]
    fn minrtt_health_stale_at_r1_keep_on_progress() {
        let subflows = [snap(0, Active, 10, NONE, NONE)];
        let fired = |n| HealthEvent::RtoFired {
            subflow: SubflowId(0),
            n,
        };
        assert_eq!(MinRtt.on_health(&fired(2), &subflows), HealthVerdict::Keep);
        assert_eq!(MinRtt.on_health(&fired(3), &subflows), HealthVerdict::Stale);
        let progress = HealthEvent::Progress {
            subflow: SubflowId(0),
        };
        assert_eq!(MinRtt.on_health(&progress, &subflows), HealthVerdict::Keep);
    }
}
