//! Opportunistic retransmission and penalization (M3 spec §2): while the subflow holding the
//! data at `send.una` blocks a full send store or connection window, its run is copied to
//! another usable subflow, and the blocking subflow's cwnd is reduced.
use std::time::Duration;

use super::sched::{HealthEvent, HealthVerdict};
use super::{Subflow, SubflowId, SubflowState, later, may_assign};
use crate::connection::Connection;
use crate::tcp::SendBuf;
use crate::tcp::rtt::INITIAL_RTO;
use crate::time::Instant;

/// The one opportunistic episode (§2.3): `[start, end)` copied to `target`.
pub(crate) struct Episode {
    /// The first DSN of the episode not DATA_ACKed yet.
    pub start: u64,
    /// One past the last DSN copied.
    pub end: u64,
    pub target: SubflowId,
    /// The later of the last install and the last DATA_ACK advance, plus `target`'s
    /// un-backed-off RTO.
    pub deadline: Instant,
    /// `target`'s relative SSN after the last copy: the tail the probe covers.
    pub ssn_end: u32,
    /// The episode's one tail loss probe went out.
    pub probed: bool,
}

/// Opportunistic retransmission counters (M3 spec §2.6), for test drivers; not a stable API.
#[doc(hidden)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DebugStats {
    /// Schedule steps at which a candidate exists while none existed at the previous step.
    pub opp_triggers: u64,
    pub opp_episodes: u64,
    /// `Penalized` events applied.
    pub penalties: u64,
    /// Octets installed as opportunistic copies and head repairs.
    pub opp_bytes: u64,
    /// Head repairs installed (§2.7 H1).
    pub opp_repairs: u64,
    /// Lookaheads started (§2.7 H2).
    pub lookaheads: u64,
}

/// The copy of the head a later repair judges (§2.7): the subflow that installed it, its DSN
/// range and its exclusive SSN end there.
#[derive(Clone, Copy)]
pub(crate) struct Pin {
    pub target: SubflowId,
    pub start: u64,
    pub end: u64,
    pub ssn_end: u32,
}

/// One bounded lookahead over S's holes (§2.7 H2).
#[derive(Clone, Copy)]
pub(crate) struct Lookahead {
    pub s: SubflowId,
    /// Exclusive: the greatest end of S's mappings when it started.
    pub boundary: u64,
    /// Everything below it was copied in this lookahead.
    pub cursor: u64,
    pub started: Instant,
}

/// Head repair (§2.7 H1) and the bounded lookahead (H2).
#[derive(Default)]
pub(crate) struct Repair {
    /// The DATA_ACK (`send.una`) the state below is about.
    head: u64,
    /// The repair clock (armed).
    pub armed: Option<Instant>,
    /// The run to copy now (due): persistent demand.
    pub due: Option<(u64, u32)>,
    pub pin: Option<Pin>,
    /// The latest repair's one tail probe: its target and SSN end, until it fires or is ACKed.
    pub probe: Option<(SubflowId, u32)>,
    pub lookahead: Option<Lookahead>,
    /// When the latest lookahead started: a later one needs a later silence origin.
    pub last_lookahead: Option<Instant>,
}

/// Usable (M3 §4.5): Active, and the peer is not advertising a zero subflow window.
pub(crate) fn usable(sf: &Subflow) -> bool {
    sf.is(SubflowState::Active) && !sf.tcb.peer_window_closed()
}

fn base_rto(sf: &Subflow) -> Duration {
    sf.tcb.base_rto().unwrap_or(INITIAL_RTO)
}

/// An opportunistic copy to schedule: `[dsn, dsn + len)`, the blocking subflow S if one holds
/// the original, and whether it is a head repair (§2.7 H1) rather than an episode copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cand {
    pub dsn: u64,
    pub len: u32,
    pub blocking: Option<SubflowId>,
    pub repair: bool,
}

/// `dsn` lies in `[start, end)`.
fn within(dsn: u64, start: u64, end: u64) -> bool {
    dsn.wrapping_sub(start) < end.wrapping_sub(start)
}

/// 2·srtt, or the initial RTO before a sample (§2.7 clocks).
fn clock(sf: &Subflow) -> Duration {
    sf.tcb.srtt().map_or(INITIAL_RTO, |s| 2 * s)
}

impl Connection {
    /// §2.2 conditions 1, 3 and 4: data is outstanding, no New data is assignable, and the
    /// store is full (allocation accounting) or the connection window is exhausted while data
    /// waits beyond it. Never while `Waiting` (M4b spec G12).
    fn blocked(&self) -> bool {
        let (Some(d), Some(m)) = (&self.hooks.data, &self.hooks.negotiation) else {
            return false;
        };
        let send = &d.send;
        if d.fallback
            || self.hooks.frozen()
            || send.una == send.next
            || self.hooks.unassigned_len() > 0
        {
            return false;
        }
        let window_full = send.end != send.next
            && (m.send_right_edge).is_some_and(|e| e.wrapping_sub(send.next) as i64 <= 0);
        window_full || send.writable() == 0
    }

    /// S for `dsn`: the subflow whose live original (not a copy) mapping covers it.
    fn blocking(&self, dsn: u64) -> Option<&Subflow> {
        self.subflows
            .iter()
            .find(|sf| sf.mp.tx.original_covers(dsn))
    }

    /// The end of the run from `dsn` that live mappings cover, contiguously.
    fn covered_end(&self, dsn: u64) -> u64 {
        let mut x = dsn;
        while let Some(end) = (self.subflows.iter()).find_map(|sf| sf.mp.tx.covering_end(x)) {
            x = end;
        }
        x
    }

    /// `[start, end)` clipped to the stored run and the DSS length limit (`65,535 − fin`).
    fn clip(&self, start: u64, end: u64) -> u32 {
        let d = self.hooks.data.as_ref().unwrap();
        let fin = usize::from(d.close.local.is_some());
        (end.wrapping_sub(start) as usize)
            .min(d.send.run_len(start))
            .min(usize::from(u16::MAX) - fin) as u32
    }

    /// The opportunistic candidate while the connection is blocked, first match wins:
    /// - a due head repair (§2.7 H1), whose target may be the previous copy's;
    /// - the active lookahead's next range of S's holes (§2.7 H2);
    /// - the head run (§2.2): S's original covers `send.una`; from `max(send.una, episode
    ///   end)` while live mappings cover it.
    ///
    /// Each needs an eligible target and is clipped by `clip`.
    pub(crate) fn opp_candidate(&self) -> Option<Cand> {
        if !self.blocked() {
            return None;
        }
        let una = self.hooks.data.as_ref()?.send.una;
        let target =
            |dsn, s, episode| (self.subflows.iter()).any(|t| self.opp_target(t, dsn, s, episode));
        if let Some((dsn, len)) = self.repair.due {
            let s = self.blocking(dsn).map(|sf| sf.id);
            let len = len.min(self.clip(dsn, dsn.wrapping_add(u64::from(len))));
            if len > 0 && target(dsn, s, false) {
                return Some(Cand {
                    dsn,
                    len,
                    blocking: s,
                    repair: true,
                });
            }
        }
        if let Some((dsn, end, s)) = self.lookahead_range() {
            let len = self.clip(dsn, end);
            if len > 0 && target(dsn, Some(s), true) {
                return Some(Cand {
                    dsn,
                    len,
                    blocking: Some(s),
                    repair: false,
                });
            }
        }
        let s = Some(self.blocking(una)?.id);
        let dsn = later(self.opp.as_ref().map(|e| e.end), una).unwrap();
        let len = self.clip(dsn, self.covered_end(dsn));
        (len > 0 && target(dsn, s, true)).then_some(Cand {
            dsn,
            len,
            blocking: s,
            repair: false,
        })
    }

    /// The active lookahead's next range `(dsn, end, S)` (§2.7 H2): from `max(send.una, cursor)`,
    /// the first DSNs below the boundary that S's live mappings cover and no other subflow's
    /// do. Nothing once S has made subflow-ACK progress since the lookahead started.
    fn lookahead_range(&self) -> Option<(u64, u64, SubflowId)> {
        let la = self.repair.lookahead?;
        let una = self.hooks.data.as_ref()?.send.una;
        let s = self.subflows.iter().find(|sf| sf.id == la.s)?;
        if s.tcb.silence_since().is_none_or(|o| o > la.started) {
            return None;
        }
        let off = |x: u64| x.wrapping_sub(una);
        let others = || self.subflows.iter().filter(|sf| sf.id != la.s);
        let mut q = later(Some(la.cursor), una).unwrap();
        loop {
            if off(q) >= off(la.boundary) {
                return None;
            }
            if let Some(end) = others().find_map(|sf| sf.mp.tx.covering_end(q)) {
                q = end;
            } else if s.mp.tx.covering_end(q).is_some() {
                break;
            } else {
                let next =
                    s.mp.tx
                        .ranges()
                        .map(|(d, _)| d)
                        .filter(|&d| off(d) > off(q));
                q = next.min_by_key(|&d| off(d))?;
            }
        }
        let mut end = q;
        while let Some(e) = s.mp.tx.covering_end(end) {
            end = if off(e) < off(la.boundary) {
                e
            } else {
                la.boundary
            };
            if end == la.boundary {
                break;
            }
        }
        Some((q, end, la.s))
    }

    /// S's silence deadline (§2.7 H2) and S: while blocked, no lookahead is active and S has
    /// data outstanding, its silence origin (the later of its last subflow-ACK advance and the
    /// start of its flight) + 2·srtt_S; never again for an origin a lookahead already used.
    pub(crate) fn silence_deadline(&self) -> Option<(Instant, SubflowId)> {
        if !self.blocked() || self.repair.lookahead.is_some() {
            return None;
        }
        let s = self.blocking(self.hooks.data.as_ref()?.send.una)?;
        let origin = s.tcb.silence_since()?;
        if self.repair.last_lookahead.is_some_and(|l| origin <= l) {
            return None;
        }
        Some((origin + clock(s), s.id))
    }

    /// When the latest head repair's tail probe is due.
    pub(crate) fn repair_probe_at(&self) -> Option<Instant> {
        let (target, end) = self.repair.probe?;
        let t = self.subflows.iter().find(|sf| sf.id == target)?;
        t.tcb.tail_probe_at(end)
    }

    /// The earliest opportunistic deadline: the episode's expiry and tail probe, the repair
    /// clock and tail probe, and S's silence deadline. Each is consumed by `update_repair`.
    pub(crate) fn opp_deadline(&self) -> Option<Instant> {
        [
            self.opp.as_ref().map(|e| e.deadline),
            self.opp_probe_at(),
            self.repair.armed,
            self.repair_probe_at(),
            self.silence_deadline().map(|d| d.0),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Head repair and lookahead state (§2.7), after every input, timeout and scheduling pass.
    /// - A lookahead ends once DATA_ACK reaches its boundary; S's silence deadline starts one.
    /// - H1: a new head drops the clock and demand, and the pin unless the head lies in it.
    ///   While blocked and the head is not queued for reinjection, a head that no live mapping
    ///   covers, or whose pinned copy is TCP-ACKed, arms the clock (2·srtt of the next target),
    ///   unless that copy is still TCP-unacknowledged; on expiry the head run becomes due.
    /// - The latest repair's one tail probe fires, or is dropped once its copy is ACKed.
    pub(crate) fn update_repair(&mut self, now: Instant) {
        let Some(d) = self.hooks.data.as_ref() else {
            return;
        };
        let una = d.send.una;
        let queued = d.reinject.first().is_some_and(|(dsn, _)| dsn == una);
        if (self.repair.lookahead)
            .is_some_and(|la| d.fallback || una.wrapping_sub(la.boundary) as i64 >= 0)
        {
            self.repair.lookahead = None;
        }
        if let Some((_, s)) = self.silence_deadline().filter(|&(at, _)| now >= at) {
            let sf = self.subflows.iter().find(|sf| sf.id == s).unwrap();
            // Signed offsets from `send.una`: a mapping a copy got DATA_ACKed ends at or below it.
            let off = |e: u64| e.wrapping_sub(una) as i64;
            let ends = sf.mp.tx.ranges().map(|(dsn, n)| dsn.wrapping_add(n));
            let boundary = (ends.filter(|&e| off(e) > 0).max_by_key(|&e| off(e))).unwrap_or(una);
            let started = now;
            self.repair.lookahead = Some(Lookahead {
                s,
                boundary,
                cursor: una,
                started,
            });
            self.repair.last_lookahead = Some(now);
            self.hooks.debug.lookaheads += 1;
        }
        if self.repair.head != una {
            self.repair.head = una;
            (self.repair.armed, self.repair.due) = (None, None);
            self.repair.pin = self.repair.pin.filter(|p| within(una, p.start, p.end));
        }
        let pin = self.repair.pin.filter(|p| within(una, p.start, p.end));
        let pin_acked = pin.map(|p| {
            (self.subflows.iter().find(|sf| sf.id == p.target))
                .is_none_or(|t| t.tcb.acked_to(p.ssn_end))
        });
        if !self.blocked() || queued {
            (self.repair.armed, self.repair.due) = (None, None);
        } else if self.repair.armed.is_none()
            && self.repair.due.is_none()
            && pin_acked != Some(false)
        {
            let uncovered = !(self.subflows.iter()).any(|sf| sf.mp.tx.covering_end(una).is_some());
            if uncovered || pin_acked == Some(true) {
                let s = self.blocking(una).map(|sf| sf.id);
                let next = (self.subflows.iter())
                    .filter(|t| self.opp_target(t, una, s, false))
                    .min_by_key(|t| t.tcb.srtt().unwrap_or(INITIAL_RTO));
                self.repair.armed = Some(now + next.map_or(INITIAL_RTO, clock));
            }
        }
        if self.repair.armed.is_some_and(|at| now >= at) {
            self.repair.armed = None;
            let end = if (self.subflows.iter()).any(|sf| sf.mp.tx.covering_end(una).is_some()) {
                self.covered_end(una)
            } else {
                // Rule 5's uncovered prefix.
                let outstanding = d.send.next.wrapping_sub(una) as usize;
                let run = (self.subflows.iter())
                    .filter(|sf| sf.is(SubflowState::Active))
                    .fold(outstanding, |n, sf| sf.mp.tx.uncovered_len(una, n));
                una.wrapping_add(run as u64)
            };
            self.repair.due = Some((una, self.clip(una, end)));
        }
        if let Some((target, end)) = self.repair.probe {
            let t = self.subflows.iter_mut().find(|sf| sf.id == target);
            match t {
                Some(t) if !t.tcb.acked_to(end) => {
                    if t.tcb.tail_probe_at(end).is_some_and(|at| now >= at) {
                        t.tcb.probe_tail();
                        self.repair.probe = None;
                    }
                }
                _ => self.repair.probe = None,
            }
        }
    }

    /// `t` is an eligible target for a copy starting at `start` (§2.2): usable, a backup only
    /// while no non-backup subflow is usable (§4.5), not the blocking subflow, no live mapping
    /// of its own covers `start`, it may take a mapping, and, for an `episode` copy, it is the
    /// current episode's target if there is one.
    pub(crate) fn opp_target(
        &self,
        t: &Subflow,
        start: u64,
        blocking: Option<SubflowId>,
        episode: bool,
    ) -> bool {
        blocking != Some(t.id)
            && usable(t)
            && !(t.mp.backup() && (self.subflows.iter()).any(|sf| usable(sf) && !sf.mp.backup()))
            && t.mp.tx.covering_end(start).is_none()
            && may_assign(&self.hooks, &t.mp, &t.tcb)
            && (!episode || self.opp.as_ref().is_none_or(|e| e.target == t.id))
    }

    /// Ends the episode once DATA_ACK reaches its end, its target is no longer usable or its
    /// deadline passes; a DATA_ACK advance moves the deadline (§2.3).
    pub(crate) fn update_episode(&mut self, now: Instant) {
        let (Some(e), Some(d)) = (&mut self.opp, &self.hooks.data) else {
            return;
        };
        let t = self.subflows.iter().find(|sf| sf.id == e.target);
        let una = d.send.una;
        if d.fallback || !t.is_some_and(usable) || una.wrapping_sub(e.end) as i64 >= 0 {
            self.opp = None;
            return;
        }
        if una.wrapping_sub(e.start) as i64 > 0 {
            e.start = una;
            e.deadline = now + base_rto(t.unwrap());
        }
        if now >= e.deadline {
            self.opp = None;
            return;
        }
        if self.opp_probe_at().is_some_and(|at| now >= at) {
            let e = self.opp.as_mut().unwrap();
            e.probed = true;
            let target = e.target;
            let t = self.subflows.iter_mut().find(|sf| sf.id == target);
            t.unwrap().tcb.probe_tail();
        }
    }

    /// When the episode's copy gets its one tail loss probe (§2.3): T has sent all of it and
    /// nothing else, and has not had all of it ACKed (`Tcb::tail_probe_at`).
    pub(crate) fn opp_probe_at(&self) -> Option<Instant> {
        let e = self.opp.as_ref().filter(|e| !e.probed)?;
        let t = self.subflows.iter().find(|sf| sf.id == e.target)?;
        t.tcb.tail_probe_at(e.ssn_end)
    }

    /// Subflow `i` took the copy `[dsn, dsn + len)` of candidate `c`. A copy of the head pins
    /// it (§2.7). A head repair clears the demand and arms its own tail probe; otherwise the
    /// episode starts or grows, the lookahead cursor passes it, and S is reported
    /// head-blocked.
    pub(crate) fn opp_installed(&mut self, i: usize, c: Cand, len: u32, now: Instant) {
        let dsn = c.dsn;
        let t = &self.subflows[i];
        let (end, deadline) = (dsn.wrapping_add(u64::from(len)), now + base_rto(t));
        let (target, ssn_end) = (t.id, t.mp.tx.assigned_end());
        self.hooks.debug.opp_bytes += u64::from(len);
        let una = self.hooks.data.as_ref().unwrap().send.una;
        if within(una, dsn, end) {
            let start = dsn;
            self.repair.pin = Some(Pin {
                target,
                start,
                end,
                ssn_end,
            });
        }
        if c.repair {
            self.repair.due = None;
            self.repair.probe = Some((target, ssn_end));
            self.hooks.debug.opp_repairs += 1;
            return;
        }
        if let Some(la) = &mut self.repair.lookahead {
            la.cursor = later(Some(la.cursor), end).unwrap();
        }
        if let Some(e) = &mut self.opp {
            // `end` only advances (§2.3): a lookahead may copy again below it.
            e.end = later(Some(e.end), end).unwrap();
            (e.deadline, e.ssn_end) = (deadline, ssn_end);
        } else {
            self.opp = Some(Episode {
                start: dsn,
                end,
                target,
                deadline,
                ssn_end,
                probed: false,
            });
            self.hooks.debug.opp_episodes += 1;
        }
        if let Some(s) = (self.subflows.iter()).position(|sf| Some(sf.id) == c.blocking) {
            self.head_blocked(s, now);
        }
    }

    /// `HealthEvent::HeadBlocked` for subflow `s`, unless fewer than two subflows are usable;
    /// a `Penalize` verdict applies at most once per `s`'s srtt and never in its loss recovery
    /// or RTO backoff (§2.5).
    pub(crate) fn head_blocked(&mut self, s: usize, now: Instant) {
        if self.subflows.iter().filter(|sf| usable(sf)).count() < 2 {
            return;
        }
        let ev = HealthEvent::HeadBlocked {
            subflow: self.subflows[s].id,
        };
        if self.hooks.scheduler.on_health(&ev, &self.hooks.snapshots) != HealthVerdict::Penalize {
            return;
        }
        let sf = &mut self.subflows[s];
        let srtt = sf.tcb.srtt().unwrap_or(INITIAL_RTO);
        if sf.mp.penalized_at.is_some_and(|at| now < at + srtt) || !sf.tcb.penalize(now) {
            return;
        }
        sf.mp.penalized_at = Some(now);
        self.hooks.debug.penalties += 1;
    }
}
