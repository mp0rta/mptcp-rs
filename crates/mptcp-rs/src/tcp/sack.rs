//! SACK-based loss recovery (RFC 6675) on the SACK option (RFC 2018): the scoreboard and the
//! recovery variables. Used in place of `recovery::NewReno` on a connection (or subflow) whose
//! SYNs both carried SACK-Permitted; the `Tcb` owns the per-segment log and the CC.
//!
//! Sequence numbers here are absolute octet offsets (u64, ISS + 1 is 0), so nothing wraps; the
//! `Tcb` converts. Ranges are half-open: `[start, end)`.
//!
//! IsLost and pipe are not traversals of the sequence space (RFC 6675 §3 leaves the scoreboard
//! structure open): IsLost(s) is monotone in s, so it holds exactly below one point,
//! `lost_end`, found from the top of the scoreboard on every Update (at most DupThresh ranges);
//! SetPipe() is then a closed formula over counters kept on Update, cumulative ACK and
//! retransmission.

use std::ops::Range;

use rangemap::RangeSet;

/// RFC 6675 §2, RFC 5681 §3.2: DupThresh.
const DUP_THRESH: u32 = 3;
/// Disjoint SACKed ranges the scoreboard holds at most (`Sack::update`).
pub(crate) const MAX_SACK_RANGES: usize = 1024;

#[derive(Debug, Default)]
pub(crate) struct Sack {
    /// SACKed octets above SND.UNA, coalesced (the scoreboard, RFC 6675 §3).
    sacked: RangeSet<u64>,
    /// Octets in `sacked`.
    total: u64,
    /// IsLost(s) (RFC 6675 §4) holds exactly for s < `lost_end`.
    lost_end: u64,
    /// SACKed octets at or above `lost_end`.
    above_lost: u64,
    /// DupAcks (§2): ACKs carrying newly SACKed octets since the last cumulative ACK.
    dupacks: u32,
    /// In loss recovery: RecoveryPoint + 1 (HighData + 1 at entry, §5 (4.1)).
    recovery: Option<u64>,
    /// After an RTO, RecoveryPoint + 1: no new recovery until SND.UNA reaches it (§5.1).
    rto_point: Option<u64>,
    /// HighRxt + 1: one past the highest octet retransmitted in this recovery (§2).
    rxt_end: u64,
    /// SACKed octets below `rxt_end` (above SND.UNA).
    sacked_below_rxt: u64,
    /// RescueRxt + 1 (§2), once set in this recovery.
    rescue: Option<u64>,
    /// Octets of a rule (4) rescue retransmission: above HighRxt, so SetPipe's closed form
    /// misses them; charged to pipe (§5 (C.4)) until the next ACK's SetPipe (B.2).
    rescue_charge: u64,
}

/// What NextSeg() (RFC 6675 §4) asks to retransmit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rxt {
    pub(crate) start: u64,
    pub(crate) end: u64,
    /// Rule (4), the rescue retransmission: HighRxt is not updated.
    pub(crate) rescue: bool,
}

/// What a newly SACKing ACK means for loss recovery (§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DupAck {
    /// Not a duplicate ACK (§2), or already in recovery.
    None,
    /// Counted; below DupThresh and IsLost(HighACK + 1) false. Limited Transmit (§5 step 3,
    /// a MAY) is not done.
    Counted,
    /// Enter loss recovery (§5 step 4).
    Enter,
}

impl Sack {
    pub(crate) fn in_recovery(&self) -> bool {
        self.recovery.is_some()
    }

    /// IsLost(s) holds exactly for s < `lost_end()`.
    pub(crate) fn lost_end(&self) -> u64 {
        self.lost_end
    }

    #[cfg(test)]
    pub(crate) fn ranges(&self) -> usize {
        self.sacked.len()
    }

    /// Update() (§4) for the blocks of one ACK, each already clipped to [SND.UNA, SND.MAX),
    /// while the scoreboard holds fewer than `MAX_SACK_RANGES` ranges. `newly` is called for
    /// every octet range SACKed for the first time; returns how many octets those were.
    pub(crate) fn update(
        &mut self,
        una: u64,
        smss: u32,
        blocks: impl Iterator<Item = Range<u64>>,
        mut newly: impl FnMut(Range<u64>),
    ) -> u64 {
        // Every ACK runs Update first (`Tcb::sack_update`): its SetPipe drops the charge.
        self.rescue_charge = 0;
        let mut new = 0;
        for b in blocks {
            // ponytail: a full scoreboard ignores further blocks (as if their ACK were lost;
            // SACK is advisory, RFC 2018 §3) until cumulative ACKs drain it, so a receiver
            // SACKing every other octet cannot grow it past 1024 ranges; losses then fall to
            // the RTO. Raise the cap if a real path loses over 1024 segments in one window.
            if self.sacked.len() >= MAX_SACK_RANGES {
                break;
            }
            for g in self.sacked.gaps(&b) {
                new += g.end - g.start;
                self.sacked_below_rxt += overlap(&g, una, self.rxt_end);
                newly(g);
            }
            self.sacked.insert(b);
        }
        self.total += new;
        if new > 0 {
            self.find_lost_end(smss);
        }
        new
    }

    /// A cumulative ACK moved SND.UNA from `old` to `una` (§5: DupAcks is reset).
    pub(crate) fn ack(&mut self, old: u64, una: u64, smss: u32) {
        self.dupacks = 0;
        let gone = self.sacked_in(old, una);
        self.sacked.remove(old..una);
        self.total -= gone;
        if self.rxt_end <= una {
            self.rxt_end = una;
            self.sacked_below_rxt = 0;
        } else {
            self.sacked_below_rxt -= gone;
        }
        if gone > 0 {
            self.find_lost_end(smss);
        }
        if self.rto_point.is_some_and(|p| una >= p) {
            self.rto_point = None;
        }
    }

    /// An ACK that SACKed `new` octets (§2: a duplicate ACK if `new > 0` and `counts`, which
    /// is false for an ACK carrying non-DSS MPTCP signaling, RFC 8684 §3.3.5 / spec §3), after
    /// its cumulative part was processed: §5 steps (1), (2) and (4)'s trigger.
    pub(crate) fn on_dup_ack(&mut self, new: u64, counts: bool, una: u64) -> DupAck {
        if new == 0 || !counts || self.recovery.is_some() {
            return DupAck::None;
        }
        self.dupacks += 1;
        let may_enter = self.rto_point.is_none_or(|p| una >= p);
        if may_enter && (self.dupacks >= DUP_THRESH || una < self.lost_end) {
            DupAck::Enter
        } else {
            DupAck::Counted
        }
    }

    /// §5 (4.1): RecoveryPoint = HighData; HighRxt starts at HighACK, so the (4.3)
    /// retransmission at SND.UNA, recorded by `on_retransmit`, is the first one.
    pub(crate) fn enter(&mut self, una: u64, max: u64) {
        self.recovery = Some(max);
        self.rxt_end = una;
        self.sacked_below_rxt = 0;
        self.rescue = None;
    }

    /// §5 (A): a cumulative ACK beyond RecoveryPoint ends recovery; the scoreboard above
    /// SND.UNA is kept. True if this ACK ended it.
    pub(crate) fn exit_if_covered(&mut self, una: u64) -> bool {
        let done = self.recovery.is_some_and(|p| una >= p);
        if done {
            self.recovery = None;
        }
        done
    }

    /// RTO (§5.1): recovery ends, RecoveryPoint = HighData holds back the next one, and the
    /// SACK information is expunged (RFC 2018 §8 SHOULD: the receiver may have reneged).
    pub(crate) fn rto(&mut self, max: u64) {
        *self = Sack {
            rto_point: Some(max),
            ..Sack::default()
        };
    }

    /// (C.2) / (4.3): `[start, end)` was just retransmitted.
    pub(crate) fn on_retransmit(&mut self, start: u64, end: u64, rescue: bool) {
        let Some(point) = self.recovery else {
            return;
        };
        if rescue {
            // Rule (4): RescueRxt = RecoveryPoint; HighRxt is not updated.
            self.rescue = Some(point);
            self.rescue_charge = end - start;
            return;
        }
        // (4.3): the first retransmission also sets RescueRxt.
        if self.rescue.is_none() && start <= self.rxt_end {
            self.rescue = Some(end);
        }
        if end > self.rxt_end {
            self.sacked_below_rxt += self.sacked_in(self.rxt_end, end);
            self.rxt_end = end;
        }
    }

    /// SetPipe() (§4): un-SACKed octets in [`una`, `max`) not lost, plus those at or below
    /// HighRxt (so a retransmission of an octet not deemed lost counts twice), plus a rescue
    /// sent since the last ACK (§5 (C.4)).
    pub(crate) fn pipe(&self, una: u64, max: u64) -> u64 {
        let lost_end = self.lost_end.clamp(una, max);
        let sacked_below_lost = if self.lost_end > una {
            self.total - self.above_lost
        } else {
            0
        };
        let lost = (lost_end - una) - sacked_below_lost;
        let rxt_end = self.rxt_end.clamp(una, max);
        let rxt = (rxt_end - una) - self.sacked_below_rxt.min(rxt_end - una);
        (max - una) - self.total - lost + rxt + self.rescue_charge
    }

    /// NextSeg() (§4) during recovery, rules (1)–(4) of at most `smss` octets; `new_data` is
    /// rule (2)'s condition (unsent data the receiver's window allows), in which case `None`
    /// means "send new data" unless rule (1) applies.
    pub(crate) fn next_seg(&self, una: u64, max: u64, smss: u32, new_data: bool) -> Option<Rxt> {
        self.recovery?;
        let smss = u64::from(smss);
        let high = self.sacked.last().map_or(una, |r| r.end);
        // The smallest un-SACKed octet above HighRxt (1.a).
        let s2 = self.skip(self.rxt_end.max(una));
        if s2 < high {
            let end = (s2 + smss).min(self.next_start(s2)).min(max);
            // (1): below the highest SACKed octet (1.b) and lost (1.c); (3) the same without
            // (1.c), only if (2) has nothing to send.
            if s2 < self.lost_end || !new_data {
                return Some(Rxt {
                    start: s2,
                    end,
                    rescue: false,
                });
            }
            return None;
        }
        if new_data {
            return None;
        }
        // (4): one rescue retransmission per recovery, once HighACK > RescueRxt, of the
        // segment ending at the highest outstanding un-SACKed octet.
        if self.rescue.is_some_and(|r| una <= r) {
            return None;
        }
        let top = match self.sacked.last() {
            Some(r) if r.end >= max => r.start,
            _ => max,
        };
        let floor = self
            .sacked
            .overlapping(una..top)
            .next_back()
            .map_or(una, |r| r.end);
        (top > una).then(|| Rxt {
            start: top.saturating_sub(smss).max(floor),
            end: top,
            rescue: true,
        })
    }

    /// The end of the SACKed range holding `x`, or `x` (§5.1 "filling in" after an RTO).
    pub(crate) fn skip(&self, x: u64) -> u64 {
        self.sacked.get(&x).map_or(x, |r| r.end)
    }

    /// The start of the first SACKed range at or above the un-SACKed octet `x`.
    pub(crate) fn next_start(&self, x: u64) -> u64 {
        self.sacked
            .overlapping(x..u64::MAX)
            .next()
            .map_or(u64::MAX, |r| r.start.max(x))
    }

    /// SACKed octets in `[a, b)`.
    pub(crate) fn sacked_in(&self, a: u64, b: u64) -> u64 {
        if a >= b {
            return 0;
        }
        self.sacked
            .overlapping(a..b)
            .map(|r| r.end.min(b) - r.start.max(a))
            .sum()
    }

    /// IsLost(s) (§4) holds when DupThresh discontiguous SACKed sequences (taken as separate
    /// SACKed ranges) lie above s, or more than (DupThresh − 1)·SMSS SACKed octets do. Walking
    /// the ranges down from the highest finds the largest such boundary.
    fn find_lost_end(&mut self, smss: u32) {
        let limit = u64::from(DUP_THRESH - 1) * u64::from(smss);
        let mut bytes = 0;
        self.lost_end = 0;
        self.above_lost = 0;
        for (n, r) in self.sacked.iter().rev().enumerate() {
            let len = r.end - r.start;
            if bytes + len > limit {
                // The octets above s = end − need − 1 number exactly limit + 1.
                let need = limit + 1 - bytes;
                self.lost_end = r.end - need;
                self.above_lost = limit + 1;
                return;
            }
            bytes += len;
            if n + 1 >= DUP_THRESH as usize {
                self.lost_end = r.start;
                self.above_lost = bytes;
                return;
            }
        }
    }
}

/// Octets of `g` in `[a, b)`.
fn overlap(g: &Range<u64>, a: u64, b: u64) -> u64 {
    g.end.min(b).saturating_sub(g.start.max(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMSS: u32 = 1000;

    fn board(blocks: &[(u64, u64)]) -> Sack {
        let mut s = Sack::default();
        s.update(0, SMSS, blocks.iter().map(|&(a, b)| a..b), |_| {});
        s
    }

    /// IsLost: three SACKed ranges above, or more than 2·SMSS SACKed octets above.
    #[test]
    fn is_lost_by_ranges_or_bytes() {
        // One 2000-octet range above 0..1000: not lost (2000 is not more than 2·SMSS).
        let s = board(&[(1000, 3000)]);
        assert_eq!(s.lost_end, 0);
        // 2001 octets: the octet below the range is lost, the range start is not.
        let s = board(&[(1000, 3001)]);
        assert_eq!((s.lost_end, s.above_lost), (1000, 2001));
        // Three ranges of 100 octets: everything below the third from the top.
        let s = board(&[(1000, 1100), (2000, 2100), (3000, 3100)]);
        assert_eq!((s.lost_end, s.above_lost), (1000, 300));
        // Two small ranges: nothing is lost.
        assert_eq!(board(&[(2000, 2100), (3000, 3100)]).lost_end, 0);
        // A large top range decides inside itself.
        let s = board(&[(1000, 1100), (5000, 9000)]);
        assert_eq!((s.lost_end, s.above_lost), (6999, 2001));
    }

    /// pipe counts un-SACKed octets not lost, plus those below HighRxt once more.
    #[test]
    fn pipe_accounting() {
        // Holes 0..1000, 2000..3000, 4000..5000; SACKed 1000..2000, 3000..4000, 5000..8000.
        let mut s = board(&[(1000, 2000), (3000, 4000), (5000, 8000)]);
        // Lost below 5999 (2001 octets above): holes at 0 and 2000 and 4000..5000.
        assert_eq!(s.lost_end, 5999);
        assert_eq!(s.pipe(0, 10_000), 2000, "only 8000..10000 in the network");
        s.enter(0, 10_000);
        s.on_retransmit(0, 1000, false);
        assert_eq!(s.pipe(0, 10_000), 3000);
        assert_eq!(s.rescue, Some(1000), "(4.3) sets RescueRxt");
        // Next hole: 2000 (rule 1), skipping the SACKed 1000..2000.
        let r = s.next_seg(0, 10_000, SMSS, true).unwrap();
        assert_eq!((r.start, r.end, r.rescue), (2000, 3000, false));
        s.on_retransmit(2000, 3000, false);
        assert_eq!(s.sacked_below_rxt, 1000);
        assert_eq!(s.pipe(0, 10_000), 4000);
        // A cumulative ACK to 3000 removes the SACKed 1000..2000.
        s.ack(0, 3000, SMSS);
        assert_eq!((s.total, s.sacked_below_rxt, s.rxt_end), (4000, 0, 3000));
        assert_eq!(s.pipe(3000, 10_000), 2000);
        // The SACK of the retransmission's octets would leave the pipe again.
        s.update(3000, SMSS, std::iter::once(8000..9000), |_| {});
        assert_eq!(s.pipe(3000, 10_000), 1000);
    }

    /// NextSeg: rule 1 before new data, rule 3 only without new data, one rescue.
    #[test]
    fn next_seg_rule_order() {
        // Hole 0..1000 lost (3000 SACKed above), hole 4000..5000 not lost (1000 above).
        let mut s = board(&[(1000, 4000), (5000, 6000)]);
        assert_eq!(s.next_seg(0, 7000, SMSS, true), None, "not in recovery");
        s.enter(0, 7000);
        assert_eq!(
            s.next_seg(0, 7000, SMSS, true),
            Some(Rxt {
                start: 0,
                end: 1000,
                rescue: false
            }),
            "rule 1"
        );
        s.on_retransmit(0, 1000, false);
        // 4000 is not lost: new data first (rule 2), else rule 3.
        assert_eq!(s.next_seg(0, 7000, SMSS, true), None, "rule 2");
        let r = s.next_seg(0, 7000, SMSS, false).unwrap();
        assert_eq!((r.start, r.end, r.rescue), (4000, 5000, false), "rule 3");
        s.on_retransmit(4000, 5000, false);
        // Above the highest SACK: no rule 1 or 3; rescue needs HighACK > RescueRxt (1000).
        assert_eq!(s.next_seg(0, 7000, SMSS, false), None);
        s.ack(0, 4000, SMSS);
        let r = s.next_seg(4000, 7000, SMSS, false).unwrap();
        assert_eq!((r.start, r.end, r.rescue), (6000, 7000, true), "rule 4");
        assert_eq!(s.pipe(4000, 7000), 3000);
        s.on_retransmit(6000, 7000, true);
        assert_eq!(s.rxt_end, 5000, "rule 4 leaves HighRxt");
        // (C.4): the rescue counts in pipe until the next ACK's SetPipe (B.2) drops it.
        assert_eq!(s.pipe(4000, 7000), 4000, "rescue charged");
        s.update(4000, SMSS, std::iter::empty(), |_| {});
        assert_eq!(s.pipe(4000, 7000), 3000, "next ACK recomputes");
        assert_eq!(s.next_seg(4000, 7000, SMSS, false), None, "one rescue");
        // RecoveryPoint (7000) covered: recovery ends, nothing more.
        assert!(!s.exit_if_covered(6999));
        assert!(s.exit_if_covered(7000));
        assert_eq!(s.next_seg(7000, 7000, SMSS, false), None);
    }

    /// DupThresh newly SACKing ACKs, or IsLost(HighACK + 1) earlier; none after an RTO until
    /// SND.UNA reaches its RecoveryPoint.
    #[test]
    fn dup_thresh_and_rto_point() {
        let mut s = Sack::default();
        for (i, b) in [(1000, 1100), (1100, 1200)].into_iter().enumerate() {
            let new = s.update(0, SMSS, std::iter::once(b.0..b.1), |_| {});
            assert_eq!(s.on_dup_ack(new, true, 0), DupAck::Counted, "{i}");
        }
        assert_eq!(s.on_dup_ack(0, true, 0), DupAck::None, "nothing new SACKed");
        let new = s.update(0, SMSS, std::iter::once(1200..1300), |_| {});
        assert_eq!(s.on_dup_ack(new, false, 0), DupAck::None, "MPTCP signal");
        assert_eq!(s.on_dup_ack(new, true, 0), DupAck::Enter, "third");
        // One ACK SACKing more than 2·SMSS: IsLost(HighACK + 1) at once.
        let mut s = Sack::default();
        let new = s.update(0, SMSS, std::iter::once(1000..4000), |_| {});
        assert_eq!(s.on_dup_ack(new, true, 0), DupAck::Enter);
        // After an RTO at HighData 9000.
        s.rto(9000);
        assert_eq!(s.total, 0, "expunged");
        let new = s.update(0, SMSS, std::iter::once(1000..4000), |_| {});
        assert_eq!(s.on_dup_ack(new, true, 0), DupAck::Counted);
        s.ack(0, 9000, SMSS);
        let new = s.update(9000, SMSS, std::iter::once(10_000..13_000), |_| {});
        assert_eq!(s.on_dup_ack(new, true, 9000), DupAck::Enter);
    }
}
