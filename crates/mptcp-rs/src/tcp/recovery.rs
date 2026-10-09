//! NewReno loss recovery on cumulative ACKs (RFC 6582, on RFC 5681 §3.2), for a connection
//! without SACK; `super::sack` (RFC 6675) is used when both SYNs carried SACK-Permitted. Both
//! are internal modules without a trait. The window arithmetic is the congestion controller's
//! (`CongestionControl::on_recovery_ack`).

use crate::seq::SeqNum;

/// What the `Tcb` does for a duplicate ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DupAck {
    /// Nothing (first and second, or below "recover").
    Ignore,
    /// Third: fast retransmit, `on_congestion(FastRetransmit)`.
    FastRetransmit,
    /// In fast recovery: `on_recovery_ack(Duplicate)`.
    Inflate,
}

/// What the `Tcb` does for an ACK that advances SND.UNA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NewAck {
    /// Not in fast recovery: `on_ack`.
    Normal,
    /// Retransmit the first unacknowledged segment; restart the RTO timer only if `first`.
    Partial { first: bool },
    /// Fast recovery is over.
    Full,
}

#[derive(Debug)]
pub(crate) struct NewReno {
    /// RFC 6582 "recover": the highest sequence number sent when fast retransmit was last
    /// entered or the retransmission timer last expired. `None` once SND.UNA has moved past it
    /// (no constraint); this keeps the modular comparison from going stale after 2^31 octets.
    recover: Option<SeqNum>,
    /// Duplicate ACKs since SND.UNA last moved.
    dupacks: u32,
    /// In fast recovery, and whether a partial ACK has arrived in it.
    in_recovery: bool,
    partial_seen: bool,
    /// Peer window (scaled) of the last incoming ACK, for RFC 5681 §2 condition (e).
    pub(crate) last_wnd: u32,
}

impl NewReno {
    /// RFC 6582 §3.2 step 1: recover = ISS, which no ACK can be below: no constraint.
    pub(crate) fn new(_iss: SeqNum) -> Self {
        Self {
            recover: None,
            dupacks: 0,
            in_recovery: false,
            partial_seen: false,
            last_wnd: 0,
        }
    }

    /// RFC 5681 §2: `abcd` is conditions (a)–(d); (e) compares `wnd` with the last ACK's
    /// window, which `wnd` then replaces. Call for every acceptable ACK, before SND.WND moves.
    pub(crate) fn is_duplicate(&mut self, abcd: bool, wnd: u32) -> bool {
        let same_wnd = std::mem::replace(&mut self.last_wnd, wnd) == wnd;
        abcd && same_wnd
    }

    /// A duplicate ACK of `ack` (= SND.UNA); `snd_max` is one past the highest sequence number
    /// sent. RFC 5681 §3.2 counts them "without any intervening ACKs which move SND.UNA".
    pub(crate) fn on_dup_ack(&mut self, ack: SeqNum, snd_max: SeqNum) -> DupAck {
        if self.in_recovery {
            return DupAck::Inflate;
        }
        self.dupacks += 1;
        // RFC 6582 §3.2 step 2: only if the ACK covers more than recover (ack − 1 > recover);
        // otherwise neither fast retransmit nor an ssthresh change.
        if self.dupacks != 3 || !self.passes_recover(ack.wrapping_add(u32::MAX)) {
            return DupAck::Ignore;
        }
        self.recover = Some(snd_max.wrapping_add(u32::MAX));
        self.in_recovery = true;
        self.partial_seen = false;
        DupAck::FastRetransmit
    }

    fn passes_recover(&self, seq: SeqNum) -> bool {
        self.recover.is_none_or(|r| seq.gt(r))
    }

    /// An ACK that moved SND.UNA to `ack` (RFC 6582 §3.2 step 3).
    pub(crate) fn on_new_ack(&mut self, ack: SeqNum) -> NewAck {
        self.dupacks = 0;
        let full = self.passes_recover(ack);
        if self.passes_recover(ack.wrapping_add(u32::MAX)) {
            self.recover = None;
        }
        if !self.in_recovery {
            NewAck::Normal
        } else if full {
            self.in_recovery = false;
            NewAck::Full
        } else {
            NewAck::Partial {
                first: !std::mem::replace(&mut self.partial_seen, true),
            }
        }
    }

    /// RFC 6582 §3.2 step 4 / §4: the retransmission timer expired.
    pub(crate) fn on_rto(&mut self, snd_max: SeqNum) {
        self.recover = Some(snd_max.wrapping_add(u32::MAX));
        self.in_recovery = false;
        self.dupacks = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "recover" must not go stale: after more than 2^31 octets without loss, three duplicate
    /// ACKs still trigger fast retransmit.
    #[test]
    fn recover_does_not_go_stale_after_2_pow_31() {
        let mut r = NewReno::new(SeqNum(0));
        r.on_rto(SeqNum(1000)); // recover = 999
        let mut ack = SeqNum(1000);
        for _ in 0..3 {
            ack = ack.wrapping_add(1 << 30);
            assert_eq!(r.on_new_ack(ack), NewAck::Normal);
        }
        let snd_max = ack.wrapping_add(5000);
        assert_eq!(r.on_dup_ack(ack, snd_max), DupAck::Ignore);
        assert_eq!(r.on_dup_ack(ack, snd_max), DupAck::Ignore);
        assert_eq!(r.on_dup_ack(ack, snd_max), DupAck::FastRetransmit);
    }
}
