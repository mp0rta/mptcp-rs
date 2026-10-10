//! Pending MPTCP signals and their ACK-only options (M3 spec §3.2): MP_PRIO per subflow,
//! ADD_ADDR echoes and REMOVE_ADDR ids per connection, and the per-subflow rate limit on
//! signal-only ACKs.
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use super::SubflowId;
use crate::tcp::AckPurpose;
use crate::time::Instant;
use crate::wire::mptcp::{self, MptcpOption, RemoveIds};

/// An ADD_ADDR echo: the announcement's id, address and port, as received.
// Queued by ADD_ADDR receive (M3 Task 9).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Echo {
    pub id: u8,
    pub addr: IpAddr,
    pub port: Option<u16>,
}

/// Distinct ADD_ADDR echoes that may wait (M3 spec §3.2).
const MAX_ECHOES: usize = 8;

/// What one `peek_ack_options` wrote, for `commit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Take {
    s: SubflowId,
    prio: bool,
    echo: bool,
    /// The first REMOVE_ADDR ids, in order.
    removes: usize,
    signal_only: bool,
}

/// The signal-only ACKs of one subflow: the last two, older first, and the wakeup for a signal
/// they hold back.
struct Limit {
    s: SubflowId,
    sent: [Option<Instant>; 2],
    wake: Option<Instant>,
}

#[derive(Default)]
pub(crate) struct Signals {
    /// At most one per subflow: the latest `set_backup` value.
    prio: Vec<(SubflowId, bool)>,
    /// In arrival order, distinct.
    echoes: Vec<Echo>,
    removes: BTreeSet<u8>,
    limits: Vec<Limit>,
    /// Set by `Connection::select_control`: the subflow that carries echoes ...
    pub echo_carrier: Option<SubflowId>,
    /// ... and the one that carries REMOVE_ADDR.
    pub remove_carrier: Option<SubflowId>,
}

impl Signals {
    /// Every call leaves one MP_PRIO for `s` with this value, whatever was sent before.
    pub fn prio(&mut self, s: SubflowId, backup: bool) {
        match self.prio.iter_mut().find(|p| p.0 == s) {
            Some(p) => p.1 = backup,
            None => self.prio.push((s, backup)),
        }
    }
    /// Queues an echo; false when 8 distinct echoes already wait. A duplicate is not queued twice.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn echo(&mut self, e: Echo) -> bool {
        if !self.echoes.contains(&e) {
            if self.echoes.len() == MAX_ECHOES {
                return false;
            }
            self.echoes.push(e);
        }
        true
    }
    // REMOVE_ADDR send (M3 Task 8).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn remove(&mut self, id: u8) {
        self.removes.insert(id);
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn cancel_remove(&mut self, id: u8) {
        self.removes.remove(&id);
    }
    /// `id` waits in a REMOVE_ADDR: no subflow using it carries one.
    pub fn removing(&self, id: u8) -> bool {
        self.removes.contains(&id)
    }

    fn pending(&self, s: SubflowId) -> bool {
        self.prio.iter().any(|p| p.0 == s)
            || (self.echo_carrier == Some(s) && !self.echoes.is_empty())
            || (self.remove_carrier == Some(s) && !self.removes.is_empty())
    }
    /// When `s` may send its next signal-only ACK: one srtt after the older of its last two.
    fn free_at(&self, s: SubflowId, srtt: Duration) -> Option<Instant> {
        let l = self.limits.iter().find(|l| l.s == s)?;
        l.sent[0].map(|t| t + srtt)
    }
    /// A signal-only ACK on `s` (which `can_send` now) is due: a signal waits for it and the
    /// rate limit allows it. A limited one sets the wakeup; anything else clears it.
    pub fn wants(&mut self, s: SubflowId, now: Instant, srtt: Duration, can_send: bool) -> bool {
        let has = can_send && self.pending(s);
        let held = self.free_at(s, srtt).filter(|&t| t > now);
        if let Some(l) = self.limits.iter_mut().find(|l| l.s == s) {
            l.wake = held.filter(|_| has);
        }
        has && held.is_none()
    }
    pub fn next_wake(&self) -> Option<Instant> {
        self.limits.iter().filter_map(|l| l.wake).min()
    }
    /// Subflow `s` is gone.
    pub fn forget(&mut self, s: SubflowId) {
        self.prio.retain(|p| p.0 != s);
        self.limits.retain(|l| l.s != s);
    }

    /// The signals for an ACK-only segment on `s`, after the forms before them (M3 spec §3.2):
    /// its MP_PRIO, then one echo and then the REMOVE_ADDR ids that fit, if `s` carries them.
    /// Each item is written whole or left waiting; the total is NOP-padded within `room`. A
    /// signal-only ACK gets nothing while the rate limit holds `s` back. Side effect free.
    #[allow(clippy::too_many_arguments)]
    pub fn peek_ack_options(
        &self,
        s: SubflowId,
        purpose: AckPurpose,
        now: Instant,
        srtt: Duration,
        room: usize,
        out: &mut [u8],
    ) -> (usize, Take) {
        let signal_only = purpose == AckPurpose::SignalOnly;
        let mut take = Take {
            s,
            prio: false,
            echo: false,
            removes: 0,
            signal_only,
        };
        if signal_only && self.free_at(s, srtt).is_some_and(|t| now < t) {
            return (0, take);
        }
        let room = room.min(out.len());
        let mut n = 0;
        // Writes `o` whole after the octets already written, or nothing.
        let mut put = |o: MptcpOption, n: &mut usize| {
            let k = mptcp::encode(&o, &mut out[*n..room]).ok();
            *n += k.unwrap_or(0);
            k.is_some()
        };
        if let Some(&(_, backup)) = self.prio.iter().find(|p| p.0 == s) {
            take.prio = put(MptcpOption::Prio { backup }, &mut n);
        }
        if let Some(e) = self.echoes.first().filter(|_| self.echo_carrier == Some(s)) {
            let echo = MptcpOption::AddAddr {
                echo: true,
                id: e.id,
                addr: e.addr,
                port: e.port,
                hmac: None,
            };
            take.echo = put(echo, &mut n);
        }
        if self.remove_carrier == Some(s) {
            let ids: Vec<u8> = self.removes.iter().copied().collect();
            // At most 25 next to DSS12 (12 + 3 + 25 = 40).
            let k = ids.len().min((room - n).saturating_sub(3));
            if let Some(ids) = RemoveIds::new(&ids[..k]) {
                take.removes = ids.len();
                put(MptcpOption::RemoveAddr { ids }, &mut n);
            }
        }
        if n == 0 {
            return (0, take);
        }
        let padded = n.next_multiple_of(4).min(room);
        out[n..padded].fill(1);
        (padded, take)
    }
    /// The ACK `take` came from went out: its signals are consumed, and a signal-only ACK is
    /// charged to its subflow's rate limit.
    pub fn commit(&mut self, take: Take, now: Instant) {
        if take.prio {
            self.prio.retain(|p| p.0 != take.s);
        }
        if take.echo {
            self.echoes.remove(0);
        }
        for _ in 0..take.removes {
            self.removes.pop_first();
        }
        if take.signal_only && (take.prio || take.echo || take.removes > 0) {
            let l = match self.limits.iter().position(|l| l.s == take.s) {
                Some(i) => &mut self.limits[i],
                None => {
                    self.limits.push(Limit {
                        s: take.s,
                        sent: [None; 2],
                        wake: None,
                    });
                    self.limits.last_mut().unwrap()
                }
            };
            l.sent = [l.sent[1], Some(now)];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::tcp_options::{TcpOpt, walk};

    const S: SubflowId = SubflowId(1);
    const SRTT: Duration = Duration::from_millis(100);
    fn ms(n: u64) -> Instant {
        Instant::from_nanos(n * 1_000_000)
    }
    fn v6_echo(id: u8) -> Echo {
        Echo {
            id,
            addr: "dead:beef::2".parse().unwrap(),
            port: Some(5201),
        }
    }
    /// `peek_ack_options` into a 40-octet buffer: the options written (parsed), their padded
    /// length and the take.
    fn peek(
        sig: &Signals,
        purpose: AckPurpose,
        now: Instant,
        room: usize,
    ) -> (Vec<MptcpOption>, usize, Take) {
        let mut out = [0; 40];
        let (n, take) = sig.peek_ack_options(S, purpose, now, SRTT, room, &mut out[..room]);
        assert!(n <= room);
        let opts = walk(&out[..n])
            .map(|o| match o {
                Ok(TcpOpt::Mptcp(raw)) => mptcp::parse(raw).unwrap(),
                o => panic!("not MPTCP: {o:?}"),
            })
            .collect();
        (opts, n, take)
    }
    fn carrier() -> Signals {
        Signals {
            echo_carrier: Some(S),
            remove_carrier: Some(S),
            ..Signals::default()
        }
    }

    #[test]
    fn signal_not_fitting_is_deferred() {
        let mut sig = carrier();
        assert!(sig.echo(v6_echo(3)));
        let e = v6_echo(3);
        let want = MptcpOption::AddAddr {
            echo: true,
            id: e.id,
            addr: e.addr,
            port: e.port,
            hmac: None,
        };
        // 21 octets of room: nothing is written, and an empty take consumes nothing.
        let (opts, n, take) = peek(&sig, AckPurpose::Ordinary, ms(0), 21);
        assert_eq!((opts, n), (vec![], 0));
        sig.commit(take, ms(0));
        // 22 octets: written intact, unpadded; 24: padded with one NOP pair.
        let (opts, n, _) = peek(&sig, AckPurpose::Ordinary, ms(0), 22);
        assert_eq!((opts, n), (vec![want], 22));
        let (opts, n, take) = peek(&sig, AckPurpose::Ordinary, ms(0), 24);
        assert_eq!((opts, n), (vec![want], 24));
        // Peeking is side effect free; only the commit consumes.
        sig.commit(take, ms(0));
        assert_eq!(peek(&sig, AckPurpose::Ordinary, ms(0), 40).1, 0);
    }

    #[test]
    fn prio_latest_value_once_per_subflow() {
        let mut sig = Signals::default();
        sig.prio(S, true);
        sig.prio(S, false);
        sig.prio(SubflowId(2), true);
        let (opts, n, take) = peek(&sig, AckPurpose::Ordinary, ms(0), 28);
        assert_eq!((opts, n), (vec![MptcpOption::Prio { backup: false }], 4));
        sig.commit(take, ms(0));
        assert_eq!(peek(&sig, AckPurpose::Ordinary, ms(0), 28).1, 0);
        // Not this subflow's item, and the echo and REMOVE_ADDR need their carrier.
        sig.remove(4);
        assert!(sig.echo(v6_echo(1)));
        assert_eq!(peek(&sig, AckPurpose::Ordinary, ms(0), 28).1, 0);
    }

    #[test]
    fn echo_queue_coalesces_and_is_bounded() {
        let mut sig = carrier();
        for id in 0..8 {
            assert!(sig.echo(v6_echo(id)));
            assert!(sig.echo(v6_echo(id)), "a duplicate is not queued twice");
        }
        assert!(!sig.echo(v6_echo(8)), "a ninth distinct echo is refused");
        // One ADD_ADDR per segment, in arrival order.
        for id in 0..8 {
            let (opts, _, take) = peek(&sig, AckPurpose::Ordinary, ms(0), 40);
            assert!(matches!(opts[..], [MptcpOption::AddAddr { id: i, .. }] if i == id));
            sig.commit(take, ms(0));
        }
        assert!(sig.echo(v6_echo(8)));
    }

    #[test]
    fn remove_prefix_fits_room_and_cancel() {
        let mut sig = carrier();
        for id in 0..26 {
            sig.remove(id);
        }
        sig.remove(30);
        sig.cancel_remove(30);
        // Next to DSS12: 28 octets, 25 ids.
        let (opts, n, take) = peek(&sig, AckPurpose::Ordinary, ms(0), 28);
        let MptcpOption::RemoveAddr { ids } = opts[0] else {
            panic!("{opts:?}")
        };
        assert_eq!((n, ids.iter().collect::<Vec<_>>()), (28, (0..25).collect()));
        sig.commit(take, ms(0));
        let (opts, n, take) = peek(&sig, AckPurpose::Ordinary, ms(0), 28);
        let MptcpOption::RemoveAddr { ids } = opts[0] else {
            panic!("{opts:?}")
        };
        assert_eq!((n, ids.iter().collect::<Vec<_>>()), (4, vec![25]));
        sig.commit(take, ms(0));
        assert_eq!(peek(&sig, AckPurpose::Ordinary, ms(0), 28).1, 0);
    }

    #[test]
    fn signal_only_limited_to_two_per_srtt() {
        let mut sig = Signals::default();
        let only = AckPurpose::SignalOnly;
        for t in [0, 10] {
            sig.prio(S, true);
            assert!(sig.wants(S, ms(t), SRTT, true));
            let (_, n, take) = peek(&sig, only, ms(t), 28);
            assert_eq!(n, 4);
            sig.commit(take, ms(t));
        }
        sig.prio(S, false);
        assert!(!sig.wants(S, ms(20), SRTT, true));
        assert_eq!(sig.next_wake(), Some(ms(100)), "first + srtt");
        assert_eq!(
            peek(&sig, only, ms(99), 28).1,
            0,
            "a signal-only peek waits too"
        );
        // An ordinary ACK carries it regardless, uncharged.
        let (_, n, take) = peek(&sig, AckPurpose::Ordinary, ms(20), 28);
        assert_eq!(n, 4);
        sig.commit(take, ms(20));
        sig.prio(S, true);
        assert!(!sig.wants(S, ms(99), SRTT, true));
        assert!(sig.wants(S, ms(100), SRTT, true));
        assert_eq!(sig.next_wake(), None);
        // Charged at 100: the next one waits for 10 + srtt; a subflow that cannot send has no
        // wakeup.
        sig.commit(peek(&sig, only, ms(100), 28).2, ms(100));
        sig.prio(S, false);
        assert!(!sig.wants(S, ms(101), SRTT, true));
        assert_eq!(sig.next_wake(), Some(ms(110)));
        assert!(!sig.wants(S, ms(101), SRTT, false));
        assert_eq!(sig.next_wake(), None);
        sig.forget(S);
        assert!(!sig.wants(S, ms(101), SRTT, true), "forgotten");
    }
}
