//! Delivery-rate and loss accounting for BBR (draft-ietf-ccwg-bbr-06 §4.1; spec §1.1–§1.6)
//! over exact octet ranges. Independent of the RFC 6675 scoreboard (`sack.rs`) and of the
//! legacy `SentRecord`: the sampler never forgets a delivery.
//!
//! Offsets are absolute octets (u64), as in `sack.rs`. Ranges are half-open: `[start, end)`.
//! Each event visits only the stored ranges it overlaps (spec §1.9); an RTO visits them all.

use std::ops::Range;
use std::time::Duration;

use rangemap::RangeMap;

use super::cc::{Delivery, LossEvent, RateSample};
use crate::time::Instant;

/// The draft's per-packet (P) state of one transmission (spec §1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Snap {
    delivered: u64,
    delivered_time: Instant,
    first_send_time: Instant,
    send_time: Instant,
    tx_in_flight: u64,
    lost: u64,
    is_app_limited: bool,
    /// Unique per transmission, rising: IsNewestPacket's tie-break (P.packet_id).
    tx_order: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Sent, outcome unknown.
    Pending,
    Lost,
    /// Permanent: never changes back.
    Delivered,
}

/// The latest transmission of a range of octets (spec §1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tx {
    snap: Snap,
    state: State,
    /// Transmissions of these octets still charged to `inflight`.
    copies: u32,
    /// Some transmission of these octets was a resend (the SACK loss rule, Karn's rule).
    ever_resent: bool,
}

/// What the `Tcb` knows about an ACK that the sampler does not (spec §1.7, §1.8).
#[derive(Debug, Clone, Copy)]
pub(crate) struct SampleCtx {
    pub(crate) in_recovery: bool,
    pub(crate) recovery_exit: bool,
    pub(crate) cwnd_filled: bool,
}

#[derive(Debug)]
pub(crate) struct RateSampler {
    map: RangeMap<u64, Tx>,
    sack: bool,
    /// C.delivered: cumulative + SACK, each octet once.
    delivered: u64,
    delivered_time: Instant,
    first_send_time: Instant,
    lost: u64,
    /// Σ len × copies.
    inflight: u64,
    /// Octets `Lost` and not resent since.
    lost_out: u64,
    /// Lifetime minimum of `RateSample::rtt`.
    min_rtt: Option<Duration>,
    /// C.app_limited: 0, or the `delivered` value that ends the app-limited phase.
    app_limited: u64,
    /// The last transmission's `Snap::tx_order`.
    tx_order: u64,
    /// Queued loss events, each with its transmission's `tx_order` for merging.
    events: Vec<(u64, LossEvent)>,
    // Since `begin_ack`:
    /// The newest newly delivered transmission (the rate-sample packet).
    newest: Option<Snap>,
    /// The newest newly delivered transmission whose range was never resent (Karn).
    rtt_from: Option<Snap>,
    newly_acked: u64,
    newly_lost: u64,
    #[cfg(test)]
    visits: u64,
}

/// IsNewestPacket over the ACK's candidates: later send time, then later transmission.
fn newer(p: &Snap, than: Option<Snap>) -> bool {
    than.is_none_or(|o| (p.send_time, p.tx_order) > (o.send_time, o.tx_order))
}

fn len(r: &Range<u64>) -> u64 {
    r.end - r.start
}

impl RateSampler {
    /// `sack` is copied into every sample and loss event.
    pub(crate) fn new(now: Instant, sack: bool) -> Self {
        Self {
            map: RangeMap::new(),
            sack,
            delivered: 0,
            delivered_time: now,
            first_send_time: now,
            lost: 0,
            inflight: 0,
            lost_out: 0,
            min_rtt: None,
            app_limited: 0,
            tx_order: 0,
            events: Vec::new(),
            newest: None,
            rtt_from: None,
            newly_acked: 0,
            newly_lost: 0,
            #[cfg(test)]
            visits: 0,
        }
    }

    /// The stored pieces overlapping `r`, clipped to it.
    fn pieces(&mut self, r: &Range<u64>) -> Vec<(Range<u64>, Tx)> {
        let v: Vec<_> = self
            .map
            .overlapping(r)
            .map(|(k, x)| (k.start.max(r.start)..k.end.min(r.end), *x))
            .collect();
        #[cfg(test)]
        {
            self.visits += v.len() as u64;
        }
        v
    }

    /// A transmission of `r`, new or resent (draft OnPacketSent; spec §1.3 "send").
    pub(crate) fn on_send(&mut self, r: Range<u64>, now: Instant, resend: bool) {
        if r.is_empty() {
            return;
        }
        if self.inflight == 0 {
            self.first_send_time = now;
            self.delivered_time = now;
        }
        self.inflight += len(&r);
        self.tx_order += 1;
        let snap = Snap {
            delivered: self.delivered,
            delivered_time: self.delivered_time,
            first_send_time: self.first_send_time,
            send_time: now,
            // After this send's own charge.
            tx_in_flight: self.inflight,
            lost: self.lost,
            is_app_limited: self.app_limited != 0,
            tx_order: self.tx_order,
        };
        let gaps: Vec<_> = self.map.gaps(&r).collect();
        #[cfg(test)]
        {
            self.visits += gaps.len() as u64;
        }
        for (k, x) in self.pieces(&r) {
            let state = match x.state {
                State::Lost => {
                    self.lost_out -= len(&k);
                    State::Pending
                }
                s => s,
            };
            let tx = Tx {
                snap,
                state,
                copies: x.copies + 1,
                ever_resent: x.ever_resent || resend,
            };
            self.map.insert(k, tx);
        }
        let fresh = Tx {
            snap,
            state: State::Pending,
            copies: 1,
            ever_resent: resend,
        };
        for g in gaps {
            self.map.insert(g, fresh);
        }
    }

    /// `r` is acknowledged: a cumulative advance or a SACK gap (spec §1.3 "delivered").
    pub(crate) fn on_delivered(&mut self, r: Range<u64>, now: Instant) {
        if r.is_empty() {
            return;
        }
        for (k, x) in self.pieces(&r) {
            if x.state == State::Delivered && x.copies == 0 {
                continue;
            }
            self.inflight -= len(&k) * u64::from(x.copies);
            if x.state != State::Delivered {
                if x.state == State::Lost {
                    self.lost_out -= len(&k);
                }
                // Draft UpdateRateSample; C.lost is not reduced by a late delivery.
                self.delivered += len(&k);
                self.delivered_time = now;
                self.newly_acked += len(&k);
                if newer(&x.snap, self.newest) {
                    self.newest = Some(x.snap);
                    self.first_send_time = x.snap.send_time;
                }
                if !x.ever_resent && newer(&x.snap, self.rtt_from) {
                    self.rtt_from = Some(x.snap);
                }
            }
            let tx = Tx {
                state: State::Delivered,
                copies: 0,
                ..x
            };
            self.map.insert(k, tx);
        }
    }

    /// Declares the `Pending` octets of `r` lost (spec §1.4); with `never_resent_only`, only
    /// those whose transmission was never resent (the SACK rule).
    pub(crate) fn declare_lost(&mut self, r: Range<u64>, now: Instant, never_resent_only: bool) {
        if r.is_empty() {
            return;
        }
        for (k, x) in self.pieces(&r) {
            if x.state == State::Pending && !(never_resent_only && x.ever_resent) {
                self.newly_lost += len(&k);
                self.lose(k, x, now);
            }
        }
    }

    /// RTO: every `Pending` range is lost, and so is every copy of a `Delivered` range.
    pub(crate) fn on_rto(&mut self, now: Instant) {
        for (k, x) in self.pieces(&(0..u64::MAX)) {
            if x.state == State::Pending || (x.state == State::Delivered && x.copies > 0) {
                self.lose(k, x, now);
            }
        }
    }

    /// Spec §1.3 "declared lost" / "RTO" for one piece, and its loss event (spec §1.4).
    fn lose(&mut self, k: Range<u64>, x: Tx, now: Instant) {
        let n = len(&k);
        self.inflight -= n * u64::from(x.copies);
        // Before the event, so its lost_since_tx includes it.
        self.lost += n;
        let state = match x.state {
            State::Pending => {
                self.lost_out += n;
                State::Lost
            }
            // A Delivered copy: nothing awaits a first delivery, lost_out unchanged.
            s => s,
        };
        let ev = LossEvent {
            start: k.start,
            end: k.end,
            len: n,
            tx_in_flight: x.snap.tx_in_flight,
            lost_since_tx: self.lost - x.snap.lost,
            is_app_limited: x.snap.is_app_limited,
            delivered: self.delivered,
            sack: self.sack,
            now,
        };
        match self.events.last_mut() {
            // Adjacent pieces of one transmission are one event.
            Some((order, last)) if *order == x.snap.tx_order && last.end == k.start => {
                *last = LossEvent {
                    start: last.start,
                    len: ev.end - last.start,
                    ..ev
                };
            }
            _ => self.events.push((x.snap.tx_order, ev)),
        }
        let tx = Tx {
            state,
            copies: 0,
            ..x
        };
        self.map.insert(k, tx);
    }

    /// Forgets the ranges below SND.UNA that no copy is charged for.
    pub(crate) fn drop_below(&mut self, una: u64) {
        if una == 0 {
            return;
        }
        for (k, x) in self.pieces(&(0..una)) {
            if x.copies == 0 {
                self.map.remove(k);
            }
        }
    }

    /// The loss events queued since the last call, in the order declared.
    pub(crate) fn take_loss_events(&mut self) -> Vec<LossEvent> {
        self.events.drain(..).map(|(_, e)| e).collect()
    }

    /// Starts an ACK's accumulation (draft InitRateSample).
    pub(crate) fn begin_ack(&mut self) {
        self.newest = None;
        self.rtt_from = None;
        self.newly_acked = 0;
        self.newly_lost = 0;
    }

    /// The ACK's sample, from what happened since `begin_ack` (draft GenerateRateSample;
    /// spec §1.5).
    pub(crate) fn sample(&mut self, now: Instant, ctx: SampleCtx) -> RateSample {
        if self.app_limited != 0 && self.delivered > self.app_limited {
            self.app_limited = 0;
        }
        let rtt = self.rtt_from.map(|p| now - p.send_time);
        if let Some(r) = rtt {
            self.min_rtt = Some(self.min_rtt.map_or(r, |m| m.min(r)));
        }
        let delivery = self.newest.map(|p| {
            let delivered = self.delivered - p.delivered;
            let send_elapsed = p.send_time - p.first_send_time;
            let ack_elapsed = self.delivered_time - p.delivered_time;
            let interval = send_elapsed.max(ack_elapsed);
            // With no RTT sample yet, min_rtt is unbounded: no reliable rate.
            let rate = self
                .min_rtt
                .filter(|&m| interval >= m && !interval.is_zero())
                .map(|_| (delivered, interval));
            Delivery {
                prior_delivered: p.delivered,
                prior_time: p.delivered_time,
                delivered,
                newly_acked: self.newly_acked,
                is_app_limited: p.is_app_limited,
                tx_in_flight: p.tx_in_flight,
                lost: self.lost - p.lost,
                rate,
            }
        });
        RateSample {
            delivery,
            rtt,
            newly_lost: self.newly_lost,
            delivered: self.delivered,
            lost: self.lost,
            inflight: self.inflight,
            in_recovery: ctx.in_recovery,
            recovery_exit: ctx.recovery_exit,
            cwnd_filled: ctx.cwnd_filled,
            sack: self.sack,
            now,
        }
    }

    /// CheckIfApplicationLimited (spec §1.6). `pending_transmissions` is always 0 here.
    pub(crate) fn check_app_limited(&mut self, no_unsent: bool, cwnd_room: bool) {
        if no_unsent && cwnd_room && self.lost_out == 0 {
            self.force_app_limited();
        }
    }

    /// MarkConnectionAppLimited.
    pub(crate) fn force_app_limited(&mut self) {
        self.app_limited = (self.delivered + self.inflight).max(1);
    }

    pub(crate) fn inflight(&self) -> u64 {
        self.inflight
    }

    pub(crate) fn lost_out(&self) -> u64 {
        self.lost_out
    }

    pub(crate) fn delivered(&self) -> u64 {
        self.delivered
    }

    pub(crate) fn is_app_limited(&self) -> bool {
        self.app_limited != 0
    }

    pub(crate) fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt
    }

    /// Stored ranges touched since construction (spec §1.9).
    #[cfg(test)]
    fn visits(&self) -> u64 {
        self.visits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(ms: u64) -> Instant {
        Instant::from_nanos(ms * 1_000_000)
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn ctx() -> SampleCtx {
        SampleCtx {
            in_recovery: false,
            recovery_exit: false,
            cwnd_filled: false,
        }
    }

    fn sampler() -> RateSampler {
        RateSampler::new(t(0), true)
    }

    /// (inflight, delivered, lost, lost_out)
    fn counters(s: &RateSampler) -> (u64, u64, u64, u64) {
        (s.inflight(), s.delivered(), s.lost, s.lost_out())
    }

    /// The range entry holding octet `at`.
    fn tx(s: &RateSampler, at: u64) -> Tx {
        *s.map.get(&at).expect("octet tracked")
    }

    /// One ACK delivering `r` at `now`.
    fn ack(s: &mut RateSampler, r: Range<u64>, now: Instant) -> RateSample {
        s.begin_ack();
        s.on_delivered(r, now);
        s.sample(now, ctx())
    }

    // ---- §1.3 transition table ----

    #[test]
    fn send_new_pending() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        assert_eq!(counters(&s), (1000, 0, 0, 0));
        let x = tx(&s, 0);
        assert_eq!(x.state, State::Pending);
        assert_eq!(x.copies, 1);
        assert!(!x.ever_resent);
        assert_eq!(x.snap.tx_in_flight, 1000);
        assert_eq!(x.snap.send_time, t(0));
    }

    #[test]
    fn resend_pending_adds_copy() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.on_send(0..1000, t(10), true);
        assert_eq!(counters(&s), (2000, 0, 0, 0));
        let x = tx(&s, 0);
        assert_eq!(x.state, State::Pending);
        assert_eq!(x.copies, 2);
        assert!(x.ever_resent);
        assert_eq!(x.snap.send_time, t(10));
        assert_eq!(x.snap.tx_in_flight, 2000);
    }

    #[test]
    fn resend_lost_becomes_pending() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.declare_lost(0..1000, t(5), true);
        assert_eq!(counters(&s), (0, 0, 1000, 1000));
        s.on_send(0..1000, t(10), true);
        assert_eq!(counters(&s), (1000, 0, 1000, 0));
        let x = tx(&s, 0);
        assert_eq!(x.state, State::Pending);
        assert_eq!(x.copies, 1);
        assert_eq!(x.snap.lost, 1000);
        assert_eq!(x.snap.tx_in_flight, 1000);
    }

    #[test]
    fn resend_delivered_stays_delivered() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        ack(&mut s, 0..1000, t(10));
        s.on_send(0..1000, t(20), true);
        assert_eq!(counters(&s), (1000, 1000, 0, 0));
        let x = tx(&s, 0);
        assert_eq!(x.state, State::Delivered);
        assert_eq!(x.copies, 1);
        assert_eq!(x.snap.send_time, t(20));
        // Its delivery is never counted again.
        let rs = ack(&mut s, 0..1000, t(30));
        assert_eq!(counters(&s), (0, 1000, 0, 0));
        assert_eq!(rs.delivery, None);
    }

    #[test]
    fn deliver_pending() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        let rs = ack(&mut s, 0..1000, t(10));
        assert_eq!(counters(&s), (0, 1000, 0, 0));
        let x = tx(&s, 0);
        assert_eq!(x.state, State::Delivered);
        assert_eq!(x.copies, 0);
        assert_eq!(rs.delivery.expect("delivered").newly_acked, 1000);
        s.drop_below(1000);
        assert!(s.map.is_empty());
        assert_eq!(counters(&s), (0, 1000, 0, 0));
    }

    #[test]
    fn deliver_lost_late_sack() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.declare_lost(0..1000, t(5), true);
        let rs = ack(&mut s, 0..1000, t(10));
        assert_eq!(counters(&s), (0, 1000, 1000, 0));
        assert_eq!(tx(&s, 0).state, State::Delivered);
        assert_eq!(rs.delivery.expect("delivered").newly_acked, 1000);
    }

    #[test]
    fn deliver_delivered_retires_copies() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        ack(&mut s, 0..1000, t(10));
        s.on_send(0..1000, t(20), true);
        s.on_send(0..1000, t(30), true);
        assert_eq!(counters(&s), (2000, 1000, 0, 0));
        let rs = ack(&mut s, 0..1000, t(40));
        assert_eq!(counters(&s), (0, 1000, 0, 0));
        assert_eq!(tx(&s, 0).copies, 0);
        assert_eq!(rs.delivery, None);
        assert_eq!(rs.rtt, None);
    }

    #[test]
    fn declare_lost_pending() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.on_send(0..1000, t(1), true);
        s.declare_lost(0..1000, t(5), false);
        assert_eq!(counters(&s), (0, 0, 1000, 1000));
        let x = tx(&s, 0);
        assert_eq!(x.state, State::Lost);
        assert_eq!(x.copies, 0);
        assert_eq!(s.take_loss_events().len(), 1);
        // Lost and Delivered ranges are not declared again.
        s.declare_lost(0..1000, t(6), false);
        assert_eq!(counters(&s), (0, 0, 1000, 1000));
        assert!(s.take_loss_events().is_empty());
    }

    #[test]
    fn rto_pending_and_delivered_copy() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.on_send(1000..2000, t(0), false);
        s.on_send(2000..3000, t(0), false);
        ack(&mut s, 1000..2000, t(10));
        s.declare_lost(2000..3000, t(11), false);
        s.take_loss_events();
        s.on_send(1000..2000, t(12), true);
        assert_eq!(counters(&s), (2000, 1000, 1000, 1000));
        s.on_rto(t(20));
        // Pending → Lost; the Delivered copy is lost without touching lost_out; Lost untouched.
        assert_eq!(counters(&s), (0, 1000, 3000, 2000));
        assert_eq!(tx(&s, 0).state, State::Lost);
        let b = tx(&s, 1000);
        assert_eq!((b.state, b.copies), (State::Delivered, 0));
        let ev = s.take_loss_events();
        assert_eq!(
            ev.iter().map(|e| e.start..e.end).collect::<Vec<_>>(),
            [0..1000, 1000..2000]
        );
    }

    // ---- §1.4, §1.5 sampling and loss events ----

    #[test]
    fn sack_only_ack_samples() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.on_send(1000..2000, t(1), false);
        let rs = ack(&mut s, 1000..2000, t(50));
        let d = rs.delivery.expect("SACK delivery samples");
        assert_eq!(d.newly_acked, 1000);
        assert_eq!(d.delivered, 1000);
        assert_eq!(rs.rtt, Some(ms(49)));
        assert_eq!((rs.delivered, rs.inflight, rs.sack), (1000, 1000, true));
    }

    #[test]
    fn mixed_ack_rtt_from_original() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.on_send(1000..2000, t(1), false);
        s.declare_lost(0..1000, t(20), false);
        s.on_send(0..1000, t(20), true);
        let rs = ack(&mut s, 0..2000, t(60));
        // RTT from the never-resent original, sent at 1 ms.
        assert_eq!(rs.rtt, Some(ms(59)));
        // Delivery from the newest transmission, the resend (P.lost = 1000, so RS.lost = 0).
        let d = rs.delivery.expect("delivered");
        assert_eq!(d.lost, 0);
        assert_eq!(d.newly_acked, 2000);
        assert_eq!(d.delivered, 2000);
        assert_eq!(d.tx_in_flight, 2000);
        assert_eq!(s.first_send_time, t(20));
    }

    #[test]
    fn all_resent_no_rtt() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.on_send(0..1000, t(10), true);
        let rs = ack(&mut s, 0..1000, t(30));
        assert_eq!(rs.rtt, None);
        assert_eq!(rs.delivery.expect("delivered").newly_acked, 1000);
        assert_eq!(s.min_rtt(), None);
    }

    #[test]
    fn rate_invalid_below_min_rtt() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        let rs = ack(&mut s, 0..1000, t(100));
        assert_eq!(s.min_rtt(), Some(ms(100)));
        assert_eq!(rs.delivery.expect("delivered").rate, Some((1000, ms(100))));
        // Sent from idle at 100 ms, resent at 120 ms, ACKed at 150 ms: interval 50 < 100.
        s.on_send(1000..2000, t(100), false);
        s.on_send(1000..2000, t(120), true);
        let rs = ack(&mut s, 1000..2000, t(150));
        assert_eq!(rs.rtt, None);
        let d = rs.delivery.expect("delivered");
        assert_eq!(d.rate, None);
        assert_eq!(d.delivered, 1000);
    }

    #[test]
    fn loss_only_sample_has_no_delivery() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.begin_ack();
        s.declare_lost(0..1000, t(10), true);
        let rs = s.sample(t(10), ctx());
        assert_eq!(rs.delivery, None);
        assert_eq!(rs.rtt, None);
        assert_eq!((rs.newly_lost, rs.lost, rs.inflight), (1000, 1000, 0));
    }

    #[test]
    fn send_time_loss_not_in_next_ack() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.on_send(1000..2000, t(0), false);
        s.declare_lost(0..1000, t(10), false);
        let rs = ack(&mut s, 1000..2000, t(50));
        assert_eq!(rs.newly_lost, 0);
        assert_eq!(rs.lost, 1000);
        assert!(rs.delivery.is_some());
    }

    #[test]
    fn loss_events_merge_per_transmission() {
        let span = |ev: Vec<LossEvent>| ev.iter().map(|e| e.start..e.end).collect::<Vec<_>>();
        // One transmission, a SACKed hole in the middle: two events.
        let mut s = sampler();
        s.on_send(0..3000, t(0), false);
        ack(&mut s, 1000..2000, t(10));
        s.declare_lost(0..3000, t(10), true);
        assert_eq!(span(s.take_loss_events()), [0..1000, 2000..3000]);
        // One transmission lost in two adjacent pieces: one event.
        let mut s = sampler();
        s.on_send(0..2000, t(0), false);
        s.declare_lost(0..1000, t(10), true);
        s.declare_lost(1000..2000, t(10), true);
        let ev = s.take_loss_events();
        assert_eq!(ev.len(), 1);
        assert_eq!((ev[0].start, ev[0].end, ev[0].len), (0, 2000, 2000));
        assert_eq!(ev[0].lost_since_tx, 2000);
        // Two adjacent transmissions: two events.
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.on_send(1000..2000, t(0), false);
        s.declare_lost(0..2000, t(10), true);
        assert_eq!(span(s.take_loss_events()), [0..1000, 1000..2000]);
    }

    #[test]
    fn loss_event_lost_since_tx_includes_itself() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.on_send(1000..2000, t(1), false);
        s.declare_lost(0..1000, t(10), true);
        s.declare_lost(1000..2000, t(11), true);
        let ev = s.take_loss_events();
        assert_eq!(ev.len(), 2);
        assert_eq!((ev[0].lost_since_tx, ev[0].tx_in_flight), (1000, 1000));
        assert_eq!((ev[1].lost_since_tx, ev[1].tx_in_flight), (2000, 2000));
        assert_eq!((ev[1].len, ev[1].delivered, ev[1].now), (1000, 0, t(11)));
        assert!(ev[1].sack);
        assert!(s.take_loss_events().is_empty());
    }

    #[test]
    fn never_resent_only_skips_resent() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.on_send(1000..2000, t(0), false);
        s.on_send(0..1000, t(5), true);
        s.declare_lost(0..2000, t(10), true);
        assert_eq!(tx(&s, 0).state, State::Pending);
        assert_eq!(tx(&s, 0).copies, 2);
        assert_eq!(tx(&s, 1000).state, State::Lost);
        assert_eq!(counters(&s), (2000, 0, 1000, 1000));
        s.declare_lost(0..2000, t(10), false);
        assert_eq!(tx(&s, 0).state, State::Lost);
        assert_eq!(counters(&s), (0, 0, 2000, 2000));
    }

    #[test]
    fn rto_after_go_back_reports_copy_loss() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.on_send(1000..2000, t(0), false);
        ack(&mut s, 1000..2000, t(10));
        s.declare_lost(0..1000, t(10), true);
        s.take_loss_events();
        s.on_send(1000..2000, t(15), true);
        assert_eq!(counters(&s), (1000, 1000, 1000, 1000));
        s.on_rto(t(20));
        let ev = s.take_loss_events();
        assert_eq!(ev.len(), 1);
        let e = ev[0];
        assert_eq!((e.start, e.end, e.len), (1000, 2000, 1000));
        // The copy's own snapshot: P.tx_in_flight 1000 and P.lost 1000.
        assert_eq!((e.tx_in_flight, e.lost_since_tx), (1000, 1000));
        assert_eq!(counters(&s), (0, 1000, 2000, 1000));
    }

    #[test]
    fn app_limited_needs_lost_out_zero() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.declare_lost(0..1000, t(5), true);
        s.check_app_limited(true, true);
        assert!(!s.is_app_limited());
        s.on_send(0..1000, t(6), true);
        s.check_app_limited(false, true);
        s.check_app_limited(true, false);
        assert!(!s.is_app_limited());
        s.check_app_limited(true, true);
        assert!(s.is_app_limited());
        assert_eq!(s.app_limited, 1000);
    }

    #[test]
    fn app_limited_clears_on_sack_delivery() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.on_send(1000..2000, t(0), false);
        s.check_app_limited(true, true);
        assert_eq!(s.app_limited, 2000);
        s.on_send(2000..3000, t(1), false);
        s.on_send(3000..4000, t(1), false);
        assert!(tx(&s, 3000).snap.is_app_limited);
        // Delivered reaches 2000, not past it.
        ack(&mut s, 1000..3000, t(10));
        assert!(s.is_app_limited());
        // SACK-only (0..1000 still outstanding): delivered 3000 > 2000 clears it.
        let rs = ack(&mut s, 3000..4000, t(11));
        assert!(!s.is_app_limited());
        assert!(rs.delivery.expect("delivered").is_app_limited);
    }

    #[test]
    fn force_app_limited_ignores_predicate() {
        let mut s = sampler();
        s.on_send(0..1000, t(0), false);
        s.declare_lost(0..1000, t(5), true);
        s.force_app_limited();
        assert!(s.is_app_limited());
        assert_eq!(s.app_limited, 1);
    }

    // ---- §1.9 cost ----

    #[test]
    fn first_hole_work_is_linear() {
        const N: u64 = 10_000;
        let mut s = sampler();
        for i in 0..N {
            s.on_send(i * 1000..(i + 1) * 1000, t(i / 100), false);
        }
        for i in 1..N {
            let rs = ack(&mut s, i * 1000..(i + 1) * 1000, t(200 + i / 100));
            assert!(rs.delivery.is_some());
        }
        assert_eq!(counters(&s), (1000, (N - 1) * 1000, 0, 0));
        assert!(s.visits() <= 8 * N, "visits {}", s.visits());
    }
}
