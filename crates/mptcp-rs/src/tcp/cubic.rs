//! CUBIC (RFC 9438) with HyStart++ (RFC 9406) as its initial slow start; fast recovery keeps
//! the NewReno window rules (RFC 9438 §4.2: CUBIC "does not make any changes to the TCP Fast
//! Recovery and Fast Retransmit algorithms").
//!
//! Windows are in octets; RFC 9438 states them in segments, so W_cubic carries a factor SMSS
//! and `segments_acked` becomes acked / SMSS (§4.1).

use std::time::Duration;

use super::cc::{
    AckSample, CongestionControl, CongestionEvent, RecoveryAck, initial_window, recovery_window,
};
use crate::time::Instant;

/// RFC 9438 §5.1: C = 0.4 segments / s³.
const C: f64 = 0.4;
/// §4.6: β_cubic = 0.7, as a ratio so that ssthresh is integer arithmetic.
const BETA: (u64, u64) = (7, 10);
/// §4.3: α_cubic = 3·(1 − β_cubic)/(1 + β_cubic).
const ALPHA: f64 = 3.0 * (1.0 - 0.7) / (1.0 + 0.7);

/// CUBIC (RFC 9438 §4); HyStart++ runs its initial slow start (§4.10).
#[derive(Debug)]
pub(crate) struct Cubic {
    smss: u32,
    /// The initial window, from `init`; the restart window of RFC 5681 §4.1 is min(iw, cwnd).
    iw: u32,
    /// Octets; congestion avoidance grows it by fractions.
    cwnd: f64,
    ssthresh: u32,
    /// §4.1.2 cwnd_prior.
    cwnd_prior: f64,
    /// §4.1.2 W_max.
    w_max: f64,
    /// The next congestion avoidance stage takes W_max = cwnd_epoch (so K = 0): after an RTO
    /// (§4.8) or a HyStart++ exit without loss (§4.10).
    plan_from_start: bool,
    /// The current congestion avoidance stage, from its first ACK.
    epoch: Option<Epoch>,
    /// The RTT of target = W_cubic(t + RTT) (§4.2), smoothed per RFC 6298 §2 (α = 1/8).
    srtt: Option<Duration>,
    /// HyStart++, for the initial slow start only (RFC 9406 §4.3 SHOULD); `None` once it is
    /// over, or to run RFC 5681 slow start throughout.
    hystart: Option<HyStart>,
}

#[derive(Debug, Clone, Copy)]
struct Epoch {
    /// t_epoch, moved later by every app-limited period so that t excludes it (§4.2).
    start: Instant,
    /// The stage's last ACK.
    last: Instant,
    /// K, in seconds (Fig. 2).
    k: f64,
    /// W_est (§4.3).
    w_est: f64,
}

impl Cubic {
    pub(crate) fn new() -> Self {
        Self {
            smss: 0,
            iw: 0,
            cwnd: 0.0,
            ssthresh: u32::MAX,
            cwnd_prior: 0.0,
            w_max: 0.0,
            plan_from_start: true,
            epoch: None,
            srtt: None,
            hystart: Some(HyStart::new()),
        }
    }

    /// Fig. 1: W_cubic(t) = C·(t − K)³ + W_max, here in octets.
    fn w_cubic(&self, ep: &Epoch, t: f64) -> f64 {
        C * f64::from(self.smss) * (t - ep.k).powi(3) + self.w_max
    }

    /// One new ACK in congestion avoidance (§4.2–§4.5).
    fn congestion_avoidance(&mut self, acked: u32, now: Instant) {
        let smss = f64::from(self.smss);
        let mut ep = match self.epoch {
            Some(ep) => ep,
            None => {
                if std::mem::take(&mut self.plan_from_start) {
                    self.w_max = self.cwnd;
                }
                Epoch {
                    start: now,
                    last: now,
                    // Fig. 2.
                    k: ((self.w_max - self.cwnd).max(0.0) / (C * smss)).cbrt(),
                    // §4.3: W_est = cwnd_epoch at the start of the stage.
                    w_est: self.cwnd,
                }
            }
        };
        ep.last = now;
        let t = (now - ep.start).as_secs_f64();
        let rtt = self.srtt.map_or(0.0, |d| d.as_secs_f64());
        let target = self.w_cubic(&ep, t + rtt).clamp(self.cwnd, 1.5 * self.cwnd);
        // Fig. 4, with α_cubic = 1 once W_est reaches cwnd_prior.
        let alpha = if ep.w_est >= self.cwnd_prior {
            1.0
        } else {
            ALPHA
        };
        let acked = f64::from(acked);
        ep.w_est += alpha * smss * acked / self.cwnd;
        self.cwnd = if self.w_cubic(&ep, t) < ep.w_est {
            // Reno-friendly region (§4.3): cwnd = W_est (never a decrease).
            self.cwnd.max(ep.w_est)
        } else {
            // Concave and convex regions (§4.4, §4.5): (target − cwnd)/cwnd per SMSS acked,
            // so one cwnd of ACKs reaches target as Fig. 1's "after the next RTT" intends; a
            // stretch ACK does not pass it.
            (self.cwnd + (target - self.cwnd) * acked / self.cwnd).min(target)
        };
        self.epoch = Some(ep);
    }
}

impl CongestionControl for Cubic {
    fn init(&mut self, smss: u32, syn_lost: bool) {
        self.smss = smss;
        self.iw = initial_window(smss, syn_lost);
        self.cwnd = f64::from(self.iw);
    }

    fn restart_cwnd(&self) -> u32 {
        self.cwnd().min(self.iw)
    }

    /// RW = min(IW, cwnd), ssthresh kept (RFC 5681 §4.1); the congestion avoidance stage
    /// restarts so that t does not count the idle period (RFC 9438 §5.8).
    fn on_idle_restart(&mut self) {
        self.cwnd = self.cwnd.min(f64::from(self.iw));
        self.epoch = None;
    }

    /// Slow start below ssthresh (§4.10: HyStart++, or RFC 5681 once it is over); congestion
    /// avoidance otherwise.
    ///
    /// §5.8: "CUBIC does not increase its congestion window if a flow is application
    /// limited" — limited by the sender application or by the receiver's advertised window —
    /// and t "MUST NOT include periods during which cwnd has not been updated due to
    /// application-limited behavior" (§4.2). cwnd grows only on an ACK that is
    /// `cwnd_limited` (its data was outstanding when the sender filled cwnd, RFC 7661 §3) and
    /// not `app_limited` (data sent inside an app-limited interval). Any other ACK grows neither cwnd nor
    /// W_est, and moves t_epoch by the time since the stage's previous ACK. W_max at the next
    /// loss is then the cwnd the flow actually used, and K stays what that implies.
    fn on_ack(&mut self, ack: &AckSample) {
        let AckSample {
            acked,
            rtt,
            in_flight,
            now,
            app_limited,
            cwnd_limited,
            ..
        } = *ack;
        let grow = cwnd_limited && !app_limited;
        if let Some(r) = rtt {
            self.srtt = Some(self.srtt.map_or(r, |s| s * 7 / 8 + r / 8));
        }
        if self.cwnd >= f64::from(self.ssthresh) {
            if grow {
                return self.congestion_avoidance(acked, now);
            }
            if let Some(ep) = &mut self.epoch {
                ep.start = ep.start + (now - ep.last);
                ep.last = now;
            }
            return;
        }
        let Some(hs) = &mut self.hystart else {
            if grow {
                self.cwnd += f64::from(acked.min(self.smss));
            }
            return;
        };
        // HyStart++ keeps its rounds and RTT samples; only the growth is withheld.
        let (n, done) = hs.on_ack(acked, rtt, in_flight, self.smss);
        if grow {
            self.cwnd += f64::from(n);
        }
        if done {
            // RFC 9406 §4.2: ssthresh = cwnd; RFC 9438 §4.10: cwnd_prior = cwnd, and the
            // stage starts with K = 0 (`plan_from_start` is still set: no loss yet).
            self.hystart = None;
            self.ssthresh = self.cwnd as u32;
            self.cwnd_prior = self.cwnd;
        }
    }

    /// §4.6 multiplicative decrease with §4.7 fast convergence; §4.8 for an RTO. Either ends
    /// HyStart++ (RFC 9406 §4.2: loss in slow start or CSS), and a new congestion avoidance
    /// stage starts after it.
    fn on_congestion(&mut self, ev: CongestionEvent, in_flight: u32, _: Instant) {
        let smss = f64::from(self.smss);
        self.hystart = None;
        self.epoch = None;
        // Fig. 5: ssthresh = max(flight_size·β_cubic, 2·SMSS).
        self.ssthresh = ((u64::from(in_flight) * BETA.0 / BETA.1) as u32).max(2 * self.smss);
        match ev {
            CongestionEvent::FastRetransmit => {
                // §4.7: W_max = cwnd·(1 + β_cubic)/2 when below the last W_max.
                self.w_max = if self.cwnd < self.w_max {
                    self.cwnd * 17.0 / 20.0
                } else {
                    self.cwnd
                };
                self.plan_from_start = false;
                self.cwnd_prior = self.cwnd;
                // RFC 5681 §3.2 step 3 inflation on top of ssthresh.
                self.cwnd = f64::from(self.ssthresh) + 3.0 * smss;
            }
            CongestionEvent::Rto => {
                // A repeated RTO finds cwnd already at the loss window: no reduction, so
                // cwnd_prior (the cwnd "just before cwnd was reduced") is kept.
                if self.cwnd > smss {
                    self.cwnd_prior = self.cwnd;
                }
                self.plan_from_start = true;
                // RFC 5681 §3.1: LW = 1 SMSS.
                self.cwnd = smss;
            }
        }
    }

    fn on_recovery_ack(&mut self, ack: RecoveryAck) {
        self.cwnd = f64::from(recovery_window(self.cwnd(), self.ssthresh, self.smss, ack));
    }

    fn cwnd(&self) -> u32 {
        self.cwnd as u32
    }
}

/// RFC 9406 §4.3 recommended constants (L for a sender that does not pace).
const MIN_RTT_THRESH: Duration = Duration::from_millis(4);
const MAX_RTT_THRESH: Duration = Duration::from_millis(16);
const MIN_RTT_DIVISOR: u32 = 8;
const N_RTT_SAMPLE: u32 = 8;
const CSS_GROWTH_DIVISOR: u32 = 4;
const CSS_ROUNDS: u32 = 5;
const L: u32 = 8;

/// HyStart++ (RFC 9406 §4.2): slow start that leaves for Conservative Slow Start (CSS) when a
/// round's minimum RTT rises, and for congestion avoidance after CSS_ROUNDS rounds of CSS.
///
/// Rounds: windowEnd = SND.NXT at the start of a round, and the round ends when windowEnd is
/// acknowledged. A round here starts at an ACK and records `in_flight` = SND.MAX − SND.UNA
/// after it; it ends once that many more octets are acknowledged. That is SND.UNA reaching
/// the SND.MAX of the round start, which is windowEnd whenever SND.NXT = SND.MAX, true
/// everywhere HyStart++ runs: SND.NXT drops below SND.MAX only on a go-back after an RTO,
/// and loss ends HyStart++. The octets the sender adds after that ACK belong to the next
/// round, as they do for windowEnd.
#[derive(Debug)]
struct HyStart {
    /// lastRoundMinRTT; `None` is infinity.
    last_min: Option<Duration>,
    /// currentRoundMinRTT; `None` is infinity.
    cur_min: Option<Duration>,
    /// rttSampleCount. Only ACKs that carry a sample count: an ACK without one has no
    /// currRTT of its own.
    samples: u32,
    /// Octets the current round has still to see acknowledged.
    round_left: u32,
    css: Option<Css>,
}

#[derive(Debug, Clone, Copy)]
struct Css {
    /// cssBaselineMinRtt.
    baseline: Duration,
    /// CSS rounds ended so far, the partial round that entered CSS included.
    rounds: u32,
}

/// RttThresh = max(MIN_RTT_THRESH, min(lastRoundMinRTT / MIN_RTT_DIVISOR, MAX_RTT_THRESH)).
fn rtt_thresh(last: Duration) -> Duration {
    (last / MIN_RTT_DIVISOR).clamp(MIN_RTT_THRESH, MAX_RTT_THRESH)
}

impl HyStart {
    fn new() -> Self {
        // Nothing is outstanding at init: the first ACK ends round 0.
        Self {
            last_min: None,
            cur_min: None,
            samples: 0,
            round_left: 0,
            css: None,
        }
    }

    /// One ACK in slow start or CSS: the cwnd increase, and whether CSS is over (the caller
    /// then sets ssthresh = cwnd).
    fn on_ack(
        &mut self,
        acked: u32,
        rtt: Option<Duration>,
        in_flight: u32,
        smss: u32,
    ) -> (u32, bool) {
        let mut grow = acked.min(L * smss);
        if self.css.is_some() {
            grow /= CSS_GROWTH_DIVISOR;
        }
        if let Some(r) = rtt {
            self.cur_min = Some(self.cur_min.map_or(r, |m| m.min(r)));
            self.samples += 1;
        }
        if let Some(cur) = self.cur_min.filter(|_| self.samples >= N_RTT_SAMPLE) {
            match self.css {
                None => {
                    if self
                        .last_min
                        .is_some_and(|last| cur >= last + rtt_thresh(last))
                    {
                        self.css = Some(Css {
                            baseline: cur,
                            rounds: 0,
                        });
                    }
                }
                // The exit was spurious: resume slow start.
                Some(css) if cur < css.baseline => self.css = None,
                Some(_) => {}
            }
        }
        self.round_left = self.round_left.saturating_sub(acked);
        if self.round_left == 0 {
            if let Some(css) = &mut self.css {
                css.rounds += 1;
                if css.rounds >= CSS_ROUNDS {
                    return (grow, true);
                }
            }
            self.last_min = self.cur_min.take();
            self.samples = 0;
            self.round_left = in_flight;
        }
        (grow, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::cc::Reno;

    const SMSS: u32 = 1000;
    const T0: Instant = Instant::from_nanos(0);

    fn ack(acked: u32, rtt: Option<Duration>, in_flight: u32, now: Instant) -> AckSample {
        AckSample {
            acked,
            rtt,
            in_flight,
            now,
            delivered: 0,
            app_limited: false,
            cwnd_limited: true,
        }
    }
    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }
    fn at(d: Duration) -> Instant {
        T0 + d
    }
    fn cubic() -> Cubic {
        let mut c = Cubic::new();
        c.init(SMSS, false);
        c
    }
    /// Slow start without RTT samples (HyStart++ cannot trigger) from IW up to `cwnd`.
    fn grown(cwnd: u32) -> Cubic {
        let mut c = cubic();
        while c.cwnd() < cwnd {
            c.on_ack(&ack(SMSS, None, 0, T0));
        }
        assert_eq!(c.cwnd(), cwnd);
        c
    }
    /// cwnd 100 000 → loss → recovery ends with cwnd = ssthresh = 70 000: congestion
    /// avoidance with W_max = 100 000.
    fn after_loss() -> Cubic {
        let mut c = grown(100_000);
        c.on_congestion(CongestionEvent::FastRetransmit, 100_000, T0);
        c.on_recovery_ack(RecoveryAck::Full { in_flight: 80_000 });
        assert_eq!(c.cwnd(), 70_000);
        c
    }

    #[test]
    fn cubic_initial_window_and_slow_start_match_reno() {
        for smss in [536, 1095, 1096, 1460, 2190, 2191] {
            for syn_lost in [false, true] {
                let (mut c, mut r) = (Cubic::new(), Reno::new());
                c.init(smss, syn_lost);
                r.init(smss, syn_lost);
                assert_eq!(c.cwnd(), r.cwnd(), "SMSS {smss} syn_lost {syn_lost}");
            }
        }
        // ACKs of at most one SMSS, no RTT samples: HyStart++ cannot leave slow start, and
        // min(N, L·SMSS) = min(N, SMSS) = N, so the growth is RFC 5681's.
        let (mut c, mut r) = (cubic(), Reno::new());
        r.init(SMSS, false);
        for (i, n) in [1000, 400, 1000, 1, 999, 1000]
            .iter()
            .cycle()
            .take(200)
            .enumerate()
        {
            c.on_ack(&ack(*n, None, 0, T0));
            r.on_ack(&ack(*n, None, 0, T0));
            assert_eq!(c.cwnd(), r.cwnd(), "ACK {i}");
        }
        assert_eq!(c.ssthresh, u32::MAX);
    }

    #[test]
    fn cubic_fast_retransmit_multiplicative_decrease() {
        let mut c = grown(100_000);
        c.on_congestion(CongestionEvent::FastRetransmit, 100_000, T0);
        // §4.6: ssthresh = flight_size·β = 70 000; W_max = cwnd_prior = 100 000 (no earlier
        // W_max, so no fast convergence); RFC 5681 §3.2 step 3: cwnd = ssthresh + 3·SMSS.
        assert_eq!((c.ssthresh, c.cwnd()), (70_000, 73_000));
        assert_eq!((c.w_max, c.cwnd_prior), (100_000.0, 100_000.0));
        assert!(c.hystart.is_none(), "loss ends HyStart++");
        // NewReno inflation and deflation as Reno; the full ACK caps cwnd at ssthresh.
        c.on_recovery_ack(RecoveryAck::Duplicate);
        assert_eq!(c.cwnd(), 74_000);
        c.on_recovery_ack(RecoveryAck::Partial { acked: 3000 });
        assert_eq!(c.cwnd(), 72_000);
        c.on_recovery_ack(RecoveryAck::Full { in_flight: 80_000 });
        assert_eq!(c.cwnd(), 70_000);
        // ssthresh never drops below 2·SMSS.
        let mut c = cubic();
        c.on_congestion(CongestionEvent::FastRetransmit, 2000, T0);
        assert_eq!((c.ssthresh, c.cwnd()), (2000, 5000));
    }

    #[test]
    fn cubic_fast_convergence() {
        let mut c = after_loss();
        // A second loss at cwnd 70 000 < W_max 100 000: W_max = cwnd·(1 + β)/2 = 59 500
        // (§4.7); ssthresh = 70 000·0.7 = 49 000.
        c.on_congestion(CongestionEvent::FastRetransmit, 70_000, T0);
        assert_eq!(c.w_max, 59_500.0);
        assert_eq!((c.ssthresh, c.cwnd()), (49_000, 52_000));
        assert_eq!(c.cwnd_prior, 70_000.0);
    }

    #[test]
    fn cubic_window_function_reaches_w_max_at_k() {
        let mut c = after_loss();
        c.on_ack(&ack(SMSS, None, 0, T0));
        let ep = c.epoch.expect("congestion avoidance started an epoch");
        // Fig. 2: K = ∛((W_max − cwnd_epoch)/C) = ∛((100 − 70) segments / 0.4) = ∛75 s.
        assert!((ep.k - 75f64.cbrt()).abs() < 1e-12, "K = {}", ep.k);
        // Fig. 1 in octets: C·SMSS·(t − K)³ + W_max.
        assert!(
            (c.w_cubic(&ep, 0.0) - 70_000.0).abs() < 1e-6,
            "W(0) = cwnd_epoch"
        );
        assert_eq!(c.w_cubic(&ep, ep.k), 100_000.0, "W(K) = W_max");
        assert!((c.w_cubic(&ep, ep.k + 1.0) - 100_400.0).abs() < 1e-6);
        assert!((c.w_cubic(&ep, ep.k - 1.0) - 99_600.0).abs() < 1e-6);
        // W_est starts at cwnd_epoch and gains α·segments_acked/cwnd; at t = 0 it is above
        // W_cubic(0), so the first ACK is in the Reno-friendly region:
        // 70 000 + 0.5294·1000·1000/70 000 = 70 007.56.
        assert_eq!(c.cwnd(), 70_007);
    }

    /// Every `rtt`, one cwnd of 1-SMSS ACKs with that RTT sample; cwnd at each round.
    fn ack_clock(c: &mut Cubic, start: Duration, rtt: Duration, rounds: u32) -> Vec<u32> {
        (0..rounds)
            .map(|i| {
                let now = at(start + rtt * i);
                let mut left = c.cwnd();
                while left > 0 {
                    c.on_ack(&ack(SMSS.min(left), Some(rtt), 0, now));
                    left = left.saturating_sub(SMSS);
                }
                c.cwnd()
            })
            .collect()
    }

    #[test]
    fn cubic_concave_then_convex() {
        let mut c = after_loss();
        let rtt = ms(100);
        let k = 75f64.cbrt();
        let w = ack_clock(&mut c, Duration::ZERO, rtt, 90);
        // Round i ends just after t = i·RTT, so cwnd[i] is about W_cubic((i + 1)·RTT).
        let gain = |a: usize, b: usize| w[b] - w[a];
        let kr = (k / 0.1) as usize; // 42
        // Concave: growth slows down on the way up to W_max.
        assert!(gain(0, kr / 2) > gain(kr / 2, kr), "{w:?}");
        // The plateau: within 1 SMSS of W_max = 100 000 around t = K.
        for (i, cw) in w.iter().enumerate().skip(kr - 2).take(4) {
            assert!(cw.abs_diff(100_000) <= SMSS, "round {i}: {cw}");
        }
        // Convex: growth speeds up past W_max.
        assert!(gain(kr, kr + 20) < gain(kr + 20, kr + 40), "{w:?}");
        // Never more than 1.5·cwnd per RTT (the target's upper bound).
        assert!(
            w.windows(2)
                .all(|p| f64::from(p[1]) <= 1.5 * f64::from(p[0]) + 1.0)
        );
    }

    #[test]
    fn cubic_reno_friendly_region() {
        // A small window on a 1 ms path: K = ∛((10 − 7)/0.4) ≈ 1.96 s, but W_est gains about
        // α SMSS per RTT, so W_est is above W_cubic(t) and cwnd follows it.
        let mut c = grown(10_000);
        c.on_congestion(CongestionEvent::FastRetransmit, 10_000, T0);
        c.on_recovery_ack(RecoveryAck::Full { in_flight: 10_000 });
        assert_eq!(c.cwnd(), 7000);
        let rtt = ms(1);
        c.on_ack(&ack(SMSS, Some(rtt), 0, T0));
        // 7000 + 0.5294·1000·1000/7000 = 7075.63.
        assert_eq!(c.cwnd(), 7075);
        let mut alpha_one = false;
        for i in 1..2000u64 {
            let before = c.cwnd;
            let ep = c.epoch.unwrap();
            let now = at(Duration::from_micros(100 * i));
            c.on_ack(&ack(SMSS, Some(rtt), 0, now));
            let ep_after = c.epoch.unwrap();
            let t = (now - ep.start).as_secs_f64();
            assert!(
                c.w_cubic(&ep_after, t) < ep_after.w_est,
                "ACK {i}: Reno-friendly"
            );
            assert_eq!(c.cwnd, ep_after.w_est, "ACK {i}: cwnd = W_est");
            // α_cubic until W_est reaches cwnd_prior = 10 000, then 1 (§4.3).
            let alpha = if ep.w_est >= 10_000.0 { 1.0 } else { ALPHA };
            alpha_one |= alpha == 1.0;
            let want = before + alpha * 1000.0 * 1000.0 / before;
            assert!(
                (c.cwnd - want).abs() < 1e-9,
                "ACK {i}: {} vs {want}",
                c.cwnd
            );
        }
        assert!(alpha_one && c.cwnd() > 40_000, "{}", c.cwnd());
    }

    #[test]
    fn cubic_rto_resets() {
        let mut c = grown(100_000);
        // §4.8: cwnd to the loss window of RFC 5681, ssthresh = flight_size·β.
        c.on_congestion(CongestionEvent::Rto, 100_000, T0);
        assert_eq!((c.cwnd(), c.ssthresh), (SMSS, 70_000));
        // A repeated RTO with SND.UNA unmoved sees the same FlightSize: ssthresh held.
        c.on_congestion(CongestionEvent::Rto, 100_000, T0);
        assert_eq!((c.cwnd(), c.ssthresh), (SMSS, 70_000));
        // Standard slow start (no HyStart++ after a loss): + min(N, SMSS).
        c.on_ack(&ack(3000, None, 0, T0));
        assert_eq!(c.cwnd(), 2000);
        while c.cwnd() < 70_000 {
            c.on_ack(&ack(SMSS, None, 0, T0));
        }
        assert_eq!(c.cwnd(), 70_000);
        // The first congestion avoidance stage after it: K = 0, W_max = W_est = cwnd_epoch.
        c.on_ack(&ack(SMSS, None, 0, at(ms(5))));
        let ep = c.epoch.unwrap();
        assert_eq!((ep.k, c.w_max, ep.start), (0.0, 70_000.0, at(ms(5))));
        assert_eq!(c.cwnd(), 70_007, "W_est = 70 000 + α·1000·1000/70 000");
    }

    #[test]
    fn cubic_idle_restart() {
        let mut c = grown(14_000);
        assert_eq!(c.restart_cwnd(), 4000, "side-effect free");
        assert_eq!(c.cwnd(), 14_000);
        c.on_idle_restart();
        assert_eq!(c.cwnd(), 4000);
        // In congestion avoidance the restart also ends the epoch: t must not count the idle
        // period (§5.8).
        let mut c = after_loss();
        c.on_ack(&ack(SMSS, None, 0, T0));
        assert!(c.epoch.is_some());
        c.on_idle_restart();
        assert_eq!((c.cwnd(), c.ssthresh), (4000, 70_000));
        assert!(c.epoch.is_none());
        // A cwnd below IW (after an RTO) is not raised.
        c.on_congestion(CongestionEvent::Rto, 8000, T0);
        c.on_idle_restart();
        assert_eq!(c.cwnd(), SMSS);
    }

    // HyStart++ (RFC 9406 §4.2). Rounds are 8 ACKs of one SMSS: each reports 8 SMSS still
    // outstanding, so the round that starts at an ACK ends once 8 SMSS more are acknowledged.

    /// After IW and one priming ACK without an RTT sample, which closes round 0 (nothing was
    /// outstanding at init): cwnd 5000, lastRoundMinRTT = infinity, round 1 next.
    fn hy() -> Cubic {
        let mut c = cubic();
        c.on_ack(&ack(SMSS, None, 8 * SMSS, T0));
        assert_eq!(c.cwnd(), 5000);
        c
    }
    fn round(c: &mut Cubic, rtt: Duration) {
        for _ in 0..8 {
            c.on_ack(&ack(SMSS, Some(rtt), 8 * SMSS, T0));
        }
    }
    fn in_css(c: &Cubic) -> bool {
        c.hystart.as_ref().is_some_and(|h| h.css.is_some())
    }
    /// Rounds at 100, 100 and 113 ms: CSS from the last ACK of the third, cwnd 29 000.
    fn css() -> Cubic {
        let mut c = hy();
        round(&mut c, ms(100));
        round(&mut c, ms(100));
        round(&mut c, ms(113));
        assert!(in_css(&c));
        assert_eq!(c.cwnd(), 29_000);
        c
    }

    #[test]
    fn hystart_rtt_thresh_is_clamped() {
        // max(MIN_RTT_THRESH, min(lastRoundMinRTT / 8, MAX_RTT_THRESH)).
        assert_eq!(rtt_thresh(ms(20)), ms(4));
        assert_eq!(rtt_thresh(ms(100)), Duration::from_micros(12_500));
        assert_eq!(rtt_thresh(ms(200)), ms(16));
    }

    #[test]
    fn hystart_delay_increase_enters_css() {
        // RttThresh = 100 ms / 8 = 12.5 ms: 112 ms stays in slow start.
        let mut c = hy();
        for rtt in [100, 100, 112] {
            round(&mut c, ms(rtt));
        }
        assert!(!in_css(&c));
        assert_eq!(c.cwnd(), 29_000, "5000 + 3 rounds of 8 SMSS");
        // 113 ms ≥ 112.5 ms: CSS once the 8th sample (N_RTT_SAMPLE) of the round is in.
        let mut c = hy();
        round(&mut c, ms(100));
        round(&mut c, ms(100));
        for i in 0..7 {
            c.on_ack(&ack(SMSS, Some(ms(113)), 8 * SMSS, T0));
            assert!(!in_css(&c), "sample {i}: fewer than N_RTT_SAMPLE");
        }
        c.on_ack(&ack(SMSS, Some(ms(113)), 8 * SMSS, T0));
        assert!(in_css(&c));
        assert_eq!(
            c.cwnd(),
            29_000,
            "the ACK that enters CSS still grew at the slow start rate"
        );
        assert_eq!(c.hystart.as_ref().unwrap().css.unwrap().baseline, ms(113));
        // In CSS: + min(N, L·SMSS) / CSS_GROWTH_DIVISOR = 250 per ACK.
        round(&mut c, ms(113));
        assert_eq!(c.cwnd(), 31_000);
        assert_eq!(c.ssthresh, u32::MAX);
    }

    #[test]
    fn hystart_css_rounds_then_congestion_avoidance() {
        let mut c = css();
        // The partial round that entered CSS counts: four more make CSS_ROUNDS = 5.
        for i in 0..3 {
            round(&mut c, ms(113));
            assert!(in_css(&c), "CSS round {}", i + 2);
        }
        round(&mut c, ms(113));
        // ssthresh = cwnd = 29 000 + 4 · 8 · 250.
        assert_eq!((c.cwnd(), c.ssthresh), (37_000, 37_000));
        assert!(c.hystart.is_none());
        assert_eq!(c.cwnd_prior, 37_000.0);
        // RFC 9438 §4.10: congestion avoidance with K = 0 and W_max = cwnd_epoch.
        c.on_ack(&ack(SMSS, Some(ms(113)), 8 * SMSS, at(ms(1))));
        let ep = c.epoch.unwrap();
        assert_eq!((ep.k, c.w_max), (0.0, 37_000.0));
        // α = 1 at once (W_est ≥ cwnd_prior): 37 000 + 1000·1000/37 000 = 37 027.03.
        assert_eq!(c.cwnd(), 37_027);
    }

    #[test]
    fn hystart_spurious_css_resumes_slow_start() {
        let mut c = css();
        // 105 ms < cssBaselineMinRtt = 113 ms after N_RTT_SAMPLE samples: back to slow start.
        // Seven ACKs at the CSS rate, the eighth too (growth comes before the check).
        round(&mut c, ms(105));
        assert!(!in_css(&c) && c.hystart.is_some());
        assert_eq!(c.cwnd(), 31_000);
        round(&mut c, ms(105));
        assert_eq!(c.cwnd(), 39_000, "slow start again");
    }

    #[test]
    fn hystart_loss_exits() {
        // Loss in slow start: HyStart++ is done; CUBIC's decrease sets ssthresh.
        let mut c = hy();
        c.on_congestion(CongestionEvent::FastRetransmit, 5000, T0);
        assert!(c.hystart.is_none());
        assert_eq!((c.ssthresh, c.cwnd()), (3500, 6500));
        // Loss in CSS.
        let mut c = css();
        c.on_congestion(CongestionEvent::FastRetransmit, 29_000, T0);
        assert!(c.hystart.is_none());
        c.on_recovery_ack(RecoveryAck::Full { in_flight: 5000 });
        assert_eq!((c.cwnd(), c.ssthresh), (6000, 20_300));
        // The later slow start is RFC 5681's: + min(N, SMSS), no L, no delay check.
        c.on_ack(&ack(3000, Some(ms(500)), 0, T0));
        assert_eq!(c.cwnd(), 7000);
    }

    #[test]
    fn hystart_growth_limit_l() {
        // Slow start under HyStart++: + min(N, L·SMSS) with L = 8 (non-paced).
        let mut c = cubic();
        c.on_ack(&ack(3000, None, 0, T0));
        assert_eq!(c.cwnd(), 7000);
        c.on_ack(&ack(10_000, None, 0, T0));
        assert_eq!(c.cwnd(), 15_000);
        // HyStart++ off: RFC 5681 slow start, + min(N, SMSS).
        let mut c = cubic();
        c.hystart = None;
        c.on_ack(&ack(3000, None, 0, T0));
        assert_eq!(c.cwnd(), 5000);
    }

    // RFC 9438 §5.8 / §4.2: app-limited ACKs neither grow cwnd nor count toward t.

    fn limited(mut a: AckSample) -> AckSample {
        a.app_limited = true;
        a
    }

    fn rate_limited(mut a: AckSample) -> AckSample {
        a.cwnd_limited = false;
        a
    }

    #[test]
    fn cubic_not_cwnd_limited_acks_do_not_advance_t_or_cwnd() {
        let mut c = cubic();
        c.on_ack(&rate_limited(ack(SMSS, None, 0, T0)));
        assert_eq!(c.cwnd(), 4000, "slow start");
        let (mut a, mut b) = (after_loss(), after_loss());
        a.on_ack(&ack(SMSS, None, 0, T0));
        b.on_ack(&ack(SMSS, None, 0, T0));
        let cwnd = a.cwnd;
        for s in 1..=10 {
            a.on_ack(&rate_limited(ack(
                SMSS,
                None,
                0,
                at(Duration::from_secs(s)),
            )));
            assert_eq!(a.cwnd, cwnd);
        }
        a.on_ack(&ack(SMSS, None, 0, at(Duration::from_secs(10) + ms(100))));
        b.on_ack(&ack(SMSS, None, 0, at(ms(100))));
        assert_eq!(a.cwnd, b.cwnd, "t excludes the period");
    }

    #[test]
    fn cubic_app_limited_acks_do_not_advance_t_or_cwnd() {
        // Slow start (HyStart++ and RFC 5681 alike): no growth.
        let mut c = cubic();
        c.on_ack(&limited(ack(SMSS, None, 0, T0)));
        assert_eq!(c.cwnd(), 4000);
        c.hystart = None;
        c.on_ack(&limited(ack(SMSS, None, 0, T0)));
        assert_eq!(c.cwnd(), 4000);
        // Congestion avoidance: two stages from the same first ACK; one then sees 10 s of
        // app-limited ACKs. Its next ACK at 10.1 s finds t = 0.1 s, as the other's at 0.1 s.
        let (mut a, mut b) = (after_loss(), after_loss());
        a.on_ack(&ack(SMSS, None, 0, T0));
        b.on_ack(&ack(SMSS, None, 0, T0));
        let cwnd = a.cwnd;
        for s in 1..=10 {
            a.on_ack(&limited(ack(SMSS, None, 0, at(Duration::from_secs(s)))));
            assert_eq!(a.cwnd, cwnd);
        }
        a.on_ack(&ack(SMSS, None, 0, at(Duration::from_secs(10) + ms(100))));
        b.on_ack(&ack(SMSS, None, 0, at(ms(100))));
        assert_eq!(a.cwnd, b.cwnd);
        assert_eq!(a.epoch.unwrap().w_est, b.epoch.unwrap().w_est);
        // Without the exclusion t = 10.1 s > K: convex growth at the 1.5×/RTT clamp.
        assert!(a.cwnd < cwnd + 100.0, "{} vs {cwnd}", a.cwnd);
    }

    #[test]
    fn cubic_w_max_after_app_limited_period_is_cwnd_reached() {
        // cwnd-limited past W_max = 100 000 (K ≈ 4.2 s at 100 ms RTT) ...
        let mut c = after_loss();
        let rtt = ms(100);
        ack_clock(&mut c, Duration::ZERO, rtt, 60);
        let reached = c.cwnd;
        assert!(reached > 100_000.0, "{reached}");
        // ... then 30 s with the application keeping well below cwnd: every ACK is
        // app-limited, a third of a window per RTT.
        for i in 0..300u32 {
            let now = at(Duration::from_secs(6) + rtt * i);
            for _ in 0..30 {
                c.on_ack(&limited(ack(SMSS, Some(rtt), 0, now)));
            }
        }
        assert_eq!(c.cwnd, reached, "no growth while not cwnd-limited");
        // The loss after it records the window actually used, not an inflated one: K stays
        // small and the backoff is not undone within a few RTTs.
        c.on_congestion(
            CongestionEvent::FastRetransmit,
            reached as u32,
            at(ms(36_000)),
        );
        assert_eq!(c.w_max, reached);
    }
}
