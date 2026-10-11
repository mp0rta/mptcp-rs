//! BBRv3 (draft-ietf-ccwg-bbr-06 §5), in the draft's names (spec §3).
//!
//! No floats: gains are rationals `(num, den)`, bandwidth is octets per second in a `u64`,
//! products go through `u128`. Infinity is `INFINITE` (octets, octets/s) or `INFINITE_RTT`.

use std::time::Duration;

use super::cc::{
    AckSample, CongestionControl, CongestionEvent, LossEvent, RateSample, RecoveryAck,
    RecoveryKind, RecoveryStart, Start, initial_window,
};
use crate::time::Instant;

/// A gain as `(numerator, denominator)`.
type Gain = (u64, u64);

/// The draft's Infinity for volumes and rates.
const INFINITE: u64 = u64::MAX;
/// The draft's Infinity for BBR.min_rtt.
const INFINITE_RTT: Duration = Duration::MAX;
const NANOS_PER_SEC: u128 = 1_000_000_000;

const UNITY_GAIN: Gain = (1, 1);
/// §2.5: 4 · ln 2 ≈ 2.77.
const STARTUP_PACING_GAIN: Gain = (277, 100);
const DRAIN_PACING_GAIN: Gain = (1, 2);
/// §5.3.3.1 and §5.6.1: ProbeBW_DOWN paces at 0.90 (Appendix: BBR.ProbeDownPacingGain).
const PROBE_DOWN_PACING_GAIN: Gain = (90, 100);
/// §5.3.3.5 and §5.6.1: ProbeBW_UP paces at 1.25 with a cwnd gain of 2.25.
const PROBE_UP_PACING_GAIN: Gain = (5, 4);
const PROBE_UP_CWND_GAIN: Gain = (9, 4);
const PACING_MARGIN_PERCENT: u64 = 1;
const DEFAULT_CWND_GAIN: Gain = (2, 1);
/// §2.8: 0.15.
const HEADROOM: Gain = (15, 100);
/// §2.8: 2%.
const LOSS_THRESH: Gain = (2, 100);
/// §2.8: 0.7.
const BETA: Gain = (7, 10);
/// §5.3.1.3: BBRStartupFullLossCnt.
const STARTUP_FULL_LOSS_CNT: u64 = 6;
/// §2.11, in ProbeBW cycles.
const MAX_BW_FILTER_LEN: u64 = 2;
/// §2.12, in packet-timed rounds.
const EXTRA_ACKED_FILTER_LEN: u64 = 10;
const MIN_RTT_FILTER_LEN: Duration = Duration::from_secs(10);
const PROBE_RTT_INTERVAL: Duration = Duration::from_secs(5);
/// §5.6.3: 64 KBytes.
const MAX_SEND_QUANTUM: u64 = 64 * 1024;

/// BBR.state (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Startup,
    Drain,
    ProbeBwDown,
    ProbeBwCruise,
    ProbeBwRefill,
    ProbeBwUp,
    ProbeRtt,
}

/// BBR.ack_phase (§2.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AckPhase {
    Init,
    Refilling,
    ProbeStarting,
    ProbeFeedback,
    ProbeStopping,
}

/// What the unit tests assert (spec §3.6).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BbrView {
    pub(crate) state: State,
    pub(crate) phase: AckPhase,
    pub(crate) round_count: u64,
    pub(crate) max_bw: u64,
    pub(crate) min_rtt: Duration,
    pub(crate) bw_shortterm: u64,
    pub(crate) inflight_shortterm: u64,
    pub(crate) inflight_longterm: u64,
    pub(crate) cwnd: u64,
    pub(crate) pacing_rate: u64,
}

/// `a × b / c` through `u128`, rounded down, saturating at `u64::MAX`.
fn mul_div(a: u128, b: u128, c: u128) -> u64 {
    u64::try_from(a.saturating_mul(b) / c).unwrap_or(u64::MAX)
}

/// SplitMix64 (Steele, Lea and Flood, 2014): the seeded PRNG behind PickProbeWait (spec §3.4).
#[derive(Debug, Clone)]
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// Slots of `WindowedMax`: the longest window it serves (ExtraAckedFilterLen).
const WINDOW_SLOTS: usize = EXTRA_ACKED_FILTER_LEN as usize;

/// UpdateWindowedMaxFilter (§5.5.5, §5.5.9) over a virtual time: the exact maximum of the
/// values seen at times `t` with `now - t < window_length`, one maximum per time slot. Each
/// update drops what has left its window, as Nichols' filter does. The
/// draft allows Kathleen Nichols' approximation; this is exact for windows up to
/// `WINDOW_SLOTS`.
#[derive(Debug, Clone, Default)]
struct WindowedMax {
    /// `(time, max value at that time)`, at index `time % WINDOW_SLOTS`.
    slots: [(u64, u64); WINDOW_SLOTS],
}

impl WindowedMax {
    fn update(&mut self, value: u64, time: u64, window_length: u64) -> u64 {
        debug_assert!(window_length as usize <= WINDOW_SLOTS);
        // Samples outside the window are forgotten for good, so a later, wider window does
        // not bring them back.
        for slot in &mut self.slots {
            if slot.0 > time || time - slot.0 >= window_length {
                slot.1 = 0;
            }
        }
        let slot = &mut self.slots[(time % WINDOW_SLOTS as u64) as usize];
        if slot.0 != time {
            *slot = (time, 0);
        }
        slot.1 = slot.1.max(value);
        self.slots.iter().map(|&(_, v)| v).max().unwrap_or(0)
    }
}

/// BBRv3 (draft-ietf-ccwg-bbr-06). Volumes are octets, rates octets per second.
#[derive(Debug)]
pub(crate) struct Bbr {
    rng: SplitMix64,
    // Connection state (§2.2, §2.4).
    smss: u64,
    /// C.InitialCwnd.
    initial_cwnd: u64,
    cwnd: u64,
    pacing_rate: u64,
    send_quantum: u64,
    // §2.5–§2.7.
    state: State,
    pacing_gain: Gain,
    cwnd_gain: Gain,
    round_count: u64,
    round_start: bool,
    next_round_delivered: u64,
    drain_start_round: u64,
    // The model (§2.9, §2.11, §2.12).
    max_bw: u64,
    max_bw_filter: WindowedMax,
    cycle_count: u64,
    bw_shortterm: u64,
    bw: u64,
    min_rtt: Duration,
    min_rtt_stamp: Instant,
    extra_acked: u64,
    extra_acked_filter: WindowedMax,
    extra_acked_interval_start: Instant,
    extra_acked_delivered: u64,
    max_inflight: u64,
    inflight_longterm: u64,
    inflight_shortterm: u64,
    // Responding to congestion (§2.10, §5.5.10.3).
    bw_latest: u64,
    inflight_latest: u64,
    loss_round_delivered: u64,
    loss_round_start: bool,
    // Startup (§2.13), and its loss exit (§5.3.1.3).
    full_bw_reached: bool,
    full_bw_now: bool,
    full_bw: u64,
    full_bw_count: u64,
    /// Discontiguous ranges lost in the current loss round.
    loss_events_in_round: u64,
    /// The end of the last range reported lost.
    last_loss_end: u64,
    /// round_count when the current fast recovery began; `None` after an RTO.
    fast_recovery_round: Option<u64>,
    // ProbeBW (§2.14).
    ack_phase: AckPhase,
    is_bw_probe_sample: bool,
    is_loss_in_round: bool,
    bw_probe_up_acked: u64,
    probe_up_acked_per_inc: u64,
    bw_probe_up_rounds: u32,
    rounds_since_probe_up: u64,
    bw_probe_wait: Duration,
    cycle_stamp: Instant,
    prev_probe_too_high: bool,
    prev_probe_precautionary: bool,
    /// C.is_cwnd_limited (spec §1.8): `cwnd_filled` OR-ed over the current round and the
    /// round before it.
    cwnd_limited_in_round: bool,
    cwnd_limited_last_round: bool,
    // min_rtt estimation inside the ProbeRTT machinery (§2.16, §5.3.4.3).
    probe_rtt_min_delay: Duration,
    probe_rtt_min_stamp: Instant,
}

impl Bbr {
    /// The state OnInit (§5.2.1) sets without the clock; `on_start` completes it.
    pub(crate) fn new(seed: u64) -> Self {
        Self {
            rng: SplitMix64(seed),
            smss: 0,
            initial_cwnd: 0,
            cwnd: 0,
            pacing_rate: 0,
            send_quantum: 0,
            state: State::Startup,
            pacing_gain: STARTUP_PACING_GAIN,
            cwnd_gain: DEFAULT_CWND_GAIN,
            // InitRoundCounting.
            round_count: 0,
            round_start: false,
            next_round_delivered: 0,
            drain_start_round: 0,
            // InitWindowedMaxFilter(value=0, time=0).
            max_bw: 0,
            max_bw_filter: WindowedMax::default(),
            cycle_count: 0,
            // ResetShortTermModel.
            bw_shortterm: INFINITE,
            bw: 0,
            min_rtt: INFINITE_RTT,
            min_rtt_stamp: Instant::from_nanos(0),
            extra_acked: 0,
            extra_acked_filter: WindowedMax::default(),
            extra_acked_interval_start: Instant::from_nanos(0),
            extra_acked_delivered: 0,
            max_inflight: 0,
            inflight_longterm: INFINITE,
            inflight_shortterm: INFINITE,
            // ResetCongestionSignals.
            bw_latest: 0,
            inflight_latest: 0,
            loss_round_delivered: 0,
            loss_round_start: false,
            // ResetFullBW.
            full_bw_reached: false,
            full_bw_now: false,
            full_bw: 0,
            full_bw_count: 0,
            loss_events_in_round: 0,
            last_loss_end: 0,
            fast_recovery_round: None,
            ack_phase: AckPhase::Init,
            is_bw_probe_sample: false,
            is_loss_in_round: false,
            bw_probe_up_acked: 0,
            probe_up_acked_per_inc: INFINITE,
            bw_probe_up_rounds: 0,
            rounds_since_probe_up: 0,
            bw_probe_wait: Duration::ZERO,
            cycle_stamp: Instant::from_nanos(0),
            prev_probe_too_high: false,
            prev_probe_precautionary: false,
            cwnd_limited_in_round: false,
            cwnd_limited_last_round: false,
            probe_rtt_min_delay: INFINITE_RTT,
            probe_rtt_min_stamp: Instant::from_nanos(0),
        }
    }

    #[cfg(test)]
    pub(crate) fn view(&self) -> BbrView {
        BbrView {
            state: self.state,
            phase: self.ack_phase,
            round_count: self.round_count,
            max_bw: self.max_bw,
            min_rtt: self.min_rtt,
            bw_shortterm: self.bw_shortterm,
            inflight_shortterm: self.inflight_shortterm,
            inflight_longterm: self.inflight_longterm,
            cwnd: self.cwnd,
            pacing_rate: self.pacing_rate,
        }
    }

    /// BBR.MinPipeCwnd (§2.8).
    fn min_pipe_cwnd(&self) -> u64 {
        4 * self.smss
    }

    // §5.2.3, per ACK.

    fn update_model_and_state(&mut self, rs: &RateSample) {
        self.update_latest_delivery_signals(rs);
        self.update_congestion_signals(rs);
        self.update_cwnd_limited(rs);
        self.update_ack_aggregation(rs);
        self.check_full_bw_reached(rs);
        self.check_startup_done(rs);
        self.check_drain_done(rs);
        self.update_probe_bw_cycle_phase(rs);
        self.update_min_rtt(rs);
        self.advance_latest_delivery_signals(rs);
        self.bound_bw_for_model();
    }

    fn update_control_parameters(&mut self, rs: &RateSample) {
        self.set_pacing_rate();
        self.set_send_quantum();
        self.set_cwnd(rs);
    }

    // State machine: Startup (§5.3.1), Drain (§5.3.2), ProbeBW entry (§5.3.3.9).

    fn enter_startup(&mut self) {
        self.state = State::Startup;
        self.pacing_gain = STARTUP_PACING_GAIN;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
    }

    fn check_startup_done(&mut self, rs: &RateSample) {
        self.check_startup_high_loss(rs);
        if self.state == State::Startup && self.full_bw_reached {
            self.enter_drain();
        }
    }

    /// §5.3.1.3. With SACK: a loss round that ends after a full packet-timed round of fast
    /// recovery, with at least six discontiguous ranges lost in it and a loss rate above
    /// LossThresh. Without SACK: any loss detected during fast recovery.
    fn check_startup_high_loss(&mut self, rs: &RateSample) {
        let in_fast_recovery = rs.in_recovery && self.fast_recovery_round.is_some();
        // The round in progress when fast recovery began ends at round r + 1; the next one,
        // wholly in fast recovery, at r + 2.
        let high_loss = if rs.sack {
            self.loss_round_start
                && in_fast_recovery
                && self
                    .fast_recovery_round
                    .is_some_and(|r| self.round_count >= r + 2)
                && self.loss_events_in_round >= STARTUP_FULL_LOSS_CNT
                && rs
                    .delivery
                    .is_some_and(|d| is_inflight_too_high(d.lost, d.tx_in_flight, true))
        } else {
            in_fast_recovery && self.loss_events_in_round > 0
        };
        if self.state == State::Startup && !self.full_bw_reached && high_loss {
            self.full_bw_reached = true;
            // Appendix A.2 expects full_bw_now as well.
            self.full_bw_now = true;
            self.inflight_longterm = self.bdp_multiple(UNITY_GAIN).max(self.inflight_latest);
        }
        if self.loss_round_start {
            self.loss_events_in_round = 0;
        }
    }

    fn reset_full_bw(&mut self) {
        self.full_bw = 0;
        self.full_bw_count = 0;
        self.full_bw_now = false;
    }

    fn check_full_bw_reached(&mut self, rs: &RateSample) {
        // round_start implies an ACK that delivered data.
        let Some(d) = rs.delivery.filter(|_| self.round_start) else {
            return;
        };
        if self.full_bw_now || d.is_app_limited {
            return;
        }
        let rate = delivery_rate(rs);
        // rate ≥ full_bw × 1.25, exactly.
        if u128::from(rate) * 4 >= u128::from(self.full_bw) * 5 {
            self.reset_full_bw();
            self.full_bw = rate;
            return;
        }
        self.full_bw_count += 1;
        self.full_bw_now = self.full_bw_count >= 3;
        if self.full_bw_now {
            self.full_bw_reached = true;
        }
    }

    fn enter_drain(&mut self) {
        self.state = State::Drain;
        self.pacing_gain = DRAIN_PACING_GAIN;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
        self.drain_start_round = self.round_count;
    }

    fn check_drain_done(&mut self, rs: &RateSample) {
        if self.state == State::Drain
            && (rs.inflight <= self.inflight(UNITY_GAIN)
                || self.round_count > self.drain_start_round + 3)
        {
            self.enter_probe_bw(rs);
        }
    }

    fn enter_probe_bw(&mut self, rs: &RateSample) {
        self.cwnd_gain = DEFAULT_CWND_GAIN;
        self.start_probe_bw_down(rs.now, rs.delivered);
    }

    // The draft gives each ProbeBW phase's gains in prose and in the table of §5.6.1.

    /// `delivered` is C.delivered.
    fn start_probe_bw_down(&mut self, now: Instant, delivered: u64) {
        self.reset_congestion_signals();
        // Not growing BBR.inflight_longterm.
        self.probe_up_acked_per_inc = INFINITE;
        self.pick_probe_wait();
        self.cycle_stamp = now;
        self.ack_phase = AckPhase::ProbeStopping;
        self.start_round(delivered);
        self.state = State::ProbeBwDown;
        self.pacing_gain = PROBE_DOWN_PACING_GAIN;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
    }

    fn start_probe_bw_cruise(&mut self) {
        self.state = State::ProbeBwCruise;
        self.pacing_gain = UNITY_GAIN;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
    }

    fn start_probe_bw_refill(&mut self, rs: &RateSample) {
        self.reset_short_term_model();
        self.bw_probe_up_rounds = 0;
        self.bw_probe_up_acked = 0;
        self.prev_probe_precautionary = false;
        self.ack_phase = AckPhase::Refilling;
        self.start_round(rs.delivered);
        self.state = State::ProbeBwRefill;
        self.pacing_gain = UNITY_GAIN;
        self.cwnd_gain = DEFAULT_CWND_GAIN;
    }

    fn start_probe_bw_up(&mut self, rs: &RateSample) {
        self.ack_phase = AckPhase::ProbeStarting;
        self.start_round(rs.delivered);
        self.reset_full_bw();
        self.full_bw = delivery_rate(rs);
        self.state = State::ProbeBwUp;
        self.pacing_gain = PROBE_UP_PACING_GAIN;
        self.cwnd_gain = PROBE_UP_CWND_GAIN;
        self.raise_inflight_longterm_slope();
    }

    /// §5.3.3.9, on each ACK that delivered data.
    fn update_probe_bw_cycle_phase(&mut self, rs: &RateSample) {
        if !self.full_bw_reached || rs.delivery.is_none() {
            return;
        }
        if self.adapt_long_term_model(rs) || !self.is_in_a_probe_bw_state() {
            return;
        }
        match self.state {
            State::ProbeBwDown => {
                if !self.is_time_to_probe_bw(rs) && self.is_time_to_cruise(rs) {
                    self.start_probe_bw_cruise();
                }
            }
            State::ProbeBwCruise => {
                self.is_time_to_probe_bw(rs);
            }
            State::ProbeBwRefill => {
                // After one round of REFILL, start UP.
                if self.round_start {
                    self.is_bw_probe_sample = true;
                    self.start_probe_bw_up(rs);
                }
            }
            State::ProbeBwUp => {
                if self.is_time_to_go_down(rs) {
                    // No high loss (yet).
                    self.prev_probe_too_high = false;
                    self.start_probe_bw_down(rs.now, rs.delivered);
                }
            }
            State::Startup | State::Drain | State::ProbeRtt => {}
        }
    }

    /// Time to go from DOWN to CRUISE? C.inflight leaves the headroom free and is within
    /// BBR.bdp (§5.3.3.1). The draft's pseudocode writes `Inflight(BBR.max_bw, 1.0)`, a
    /// signature it defines nowhere; this is its Inflight(1.0), on BBR.bw.
    fn is_time_to_cruise(&self, rs: &RateSample) -> bool {
        rs.inflight <= self.inflight_with_headroom() && rs.inflight <= self.inflight(UNITY_GAIN)
    }

    /// Time to go from UP to DOWN?
    fn is_time_to_go_down(&mut self, rs: &RateSample) -> bool {
        // Precautionary bandwidth probing: deceleration.
        if self.prev_probe_too_high && rs.inflight >= self.inflight_longterm {
            self.prev_probe_precautionary = true;
            return true;
        }
        if self.is_cwnd_limited() && self.cwnd >= self.inflight_longterm {
            // bw is limited by inflight_longterm.
            self.reset_full_bw();
            self.full_bw = delivery_rate(rs);
            false
        } else {
            // Have we fully used the path's bw?
            self.full_bw_now
        }
    }

    fn is_probing_bw(&self) -> bool {
        matches!(
            self.state,
            State::Startup | State::ProbeBwRefill | State::ProbeBwUp
        )
    }

    fn has_elapsed_in_phase(&self, interval: Duration, now: Instant) -> bool {
        now > self.cycle_stamp + interval
    }

    fn raise_inflight_longterm_slope(&mut self) {
        let growth_this_round = 1u64 << self.bw_probe_up_rounds;
        self.bw_probe_up_rounds = (self.bw_probe_up_rounds + 1).min(30);
        // Rounded up: inflight_longterm grows no faster than the slope.
        self.probe_up_acked_per_inc = self.cwnd.div_ceil(growth_this_round).max(self.smss);
    }

    fn probe_inflight_longterm_upward(&mut self, rs: &RateSample) {
        if !self.is_cwnd_limited() || self.cwnd < self.inflight_longterm {
            // Not fully using inflight_longterm, so not growing it.
            return;
        }
        self.bw_probe_up_acked += rs.delivery.map_or(0, |d| d.newly_acked);
        if self.bw_probe_up_acked >= self.probe_up_acked_per_inc {
            let delta = self.bw_probe_up_acked / self.probe_up_acked_per_inc;
            self.bw_probe_up_acked -= delta * self.probe_up_acked_per_inc;
            self.inflight_longterm = self
                .inflight_longterm
                .saturating_add(delta.saturating_mul(self.smss));
        }
        if self.round_start {
            self.raise_inflight_longterm_slope();
        }
    }

    /// Tracks the ACK phase, advances the max_bw filter and raises inflight_longterm. True if
    /// it decided a state transition.
    fn adapt_long_term_model(&mut self, rs: &RateSample) -> bool {
        let Some(d) = rs.delivery else {
            return false;
        };
        if self.ack_phase == AckPhase::ProbeStarting && self.round_start {
            // Starting to get bw probing samples.
            self.ack_phase = AckPhase::ProbeFeedback;
        }
        if self.ack_phase == AckPhase::ProbeStopping && self.round_start {
            // End of samples from the bw probing phase.
            self.is_bw_probe_sample = false;
            self.ack_phase = AckPhase::Init;
            if self.is_in_a_probe_bw_state() && !d.is_app_limited {
                self.advance_max_bw_filter();
            }
            // Precautionary bandwidth probing: acceleration.
            if self.is_in_a_probe_bw_state()
                && self.prev_probe_precautionary
                && !self.prev_probe_too_high
            {
                self.start_probe_bw_refill(rs);
                return true;
            }
        }
        if !is_inflight_too_high(d.lost, d.tx_in_flight, rs.sack) {
            // The loss rate is safe: adjust the upper bounds upward.
            if self.inflight_longterm == INFINITE {
                return false;
            }
            self.inflight_longterm = self.inflight_longterm.max(d.tx_in_flight);
            if self.state == State::ProbeBwUp {
                self.probe_inflight_longterm_upward(rs);
            }
        }
        false
    }

    /// Time to go from DOWN or CRUISE to REFILL? Starts REFILL if so (§5.3.3.8.2).
    fn is_time_to_probe_bw(&mut self, rs: &RateSample) -> bool {
        if self.has_elapsed_in_phase(self.bw_probe_wait, rs.now)
            || self.is_reno_coexistence_probe_time()
        {
            self.start_probe_bw_refill(rs);
            return true;
        }
        false
    }

    /// T_reno: TargetInflight in packets, at most 63 rounds.
    fn is_reno_coexistence_probe_time(&self) -> bool {
        // Rounded up: never probes sooner than Reno's sawtooth would.
        let reno_rounds = self.target_inflight().div_ceil(self.smss);
        self.rounds_since_probe_up >= reno_rounds.min(63)
    }

    /// Our estimated BDP, unless congestion cut C.cwnd.
    fn target_inflight(&self) -> u64 {
        self.bdp_multiple(UNITY_GAIN).min(self.cwnd)
    }

    /// §5.3.3.8.2: 0 or 1 rounds, and 2 s plus a uniform 0..1 s.
    fn pick_probe_wait(&mut self) {
        self.rounds_since_probe_up = self.rng.next() >> 63;
        self.bw_probe_wait =
            Duration::from_secs(2) + Duration::from_nanos(self.rng.next() % 1_000_000_000);
    }

    fn is_in_a_probe_bw_state(&self) -> bool {
        matches!(
            self.state,
            State::ProbeBwDown | State::ProbeBwCruise | State::ProbeBwRefill | State::ProbeBwUp
        )
    }

    /// A volume that leaves free headroom below inflight_longterm (§5.3.3.9).
    fn inflight_with_headroom(&self) -> u64 {
        if self.inflight_longterm == INFINITE {
            return INFINITE;
        }
        let (num, den) = HEADROOM;
        // Rounded up: the headroom left free is never below 15%.
        let headroom =
            (u128::from(self.inflight_longterm) * u128::from(num)).div_ceil(u128::from(den));
        let headroom = u64::try_from(headroom).unwrap_or(INFINITE).max(self.smss);
        self.inflight_longterm
            .saturating_sub(headroom)
            .max(self.min_pipe_cwnd())
    }

    // The model (§5.5).

    /// UpdateRound (§5.5.1), for an ACK that delivered data sent after `prior_delivered`.
    fn update_round(&mut self, prior_delivered: u64, delivered: u64) {
        if prior_delivered >= self.next_round_delivered {
            self.start_round(delivered);
            self.round_count += 1;
            self.rounds_since_probe_up += 1;
            self.round_start = true;
        } else {
            self.round_start = false;
        }
    }

    fn start_round(&mut self, delivered: u64) {
        self.next_round_delivered = delivered;
    }

    /// §5.5.5, for every ACK that delivered data (RS.has_data), with or without a rate.
    fn update_max_bw(&mut self, rs: &RateSample) {
        let Some(d) = rs.delivery else {
            // An ACK that delivered nothing ends no round.
            self.round_start = false;
            return;
        };
        self.update_round(d.prior_delivered, rs.delivered);
        let rate = delivery_rate(rs);
        if rate > 0 && (rate >= self.max_bw || !d.is_app_limited) {
            self.max_bw = self
                .max_bw_filter
                .update(rate, self.cycle_count, MAX_BW_FILTER_LEN);
        }
    }

    /// §5.5.6: one ProbeBW cycle of virtual time for the max_bw filter.
    fn advance_max_bw_filter(&mut self) {
        self.cycle_count += 1;
    }

    /// The min_rtt filter of §5.5.7.2, as the draft integrates it with ProbeRTT (§5.3.4.3).
    fn update_min_rtt(&mut self, rs: &RateSample) {
        let now = rs.now;
        let probe_rtt_expired = now > self.probe_rtt_min_stamp + PROBE_RTT_INTERVAL;
        if let Some(rtt) = rs.rtt {
            if rtt < self.probe_rtt_min_delay || probe_rtt_expired {
                self.probe_rtt_min_delay = rtt;
                self.probe_rtt_min_stamp = now;
            }
        }
        let min_rtt_expired = now > self.min_rtt_stamp + MIN_RTT_FILTER_LEN;
        if self.probe_rtt_min_delay < self.min_rtt || min_rtt_expired {
            self.min_rtt = self.probe_rtt_min_delay;
            self.min_rtt_stamp = self.probe_rtt_min_stamp;
        }
    }

    /// §5.5.9.
    fn update_ack_aggregation(&mut self, rs: &RateSample) {
        let interval = rs.now - self.extra_acked_interval_start;
        // Rounded down: at most one octet more extra_acked.
        let mut expected_delivered =
            mul_div(u128::from(self.bw), interval.as_nanos(), NANOS_PER_SEC);
        if self.extra_acked_delivered <= expected_delivered {
            self.extra_acked_delivered = 0;
            self.extra_acked_interval_start = rs.now;
            expected_delivered = 0;
        }
        self.extra_acked_delivered += rs.delivery.map_or(0, |d| d.newly_acked);
        let extra = (self.extra_acked_delivered - expected_delivered).min(self.cwnd);
        let filter_len = if self.full_bw_reached {
            EXTRA_ACKED_FILTER_LEN
        } else {
            // In Startup, just remember 1 round.
            1
        };
        self.extra_acked = self
            .extra_acked_filter
            .update(extra, self.round_count, filter_len);
    }

    // Responding to congestion (§5.5.10).

    /// Near the start of ACK processing.
    fn update_latest_delivery_signals(&mut self, rs: &RateSample) {
        self.loss_round_start = false;
        let Some(d) = rs.delivery else {
            return;
        };
        self.bw_latest = self.bw_latest.max(delivery_rate(rs));
        self.inflight_latest = self.inflight_latest.max(d.delivered);
        if d.prior_delivered >= self.loss_round_delivered {
            self.loss_round_delivered = rs.delivered;
            self.loss_round_start = true;
        }
    }

    /// Near the end of ACK processing.
    fn advance_latest_delivery_signals(&mut self, rs: &RateSample) {
        if let Some(d) = rs.delivery.filter(|_| self.loss_round_start) {
            self.bw_latest = delivery_rate(rs);
            self.inflight_latest = d.delivered;
        }
    }

    fn reset_congestion_signals(&mut self) {
        self.is_loss_in_round = false;
        self.bw_latest = 0;
        self.inflight_latest = 0;
    }

    fn update_congestion_signals(&mut self, rs: &RateSample) {
        self.update_max_bw(rs);
        if !self.loss_round_start {
            // Wait until the end of the round trip.
            return;
        }
        self.adapt_lower_bounds_from_congestion();
        self.is_loss_in_round = false;
    }

    /// Once per round trip, respond to congestion.
    fn adapt_lower_bounds_from_congestion(&mut self) {
        if self.is_probing_bw() {
            return;
        }
        if self.is_loss_in_round {
            self.init_lower_bounds();
            self.loss_lower_bounds();
        }
    }

    /// The first congestion episode in this cycle.
    fn init_lower_bounds(&mut self) {
        if self.bw_shortterm == INFINITE {
            self.bw_shortterm = self.max_bw;
        }
        if self.inflight_shortterm == INFINITE {
            self.inflight_shortterm = self.cwnd;
        }
    }

    fn loss_lower_bounds(&mut self) {
        self.bw_shortterm = self.bw_latest.max(times_beta(self.bw_shortterm));
        self.inflight_shortterm = self
            .inflight_latest
            .max(times_beta(self.inflight_shortterm));
    }

    fn reset_short_term_model(&mut self) {
        self.bw_shortterm = INFINITE;
        self.inflight_shortterm = INFINITE;
    }

    /// C.is_cwnd_limited (spec §1.8), after this ACK's round_start is known.
    fn update_cwnd_limited(&mut self, rs: &RateSample) {
        self.cwnd_limited_in_round |= rs.cwnd_filled;
        if self.round_start {
            self.cwnd_limited_last_round = self.cwnd_limited_in_round;
            self.cwnd_limited_in_round = false;
        }
    }

    fn is_cwnd_limited(&self) -> bool {
        self.cwnd_limited_last_round || self.cwnd_limited_in_round
    }

    /// `delivered` is C.delivered.
    fn note_loss(&mut self, delivered: u64) {
        // First loss in this round trip?
        if !self.is_loss_in_round {
            self.loss_round_delivered = delivered;
        }
        self.is_loss_in_round = true;
    }

    /// HandleLostPacket (§5.2.4, §5.5.10.2) for one lost range. Losses from fast-retransmit
    /// sends arrive here outside any ACK; the per-round accounting takes them at the next
    /// delivery sample (spec §1.4).
    fn handle_lost_packet(&mut self, e: &LossEvent) {
        self.note_loss(e.delivered);
        // Startup's loss exit counts discontiguous ranges (§5.3.1.3).
        if self.loss_events_in_round == 0 || e.start != self.last_loss_end {
            self.loss_events_in_round += 1;
        }
        self.last_loss_end = e.end;
        if !self.is_bw_probe_sample {
            // Not sent while probing bandwidth.
            return;
        }
        if is_inflight_too_high(e.lost_since_tx, e.tx_in_flight, e.sack) {
            let tx_in_flight = inflight_at_loss(e);
            self.handle_inflight_too_high(tx_in_flight, e.is_app_limited, e.now, e.delivered);
        }
    }

    fn handle_inflight_too_high(
        &mut self,
        tx_in_flight: u64,
        is_app_limited: bool,
        now: Instant,
        delivered: u64,
    ) {
        self.prev_probe_too_high = true;
        // Only react once per bw probe.
        self.is_bw_probe_sample = false;
        if !is_app_limited {
            self.inflight_longterm = tx_in_flight.max(times_beta(self.target_inflight()));
        }
        if self.state == State::ProbeBwUp {
            self.start_probe_bw_down(now, delivered);
        }
    }

    fn bound_bw_for_model(&mut self) {
        self.bw = self.max_bw.min(self.bw_shortterm);
    }

    // Control parameters (§5.6).

    fn init_pacing_rate(&mut self, srtt: Option<Duration>) {
        let (num, den) = STARTUP_PACING_GAIN;
        let srtt = srtt.unwrap_or(Duration::from_millis(1)).as_nanos();
        // Rounded down: never paced above the gain.
        self.pacing_rate = mul_div(
            u128::from(self.initial_cwnd),
            u128::from(num) * NANOS_PER_SEC,
            u128::from(den) * srtt,
        );
    }

    fn set_pacing_rate_with_gain(&mut self, (num, den): Gain) {
        // Rounded down: never paced above the gain.
        let rate = mul_div(
            u128::from(self.bw),
            u128::from(num * (100 - PACING_MARGIN_PERCENT)),
            u128::from(den) * 100,
        );
        if self.full_bw_reached || rate > self.pacing_rate {
            self.pacing_rate = rate;
        }
    }

    fn set_pacing_rate(&mut self) {
        self.set_pacing_rate_with_gain(self.pacing_gain);
    }

    fn set_send_quantum(&mut self) {
        // pacing_rate × 1 ms, rounded down; the 2·SMSS floor bounds the loss.
        let quantum = self.pacing_rate / 1000;
        self.send_quantum = quantum.min(MAX_SEND_QUANTUM).max(2 * self.smss);
    }

    /// §5.6.4.2.
    fn bdp_multiple(&self, (num, den): Gain) -> u64 {
        if self.min_rtt == INFINITE_RTT {
            // No valid RTT samples yet.
            return self.initial_cwnd;
        }
        // gain × bw × min_rtt, rounded down: the model's volume is never overstated.
        mul_div(
            u128::from(self.bw),
            self.min_rtt.as_nanos() * u128::from(num),
            u128::from(den) * NANOS_PER_SEC,
        )
    }

    fn quantization_budget(&self, inflight_cap: u64) -> u64 {
        // UpdateOffloadBudget for TCP (§5.5.8.1).
        let offload_budget = 3 * self.send_quantum;
        let mut inflight_cap = inflight_cap.max(offload_budget).max(self.min_pipe_cwnd());
        if self.state == State::ProbeBwUp {
            inflight_cap = inflight_cap.saturating_add(2 * self.smss);
        }
        inflight_cap
    }

    fn inflight(&self, gain: Gain) -> u64 {
        self.quantization_budget(self.bdp_multiple(gain))
    }

    fn update_max_inflight(&mut self) {
        let inflight_cap = self
            .bdp_multiple(self.cwnd_gain)
            .saturating_add(self.extra_acked);
        self.max_inflight = self.quantization_budget(inflight_cap);
    }

    /// §5.6.4.6.
    fn set_cwnd(&mut self, rs: &RateSample) {
        self.update_max_inflight();
        let newly_acked = rs.delivery.map_or(0, |d| d.newly_acked);
        if self.full_bw_reached {
            self.cwnd = self.cwnd.saturating_add(newly_acked).min(self.max_inflight);
        } else if self.cwnd < self.max_inflight || rs.delivered < self.initial_cwnd {
            self.cwnd = self.cwnd.saturating_add(newly_acked);
        }
        self.cwnd = self.cwnd.max(self.min_pipe_cwnd());
        self.bound_cwnd_for_model();
    }

    /// §5.6.4.7.
    fn bound_cwnd_for_model(&mut self) {
        let mut cap = INFINITE;
        if self.is_in_a_probe_bw_state() && self.state != State::ProbeBwCruise {
            cap = self.inflight_longterm;
        } else if matches!(self.state, State::ProbeRtt | State::ProbeBwCruise) {
            cap = self.inflight_with_headroom();
        }
        // inflight_shortterm, possibly infinite.
        cap = cap.min(self.inflight_shortterm).max(self.min_pipe_cwnd());
        self.cwnd = self.cwnd.min(cap);
    }
}

/// IsInflightTooHigh (§5.5.10.2): `lost` > LossThresh × `tx_in_flight`, compared exactly, or
/// any loss without SACK.
fn is_inflight_too_high(lost: u64, tx_in_flight: u64, sack: bool) -> bool {
    let (num, den) = LOSS_THRESH;
    u128::from(lost) * u128::from(den) > u128::from(tx_in_flight) * u128::from(num)
        || (lost > 0 && !sack)
}

/// InflightAtLoss (§5.5.10.2): the C.inflight at which losses crossed LossThresh within the
/// lost range, solving (lost_prev + lost_prefix) / (inflight_prev + lost_prefix) = LossThresh.
fn inflight_at_loss(e: &LossEvent) -> u64 {
    let (num, den) = (i128::from(LOSS_THRESH.0), i128::from(LOSS_THRESH.1));
    let inflight_prev = i128::from(e.tx_in_flight.saturating_sub(e.len));
    let lost_prev = i128::from(e.lost_since_tx.saturating_sub(e.len));
    // Rounded toward −∞: inflight_longterm is never set above the crossing point.
    let lost_prefix = (num * inflight_prev - den * lost_prev).div_euclid(den - num);
    u64::try_from((inflight_prev + lost_prefix).max(0)).unwrap_or(0)
}

/// BBR.Beta × `x`.
fn times_beta(x: u64) -> u64 {
    let (num, den) = BETA;
    // Rounded down: the bound is never above Beta × x.
    mul_div(u128::from(x), u128::from(num), u128::from(den))
}

/// RS.delivery_rate: 0 when the sample has no valid rate (§4.1.2.3).
fn delivery_rate(rs: &RateSample) -> u64 {
    rs.delivery
        .and_then(|d| d.rate)
        .map_or(0, |(delivered, interval)| {
            // Rounded down: max_bw is never overstated.
            mul_div(
                u128::from(delivered),
                NANOS_PER_SEC,
                interval.as_nanos().max(1),
            )
        })
}

impl CongestionControl for Bbr {
    /// C.InitialCwnd is the transport's (§5.6.4.1).
    fn init(&mut self, smss: u32, syn_lost: bool) {
        self.smss = u64::from(smss);
        self.initial_cwnd = u64::from(initial_window(smss, syn_lost));
        self.cwnd = self.initial_cwnd;
    }

    /// The clock-dependent rest of OnInit (§5.2.1). A zero srtt counts as none.
    fn on_start(&mut self, start: &Start) {
        let srtt = start.srtt.filter(|d| !d.is_zero());
        self.min_rtt = srtt.unwrap_or(INFINITE_RTT);
        self.min_rtt_stamp = start.now;
        self.probe_rtt_min_delay = self.min_rtt;
        self.probe_rtt_min_stamp = start.now;
        self.extra_acked_interval_start = start.now;
        self.init_pacing_rate(srtt);
        // The draft sets no initial C.send_quantum; the first sends need one.
        self.set_send_quantum();
        self.enter_startup();
    }

    /// UpdateOnACK (§5.2.3); the sampler has already generated the rate sample.
    fn on_rate_sample(&mut self, rs: &RateSample) {
        self.update_model_and_state(rs);
        self.update_control_parameters(rs);
    }

    /// Records when fast recovery began, for Startup's loss exit (§5.3.1.3).
    fn on_recovery_start(&mut self, r: &RecoveryStart) {
        self.fast_recovery_round = (r.kind == RecoveryKind::Fast).then_some(self.round_count);
    }

    fn on_loss(&mut self, e: &LossEvent) {
        self.handle_lost_packet(e);
    }

    fn on_ack(&mut self, _: &AckSample) {}

    fn on_congestion(&mut self, _: CongestionEvent, _: u32, _: Instant) {}

    fn on_recovery_ack(&mut self, _: RecoveryAck) {}

    fn cwnd(&self) -> u32 {
        u32::try_from(self.cwnd).unwrap_or(u32::MAX)
    }

    fn send_quantum(&self) -> Option<u32> {
        Some(u32::try_from(self.send_quantum).unwrap_or(u32::MAX))
    }

    fn pacing_rate(&self) -> Option<u64> {
        Some(self.pacing_rate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::cc::Delivery;

    const SMSS: u32 = 1000;
    const T0: Instant = Instant::from_nanos(0);
    const SEED: u64 = 7;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn at(n_ms: u64) -> Instant {
        T0 + ms(n_ms)
    }

    fn started(smss: u32, srtt: Option<Duration>) -> Bbr {
        let mut bbr = Bbr::new(SEED);
        bbr.init(smss, false);
        bbr.on_start(&Start {
            smss,
            syn_lost: false,
            srtt,
            sack: true,
            now: T0,
        });
        bbr
    }

    /// One ACK ending a packet-timed round: `delivered` octets, all sent after the round's
    /// start, acknowledged over `interval`.
    fn sample(
        bbr: &Bbr,
        delivered: u64,
        interval: Duration,
        rtt: Duration,
        now: Instant,
    ) -> RateSample {
        let prior = bbr.next_round_delivered;
        RateSample {
            delivery: Some(Delivery {
                prior_delivered: prior,
                prior_time: T0,
                delivered,
                newly_acked: delivered,
                is_app_limited: false,
                tx_in_flight: 0,
                lost: 0,
                rate: Some((delivered, interval)),
            }),
            rtt: Some(rtt),
            newly_lost: 0,
            delivered: prior + delivered,
            lost: 0,
            inflight: 0,
            in_recovery: false,
            recovery_exit: false,
            cwnd_filled: true,
            sack: true,
            now,
        }
    }

    fn ack(bbr: &mut Bbr, delivered: u64, interval: Duration, rtt: Duration, now: Instant) {
        let rs = sample(bbr, delivered, interval, rtt, now);
        bbr.on_rate_sample(&rs);
    }

    /// A round over a 10 ms RTT with `inflight` left outstanding.
    fn ack_with(bbr: &mut Bbr, delivered: u64, inflight: u64, now: Instant) {
        let mut rs = sample(bbr, delivered, ms(10), ms(10), now);
        rs.inflight = inflight;
        bbr.on_rate_sample(&rs);
    }

    /// Four rounds at 10 MB/s over 10 ms (BDP 100 000) with 300 000 in flight: a baseline and
    /// three rounds without growth, ending in Drain.
    fn to_drain(bbr: &mut Bbr) {
        for i in 1..=4 {
            ack_with(bbr, 100_000, 300_000, at(10 * i));
        }
        assert_eq!(bbr.view().state, State::Drain);
    }

    /// ProbeBW_DOWN after Drain's three-round limit, with C.inflight held above BBR.bdp
    /// (100 000) so DOWN does not move on to CRUISE.
    fn to_probe_bw_down(bbr: &mut Bbr) {
        to_drain(bbr);
        for i in 5..=8 {
            ack_with(bbr, 100_000, 300_000, at(10 * i));
        }
        assert_eq!(bbr.view().state, State::ProbeBwDown);
    }

    /// DOWN, CRUISE, then REFILL once bw_probe_wait has elapsed. Returns REFILL's start.
    fn to_probe_bw_refill(bbr: &mut Bbr) -> Instant {
        to_probe_bw_down(bbr);
        ack_with(bbr, 100_000, 100_000, at(90));
        assert_eq!(bbr.view().state, State::ProbeBwCruise);
        let t = bbr.cycle_stamp + bbr.bw_probe_wait + ms(1);
        ack_with(bbr, 100_000, 100_000, t);
        assert_eq!(bbr.view().state, State::ProbeBwRefill);
        t
    }

    /// REFILL, then UP after one round. Returns UP's start.
    fn to_probe_bw_up(bbr: &mut Bbr) -> Instant {
        let t = to_probe_bw_refill(bbr) + ms(10);
        ack_with(bbr, 100_000, 100_000, t);
        assert_eq!(bbr.view().state, State::ProbeBwUp);
        t
    }

    /// A lost range (SACK), noted at the current C.delivered.
    fn loss(bbr: &Bbr, start: u64, len: u64, tx_in_flight: u64, lost_since_tx: u64) -> LossEvent {
        LossEvent {
            start,
            end: start + len,
            len,
            tx_in_flight,
            lost_since_tx,
            is_app_limited: false,
            delivered: bbr.next_round_delivered,
            sack: true,
            now: T0,
        }
    }

    fn recovery_start(bbr: &mut Bbr, kind: RecoveryKind) {
        bbr.on_recovery_start(&RecoveryStart {
            kind,
            inflight: 0,
            now: T0,
        });
    }

    /// An ACK that delivers nothing (a duplicate ACK) during recovery, without SACK.
    fn dup_ack_no_sack(bbr: &mut Bbr, now: Instant) {
        let mut rs = sample(bbr, 0, ms(10), ms(10), now);
        rs.delivery = None;
        rs.delivered = bbr.next_round_delivered;
        rs.inflight = 1_000_000;
        rs.in_recovery = true;
        rs.sack = false;
        bbr.on_rate_sample(&rs);
    }

    /// Six discontiguous 1000-octet ranges from `base`.
    fn six_ranges(base: u64) -> [(u64, u64); 6] {
        std::array::from_fn(|i| (base + 2_000 * i as u64, 1_000))
    }

    /// One Startup round in fast recovery: `ranges` are lost, then a round-ending ACK
    /// delivers `delivered` over 10 ms; its packet saw `lost` of 400 000 in flight lost. A
    /// million octets stay in flight, so a Drain entered here does not end at once.
    fn recovery_round(
        bbr: &mut Bbr,
        ranges: &[(u64, u64)],
        delivered: u64,
        lost: u64,
        now: Instant,
    ) {
        for &(start, len) in ranges {
            let e = loss(bbr, start, len, 400_000, lost);
            bbr.on_loss(&e);
        }
        let mut rs = sample(bbr, delivered, ms(10), ms(10), now);
        rs.inflight = 1_000_000;
        rs.in_recovery = true;
        let d = rs.delivery.as_mut().expect("delivery");
        d.lost = lost;
        d.tx_in_flight = 400_000;
        bbr.on_rate_sample(&rs);
    }

    #[test]
    fn probe_bw_cycle_down_cruise_refill_up() {
        let mut bbr = started(SMSS, None);
        to_probe_bw_down(&mut bbr);
        // The round-ending ACK that entered DOWN also ended ACKS_PROBE_STOPPING.
        assert_eq!(bbr.view().phase, AckPhase::Init);
        assert_eq!(bbr.cycle_count, 1);
        assert_eq!(bbr.view().pacing_rate, 8_910_000);

        // DOWN until C.inflight is within BBR.bdp; then CRUISE at 1.0.
        ack_with(&mut bbr, 100_000, 100_001, at(90));
        assert_eq!(bbr.view().state, State::ProbeBwDown);
        ack_with(&mut bbr, 100_000, 100_000, at(100));
        assert_eq!(bbr.view().state, State::ProbeBwCruise);
        assert_eq!(bbr.view().pacing_rate, 9_900_000);

        // CRUISE until bw_probe_wait has elapsed (strictly), then REFILL at 1.0.
        let probe_at = bbr.cycle_stamp + bbr.bw_probe_wait;
        ack_with(&mut bbr, 100_000, 100_000, probe_at);
        assert_eq!(bbr.view().state, State::ProbeBwCruise);
        ack_with(&mut bbr, 100_000, 100_000, probe_at + ms(1));
        let v = bbr.view();
        assert_eq!(v.state, State::ProbeBwRefill);
        assert_eq!(v.phase, AckPhase::Refilling);
        assert_eq!(v.pacing_rate, 9_900_000);
        assert_eq!(bbr.cwnd_gain, DEFAULT_CWND_GAIN);
        assert_eq!(bbr.next_round_delivered, 1_200_000, "StartRound");

        // An ACK that ends no round stays in REFILL.
        let mut rs = sample(&bbr, 100_000, ms(10), ms(10), probe_at + ms(5));
        rs.delivery.as_mut().expect("delivery").prior_delivered = 0;
        bbr.on_rate_sample(&rs);
        assert_eq!(bbr.view().state, State::ProbeBwRefill);

        // After one round, UP: 1.25 × 10 MB/s × 99%, cwnd gain 2.25.
        ack_with(&mut bbr, 100_000, 100_000, probe_at + ms(10));
        let v = bbr.view();
        assert_eq!(v.state, State::ProbeBwUp);
        assert_eq!(v.phase, AckPhase::ProbeStarting);
        assert!(bbr.is_bw_probe_sample);
        assert_eq!(v.pacing_rate, 12_375_000);
        assert_eq!(bbr.cwnd_gain, PROBE_UP_CWND_GAIN);
        assert_eq!(bbr.full_bw, 10_000_000);
        assert_eq!(bbr.bw_probe_up_rounds, 1);

        // UP until three rounds without 25% growth fill the pipe.
        ack_with(&mut bbr, 100_000, 100_000, probe_at + ms(20));
        assert_eq!(bbr.view().phase, AckPhase::ProbeFeedback);
        ack_with(&mut bbr, 100_000, 100_000, probe_at + ms(30));
        assert_eq!(bbr.view().state, State::ProbeBwUp);
        let down_at = probe_at + ms(40);
        ack_with(&mut bbr, 100_000, 100_000, down_at);
        let v = bbr.view();
        assert_eq!(v.state, State::ProbeBwDown);
        assert_eq!(v.phase, AckPhase::ProbeStopping);
        assert_eq!(v.pacing_rate, 8_910_000);
        assert_eq!(bbr.cycle_stamp, down_at);
        assert!(!bbr.prev_probe_too_high);

        // The next round ends the probe's feedback and advances the max_bw filter.
        ack_with(&mut bbr, 100_000, 300_000, down_at + ms(10));
        assert_eq!(bbr.view().phase, AckPhase::Init);
        assert!(!bbr.is_bw_probe_sample);
        assert_eq!(bbr.cycle_count, 2);
        assert_eq!(bbr.view().state, State::ProbeBwDown);
    }

    #[test]
    fn probe_wait_randomized_by_seed() {
        let wait = |seed| {
            let mut bbr = Bbr::new(seed);
            bbr.pick_probe_wait();
            (bbr.rounds_since_probe_up, bbr.bw_probe_wait)
        };
        let waits: Vec<_> = (0..64).map(wait).collect();
        for &(rounds, wait) in &waits {
            assert!(rounds <= 1);
            assert!(wait >= Duration::from_secs(2) && wait < Duration::from_secs(3));
        }
        assert!(waits.iter().any(|w| w.0 == 0) && waits.iter().any(|w| w.0 == 1));
        assert_ne!(waits[1].1, waits[2].1, "two seeds, two waits");
        assert_eq!(wait(1), waits[1], "one seed, one wait");
    }

    #[test]
    fn inflight_too_high_cuts_longterm() {
        let mut bbr = started(SMSS, None);
        to_probe_bw_up(&mut bbr);
        assert!(bbr.cwnd >= 100_000);
        // Exactly 2% lost since transmit is not too high.
        bbr.on_loss(&loss(&bbr, 2_000_000, 1_000, 100_000, 2_000));
        assert_eq!(bbr.view().state, State::ProbeBwUp);
        assert_eq!(bbr.view().inflight_longterm, INFINITE);

        // Above 2%: inflight_longterm is where the loss rate crossed 2% within the range.
        // inflight_prev 99 000, lost_prev 1 100: lost_prefix = (0.02 × 99 000 − 1 100) / 0.98
        // = 897.9…, so 99 897.
        let down_at = at(5_000);
        let mut e = loss(&bbr, 2_010_000, 1_000, 100_000, 2_100);
        e.now = down_at;
        bbr.on_loss(&e);
        let v = bbr.view();
        assert_eq!(v.inflight_longterm, 99_897);
        assert_eq!(v.state, State::ProbeBwDown);
        assert_eq!(bbr.cycle_stamp, down_at);
        assert!(bbr.prev_probe_too_high && !bbr.is_bw_probe_sample);
        // Once per probe.
        bbr.on_loss(&loss(&bbr, 2_020_000, 1_000, 50_000, 10_000));
        assert_eq!(bbr.view().inflight_longterm, 99_897);

        // Heavy loss: the crossing point (9 000 − 3 897.9…) is below Beta × TargetInflight,
        // 0.7 × min(BBR.bdp 100 000, cwnd), which is the floor.
        let mut bbr = started(SMSS, None);
        to_probe_bw_up(&mut bbr);
        bbr.on_loss(&loss(&bbr, 2_000_000, 1_000, 10_000, 5_000));
        assert_eq!(bbr.view().inflight_longterm, 70_000);
        assert_eq!(bbr.view().state, State::ProbeBwDown);

        // Without SACK any loss is too high, even 1%. InflightAtLoss still solves for the 2%
        // crossing, which here lies above tx_in_flight: 99 000 + 0.02 × 99 000 / 0.98.
        let mut bbr = started(SMSS, None);
        to_probe_bw_up(&mut bbr);
        let mut e = loss(&bbr, 2_000_000, 1_000, 100_000, 1_000);
        e.sack = false;
        bbr.on_loss(&e);
        assert_eq!(bbr.view().inflight_longterm, 101_020);
        assert_eq!(bbr.view().state, State::ProbeBwDown);

        // An app-limited range leaves inflight_longterm but still ends the probe.
        let mut bbr = started(SMSS, None);
        to_probe_bw_up(&mut bbr);
        let mut e = loss(&bbr, 2_000_000, 1_000, 100_000, 3_000);
        e.is_app_limited = true;
        bbr.on_loss(&e);
        assert_eq!(bbr.view().inflight_longterm, INFINITE);
        assert_eq!(bbr.view().state, State::ProbeBwDown);
    }

    #[test]
    fn startup_exits_on_loss_after_full_recovery_round() {
        // Six discontiguous ranges and 10 000 of 400 000 (2.5%) lost exit Startup; five
        // discontiguous ranges, or exactly 2%, do not.
        let mut five = six_ranges(100_000);
        five[1].0 = five[0].0 + five[0].1;
        for (ranges, lost, exits) in [
            (six_ranges(100_000), 10_000, true),
            (five, 10_000, false),
            (six_ranges(100_000), 8_000, false),
        ] {
            let mut bbr = started(SMSS, None);
            ack(&mut bbr, 100_000, ms(10), ms(10), at(10));
            recovery_start(&mut bbr, RecoveryKind::Fast);
            // The round in progress when fast recovery began is not a full one.
            recovery_round(&mut bbr, &six_ranges(0), 200_000, 10_000, at(20));
            assert_eq!(bbr.view().state, State::Startup);
            recovery_round(&mut bbr, &ranges, 400_000, lost, at(30));
            let v = bbr.view();
            assert_eq!(v.round_count, 3);
            if !exits {
                assert_eq!(v.state, State::Startup, "{ranges:?} {lost}");
                assert_eq!(v.inflight_longterm, INFINITE);
                continue;
            }
            assert_eq!(v.state, State::Drain);
            assert!(bbr.full_bw_reached && bbr.full_bw_now);
            // max(BBR.bdp = 20 MB/s × 10 ms, inflight_latest = this round's 400 000).
            assert_eq!(v.inflight_longterm, 400_000);
        }
    }

    #[test]
    fn startup_stays_when_threshold_before_recovery_round() {
        let mut bbr = started(SMSS, None);
        ack(&mut bbr, 100_000, ms(10), ms(10), at(10));
        recovery_start(&mut bbr, RecoveryKind::Fast);
        // Six ranges and 2.5% in the round fast recovery began in: too early.
        recovery_round(&mut bbr, &six_ranges(0), 200_000, 10_000, at(20));
        let v = bbr.view();
        assert_eq!(v.state, State::Startup);
        assert!(!bbr.full_bw_reached);
        assert_eq!(v.inflight_longterm, INFINITE);
        // Each loss round counts its own ranges: a full recovery round that loses none does
        // not exit on the earlier round's.
        recovery_round(&mut bbr, &[], 400_000, 10_000, at(30));
        assert_eq!(bbr.view().state, State::Startup);
    }

    #[test]
    fn startup_no_sack_rule() {
        let mut bbr = started(SMSS, None);
        let mut rs = sample(&bbr, 100_000, ms(10), ms(10), at(10));
        rs.sack = false;
        bbr.on_rate_sample(&rs);
        recovery_start(&mut bbr, RecoveryKind::Fast);
        // The ACK that enters fast recovery: the fast retransmit reports its range later.
        dup_ack_no_sack(&mut bbr, at(15));
        assert_eq!(bbr.view().state, State::Startup);
        let mut e = loss(&bbr, 100_000, 1_000, 100_000, 1_000);
        e.sack = false;
        bbr.on_loss(&e);
        // One loss during fast recovery is enough without SACK.
        dup_ack_no_sack(&mut bbr, at(16));
        let v = bbr.view();
        assert_eq!(v.state, State::Drain);
        assert!(bbr.full_bw_reached);
        // max(BBR.bdp = 10 MB/s × 10 ms, inflight_latest 100 000).
        assert_eq!(v.inflight_longterm, 100_000);

        // A loss in RTO recovery does not exit Startup.
        let mut bbr = started(SMSS, None);
        ack(&mut bbr, 100_000, ms(10), ms(10), at(10));
        recovery_start(&mut bbr, RecoveryKind::Rto);
        bbr.on_loss(&e);
        dup_ack_no_sack(&mut bbr, at(16));
        assert_eq!(bbr.view().state, State::Startup);

        // With SACK one lost range in fast recovery does not either.
        let mut bbr = started(SMSS, None);
        ack(&mut bbr, 100_000, ms(10), ms(10), at(10));
        recovery_start(&mut bbr, RecoveryKind::Fast);
        recovery_round(&mut bbr, &[(100_000, 1_000)], 100_000, 10_000, at(20));
        recovery_round(&mut bbr, &[(200_000, 1_000)], 100_000, 10_000, at(30));
        assert_eq!(bbr.view().state, State::Startup);
    }

    #[test]
    fn shortterm_adapts_when_not_probing() {
        let mut bbr = started(SMSS, None);
        to_probe_bw_down(&mut bbr);
        assert_eq!(bbr.inflight_latest, 100_000);
        bbr.on_loss(&loss(&bbr, 2_000_000, 1_000, 1_000_000, 1_000));
        let cwnd = bbr.cwnd;
        // At the end of the loss round, at 5 MB/s: InitLowerBounds (max_bw, cwnd), then
        // max(latest, Beta × bound). bw_latest is still last round's 10 MB/s.
        ack_with(&mut bbr, 50_000, 300_000, at(90));
        let v = bbr.view();
        assert_eq!(v.state, State::ProbeBwDown);
        assert_eq!(v.bw_shortterm, 10_000_000);
        let inflight_shortterm = (cwnd * 7 / 10).max(100_000);
        assert_eq!(v.inflight_shortterm, inflight_shortterm);

        // Another loss round: the latest round's 5 MB/s and 50 000 are below Beta × bound.
        bbr.on_loss(&loss(&bbr, 2_100_000, 1_000, 1_000_000, 1_000));
        ack_with(&mut bbr, 50_000, 300_000, at(100));
        let v = bbr.view();
        assert_eq!(v.bw_shortterm, 7_000_000);
        assert_eq!(
            v.inflight_shortterm,
            (inflight_shortterm * 7 / 10).max(50_000)
        );
        assert_eq!(bbr.bw, 7_000_000, "BoundBWForModel");

        // A round without loss leaves them.
        ack_with(&mut bbr, 50_000, 300_000, at(110));
        assert_eq!(bbr.view().bw_shortterm, 7_000_000);
    }

    #[test]
    fn shortterm_not_adapted_while_probing() {
        // Startup.
        let mut bbr = started(SMSS, None);
        ack(&mut bbr, 100_000, ms(10), ms(10), at(10));
        bbr.on_loss(&loss(&bbr, 0, 1_000, 1_000_000, 1_000));
        ack(&mut bbr, 200_000, ms(10), ms(10), at(20));
        let v = bbr.view();
        assert_eq!(v.state, State::Startup);
        assert_eq!((v.bw_shortterm, v.inflight_shortterm), (INFINITE, INFINITE));

        // REFILL, whose round-ending ACK starts UP, then UP.
        let mut bbr = started(SMSS, None);
        let t = to_probe_bw_refill(&mut bbr);
        bbr.on_loss(&loss(&bbr, 2_000_000, 1_000, 1_000_000, 1_000));
        ack_with(&mut bbr, 100_000, 100_000, t + ms(10));
        assert_eq!(bbr.view().state, State::ProbeBwUp);
        bbr.on_loss(&loss(&bbr, 2_100_000, 1_000, 1_000_000, 1_000));
        ack_with(&mut bbr, 100_000, 100_000, t + ms(20));
        let v = bbr.view();
        assert_eq!(v.state, State::ProbeBwUp);
        assert_eq!((v.bw_shortterm, v.inflight_shortterm), (INFINITE, INFINITE));
        assert!(
            !bbr.is_loss_in_round,
            "taken at the round's end all the same"
        );
    }

    #[test]
    fn refill_resets_shortterm() {
        let mut bbr = started(SMSS, None);
        to_probe_bw_down(&mut bbr);
        bbr.on_loss(&loss(&bbr, 2_000_000, 1_000, 1_000_000, 1_000));
        ack_with(&mut bbr, 50_000, 300_000, at(90));
        ack_with(&mut bbr, 100_000, 50_000, at(100));
        let v = bbr.view();
        assert_eq!(v.state, State::ProbeBwCruise);
        assert_eq!(v.bw_shortterm, 10_000_000);
        assert_ne!(v.inflight_shortterm, INFINITE);

        let t = bbr.cycle_stamp + bbr.bw_probe_wait + ms(1);
        ack_with(&mut bbr, 100_000, 50_000, t);
        let v = bbr.view();
        assert_eq!(v.state, State::ProbeBwRefill);
        assert_eq!((v.bw_shortterm, v.inflight_shortterm), (INFINITE, INFINITE));
        assert_eq!(bbr.bw, v.max_bw);
    }

    #[test]
    fn longterm_grows_only_when_cwnd_limited() {
        let mut bbr = started(SMSS, None);
        let t = to_probe_bw_up(&mut bbr);
        // As a loss in an earlier probe would have left it.
        bbr.inflight_longterm = 80_000;
        bbr.probe_up_acked_per_inc = 10_000;
        assert!(bbr.cwnd >= 80_000);

        // A round in which no send filled cwnd: no growth.
        let mut rs = sample(&bbr, 100_000, ms(10), ms(10), t + ms(10));
        rs.cwnd_filled = false;
        bbr.on_rate_sample(&rs);
        assert_eq!(bbr.view().state, State::ProbeBwUp);
        assert_eq!(bbr.view().inflight_longterm, 80_000);
        assert_eq!(bbr.cwnd, 80_000, "bounded by inflight_longterm");
        assert_eq!(bbr.bw_probe_up_acked, 0);

        // cwnd filled: 100 000 acked at 10 000 per increment grows it by 10 SMSS.
        ack_with(&mut bbr, 100_000, 80_000, t + ms(20));
        assert_eq!(bbr.view().state, State::ProbeBwUp);
        assert_eq!(bbr.view().inflight_longterm, 90_000);
        assert_eq!(
            bbr.bw_probe_up_rounds, 2,
            "the round's end raised the slope"
        );
    }

    #[test]
    fn splitmix64_known_vector() {
        let mut rng = SplitMix64(0);
        assert_eq!(rng.next(), 0xe220_a839_7b1d_cdaf);
        assert_eq!(rng.next(), 0x6e78_9e6a_a1b9_65f4);
        assert_eq!(rng.next(), 0x06c4_5d18_8009_454f);
    }

    #[test]
    fn init_fallbacks() {
        let bbr = started(SMSS, None);
        let v = bbr.view();
        assert_eq!(v.state, State::Startup);
        assert_eq!(v.phase, AckPhase::Init);
        assert_eq!(v.round_count, 0);
        assert_eq!(v.max_bw, 0);
        assert_eq!(v.min_rtt, INFINITE_RTT);
        assert_eq!(v.bw_shortterm, INFINITE);
        assert_eq!(v.inflight_shortterm, INFINITE);
        assert_eq!(v.inflight_longterm, INFINITE);
        assert_eq!(bbr.pacing_gain, STARTUP_PACING_GAIN);
        assert_eq!(bbr.cwnd_gain, DEFAULT_CWND_GAIN);
        // C.InitialCwnd = 4 SMSS; 4000 octets per 1 ms nominal interval, times 2.77.
        assert_eq!(v.cwnd, 4000);
        assert_eq!(v.pacing_rate, 11_080_000);
        assert_eq!(bbr.pacing_rate(), Some(11_080_000));
        // Infinite min_rtt: BDPMultiple falls back to C.InitialCwnd.
        assert_eq!(bbr.bdp_multiple(DEFAULT_CWND_GAIN), 4000);

        // A handshake RTT, when there is one, replaces both fallbacks.
        let bbr = started(SMSS, Some(ms(10)));
        assert_eq!(bbr.view().min_rtt, ms(10));
        assert_eq!(bbr.view().pacing_rate, 1_108_000);
    }

    #[test]
    fn startup_exits_on_plateau() {
        let mut bbr = started(SMSS, None);
        // 10, 13 (+30%: a new baseline), then 14, 15, 16 MB/s: each < 1.25 × 13.
        for (i, d) in [100_000, 130_000, 140_000, 150_000].into_iter().enumerate() {
            ack_with(&mut bbr, d, 1_000_000, at(10 * (i as u64 + 1)));
            assert_eq!(bbr.view().state, State::Startup);
            assert!(!bbr.full_bw_reached);
        }
        assert_eq!(bbr.full_bw, 13_000_000);
        assert_eq!(bbr.full_bw_count, 2);
        ack_with(&mut bbr, 160_000, 1_000_000, at(50));
        let v = bbr.view();
        assert!(bbr.full_bw_reached && bbr.full_bw_now);
        assert_eq!(v.state, State::Drain);
        assert_eq!(v.round_count, 5);
        assert_eq!(v.max_bw, 16_000_000);
        assert_eq!(bbr.drain_start_round, 5);
        assert_eq!(bbr.pacing_gain, DRAIN_PACING_GAIN);
        assert_eq!(bbr.cwnd_gain, DEFAULT_CWND_GAIN);
        // Full bandwidth reached: the pacing rate follows the gain down (0.5 × 16 MB/s × 99%).
        assert_eq!(v.pacing_rate, 7_920_000);
    }

    #[test]
    fn startup_ignores_app_limited_rounds() {
        let mut bbr = started(SMSS, None);
        ack_with(&mut bbr, 100_000, 1_000_000, at(10));
        for i in 2..=6 {
            let mut rs = sample(&bbr, 100_000, ms(10), ms(10), at(10 * i));
            rs.delivery.as_mut().expect("delivery").is_app_limited = true;
            bbr.on_rate_sample(&rs);
        }
        assert_eq!(bbr.full_bw_count, 0);
        assert_eq!(bbr.view().state, State::Startup);
    }

    #[test]
    fn drain_exits_to_probe_bw_down() {
        let mut bbr = started(SMSS, None);
        to_drain(&mut bbr);
        assert_eq!(bbr.drain_start_round, 4);
        // Inflight(1.0) = BDP = 10 MB/s × 10 ms; one octet above it stays in Drain.
        assert_eq!(bbr.inflight(UNITY_GAIN), 100_000);
        ack_with(&mut bbr, 100_000, 100_001, at(50));
        assert_eq!(bbr.view().state, State::Drain);

        let rs = {
            let mut rs = sample(&bbr, 100_000, ms(10), ms(10), at(60));
            rs.inflight = 100_000;
            rs
        };
        bbr.on_rate_sample(&rs);
        let v = bbr.view();
        // ProbeBW_DOWN, and on the same ACK CRUISE: C.inflight is within BBR.bdp and there is
        // no inflight_longterm. That ACK also ends a round, which ends ACKS_PROBE_STOPPING.
        assert_eq!(v.state, State::ProbeBwCruise);
        assert_eq!(v.phase, AckPhase::Init);
        assert_eq!(bbr.cycle_count, 1);
        assert_eq!(bbr.pacing_gain, UNITY_GAIN);
        assert_eq!(bbr.cwnd_gain, DEFAULT_CWND_GAIN);
        assert_eq!(bbr.cycle_stamp, at(60));
        assert_eq!(bbr.probe_up_acked_per_inc, INFINITE);
        // StartRound: the next round ends with data sent after this ACK.
        assert_eq!(bbr.next_round_delivered, rs.delivered);
        // PickProbeWait with the seeded PRNG: 0 or 1 rounds, and 2 s plus up to 1 s.
        let mut rng = SplitMix64(SEED);
        assert_eq!(bbr.rounds_since_probe_up, rng.next() >> 63);
        let wait = Duration::from_secs(2) + Duration::from_nanos(rng.next() % 1_000_000_000);
        assert_eq!(bbr.bw_probe_wait, wait);
        assert!(bbr.bw_probe_wait >= Duration::from_secs(2));
        assert!(bbr.bw_probe_wait < Duration::from_secs(3));
        // 1.0 × 10 MB/s × 99%.
        assert_eq!(v.pacing_rate, 9_900_000);
    }

    #[test]
    fn drain_exits_after_three_rounds() {
        let mut bbr = started(SMSS, None);
        to_drain(&mut bbr);
        for i in 5..=7 {
            ack_with(&mut bbr, 100_000, 300_000, at(10 * i));
            assert_eq!(bbr.view().state, State::Drain, "round {i}");
        }
        ack_with(&mut bbr, 100_000, 300_000, at(80));
        assert_eq!(bbr.view().round_count, 8);
        assert_eq!(bbr.view().state, State::ProbeBwDown);
    }

    #[test]
    fn update_max_inflight_formula() {
        let mut bbr = started(SMSS, None);
        bbr.bw = 1_000_000;
        bbr.min_rtt = ms(100);
        bbr.extra_acked = 5_000;
        bbr.send_quantum = 10_000;
        let cwnd = bbr.cwnd;
        for (state, up) in [(State::ProbeBwDown, 0), (State::ProbeBwUp, 2 * 1000)] {
            bbr.state = state;
            // BDP = 1 MB/s × 100 ms = 100 000, above the offload budget (30 000).
            assert_eq!(bbr.inflight(UNITY_GAIN), 100_000 + up);
            assert_eq!(bbr.inflight((5, 4)), 125_000 + up);
            bbr.update_max_inflight();
            assert_eq!(bbr.max_inflight, 2 * 100_000 + 5_000 + up);

            // The offload budget, 3 × send_quantum, is a floor for both.
            bbr.send_quantum = 50_000;
            assert_eq!(bbr.inflight(UNITY_GAIN), 150_000 + up);
            bbr.update_max_inflight();
            assert_eq!(bbr.max_inflight, 205_000 + up);
            bbr.send_quantum = 80_000;
            bbr.update_max_inflight();
            assert_eq!(bbr.max_inflight, 240_000 + up);

            // MinPipeCwnd is the other floor; a quantum below the 2·SMSS that SetSendQuantum
            // keeps exposes it.
            bbr.send_quantum = 1_000;
            bbr.bw = 0;
            assert_eq!(bbr.inflight(UNITY_GAIN), 4_000 + up);
            bbr.update_max_inflight();
            assert_eq!(bbr.max_inflight, 5_000 + up);

            bbr.bw = 1_000_000;
            bbr.send_quantum = 10_000;
        }
        // The model, not cwnd.
        assert_eq!(bbr.cwnd, cwnd);
    }

    #[test]
    fn cwnd_grows_toward_max_inflight() {
        let mut bbr = started(SMSS, None);
        to_drain(&mut bbr);
        // ACKs without a rate sample keep the model (and so max_inflight) still.
        let ack_no_rate = |bbr: &mut Bbr, newly_acked: u64, now: Instant| {
            let mut rs = sample(bbr, newly_acked, ms(10), ms(10), now);
            rs.inflight = 300_000;
            rs.delivery.as_mut().expect("delivery").rate = None;
            bbr.on_rate_sample(&rs);
        };
        bbr.cwnd = 50_000;
        ack_no_rate(&mut bbr, 10_000, at(50));
        assert_eq!(bbr.cwnd, 60_000, "+ newly_acked");
        assert!(bbr.cwnd < bbr.max_inflight, "and may stay below the target");
        ack_no_rate(&mut bbr, 1_000_000, at(60));
        assert_eq!(bbr.cwnd, bbr.max_inflight, "never above it");
        bbr.cwnd = 10 * bbr.max_inflight;
        ack_no_rate(&mut bbr, 0, at(70));
        assert_eq!(bbr.view().state, State::Drain);
        assert_eq!(bbr.cwnd, bbr.max_inflight, "cut at once");
        assert_eq!(u64::from(bbr.cwnd()), bbr.max_inflight);
    }

    #[test]
    fn startup_cwnd_not_bounded_by_max_inflight() {
        let mut bbr = started(SMSS, None);
        ack(&mut bbr, 3_000, ms(10), ms(10), at(10));
        assert_eq!(bbr.cwnd, 7_000, "+ newly_acked below the target");
        // Before full_bw_reached a cwnd above the target is not cut; with C.InitialCwnd
        // delivered it does not grow either.
        bbr.cwnd = 10_000_000;
        ack(&mut bbr, 3_000, ms(10), ms(10), at(20));
        assert!(bbr.max_inflight < 10_000_000);
        assert_eq!(bbr.cwnd, 10_000_000);
    }

    #[test]
    fn send_quantum_clamped() {
        // pacing_rate × 1 ms, between 2·SMSS and 64 KiB.
        assert_eq!(started(SMSS, None).send_quantum(), Some(11_080));
        let fast = started(SMSS, Some(Duration::from_micros(1)));
        assert_eq!(fast.send_quantum(), Some(64 * 1024));
        let slow = started(SMSS, Some(Duration::from_secs(10)));
        assert_eq!(slow.pacing_rate(), Some(1_108));
        assert_eq!(slow.send_quantum(), Some(2 * SMSS));
    }

    #[test]
    fn min_pipe_cwnd_floor() {
        // SMSS 1460: C.InitialCwnd is 3 SMSS, or 1 SMSS after a lost SYN; both rise to 4 SMSS.
        for syn_lost in [false, true] {
            let mut bbr = Bbr::new(SEED);
            bbr.init(1460, syn_lost);
            bbr.on_start(&Start {
                smss: 1460,
                syn_lost,
                srtt: None,
                sack: true,
                now: T0,
            });
            assert!(bbr.cwnd() < 4 * 1460);
            ack(&mut bbr, 0, ms(10), ms(10), at(10));
            assert_eq!(bbr.cwnd(), 4 * 1460, "syn_lost {syn_lost}");
        }
    }

    #[test]
    fn ipv6_min_mtu_floors() {
        // IPv6 minimum MTU 1280 − 40 (IPv6) − 20 (TCP) − 12 (timestamps).
        const V6_SMSS: u32 = 1208;
        let mut bbr = started(V6_SMSS, None);
        // 100 kB/s: a pacing rate whose 1 ms quantum is far below 2·SMSS.
        for i in 1..=4 {
            ack(&mut bbr, 1_000, ms(10), ms(10), at(10 * i));
        }
        // BBR.bdp is below one SMSS, so ProbeBW goes straight on to CRUISE or REFILL; both
        // pace at 1.0.
        assert!(bbr.is_in_a_probe_bw_state());
        assert_eq!(bbr.view().pacing_rate, 99_000);
        assert_eq!(bbr.send_quantum(), Some(2 * V6_SMSS));
        assert!(bbr.cwnd() >= 4 * V6_SMSS);
        assert!(bbr.inflight(UNITY_GAIN) >= u64::from(4 * V6_SMSS));
    }

    #[test]
    fn round_counting_uses_delivery_not_rate() {
        let mut bbr = started(SMSS, None);
        let mut rs = sample(&bbr, 1_000, ms(10), ms(10), at(10));
        rs.delivery.as_mut().expect("delivery").rate = None;
        bbr.on_rate_sample(&rs);
        assert_eq!(bbr.view().round_count, 1);
        assert!(bbr.round_start);
        assert_eq!(bbr.view().max_bw, 0, "no rate, no bandwidth sample");
        assert_eq!(bbr.next_round_delivered, 1_000);
    }

    #[test]
    fn no_delivery_no_round() {
        let mut bbr = started(SMSS, None);
        ack(&mut bbr, 1_000, ms(10), ms(10), at(10));
        assert!(bbr.round_start);
        let max_bw = bbr.view().max_bw;
        let mut rs = sample(&bbr, 1_000, ms(10), ms(10), at(20));
        rs.delivery = None;
        rs.delivered = 1_000;
        bbr.on_rate_sample(&rs);
        assert_eq!(bbr.view().round_count, 1);
        assert!(!bbr.round_start);
        assert_eq!(bbr.view().max_bw, max_bw);
    }

    #[test]
    fn max_bw_filter_spans_two_cycles() {
        let mut bbr = started(SMSS, None);
        ack(&mut bbr, 100_000, ms(10), ms(10), at(10));
        assert_eq!(bbr.view().max_bw, 10_000_000);
        bbr.advance_max_bw_filter();
        ack(&mut bbr, 50_000, ms(10), ms(10), at(20));
        assert_eq!(
            bbr.view().max_bw,
            10_000_000,
            "the previous cycle still counts"
        );
        bbr.advance_max_bw_filter();
        ack(&mut bbr, 50_000, ms(10), ms(10), at(30));
        assert_eq!(bbr.view().max_bw, 5_000_000, "two cycles back is gone");

        // App-limited samples count only when they raise max_bw.
        let mut rs = sample(&bbr, 40_000, ms(10), ms(10), at(40));
        rs.delivery.as_mut().expect("delivery").is_app_limited = true;
        bbr.on_rate_sample(&rs);
        assert_eq!(bbr.view().max_bw, 5_000_000);
        let mut rs = sample(&bbr, 60_000, ms(10), ms(10), at(50));
        rs.delivery.as_mut().expect("delivery").is_app_limited = true;
        bbr.on_rate_sample(&rs);
        assert_eq!(bbr.view().max_bw, 6_000_000);
    }

    #[test]
    fn windowed_max_filter() {
        let mut f = WindowedMax::default();
        assert_eq!(f.update(5, 0, 2), 5);
        assert_eq!(f.update(3, 1, 2), 5);
        assert_eq!(f.update(4, 2, 2), 4, "time 0 left the 2-long window");
        assert_eq!(f.update(1, 2, 1), 4, "same time slot");
        assert_eq!(f.update(1, 3, 1), 1);
        assert_eq!(
            f.update(0, 3, 10),
            1,
            "a wider window does not revive forgotten slots"
        );
        assert_eq!(f.update(0, 20, 10), 0);
    }

    #[test]
    fn extra_acked_tracks_aggregation() {
        let mut bbr = started(SMSS, None);
        // bw is 0: nothing expected, so the first ACK is all extra.
        ack(&mut bbr, 2_000, ms(10), ms(10), at(10));
        assert_eq!(bbr.extra_acked, 2_000);
        // bw 200 kB/s; 10 ms later 2000 octets are expected and 2000 arrived: a new interval.
        ack(&mut bbr, 6_000, ms(10), ms(10), at(20));
        assert_eq!(bbr.extra_acked, 6_000);
        // bw 600 kB/s; 1 ms later 600 are expected and 12 000 have arrived.
        ack(&mut bbr, 6_000, ms(10), ms(10), at(21));
        assert_eq!(bbr.extra_acked, 11_400);
        // In Startup the filter remembers one round.
        ack(&mut bbr, 100, ms(10), ms(10), at(22));
        assert_eq!(bbr.extra_acked, 12_100 - 1_200);
        // Past Startup the window widens to 10 rounds, but round 3's 11 400, dropped while
        // the window was 1, stays dropped: the max is round 4's 10 900 (this round's sample:
        // 12 200 − 1 800 = 10 400).
        bbr.full_bw_reached = true;
        ack(&mut bbr, 100, ms(10), ms(10), at(23));
        assert_eq!(bbr.extra_acked, 10_900);
    }

    #[test]
    fn min_rtt_filter() {
        let mut bbr = started(SMSS, None);
        ack(&mut bbr, 1_000, ms(10), ms(30), at(30));
        assert_eq!(bbr.view().min_rtt, ms(30));
        ack(&mut bbr, 1_000, ms(10), ms(20), at(60));
        assert_eq!(bbr.view().min_rtt, ms(20));
        ack(&mut bbr, 1_000, ms(10), ms(40), at(100));
        assert_eq!(
            bbr.view().min_rtt,
            ms(20),
            "a larger sample does not replace it"
        );
        // After the 5 s ProbeRTTInterval the ProbeRTT sample refreshes, but min_rtt keeps its
        // 10 s window.
        ack(&mut bbr, 1_000, ms(10), ms(40), at(5_100));
        assert_eq!(bbr.view().min_rtt, ms(20));
        assert_eq!(bbr.probe_rtt_min_delay, ms(40));
        ack(&mut bbr, 1_000, ms(10), ms(50), at(10_100));
        assert_eq!(
            bbr.view().min_rtt,
            ms(40),
            "expired: the ProbeRTT sample takes over"
        );
        assert_eq!(bbr.min_rtt_stamp, at(5_100));
    }

    #[test]
    fn bound_cwnd_for_model_caps() {
        let mut bbr = started(SMSS, None);
        bbr.inflight_longterm = 100_000;
        let unbounded = 1_000_000;
        for (state, cap) in [
            (State::Startup, unbounded),
            (State::Drain, unbounded),
            (State::ProbeBwDown, 100_000),
            (State::ProbeBwRefill, 100_000),
            (State::ProbeBwUp, 100_000),
            // InflightWithHeadroom: 15% below inflight_longterm.
            (State::ProbeBwCruise, 85_000),
            (State::ProbeRtt, 85_000),
        ] {
            bbr.state = state;
            bbr.cwnd = unbounded;
            bbr.bound_cwnd_for_model();
            assert_eq!(bbr.cwnd, cap, "{state:?}");
        }
        // The headroom is at least one SMSS.
        bbr.inflight_longterm = 6_000;
        assert_eq!(bbr.inflight_with_headroom(), 5_000);
        // inflight_shortterm applies in every state, and MinPipeCwnd is the floor.
        bbr.inflight_longterm = INFINITE;
        assert_eq!(bbr.inflight_with_headroom(), INFINITE);
        bbr.inflight_shortterm = 50_000;
        for state in [State::Startup, State::ProbeBwDown] {
            bbr.state = state;
            bbr.cwnd = unbounded;
            bbr.bound_cwnd_for_model();
            assert_eq!(bbr.cwnd, 50_000);
        }
        bbr.inflight_shortterm = 1_000;
        bbr.cwnd = unbounded;
        bbr.bound_cwnd_for_model();
        assert_eq!(bbr.cwnd, 4_000);
    }
}
