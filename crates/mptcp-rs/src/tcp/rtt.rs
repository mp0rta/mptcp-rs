//! RFC 6298 retransmission timer: SRTT, RTTVAR and RTO.

use std::time::Duration;

pub(crate) const INITIAL_RTO: Duration = Duration::from_secs(1);
const MIN_RTO: Duration = Duration::from_secs(1);
pub(crate) const MAX_RTO: Duration = Duration::from_secs(60);
/// RFC 6298 §5.7.
const SYN_RETX_RTO: Duration = Duration::from_secs(3);
/// Clock granularity G (§4); the caller's clock is finer, so this only matters when RTTVAR = 0.
const G: Duration = Duration::from_millis(1);

#[derive(Debug)]
pub(crate) struct RttEstimator {
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
}

impl RttEstimator {
    pub(crate) fn new() -> Self {
        Self {
            srtt: None,
            rttvar: Duration::ZERO,
            rto: INITIAL_RTO,
        }
    }

    pub(crate) fn rto(&self) -> Duration {
        self.rto
    }

    pub(crate) fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// §2.2 / §2.3 with alpha = 1/8, beta = 1/4, K = 4; then §2.4 / §2.5 bounds.
    pub(crate) fn sample(&mut self, r: Duration) {
        let srtt = match self.srtt {
            None => {
                self.rttvar = r / 2;
                r
            }
            Some(srtt) => {
                self.rttvar = self.rttvar * 3 / 4 + srtt.abs_diff(r) / 4;
                srtt * 7 / 8 + r / 8
            }
        };
        self.srtt = Some(srtt);
        self.rto = (srtt + (self.rttvar * 4).max(G)).clamp(MIN_RTO, MAX_RTO);
    }

    /// §5.5: RTO ← RTO · 2, capped at 60 s.
    pub(crate) fn backoff(&mut self) {
        self.rto = (self.rto * 2).min(MAX_RTO);
    }

    /// §5.7: the SYN was retransmitted, so data transmission starts with RTO = 3 s.
    pub(crate) fn reinit_after_syn_retransmission(&mut self) {
        self.rto = SYN_RETX_RTO;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn first_and_subsequent_samples() {
        let mut e = RttEstimator::new();
        assert_eq!(e.rto(), ms(1000));
        // §2.2: SRTT = 2 s, RTTVAR = 1 s, RTO = 2 + 4·1 = 6 s.
        e.sample(ms(2000));
        assert_eq!(
            (e.srtt(), e.rttvar, e.rto()),
            (Some(ms(2000)), ms(1000), ms(6000))
        );
        // §2.3: RTTVAR = 3/4·1 + 1/4·|2 − 4| = 1.25 s; SRTT = 7/8·2 + 1/8·4 = 2.25 s;
        // RTO = 2.25 + 5 = 7.25 s.
        e.sample(ms(4000));
        assert_eq!(
            (e.srtt(), e.rttvar, e.rto()),
            (Some(ms(2250)), ms(1250), ms(7250))
        );
    }

    #[test]
    fn rto_bounds_and_backoff() {
        let mut e = RttEstimator::new();
        e.sample(ms(10));
        assert_eq!(e.rto(), MIN_RTO);
        for _ in 0..10 {
            e.backoff();
        }
        assert_eq!(e.rto(), MAX_RTO);
        // A new sample collapses the backed-off value.
        e.sample(ms(10));
        assert_eq!(e.rto(), MIN_RTO);
        e.sample(ms(100_000));
        assert_eq!(e.rto(), MAX_RTO);
    }

    #[test]
    fn syn_retransmission_reinit() {
        let mut e = RttEstimator::new();
        e.backoff();
        e.reinit_after_syn_retransmission();
        assert_eq!(e.rto(), SYN_RETX_RTO);
        assert_eq!(e.srtt(), None);
    }
}
