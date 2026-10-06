use std::ops::{Add, Sub};
use std::time::Duration;

/// Monotonic time in nanoseconds, always supplied by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl Instant {
    pub const fn from_nanos(ns: u64) -> Self {
        Self(ns)
    }
    pub const fn as_nanos(self) -> u64 {
        self.0
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;
    fn add(self, d: Duration) -> Instant {
        Instant(
            self.0
                .saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)),
        )
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;
    fn sub(self, o: Instant) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(o.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn instant_sub_saturates() {
        assert_eq!(
            Instant::from_nanos(5) - Instant::from_nanos(9),
            Duration::ZERO
        );
    }
}
