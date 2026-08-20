use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::DomainError;

/// A whole-second timestamp relative to the Unix epoch.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnixTimestamp(u64);

impl UnixTimestamp {
    /// Creates a timestamp from whole seconds since the Unix epoch.
    #[must_use]
    pub const fn from_secs(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns the number of whole seconds since the Unix epoch.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }
}

/// Supplies wall-clock time to freshness and retention policy.
pub trait Clock: Send + Sync {
    /// Returns the current Unix timestamp.
    fn now(&self) -> UnixTimestamp;
}

/// A clock backed by the operating system wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> UnixTimestamp {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        UnixTimestamp::from_secs(seconds)
    }
}

/// Divides a platform background window into execution and cleanup time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackgroundBudget {
    total: Duration,
    cleanup_reserve: Duration,
}

impl BackgroundBudget {
    /// Creates a background budget.
    ///
    /// The cleanup reserve must be non-zero and strictly smaller than the total
    /// platform window.
    pub fn new(total: Duration, cleanup_reserve: Duration) -> Result<Self, DomainError> {
        if total.is_zero() || cleanup_reserve.is_zero() || cleanup_reserve >= total {
            return Err(DomainError::InvalidBackgroundBudget);
        }
        Ok(Self {
            total,
            cleanup_reserve,
        })
    }

    /// Returns the complete platform-provided window.
    #[must_use]
    pub const fn total(self) -> Duration {
        self.total
    }

    /// Returns the time reserved for checkpointing and native completion.
    #[must_use]
    pub const fn cleanup_reserve(self) -> Duration {
        self.cleanup_reserve
    }

    /// Returns the maximum time available for request execution.
    #[must_use]
    pub fn execution_budget(self) -> Duration {
        self.total - self.cleanup_reserve
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_budget_reserves_cleanup_time() {
        let budget = BackgroundBudget::new(Duration::from_secs(30), Duration::from_secs(5))
            .expect("valid budget");

        assert_eq!(budget.execution_budget(), Duration::from_secs(25));
    }

    #[test]
    fn background_budget_requires_nonzero_cleanup_window() {
        assert_eq!(
            BackgroundBudget::new(Duration::from_secs(30), Duration::ZERO),
            Err(DomainError::InvalidBackgroundBudget)
        );
        assert_eq!(
            BackgroundBudget::new(Duration::from_secs(30), Duration::from_secs(30)),
            Err(DomainError::InvalidBackgroundBudget)
        );
    }
}
