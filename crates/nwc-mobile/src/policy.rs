use std::collections::BTreeSet;
use std::time::Duration;

use crate::{DomainError, NwcMethod, UnixTimestamp};

/// How often a connection's spending budget renews.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BudgetInterval {
    /// The budget never renews automatically.
    Never,
    /// The budget renews hourly.
    Hourly,
    /// The budget renews daily.
    Daily,
    /// The budget renews weekly.
    Weekly,
    /// The budget renews every 30 days.
    Monthly,
    /// The budget renews every 365 days.
    Yearly,
}

impl BudgetInterval {
    /// Returns the fixed duration of a renewable interval.
    #[must_use]
    pub const fn duration(self) -> Option<Duration> {
        match self {
            Self::Never => None,
            Self::Hourly => Some(Duration::from_secs(60 * 60)),
            Self::Daily => Some(Duration::from_secs(24 * 60 * 60)),
            Self::Weekly => Some(Duration::from_secs(7 * 24 * 60 * 60)),
            Self::Monthly => Some(Duration::from_secs(30 * 24 * 60 * 60)),
            Self::Yearly => Some(Duration::from_secs(365 * 24 * 60 * 60)),
        }
    }
}

/// Defines whether and how Lightning fees consume an NWC budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FeePolicy {
    /// Reserve the maximum fee before payment and charge the actual fee after
    /// settlement.
    CountTowardBudget {
        /// Maximum fee that may be reserved for one payment.
        maximum_fee_sat: u64,
    },
    /// Exclude fees for compatibility with an existing wallet policy.
    ///
    /// Hosts must opt into this explicitly; it is not a conservative default.
    ExcludeForCompatibility,
}

/// The spending constraint attached to an NWC connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetPolicy {
    limit_sat: u64,
    interval: BudgetInterval,
    fee_policy: FeePolicy,
}

impl BudgetPolicy {
    /// Creates an explicit spending policy.
    #[must_use]
    pub const fn new(limit_sat: u64, interval: BudgetInterval, fee_policy: FeePolicy) -> Self {
        Self {
            limit_sat,
            interval,
            fee_policy,
        }
    }

    /// Returns the maximum spend for one budget period.
    #[must_use]
    pub const fn limit_sat(self) -> u64 {
        self.limit_sat
    }

    /// Returns the renewal interval.
    #[must_use]
    pub const fn interval(self) -> BudgetInterval {
        self.interval
    }

    /// Returns the fee-accounting policy.
    #[must_use]
    pub const fn fee_policy(self) -> FeePolicy {
        self.fee_policy
    }

    /// Returns the amount that must be reserved before a payment starts.
    pub fn reservation_sat(self, principal_sat: u64) -> Result<u64, DomainError> {
        let fee_reserve = match self.fee_policy {
            FeePolicy::CountTowardBudget { maximum_fee_sat } => maximum_fee_sat,
            FeePolicy::ExcludeForCompatibility => 0,
        };
        principal_sat
            .checked_add(fee_reserve)
            .ok_or(DomainError::PaymentAmountOverflow)
    }
}

/// Wallet-side authorization policy for one NWC connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionPolicy {
    methods: BTreeSet<NwcMethod>,
    budget: BudgetPolicy,
}

impl ConnectionPolicy {
    /// Creates a policy from explicit methods and a budget.
    #[must_use]
    pub fn new(methods: impl IntoIterator<Item = NwcMethod>, budget: BudgetPolicy) -> Self {
        Self {
            methods: methods.into_iter().collect(),
            budget,
        }
    }

    /// Creates a read-only, zero-spend policy suitable for omitted NWA values.
    #[must_use]
    pub fn conservative_default() -> Self {
        Self::new(
            [NwcMethod::GetInfo],
            BudgetPolicy::new(
                0,
                BudgetInterval::Never,
                FeePolicy::CountTowardBudget { maximum_fee_sat: 0 },
            ),
        )
    }

    /// Returns whether the method was explicitly granted.
    #[must_use]
    pub fn allows(&self, method: NwcMethod) -> bool {
        self.methods.contains(&method)
    }

    /// Iterates over granted methods in stable order.
    pub fn methods(&self) -> impl ExactSizeIterator<Item = NwcMethod> + '_ {
        self.methods.iter().copied()
    }

    /// Returns the connection's budget policy.
    #[must_use]
    pub const fn budget(&self) -> BudgetPolicy {
        self.budget
    }
}

/// Bounds untrusted wake inputs and replay retention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WakePolicy {
    maximum_event_age: Duration,
    maximum_future_skew: Duration,
    replay_retention: Duration,
    maximum_payload_bytes: usize,
    maximum_relays_per_connection: usize,
}

impl WakePolicy {
    /// Creates a wake policy after checking its retention and size invariants.
    pub fn new(
        maximum_event_age: Duration,
        maximum_future_skew: Duration,
        replay_retention: Duration,
        maximum_payload_bytes: usize,
        maximum_relays_per_connection: usize,
    ) -> Result<Self, DomainError> {
        let required_retention = maximum_event_age
            .checked_add(maximum_future_skew)
            .ok_or(DomainError::InvalidWakePolicy)?;
        if maximum_event_age.is_zero()
            || replay_retention < required_retention
            || maximum_payload_bytes == 0
            || maximum_relays_per_connection == 0
        {
            return Err(DomainError::InvalidWakePolicy);
        }
        Ok(Self {
            maximum_event_age,
            maximum_future_skew,
            replay_retention,
            maximum_payload_bytes,
            maximum_relays_per_connection,
        })
    }

    /// Returns the oldest accepted event age.
    #[must_use]
    pub const fn maximum_event_age(self) -> Duration {
        self.maximum_event_age
    }

    /// Returns the allowed positive clock skew.
    #[must_use]
    pub const fn maximum_future_skew(self) -> Duration {
        self.maximum_future_skew
    }

    /// Returns how long replay and terminal state must be retained.
    #[must_use]
    pub const fn replay_retention(self) -> Duration {
        self.replay_retention
    }

    /// Returns the largest accepted platform wake payload.
    #[must_use]
    pub const fn maximum_payload_bytes(self) -> usize {
        self.maximum_payload_bytes
    }

    /// Returns the connection relay limit.
    #[must_use]
    pub const fn maximum_relays_per_connection(self) -> usize {
        self.maximum_relays_per_connection
    }

    /// Checks an event timestamp against age and future-skew bounds.
    #[must_use]
    pub fn accepts_event_time(self, created_at: UnixTimestamp, now: UnixTimestamp) -> bool {
        let created_at = created_at.as_secs();
        let now = now.as_secs();
        if created_at > now {
            return created_at - now <= self.maximum_future_skew.as_secs();
        }
        now - created_at <= self.maximum_event_age.as_secs()
    }
}

impl Default for WakePolicy {
    fn default() -> Self {
        Self::new(
            Duration::from_secs(10 * 60),
            Duration::from_secs(30),
            Duration::from_secs(24 * 60 * 60),
            64 * 1024,
            2,
        )
        .expect("default wake policy is internally consistent")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conservative_connection_policy_does_not_grant_payment() {
        let policy = ConnectionPolicy::conservative_default();

        assert!(policy.allows(NwcMethod::GetInfo));
        assert!(!policy.allows(NwcMethod::PayInvoice));
        assert_eq!(policy.budget().limit_sat(), 0);
    }

    #[test]
    fn budget_reservation_includes_maximum_fee() {
        let policy = BudgetPolicy::new(
            1_000,
            BudgetInterval::Daily,
            FeePolicy::CountTowardBudget {
                maximum_fee_sat: 25,
            },
        );

        assert_eq!(policy.reservation_sat(600), Ok(625));
        assert_eq!(
            policy.reservation_sat(u64::MAX),
            Err(DomainError::PaymentAmountOverflow)
        );
    }

    #[test]
    fn wake_policy_requires_replay_retention_to_cover_freshness() {
        let policy = WakePolicy::new(
            Duration::from_secs(600),
            Duration::from_secs(30),
            Duration::from_secs(629),
            1,
            1,
        );

        assert_eq!(policy, Err(DomainError::InvalidWakePolicy));
    }

    #[test]
    fn wake_policy_accepts_only_bounded_event_times() {
        let policy = WakePolicy::default();
        let now = UnixTimestamp::from_secs(10_000);

        assert!(policy.accepts_event_time(UnixTimestamp::from_secs(9_400), now));
        assert!(!policy.accepts_event_time(UnixTimestamp::from_secs(9_399), now));
        assert!(policy.accepts_event_time(UnixTimestamp::from_secs(10_030), now));
        assert!(!policy.accepts_event_time(UnixTimestamp::from_secs(10_031), now));
    }
}
