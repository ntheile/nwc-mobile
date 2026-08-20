use std::fmt;

/// An error produced while constructing a domain value or policy.
///
/// Variants intentionally omit the rejected input so the error is safe to place
/// in diagnostic logs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DomainError {
    /// A required identifier was empty.
    EmptyIdentifier,
    /// An identifier exceeded its maximum encoded length.
    IdentifierTooLong {
        /// Maximum accepted length in bytes.
        maximum: usize,
    },
    /// An identifier contained a character outside its conservative allowlist.
    InvalidIdentifierCharacter,
    /// A hexadecimal value did not encode exactly 32 bytes.
    InvalidHexLength {
        /// Expected hexadecimal string length.
        expected: usize,
        /// Actual hexadecimal string length.
        actual: usize,
    },
    /// A value contained a non-hexadecimal character.
    InvalidHex,
    /// Incrementing a durable revision would overflow.
    RevisionOverflow,
    /// A background budget was empty or left no cleanup reserve.
    InvalidBackgroundBudget,
    /// A host operation was given no execution time.
    InvalidOperationBudget,
    /// A relay URL was malformed or did not use secure WebSockets.
    InvalidRelayUrl,
    /// A wake-provider URL was malformed or did not use HTTPS.
    InvalidWakeServerUrl,
    /// A wake policy contained incompatible bounds.
    InvalidWakePolicy,
    /// Adding the fee reserve to a payment principal would overflow.
    PaymentAmountOverflow,
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentifier => formatter.write_str("identifier is empty"),
            Self::IdentifierTooLong { maximum } => {
                write!(formatter, "identifier exceeds {maximum} bytes")
            }
            Self::InvalidIdentifierCharacter => {
                formatter.write_str("identifier contains an unsupported character")
            }
            Self::InvalidHexLength { expected, actual } => write!(
                formatter,
                "hexadecimal value has length {actual}; expected {expected}"
            ),
            Self::InvalidHex => formatter.write_str("value is not valid hexadecimal"),
            Self::RevisionOverflow => formatter.write_str("connection revision overflowed"),
            Self::InvalidBackgroundBudget => {
                formatter.write_str("background budget must leave time for cleanup")
            }
            Self::InvalidOperationBudget => {
                formatter.write_str("host operation budget must be non-zero")
            }
            Self::InvalidRelayUrl => formatter.write_str("relay URL is invalid or insecure"),
            Self::InvalidWakeServerUrl => {
                formatter.write_str("wake-provider URL is invalid or insecure")
            }
            Self::InvalidWakePolicy => formatter.write_str("wake policy bounds are inconsistent"),
            Self::PaymentAmountOverflow => {
                formatter.write_str("payment amount and fee reserve overflowed")
            }
        }
    }
}

impl std::error::Error for DomainError {}
