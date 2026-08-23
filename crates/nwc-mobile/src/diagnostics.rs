use std::sync::Mutex;

const MAX_WAKE_DIAGNOSTIC_CODES: usize = 32;

/// A bounded, non-secret classification emitted while executing a wake request.
///
/// Codes deliberately contain no identifiers, amounts, invoices, relay URLs,
/// keys, or backend error text. Hosts may persist their stable string forms in
/// development diagnostics without exposing NWC request content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WakeDiagnosticCode {
    /// A `pay_invoice` request passed request parsing and authorization.
    PaymentRequestAccepted,
    /// The invoice could not be quoted by the wallet adapter.
    PaymentQuoteFailed,
    /// The connection budget could not reserve the payment and fee allowance.
    PaymentBudgetExceeded,
    /// The wallet could not determine an existing payment's status.
    PaymentStatusLookupFailed,
    /// The wallet's estimated fee exceeded the connection's fee allowance.
    PaymentFeeLimitExceeded,
    /// Spendable wallet funds could not cover the payment and estimated fee.
    PaymentInsufficientFunds,
    /// The wallet backend failed while attempting the payment.
    PaymentBackendFailed,
    /// The payment remains pending and requires reconciliation or retry.
    PaymentPending,
    /// The wallet reported a successful payment.
    PaymentSucceeded,
    /// An invoice lookup found no matching wallet transaction.
    InvoiceLookupNotFound,
    /// An invoice lookup found a transaction that has not settled yet.
    InvoiceLookupPending,
    /// An invoice lookup found a settled transaction.
    InvoiceLookupSettled,
    /// The wallet backend could not complete an invoice lookup.
    InvoiceLookupFailed,
    /// A durable NIP-47 response could not be published to the relay.
    ResponsePublishFailed,
}

impl WakeDiagnosticCode {
    /// Returns a stable, non-secret host log value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PaymentRequestAccepted => "payment_request_accepted",
            Self::PaymentQuoteFailed => "payment_quote_failed",
            Self::PaymentBudgetExceeded => "payment_budget_exceeded",
            Self::PaymentStatusLookupFailed => "payment_status_lookup_failed",
            Self::PaymentFeeLimitExceeded => "payment_fee_limit_exceeded",
            Self::PaymentInsufficientFunds => "payment_insufficient_funds",
            Self::PaymentBackendFailed => "payment_backend_failed",
            Self::PaymentPending => "payment_pending",
            Self::PaymentSucceeded => "payment_succeeded",
            Self::InvoiceLookupNotFound => "invoice_lookup_not_found",
            Self::InvoiceLookupPending => "invoice_lookup_pending",
            Self::InvoiceLookupSettled => "invoice_lookup_settled",
            Self::InvoiceLookupFailed => "invoice_lookup_failed",
            Self::ResponsePublishFailed => "response_publish_failed",
        }
    }
}

/// Receives non-secret wake execution classifications.
pub trait WakeDiagnosticSink: Send + Sync {
    /// Records one bounded diagnostic code.
    fn record(&self, code: WakeDiagnosticCode);
}

/// Thread-safe bounded collector for one wake execution.
#[derive(Debug, Default)]
pub struct WakeDiagnosticCollector {
    codes: Mutex<Vec<WakeDiagnosticCode>>,
}

impl WakeDiagnosticCollector {
    /// Returns the recorded codes without exposing lock failures.
    #[must_use]
    pub fn codes(&self) -> Vec<WakeDiagnosticCode> {
        self.codes
            .lock()
            .map(|codes| codes.clone())
            .unwrap_or_default()
    }
}

impl WakeDiagnosticSink for WakeDiagnosticCollector {
    fn record(&self, code: WakeDiagnosticCode) {
        let Ok(mut codes) = self.codes.lock() else {
            return;
        };
        if codes.len() < MAX_WAKE_DIAGNOSTIC_CODES && !codes.contains(&code) {
            codes.push(code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_deduplicates_codes_and_exposes_only_stable_names() {
        let collector = WakeDiagnosticCollector::default();
        collector.record(WakeDiagnosticCode::PaymentRequestAccepted);
        collector.record(WakeDiagnosticCode::PaymentRequestAccepted);
        collector.record(WakeDiagnosticCode::PaymentFeeLimitExceeded);

        let codes = collector.codes();
        assert_eq!(
            codes,
            [
                WakeDiagnosticCode::PaymentRequestAccepted,
                WakeDiagnosticCode::PaymentFeeLimitExceeded,
            ]
        );
        assert_eq!(codes[0].as_str(), "payment_request_accepted");
        assert_eq!(codes[1].as_str(), "payment_fee_limit_exceeded");
    }
}
