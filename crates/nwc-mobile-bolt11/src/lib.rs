//! BOLT11 invoice helpers for `nwc-mobile` wallet adapters.
//!
//! The core engine deliberately does not depend on a Lightning implementation.
//! Wallets that already use `lightning-invoice` can opt into this crate to share
//! invoice parsing, payment-hash extraction, and unit-boundary validation.

#![forbid(unsafe_code)]

use std::str::FromStr;

use lightning_invoice::Bolt11Invoice;
use nwc_mobile::{
    AmountMsat, CreatedInvoice, HostError, HostErrorKind, PaymentHash, PaymentQuote, UnixTimestamp,
};

/// Parses and validates a signed BOLT11 invoice supplied by an NWC client.
pub fn parse_invoice(invoice: &str) -> Result<Bolt11Invoice, HostError> {
    Bolt11Invoice::from_str(invoice).map_err(|_| rejected())
}

/// Extracts the NWC payment hash from a validated BOLT11 invoice.
#[must_use]
pub fn payment_hash(invoice: &Bolt11Invoice) -> PaymentHash {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(invoice.payment_hash().as_ref());
    PaymentHash::from_bytes(bytes)
}

/// Builds a side-effect-free NWC quote from a client-supplied BOLT11 invoice.
///
/// The returned principal is the amount encoded by the invoice, or the explicit
/// NWC amount for an amountless invoice. Expired, zero-valued, ambiguous, and
/// amountless requests without an explicit amount are rejected.
pub fn quote_invoice(
    invoice: &str,
    explicit_amount: Option<AmountMsat>,
) -> Result<PaymentQuote, HostError> {
    let invoice = parse_invoice(invoice)?;
    let principal = payment_amount(&invoice, explicit_amount)?;
    Ok(PaymentQuote::new(payment_hash(&invoice), principal))
}

/// Builds an NWC quote for a wallet that can only pay whole satoshis.
///
/// This keeps quote validation aligned with [`payment_amount_sats`], so the
/// engine never reserves a fractional-satoshi principal that the wallet adapter
/// must later reject when starting the payment.
pub fn quote_invoice_sats(
    invoice: &str,
    explicit_amount: Option<AmountMsat>,
) -> Result<PaymentQuote, HostError> {
    let invoice = parse_invoice(invoice)?;
    let principal = sats_to_msats(payment_amount_sats(&invoice, explicit_amount)?);
    Ok(PaymentQuote::new(payment_hash(&invoice), principal))
}

/// Returns the exact millisatoshi principal a wallet should pay.
///
/// An explicit amount is required for amountless invoices and rejected for
/// invoices that already carry an amount. Expired and zero-valued invoices are
/// also rejected before a wallet operation can start.
pub fn payment_amount(
    invoice: &Bolt11Invoice,
    explicit_amount: Option<AmountMsat>,
) -> Result<AmountMsat, HostError> {
    if invoice.is_expired() {
        return Err(rejected());
    }
    let amount = match (invoice.amount_milli_satoshis(), explicit_amount) {
        (Some(amount), None) => AmountMsat::from_msat(amount),
        (None, Some(amount)) => amount,
        (Some(_), Some(_)) | (None, None) => return Err(rejected()),
    };
    if amount.as_msat() == 0 {
        return Err(rejected());
    }
    Ok(amount)
}

/// Converts a millisatoshi amount at a whole-satoshi wallet boundary.
pub fn exact_sats(amount: AmountMsat) -> Result<u64, HostError> {
    let amount_msat = amount.as_msat();
    if amount_msat % 1_000 != 0 {
        return Err(rejected());
    }
    Ok(amount_msat / 1_000)
}

/// Returns the positive, whole-satoshi principal for a satoshi-only wallet.
pub fn payment_amount_sats(
    invoice: &Bolt11Invoice,
    explicit_amount: Option<AmountMsat>,
) -> Result<u64, HostError> {
    let amount = exact_sats(payment_amount(invoice, explicit_amount)?)?;
    if amount == 0 {
        return Err(rejected());
    }
    Ok(amount)
}

/// Converts satoshis to millisatoshis without wrapping on overflow.
#[must_use]
pub fn sats_to_msats(amount_sat: u64) -> AmountMsat {
    AmountMsat::from_msat(amount_sat.saturating_mul(1_000))
}

/// Converts a wallet-created invoice into the engine's typed result.
///
/// Missing amounts and timestamp overflow indicate a wallet integration error,
/// so they are classified as internal rather than client rejection.
pub fn created_invoice(invoice: Bolt11Invoice) -> Result<CreatedInvoice, HostError> {
    let amount = invoice
        .amount_milli_satoshis()
        .map(AmountMsat::from_msat)
        .ok_or_else(internal)?;
    let expires_at = invoice
        .expires_at()
        .map(|time| UnixTimestamp::from_secs(time.as_secs()))
        .ok_or_else(internal)?;
    Ok(CreatedInvoice::new(
        invoice.to_string(),
        payment_hash(&invoice),
        amount,
        expires_at,
    ))
}

const fn rejected() -> HostError {
    HostError::new(HostErrorKind::Rejected)
}

const fn internal() -> HostError {
    HostError::new(HostErrorKind::Internal)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use lightning_invoice::{Currency, InvoiceBuilder};
    use lightning_types::payment::PaymentSecret;

    use super::*;

    fn signed_invoice(amount_msat: Option<u64>, timestamp: Duration) -> Bolt11Invoice {
        let mut builder = InvoiceBuilder::new(Currency::Bitcoin)
            .description("nwc-mobile test".to_owned())
            .payment_hash(sha256::Hash::hash(b"nwc-mobile payment"))
            .payment_secret(PaymentSecret([42; 32]))
            .duration_since_epoch(timestamp)
            .expiry_time(Duration::from_secs(3_600))
            .min_final_cltv_expiry_delta(18);
        if let Some(amount_msat) = amount_msat {
            builder = builder.amount_milli_satoshis(amount_msat);
        }
        let signing_key = SecretKey::from_slice(&[7; 32]).expect("signing key");
        builder
            .build_signed(|message| Secp256k1::new().sign_ecdsa_recoverable(message, &signing_key))
            .expect("signed invoice")
    }

    fn current_timestamp() -> Duration {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current timestamp")
    }

    #[test]
    fn quote_uses_invoice_amount_and_hash() {
        let invoice = signed_invoice(Some(250_000_000), current_timestamp());
        let expected_hash = payment_hash(&invoice);
        let quote = quote_invoice(&invoice.to_string(), None).expect("quote");

        assert_eq!(quote.principal(), AmountMsat::from_msat(250_000_000));
        assert_eq!(quote.payment_hash(), &expected_hash);
    }

    #[test]
    fn amountless_invoice_requires_positive_explicit_amount() {
        let invoice = signed_invoice(None, current_timestamp()).to_string();
        assert_eq!(
            quote_invoice(&invoice, None)
                .expect_err("missing amount")
                .kind(),
            HostErrorKind::Rejected
        );
        assert_eq!(
            quote_invoice(&invoice, Some(AmountMsat::from_msat(0)))
                .expect_err("zero amount")
                .kind(),
            HostErrorKind::Rejected
        );
        assert_eq!(
            quote_invoice(&invoice, Some(AmountMsat::from_msat(42_000)))
                .expect("quote")
                .principal(),
            AmountMsat::from_msat(42_000)
        );
    }

    #[test]
    fn satoshi_boundary_rejects_fractional_amounts() {
        let invoice = signed_invoice(None, current_timestamp());
        assert_eq!(
            payment_amount_sats(&invoice, Some(AmountMsat::from_msat(2_000))).expect("sats"),
            2
        );
        assert_eq!(
            payment_amount_sats(&invoice, Some(AmountMsat::from_msat(2_001)))
                .expect_err("fractional sats")
                .kind(),
            HostErrorKind::Rejected
        );
        assert_eq!(
            quote_invoice_sats(&invoice.to_string(), Some(AmountMsat::from_msat(2_001)))
                .expect_err("fractional quote")
                .kind(),
            HostErrorKind::Rejected
        );
    }

    #[test]
    fn created_invoice_preserves_metadata() {
        let invoice = signed_invoice(Some(250_000_000), current_timestamp());
        let encoded = invoice.to_string();
        let expected_expiry = invoice.expires_at().expect("expiry").as_secs();
        let created = created_invoice(invoice).expect("created invoice");

        assert_eq!(created.invoice(), encoded);
        assert_eq!(created.amount(), AmountMsat::from_msat(250_000_000));
        assert_eq!(
            created.expires_at(),
            UnixTimestamp::from_secs(expected_expiry)
        );
    }

    #[test]
    fn invalid_invoice_is_rejected_without_details() {
        assert_eq!(
            parse_invoice("not-an-invoice").expect_err("invalid").kind(),
            HostErrorKind::Rejected
        );
    }

    #[test]
    fn fixed_invoice_rejects_any_explicit_amount_override() {
        let invoice = signed_invoice(Some(500_000), current_timestamp());
        for amount in [1_000, 500_000, 1_000_000] {
            assert_eq!(
                quote_invoice(&invoice.to_string(), Some(AmountMsat::from_msat(amount)))
                    .expect_err("ambiguous amount")
                    .kind(),
                HostErrorKind::Rejected
            );
            assert_eq!(
                payment_amount_sats(&invoice, Some(AmountMsat::from_msat(amount)))
                    .expect_err("ambiguous payment")
                    .kind(),
                HostErrorKind::Rejected
            );
        }
    }

    #[test]
    fn expired_invoice_is_rejected_before_quote_or_payment() {
        let invoice = signed_invoice(Some(500_000), Duration::from_secs(1));
        assert!(invoice.is_expired());
        assert_eq!(
            quote_invoice(&invoice.to_string(), None)
                .expect_err("expired quote")
                .kind(),
            HostErrorKind::Rejected
        );
        assert_eq!(
            payment_amount_sats(&invoice, None)
                .expect_err("expired payment")
                .kind(),
            HostErrorKind::Rejected
        );
        assert!(parse_invoice(&invoice.to_string()).is_ok());
    }
}
