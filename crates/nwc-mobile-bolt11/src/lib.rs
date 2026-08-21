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
/// The returned principal is the explicit NWC amount when present, otherwise
/// the amount encoded by the invoice. Zero-valued and amountless requests are
/// rejected.
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
/// An explicit amount is required for amountless invoices. When supplied for
/// an invoice that already carries an amount, it intentionally takes precedence
/// to match NIP-47's `amount` parameter semantics.
pub fn payment_amount(
    invoice: &Bolt11Invoice,
    explicit_amount: Option<AmountMsat>,
) -> Result<AmountMsat, HostError> {
    let amount = explicit_amount
        .or_else(|| invoice.amount_milli_satoshis().map(AmountMsat::from_msat))
        .ok_or_else(rejected)?;
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
    use super::*;

    const AMOUNTLESS_INVOICE: &str = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";
    const AMOUNT_INVOICE: &str = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";

    #[test]
    fn quote_uses_invoice_amount_and_hash() {
        let quote = quote_invoice(AMOUNT_INVOICE, None).expect("quote");

        assert_eq!(quote.principal(), AmountMsat::from_msat(250_000_000));
        assert_eq!(
            quote.payment_hash().to_hex(),
            "0001020304050607080900010203040506070809000102030405060708090102"
        );
    }

    #[test]
    fn amountless_invoice_requires_positive_explicit_amount() {
        assert_eq!(
            quote_invoice(AMOUNTLESS_INVOICE, None)
                .expect_err("missing amount")
                .kind(),
            HostErrorKind::Rejected
        );
        assert_eq!(
            quote_invoice(AMOUNTLESS_INVOICE, Some(AmountMsat::from_msat(0)))
                .expect_err("zero amount")
                .kind(),
            HostErrorKind::Rejected
        );
        assert_eq!(
            quote_invoice(AMOUNTLESS_INVOICE, Some(AmountMsat::from_msat(42_000)))
                .expect("quote")
                .principal(),
            AmountMsat::from_msat(42_000)
        );
    }

    #[test]
    fn satoshi_boundary_rejects_fractional_amounts() {
        let invoice = parse_invoice(AMOUNTLESS_INVOICE).expect("invoice");
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
            quote_invoice_sats(AMOUNTLESS_INVOICE, Some(AmountMsat::from_msat(2_001)))
                .expect_err("fractional quote")
                .kind(),
            HostErrorKind::Rejected
        );
    }

    #[test]
    fn created_invoice_preserves_metadata() {
        let invoice = parse_invoice(AMOUNT_INVOICE).expect("invoice");
        let expected_expiry = invoice.expires_at().expect("expiry").as_secs();
        let created = created_invoice(invoice).expect("created invoice");

        assert_eq!(created.invoice(), AMOUNT_INVOICE);
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
}
