//! Restricted React Native protocol. Native UniFFI APIs are not JavaScript APIs.
//! The containing application still owns consent UI; its JavaScript is trusted
//! to submit approvals. This boundary does not establish native user presence.
use crate::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const MAX_REQUEST_BYTES: usize = 131_072;
const MAX_RESPONSE_BYTES: usize = 2_097_152;

#[derive(Deserialize)]
#[serde(try_from = "String")]
struct Uint64(u64);
impl TryFrom<String> for Uint64 {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > 20
            || !value.bytes().all(|b| b.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err("invalid unsigned integer");
        }
        value
            .parse()
            .map(Self)
            .map_err(|_| "unsigned integer out of range")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Approval {
    methods: Vec<MobileNwcMethod>,
    budget_limit_sat: Uint64,
    budget_interval: MobileBudgetInterval,
    encryption: MobileNwcEncryption,
    expires_at: Option<Uint64>,
    payer_username: Option<String>,
    wallet_name: Option<String>,
    payer_address_json: Option<String>,
}
impl From<Approval> for MobileConnectionOptions {
    fn from(value: Approval) -> Self {
        Self {
            methods: value.methods,
            budget_limit_sat: value.budget_limit_sat.0,
            budget_interval: value.budget_interval,
            encryption: value.encryption,
            expires_at: value.expires_at.map(|v| v.0),
            payer_username: value.payer_username,
            wallet_name: value.wallet_name,
            payer_address_json: value.payer_address_json,
        }
    }
}

#[derive(Deserialize)]
#[serde(
    tag = "method",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Command {
    ServicePublicKey {},
    ListConnections {},
    RevokeConnection {
        connection_id: String,
    },
    ParseNwaRequest {
        uri: String,
    },
    PendingNwaRequest {},
    ApproveNwaRequest {
        request_id: String,
        options: Approval,
    },
    ApproveNwaReusablePayment {
        request_id: String,
        options: Approval,
        wallet_id: String,
    },
    ApproveNwaWalletManagedPayment {
        request_id: String,
        options: Approval,
        wallet_id: String,
        invoice: String,
        payment_hash_hex: String,
        invoice_amount_msat: Uint64,
    },
    CancelNwaRequest {},
    ParseBrowserPairingChallenge {
        connection_id: String,
        signed_encrypted_event_json: String,
    },
    ApproveBrowserPairing {
        challenge_id: String,
    },
    CancelBrowserPairing {
        challenge_id: String,
    },
    RefreshWakeRegistrations {
        enabled: bool,
    },
    ProcessFcmWakeRegistrations {
        server_url: String,
        push_token: String,
        app_id: String,
        install_id: String,
    },
    ProcessApnsWakeRegistrations {
        server_url: String,
        push_token: String,
        app_id: String,
        install_id: String,
        environment: String,
    },
    BindConnectionPayment {
        connection_id: String,
        wallet_id: String,
        payment_hash_hex: String,
        amount_msat: Uint64,
        maximum_fee_sat: Uint64,
    },
    PollRequests {
        execution_milliseconds: Uint64,
    },
    ListPendingPayments {},
    BeginPayment {
        event_id_hex: String,
        wallet_id: String,
    },
    BeginPaymentWithConsent {
        event_id_hex: String,
        wallet_id: String,
        customer_data_json: String,
    },
    CompletePayment {
        event_id_hex: String,
        preimage_hex: String,
        amount_msat: Uint64,
        fee_msat: Uint64,
    },
    RejectPayment {
        event_id_hex: String,
    },
    FailPayment {
        event_id_hex: String,
    },
    ResumePayment {
        event_id_hex: String,
        execution_milliseconds: Uint64,
    },
}
fn parse_request(request: &str) -> Result<Command, MobileEngineError> {
    if request.len() > MAX_REQUEST_BYTES {
        return Err(MobileEngineError::InvalidArgument);
    }
    serde_json::from_str(request).map_err(|_| MobileEngineError::InvalidArgument)
}

// u64 is never transported as a JSON number: JS cannot represent its full range.
fn encode(value: impl Serialize) -> Result<String, MobileEngineError> {
    fn integers(value: &mut Value) {
        match value {
            Value::Number(n) => *value = serde_json::json!({ "$nwcU64": n.to_string() }),
            Value::Array(items) => items.iter_mut().for_each(integers),
            Value::Object(items) => items.values_mut().for_each(integers),
            _ => {}
        }
    }
    let mut value = serde_json::to_value(value).map_err(|_| MobileEngineError::CorruptData)?;
    integers(&mut value);
    let encoded = value.to_string();
    if encoded.len() > MAX_RESPONSE_BYTES {
        return Err(MobileEngineError::InvalidArgument);
    }
    Ok(encoded)
}

/// The only wallet operation exposed by the RN platform adapter. Parse the
/// complete bounded command before invoking the native wallet factory. Unknown
/// operations, fields, enums and malformed integers fail without side effects.
#[uniffi::export]
pub async fn dispatch_mobile_wallet_json(
    wallet_id: String,
    request_json: String,
) -> Result<String, MobileEngineError> {
    // Keep the closed error classification through platform promise adapters.
    // Never serialize host error text or remote payloads.
    Ok(match dispatch(wallet_id, request_json).await {
        Ok(value) => value,
        Err(error) => serde_json::json!({ "$nwcError": format!("{error:?}") }).to_string(),
    })
}

async fn dispatch(wallet_id: String, request_json: String) -> Result<String, MobileEngineError> {
    let command = parse_request(&request_json)?;
    let wallet = open_registered_mobile_wallet(wallet_id)?;
    match command {
        Command::ServicePublicKey {} => encode(wallet.service_public_key()),
        Command::ListConnections {} => encode(wallet.list_connections()?),
        Command::RevokeConnection { connection_id } => {
            encode(wallet.revoke_connection(connection_id)?)
        }
        Command::ParseNwaRequest { uri } => encode(wallet.parse_nwa_request(uri)?),
        Command::PendingNwaRequest {} => encode(wallet.pending_nwa_request()?),
        Command::ApproveNwaRequest {
            request_id,
            options,
        } => encode(wallet.approve_nwa_request(request_id, options.into())?),
        Command::ApproveNwaReusablePayment {
            request_id,
            options,
            wallet_id,
        } => encode(wallet.approve_nwa_reusable_payment(request_id, options.into(), wallet_id)?),
        Command::ApproveNwaWalletManagedPayment {
            request_id,
            options,
            wallet_id,
            invoice,
            payment_hash_hex,
            invoice_amount_msat,
        } => encode(wallet.approve_nwa_wallet_managed_payment(
            request_id,
            options.into(),
            wallet_id,
            invoice,
            payment_hash_hex,
            invoice_amount_msat.0,
        )?),
        Command::CancelNwaRequest {} => encode(wallet.cancel_nwa_request()?),
        Command::ParseBrowserPairingChallenge {
            connection_id,
            signed_encrypted_event_json,
        } => encode(
            wallet.parse_browser_pairing_challenge(connection_id, signed_encrypted_event_json)?,
        ),
        Command::ApproveBrowserPairing { challenge_id } => {
            encode(wallet.approve_browser_pairing(challenge_id).await?)
        }
        Command::CancelBrowserPairing { challenge_id } => {
            encode(wallet.cancel_browser_pairing(challenge_id)?)
        }
        Command::RefreshWakeRegistrations { enabled } => {
            encode(wallet.refresh_wake_registrations(enabled)?)
        }
        Command::ProcessFcmWakeRegistrations {
            server_url,
            push_token,
            app_id,
            install_id,
        } => encode(
            wallet
                .process_fcm_wake_registrations(server_url, push_token, app_id, install_id)
                .await?,
        ),
        Command::ProcessApnsWakeRegistrations {
            server_url,
            push_token,
            app_id,
            install_id,
            environment,
        } => encode(
            wallet
                .process_apns_wake_registrations(
                    server_url,
                    push_token,
                    app_id,
                    install_id,
                    environment,
                )
                .await?,
        ),
        Command::BindConnectionPayment {
            connection_id,
            wallet_id,
            payment_hash_hex,
            amount_msat,
            maximum_fee_sat,
        } => encode(wallet.bind_connection_payment(
            connection_id,
            wallet_id,
            payment_hash_hex,
            amount_msat.0,
            maximum_fee_sat.0,
        )?),
        Command::PollRequests {
            execution_milliseconds,
        } => Ok(wallet
            .poll_requests(execution_milliseconds.0)
            .await?
            .to_string()),
        Command::ListPendingPayments {} => encode(wallet.list_pending_payments()?),
        Command::BeginPayment {
            event_id_hex,
            wallet_id,
        } => encode(wallet.begin_payment(event_id_hex, wallet_id)?),
        Command::BeginPaymentWithConsent {
            event_id_hex,
            wallet_id,
            customer_data_json,
        } => encode(wallet.begin_payment_with_consent(
            event_id_hex,
            wallet_id,
            customer_data_json,
        )?),
        Command::CompletePayment {
            event_id_hex,
            preimage_hex,
            amount_msat,
            fee_msat,
        } => encode(wallet.complete_payment(
            event_id_hex,
            preimage_hex,
            amount_msat.0,
            fee_msat.0,
        )?),
        Command::RejectPayment { event_id_hex } => encode(wallet.reject_payment(event_id_hex)?),
        Command::FailPayment { event_id_hex } => encode(wallet.fail_payment(event_id_hex)?),
        Command::ResumePayment {
            event_id_hex,
            execution_milliseconds,
        } => {
            wallet
                .resume_payment(event_id_hex, execution_milliseconds.0)
                .await?;
            Ok("null".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_native_only_operations_and_extra_fields_before_opening_wallet() {
        for method in [
            "engine",
            "createConnection",
            "exportConnectionUri",
            "addConnection",
            "migrateLegacyConnections",
            "registerMobileWalletFactory",
            "rustbufferFree",
            "installRustCrate",
        ] {
            assert!(parse_request(&format!(r#"{{"method":"{method}"}}"#)).is_err());
        }
        assert!(parse_request(r#"{"method":"listConnections","engine":true}"#).is_err());
        assert!(parse_request(&"x".repeat(MAX_REQUEST_BYTES + 1)).is_err());
        assert!(parse_request(r#"{"method":"listConnections"}"#).is_ok());
    }

    #[test]
    fn unsigned_input_does_not_wrap_or_coerce() {
        for value in [
            "-1",
            "18446744073709551616",
            "+1",
            "1.0",
            "1e3",
            " 1",
            "01",
            "",
        ] {
            assert!(Uint64::try_from(value.to_string()).is_err(), "{value}");
        }
        assert_eq!(Uint64::try_from(u64::MAX.to_string()).unwrap().0, u64::MAX);
        assert!(serde_json::from_str::<Uint64>("1000").is_err());
        assert!(
            parse_request(r#"{"method":"pollRequests","executionMilliseconds":"-1"}"#).is_err()
        );
    }

    #[test]
    fn approval_rejects_unknown_enums_and_unsigned_overflow() {
        let valid = r#"{"method":"approveNwaRequest","requestId":"reviewed","options":{"methods":["GetInfo"],"budgetLimitSat":"100","budgetInterval":"Never","encryption":"Nip44V2"}}"#;
        assert!(parse_request(valid).is_ok());
        for invalid in [
            valid.replace("GetInfo", "pay_invoice"),
            valid.replace("Never", "Sometimes"),
            valid.replace("\"100\"", "\"-1\""),
            valid.replace("\"100\"", "100"),
            valid.replace("Nip44V2", "unknown"),
        ] {
            assert!(parse_request(&invalid).is_err());
        }
    }

    #[test]
    fn response_preserves_full_integer_range_and_optional_values() {
        let encoded = encode(MobileConnectionState {
            connection_id: "123".into(),
            revision: u64::MAX,
            active: true,
        })
        .unwrap();
        let value: Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["revision"]["$nwcU64"], u64::MAX.to_string());
        assert_eq!(value["connectionId"], "123");
        assert_eq!(
            encode(Option::<MobileConnectionState>::None).unwrap(),
            "null"
        );
    }
}
