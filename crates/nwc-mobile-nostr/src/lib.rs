//! Bounded Nostr relay transport for the `nwc-mobile` host contract.
//!
//! This integration crate owns runtime-specific WebSocket behavior while the
//! core crate remains independent of a network stack.

#![forbid(unsafe_code)]

use futures_util::{SinkExt, StreamExt};
use nwc_mobile::{
    EventId, HostError, HostErrorKind, HostFuture, OperationContext, RelayTransport, SecureRelayUrl,
};
use nwc_mobile_tokio::run_with_context;
use serde_json::{json, Value};
use tokio_tungstenite::connect_async_with_config;
use tokio_tungstenite::tungstenite::error::Error as WebSocketError;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

const NWC_REQUEST_KIND: u16 = 23_194;
const RELAY_ACK_MAX_BYTES: usize = 16 * 1_024;
const RELAY_EVENT_ENVELOPE_MAX_BYTES: usize = 512;

/// A bounded relay transport that rejects redirects and enforces host budgets.
#[derive(Clone, Copy, Debug, Default)]
pub struct NostrRelayTransport;

impl RelayTransport for NostrRelayTransport {
    fn fetch_event<'a>(
        &'a self,
        relay: &'a SecureRelayUrl,
        event_id: &'a EventId,
        maximum_event_bytes: usize,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<Option<String>, HostError>> {
        Box::pin(async move {
            if maximum_event_bytes == 0 {
                return Err(host_error(HostErrorKind::Rejected));
            }
            run_with_context(
                context,
                fetch_relay_event(relay, event_id, maximum_event_bytes),
            )
            .await
        })
    }

    fn publish_event<'a>(
        &'a self,
        relay: &'a SecureRelayUrl,
        event_json: &'a str,
        context: OperationContext<'a>,
    ) -> HostFuture<'a, Result<(), HostError>> {
        Box::pin(
            async move { run_with_context(context, publish_relay_event(relay, event_json)).await },
        )
    }
}

async fn fetch_relay_event(
    relay: &SecureRelayUrl,
    event_id: &EventId,
    maximum_event_bytes: usize,
) -> Result<Option<String>, HostError> {
    let config =
        bounded_websocket_config(fetch_wire_message_limit(maximum_event_bytes)?, 4 * 1_024);
    let (mut socket, response) = connect_async_with_config(relay.as_str(), Some(config), false)
        .await
        .map_err(relay_connect_error)?;
    if response.status().is_redirection() {
        return Err(host_error(HostErrorKind::Rejected));
    }

    let expected_event_id = event_id.to_hex();
    let subscription_id = format!("nwc-mobile-{}", &expected_event_id[..16]);
    let request = json!(["REQ", subscription_id, {
        "ids": [expected_event_id],
        "kinds": [NWC_REQUEST_KIND],
        "limit": 1
    }]);
    socket
        .send(Message::Text(request.to_string().into()))
        .await
        .map_err(relay_io_error)?;

    while let Some(message) = socket.next().await {
        match message.map_err(relay_io_error)? {
            Message::Text(text) => {
                match parse_fetch_message(
                    text.as_str(),
                    &subscription_id,
                    &expected_event_id,
                    maximum_event_bytes,
                )? {
                    FetchMessage::Event(event_json) => return Ok(Some(event_json)),
                    FetchMessage::EndOfStoredEvents => return Ok(None),
                    FetchMessage::Ignore => {}
                }
            }
            Message::Ping(payload) => socket
                .send(Message::Pong(payload))
                .await
                .map_err(relay_io_error)?,
            Message::Close(_) => return Ok(None),
            Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
    Ok(None)
}

async fn publish_relay_event(relay: &SecureRelayUrl, event_json: &str) -> Result<(), HostError> {
    let event: Value =
        serde_json::from_str(event_json).map_err(|_| host_error(HostErrorKind::Rejected))?;
    let event_id = event
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| value.len() == 64)
        .ok_or_else(|| host_error(HostErrorKind::Rejected))?
        .to_owned();
    let (mut socket, response) = connect_async_with_config(
        relay.as_str(),
        Some(bounded_websocket_config(
            RELAY_ACK_MAX_BYTES,
            event_json.len().saturating_add(512),
        )),
        false,
    )
    .await
    .map_err(relay_connect_error)?;
    if response.status().is_redirection() {
        return Err(host_error(HostErrorKind::Rejected));
    }
    socket
        .send(Message::Text(json!(["EVENT", event]).to_string().into()))
        .await
        .map_err(relay_io_error)?;

    while let Some(message) = socket.next().await {
        match message.map_err(relay_io_error)? {
            Message::Text(text) => {
                if let Some(accepted) = parse_publish_ack(text.as_str(), &event_id)? {
                    return accepted
                        .then_some(())
                        .ok_or_else(|| host_error(HostErrorKind::Unavailable));
                }
            }
            Message::Ping(payload) => socket
                .send(Message::Pong(payload))
                .await
                .map_err(relay_io_error)?,
            Message::Close(_) => return Err(host_error(HostErrorKind::Unavailable)),
            Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
    Err(host_error(HostErrorKind::Unavailable))
}

enum FetchMessage {
    Event(String),
    EndOfStoredEvents,
    Ignore,
}

fn parse_fetch_message(
    message: &str,
    subscription_id: &str,
    expected_event_id: &str,
    maximum_event_bytes: usize,
) -> Result<FetchMessage, HostError> {
    let value: Value =
        serde_json::from_str(message).map_err(|_| host_error(HostErrorKind::Rejected))?;
    let Some(values) = value.as_array() else {
        return Err(host_error(HostErrorKind::Rejected));
    };
    match values.first().and_then(Value::as_str) {
        Some("EVENT") if values.get(1).and_then(Value::as_str) == Some(subscription_id) => {
            let Some(event) = values.get(2).filter(|event| event.is_object()) else {
                return Ok(FetchMessage::Ignore);
            };
            if event.get("id").and_then(Value::as_str) != Some(expected_event_id)
                || event.get("kind").and_then(Value::as_u64) != Some(u64::from(NWC_REQUEST_KIND))
            {
                return Ok(FetchMessage::Ignore);
            }
            let event_json =
                serde_json::to_string(event).map_err(|_| host_error(HostErrorKind::Rejected))?;
            if event_json.len() > maximum_event_bytes {
                return Err(host_error(HostErrorKind::Rejected));
            }
            Ok(FetchMessage::Event(event_json))
        }
        Some("EOSE") if values.get(1).and_then(Value::as_str) == Some(subscription_id) => {
            Ok(FetchMessage::EndOfStoredEvents)
        }
        Some("CLOSED") if values.get(1).and_then(Value::as_str) == Some(subscription_id) => {
            Err(host_error(HostErrorKind::Unavailable))
        }
        _ => Ok(FetchMessage::Ignore),
    }
}

fn fetch_wire_message_limit(maximum_event_bytes: usize) -> Result<usize, HostError> {
    maximum_event_bytes
        .checked_add(RELAY_EVENT_ENVELOPE_MAX_BYTES)
        .ok_or_else(|| host_error(HostErrorKind::Rejected))
}

fn parse_publish_ack(message: &str, event_id: &str) -> Result<Option<bool>, HostError> {
    let value: Value =
        serde_json::from_str(message).map_err(|_| host_error(HostErrorKind::Rejected))?;
    let Some(values) = value.as_array() else {
        return Err(host_error(HostErrorKind::Rejected));
    };
    if values.first().and_then(Value::as_str) != Some("OK")
        || values.get(1).and_then(Value::as_str) != Some(event_id)
    {
        return Ok(None);
    }
    values
        .get(2)
        .and_then(Value::as_bool)
        .map(Some)
        .ok_or_else(|| host_error(HostErrorKind::Rejected))
}

fn bounded_websocket_config(
    maximum_message_bytes: usize,
    maximum_outgoing_bytes: usize,
) -> WebSocketConfig {
    let buffer = maximum_message_bytes.clamp(1_024, 16 * 1_024);
    WebSocketConfig::default()
        .read_buffer_size(buffer)
        .write_buffer_size(4 * 1_024)
        .max_write_buffer_size(maximum_outgoing_bytes.saturating_add(8 * 1_024))
        .max_message_size(Some(maximum_message_bytes))
        .max_frame_size(Some(maximum_message_bytes))
}

fn relay_connect_error(error: WebSocketError) -> HostError {
    match error {
        WebSocketError::Http(response) if response.status().is_redirection() => {
            host_error(HostErrorKind::Rejected)
        }
        _ => host_error(HostErrorKind::Unavailable),
    }
}

fn relay_io_error(error: WebSocketError) -> HostError {
    match error {
        WebSocketError::Capacity(_) => host_error(HostErrorKind::Rejected),
        _ => host_error(HostErrorKind::Unavailable),
    }
}

const fn host_error(kind: HostErrorKind) -> HostError {
    HostError::new(kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVENT_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn relay_parser_returns_only_the_requested_bounded_event() {
        let message = json!(["EVENT", "subscription", {"id": EVENT_ID, "kind": NWC_REQUEST_KIND}])
            .to_string();
        assert!(matches!(
            parse_fetch_message(&message, "subscription", EVENT_ID, 1_024),
            Ok(FetchMessage::Event(_))
        ));
        assert!(matches!(
            parse_fetch_message(&message, "other", EVENT_ID, 1_024),
            Ok(FetchMessage::Ignore)
        ));
        assert!(parse_fetch_message(&message, "subscription", EVENT_ID, 1).is_err());

        let wrong_event = json!([
            "EVENT",
            "subscription",
            {"id": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "kind": NWC_REQUEST_KIND}
        ])
        .to_string();
        assert!(matches!(
            parse_fetch_message(&wrong_event, "subscription", EVENT_ID, 1_024),
            Ok(FetchMessage::Ignore)
        ));

        let wrong_kind = json!(["EVENT", "subscription", {"id": EVENT_ID, "kind": 1}]).to_string();
        assert!(matches!(
            parse_fetch_message(&wrong_kind, "subscription", EVENT_ID, 1_024),
            Ok(FetchMessage::Ignore)
        ));

        for malformed_event in [
            json!(["EVENT", "subscription"]).to_string(),
            json!(["EVENT", "subscription", null]).to_string(),
            json!(["EVENT", "subscription", []]).to_string(),
            json!(["EVENT", "subscription", "not-an-event"]).to_string(),
        ] {
            assert!(matches!(
                parse_fetch_message(&malformed_event, "subscription", EVENT_ID, 1_024),
                Ok(FetchMessage::Ignore)
            ));
        }
    }

    #[test]
    fn publish_ack_must_match_event_and_boolean_shape() {
        assert_eq!(
            parse_publish_ack(&json!(["OK", EVENT_ID, true, ""]).to_string(), EVENT_ID),
            Ok(Some(true))
        );
        assert_eq!(
            parse_publish_ack(&json!(["OK", "other", true, ""]).to_string(), EVENT_ID),
            Ok(None)
        );
        assert!(
            parse_publish_ack(&json!(["OK", EVENT_ID, "true", ""]).to_string(), EVENT_ID).is_err()
        );
    }

    #[test]
    fn websocket_limits_are_applied_before_reads() {
        let wire_limit = fetch_wire_message_limit(2_048).expect("bounded wire limit");
        let config = bounded_websocket_config(wire_limit, 4_096);
        assert_eq!(wire_limit, 2_048 + RELAY_EVENT_ENVELOPE_MAX_BYTES);
        assert_eq!(config.max_message_size, Some(wire_limit));
        assert_eq!(config.max_frame_size, Some(wire_limit));
        assert_eq!(config.read_buffer_size, wire_limit);
        assert!(config.max_write_buffer_size > 4_096);
        assert!(fetch_wire_message_limit(usize::MAX).is_err());
    }
}
