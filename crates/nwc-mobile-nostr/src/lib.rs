//! Bounded Nostr relay transport for the `nwc-mobile` host contract.
//!
//! This integration crate owns runtime-specific WebSocket behavior while the
//! core crate remains independent of a network stack.

#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures_util::{
    lock::{Mutex as AsyncMutex, OwnedMutexGuard},
    Sink, SinkExt, Stream, StreamExt,
};
use nwc_mobile::{
    build_nwc_info_event, build_nwc_info_event_with_notifications, Clock, EventId, HostError,
    HostErrorKind, HostFuture, NeverCancelled, NwcEncryption, NwcMethod, NwcNotificationType,
    NwcSecretKey, OperationBudget, OperationContext, PublicKey, RelayTransport, SecureRelayUrl,
    SystemClock, UnixTimestamp,
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

const SESSION_MAX_BYTES: usize = 132_000;
const SESSION_IDLE_LIMIT: Duration = Duration::from_secs(120);
const MAX_RELAY_SESSIONS: usize = 64;
trait RelaySocket:
    Stream<Item = Result<Message, WebSocketError>>
    + Sink<Message, Error = WebSocketError>
    + Send
    + Unpin
{
}
impl<T> RelaySocket for T where
    T: Stream<Item = Result<Message, WebSocketError>>
        + Sink<Message, Error = WebSocketError>
        + Send
        + Unpin
{
}
type BoxSocket = Box<dyn RelaySocket>;
struct IdleSocket {
    socket: BoxSocket,
    returned_at: Instant,
}
type SessionSlot = Arc<AsyncMutex<Option<IdleSocket>>>;
struct SessionEntry {
    slot: SessionSlot,
    used_at: Instant,
}
fn session_slot(relay: &str) -> Result<SessionSlot, HostError> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, SessionEntry>>> = OnceLock::new();
    let now = Instant::now();
    let mut sessions = SESSIONS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| host_error(HostErrorKind::Unavailable))?;
    sessions.retain(|_, entry| {
        Arc::strong_count(&entry.slot) > 1 || now.duration_since(entry.used_at) < SESSION_IDLE_LIMIT
    });
    if let Some(entry) = sessions.get_mut(relay) {
        entry.used_at = now;
        return Ok(entry.slot.clone());
    }
    if sessions.len() == MAX_RELAY_SESSIONS {
        return Err(host_error(HostErrorKind::Unavailable));
    }
    let slot = Arc::new(AsyncMutex::new(None));
    sessions.insert(
        relay.to_owned(),
        SessionEntry {
            slot: slot.clone(),
            used_at: now,
        },
    );
    Ok(slot)
}
// The socket is removed from its slot while leased. Cancellation or any error
// drops it, so an incomplete request can never contaminate the next operation.
struct RelaySession {
    socket: BoxSocket,
    slot: OwnedMutexGuard<Option<IdleSocket>>,
}
impl RelaySession {
    async fn open(relay: &SecureRelayUrl) -> Result<Self, HostError> {
        check_relay_cooldown(relay.as_str())?;
        let mut slot = session_slot(relay.as_str())?.lock_owned().await;
        check_relay_cooldown(relay.as_str())?;
        if let Some(idle) = slot
            .take()
            .filter(|idle| idle.returned_at.elapsed() < SESSION_IDLE_LIMIT)
        {
            return Ok(Self {
                socket: idle.socket,
                slot,
            });
        }
        let (socket, response) = connect_async_with_config(
            relay.as_str(),
            Some(bounded_websocket_config(
                SESSION_MAX_BYTES,
                SESSION_MAX_BYTES,
            )),
            false,
        )
        .await
        .map_err(|error| relay_connect_error_for(relay.as_str(), error))?;
        if response.status().is_redirection() {
            return Err(host_error(HostErrorKind::Rejected));
        }
        Ok(Self {
            socket: Box::new(socket),
            slot,
        })
    }
    fn recycle(mut self) {
        *self.slot = Some(IdleSocket {
            socket: self.socket,
            returned_at: Instant::now(),
        });
    }
    async fn finish_subscription(mut self, subscription: &str) -> Result<(), HostError> {
        self.socket
            .send(Message::Text(
                json!(["CLOSE", subscription]).to_string().into(),
            ))
            .await
            .map_err(relay_io_error)?;
        self.recycle();
        Ok(())
    }
}
fn next_subscription_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("nwc-mobile-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// A bounded relay transport that rejects redirects and enforces host budgets.
#[derive(Clone, Copy, Debug, Default)]
pub struct NostrRelayTransport;

/// Builds, signs, and publishes one bounded NIP-47 info event.
///
/// This is the high-level host boundary for wallet applications. It keeps
/// relay validation, event construction, operation budgeting, and transport
/// behavior under the same reviewed implementation.
pub async fn publish_nwc_info_event(
    relay_url: &str,
    wallet_service_secret: &NwcSecretKey,
    client_pubkey: Option<&PublicKey>,
    methods: Vec<NwcMethod>,
    encryption: NwcEncryption,
    timeout: Duration,
) -> Result<(), HostError> {
    let (relay, event_json, budget) = prepare_nwc_info_publication(
        relay_url,
        wallet_service_secret,
        client_pubkey,
        methods,
        encryption,
        SystemClock.now(),
        timeout,
    )?;
    NostrRelayTransport
        .publish_event(
            &relay,
            &event_json,
            OperationContext::new(budget, &NeverCancelled),
        )
        .await
}

/// Publishes one wallet-info event with notification capability advertisement.
pub async fn publish_nwc_info_event_with_notifications(
    relay_url: &str,
    wallet_service_secret: &NwcSecretKey,
    client_pubkey: Option<&PublicKey>,
    methods: Vec<NwcMethod>,
    notifications: Vec<NwcNotificationType>,
    encryption: NwcEncryption,
    timeout: Duration,
) -> Result<(), HostError> {
    let relay =
        SecureRelayUrl::parse(relay_url).map_err(|_| host_error(HostErrorKind::Rejected))?;
    let event_json = build_nwc_info_event_with_notifications(
        wallet_service_secret,
        client_pubkey,
        methods,
        notifications,
        encryption,
        SystemClock.now(),
    )
    .map_err(|_| host_error(HostErrorKind::Rejected))?;
    let budget = OperationBudget::new(timeout).map_err(|_| host_error(HostErrorKind::Rejected))?;
    NostrRelayTransport
        .publish_event(
            &relay,
            &event_json,
            OperationContext::new(budget, &NeverCancelled),
        )
        .await
}

fn prepare_nwc_info_publication(
    relay_url: &str,
    wallet_service_secret: &NwcSecretKey,
    client_pubkey: Option<&PublicKey>,
    methods: Vec<NwcMethod>,
    encryption: NwcEncryption,
    created_at: UnixTimestamp,
    timeout: Duration,
) -> Result<(SecureRelayUrl, String, OperationBudget), HostError> {
    let relay =
        SecureRelayUrl::parse(relay_url).map_err(|_| host_error(HostErrorKind::Rejected))?;
    let event_json = build_nwc_info_event(
        wallet_service_secret,
        client_pubkey,
        methods,
        encryption,
        created_at,
    )
    .map_err(|_| host_error(HostErrorKind::Rejected))?;
    let budget = OperationBudget::new(timeout).map_err(|_| host_error(HostErrorKind::Rejected))?;
    Ok((relay, event_json, budget))
}

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
    if fetch_wire_message_limit(maximum_event_bytes)? > SESSION_MAX_BYTES {
        return Err(host_error(HostErrorKind::Rejected));
    }
    let mut session = RelaySession::open(relay).await?;
    let socket = &mut session.socket;
    let expected_event_id = event_id.to_hex();
    let subscription_id = next_subscription_id();
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
                    FetchMessage::Event(event_json) => {
                        session.finish_subscription(&subscription_id).await?;
                        return Ok(Some(event_json));
                    }
                    FetchMessage::EndOfStoredEvents => {
                        session.finish_subscription(&subscription_id).await?;
                        return Ok(None);
                    }
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
    if event_json.len() > SESSION_MAX_BYTES - RELAY_EVENT_ENVELOPE_MAX_BYTES {
        return Err(host_error(HostErrorKind::Rejected));
    }
    let mut session = RelaySession::open(relay).await?;
    let socket = &mut session.socket;
    socket
        .send(Message::Text(json!(["EVENT", event]).to_string().into()))
        .await
        .map_err(relay_io_error)?;

    while let Some(message) = socket.next().await {
        match message.map_err(relay_io_error)? {
            Message::Text(text) => {
                if text.len() > RELAY_ACK_MAX_BYTES {
                    continue;
                }
                if let Some(accepted) = parse_publish_ack(text.as_str(), &event_id)? {
                    if !accepted {
                        return Err(host_error(HostErrorKind::Unavailable));
                    }
                    session.recycle();
                    return Ok(());
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

// Shared across info/response publication, exact fetches, and foreground polling.
// Failed provider attempts never acknowledge durable outbox work.
const MAX_RELAY_COOLDOWNS: usize = 64;
#[derive(Default)]
struct RelayCooldowns {
    until: HashMap<String, Instant>,
    overflow_until: Option<Instant>,
}
impl RelayCooldowns {
    fn blocked(&mut self, relay: &str, now: Instant) -> bool {
        self.until.retain(|_, deadline| *deadline > now);
        self.overflow_until.is_some_and(|deadline| deadline > now) || self.until.contains_key(relay)
    }
    fn record(&mut self, relay: &str, now: Instant, duration: Duration) {
        self.until.retain(|_, deadline| *deadline > now);
        let deadline = now + duration;
        if self.until.len() < MAX_RELAY_COOLDOWNS || self.until.contains_key(relay) {
            self.until
                .entry(relay.to_owned())
                .and_modify(|current| *current = (*current).max(deadline))
                .or_insert(deadline);
        } else {
            // Keep every recorded cooldown intact rather than evicting a throttled relay.
            self.overflow_until = Some(
                self.overflow_until
                    .map_or(deadline, |current| current.max(deadline)),
            );
        }
    }
}
fn relay_cooldowns() -> &'static Mutex<RelayCooldowns> {
    static COOLDOWNS: OnceLock<Mutex<RelayCooldowns>> = OnceLock::new();
    COOLDOWNS.get_or_init(|| Mutex::new(RelayCooldowns::default()))
}
fn check_relay_cooldown(relay: &str) -> Result<(), HostError> {
    let mut cooldowns = relay_cooldowns()
        .lock()
        .map_err(|_| host_error(HostErrorKind::Unavailable))?;
    if cooldowns.blocked(relay, Instant::now()) {
        Err(host_error(HostErrorKind::Unavailable))
    } else {
        Ok(())
    }
}
fn relay_connect_error_for(relay: &str, error: WebSocketError) -> HostError {
    if let WebSocketError::Http(response) = &error {
        if response.status().as_u16() == 429 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let delay = retry_after_delay(
                response
                    .headers()
                    .get("retry-after")
                    .and_then(|header| header.to_str().ok()),
                now,
            );
            if let Ok(mut cooldowns) = relay_cooldowns().lock() {
                cooldowns.record(relay, Instant::now(), delay);
            }
        }
    }
    relay_connect_error(error)
}
fn retry_after_delay(value: Option<&str>, now_seconds: u64) -> Duration {
    let seconds = value
        .and_then(|value| {
            let value = value.trim();
            if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
                value.parse::<u64>().ok().or(Some(u64::MAX))
            } else {
                http_date_seconds(value).map(|deadline| deadline.saturating_sub(now_seconds))
            }
        })
        .unwrap_or(60);
    Duration::from_secs(seconds.clamp(1, 300))
}
// IMF-fixdate, the HTTP-date format emitted by conforming Retry-After servers.
fn http_date_seconds(value: &str) -> Option<u64> {
    if value.len() != 29 || !value.is_ascii() {
        return None;
    }
    let fields = value.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 6
        || !matches!(
            fields[0],
            "Mon," | "Tue," | "Wed," | "Thu," | "Fri," | "Sat," | "Sun,"
        )
        || fields[5] != "GMT"
    {
        return None;
    }
    let day = fields[1].parse::<u64>().ok()?;
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|month| *month == fields[2])?;
    let year = fields[3].parse::<u64>().ok()?;
    if !(1970..=9999).contains(&year) {
        return None;
    }
    let leap = |year: u64| {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    };
    let month_days = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > month_days[month] {
        return None;
    }
    let time = fields[4]
        .split(':')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if time.len() != 3 || time[0] > 23 || time[1] > 59 || time[2] > 59 {
        return None;
    }
    let days = (1970..year)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<u64>()
        + month_days[..month].iter().sum::<u64>()
        + day
        - 1;
    Some(days * 86400 + time[0] * 3600 + time[1] * 60 + time[2])
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

/// Fetches at most 32 stored request candidates for one approved client and wallet.
/// The caller must pass every result through the authenticated engine before using it.
pub async fn fetch_request_candidates(
    relay: &SecureRelayUrl,
    wallet: &PublicKey,
    client: &PublicKey,
    since: UnixTimestamp,
    context: OperationContext<'_>,
) -> Result<Vec<(EventId, String)>, HostError> {
    run_with_context(context, async {
        let mut session = RelaySession::open(relay).await?;
        let socket = &mut session.socket;
        let subscription=next_subscription_id();
        let request=json!(["REQ",subscription,{"kinds":[NWC_REQUEST_KIND],"authors":[client.to_hex()],"#p":[wallet.to_hex()],"since":since.as_secs(),"limit":32}]);
        socket.send(Message::Text(request.to_string().into())).await.map_err(relay_io_error)?;
        let mut events=Vec::new();
        let mut frames=0;
        while let Some(message)=socket.next().await {
            frames+=1;
            if frames>128 {break;}
            match message.map_err(relay_io_error)? {
                Message::Text(text)=>{
                    let value:Value=serde_json::from_str(&text).map_err(|_|host_error(HostErrorKind::Rejected))?;
                    let Some(parts)=value.as_array() else {continue;};
                    if parts.get(1).and_then(Value::as_str)!=Some(subscription.as_str()){continue;}
                    if parts.first().and_then(Value::as_str)==Some("EOSE"){session.finish_subscription(&subscription).await?; return Ok(events);}
                    if parts.first().and_then(Value::as_str)==Some("CLOSED"){return Err(host_error(HostErrorKind::Unavailable));}
                    if parts.first().and_then(Value::as_str)==Some("EVENT") {
                        let Some(event)=parts.get(2) else {continue;};
                        let Some(id)=event.get("id").and_then(Value::as_str) else {continue;};
                        let Ok(id)=EventId::from_hex(id) else {continue;};
                        let json=event.to_string();
                        if json.len()>131_072{return Err(host_error(HostErrorKind::Rejected));}
                        events.push((id,json));
                        if events.len()==32{break;}
                    }
                }
                Message::Ping(payload)=>socket.send(Message::Pong(payload)).await.map_err(relay_io_error)?,
                Message::Close(_)=>break,
                _=>{}
            }
        }
        // Frame/event bounds or socket closure discard the lease rather than
        // reusing a session with an unfinished subscription.
        Ok(events)
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSocket {
        sent: Arc<Mutex<Vec<Value>>>,
        incoming: std::collections::VecDeque<Message>,
        dropped: Arc<std::sync::atomic::AtomicUsize>,
        respond: bool,
    }
    impl Drop for MockSocket {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl Stream for MockSocket {
        type Item = Result<Message, WebSocketError>;
        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            self.incoming
                .pop_front()
                .map_or(std::task::Poll::Pending, |message| {
                    std::task::Poll::Ready(Some(Ok(message)))
                })
        }
    }
    impl Sink<Message> for MockSocket {
        type Error = WebSocketError;
        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn start_send(
            mut self: std::pin::Pin<&mut Self>,
            message: Message,
        ) -> Result<(), Self::Error> {
            if let Message::Text(text) = message {
                let value: Value = serde_json::from_str(&text).unwrap();
                if self.respond {
                    if value[0] == "REQ" {
                        self.incoming.push_back(Message::Text(
                            json!(["EOSE", "stale-subscription"]).to_string().into(),
                        ));
                        self.incoming
                            .push_back(Message::Text(json!(["EOSE", value[1]]).to_string().into()));
                    } else if value[0] == "EVENT" {
                        self.incoming.push_back(Message::Text(
                            json!(["OK", value[1]["id"], true, ""]).to_string().into(),
                        ));
                    }
                }
                self.sent.lock().unwrap().push(value);
            }
            Ok(())
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
    fn ready<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
        {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => panic!("mock operation unexpectedly blocked"),
        }
    }
    #[test]
    fn pooled_session_reuses_socket_and_closes_unique_subscriptions() {
        let relay = SecureRelayUrl::parse("wss://session-reuse.invalid").unwrap();
        let slot = session_slot(relay.as_str()).unwrap();
        let sent = Arc::new(Mutex::new(Vec::new()));
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        *ready(slot.lock()) = Some(IdleSocket {
            socket: Box::new(MockSocket {
                sent: sent.clone(),
                incoming: Default::default(),
                dropped: dropped.clone(),
                respond: true,
            }),
            returned_at: Instant::now(),
        });
        let id = EventId::from_hex(EVENT_ID).unwrap();
        assert_eq!(
            ready(fetch_relay_event(&relay, &id, 131_072)).unwrap(),
            None
        );
        assert_eq!(
            ready(fetch_relay_event(&relay, &id, 131_072)).unwrap(),
            None
        );
        ready(publish_relay_event(
            &relay,
            &json!({"id":EVENT_ID}).to_string(),
        ))
        .unwrap();
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 5);
        assert_eq!(sent[0][0], "REQ");
        assert_eq!(sent[1], json!(["CLOSE", sent[0][1]]));
        assert_eq!(sent[2][0], "REQ");
        assert_eq!(sent[3], json!(["CLOSE", sent[2][1]]));
        assert_ne!(sent[0][1], sent[2][1]);
        assert_eq!(sent[4][0], "EVENT");
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        ready(slot.lock()).take();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn cancelling_session_discards_socket_and_releases_waiting_operation() {
        let relay = SecureRelayUrl::parse("wss://session-cancellation.invalid").unwrap();
        let slot = session_slot(relay.as_str()).unwrap();
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        *ready(slot.lock()) = Some(IdleSocket {
            socket: Box::new(MockSocket {
                sent: Default::default(),
                incoming: Default::default(),
                dropped: dropped.clone(),
                respond: false,
            }),
            returned_at: Instant::now(),
        });
        let id = EventId::from_hex(EVENT_ID).unwrap();
        let mut fetch = Box::pin(fetch_relay_event(&relay, &id, 131_072));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(std::future::Future::poll(fetch.as_mut(), &mut cx).is_pending());
        let mut waiter = Box::pin(slot.clone().lock_owned());
        assert!(std::future::Future::poll(waiter.as_mut(), &mut cx).is_pending());
        drop(fetch);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(ready(waiter).is_none());
    }

    const EVENT_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn http_429_blocks_every_transport_path_for_that_relay_only() {
        let relay = "wss://cooldown-test.invalid";
        assert!(check_relay_cooldown(relay).is_ok());
        let response = tokio_tungstenite::tungstenite::http::Response::builder()
            .status(429)
            .header("retry-after", "135")
            .body(None)
            .unwrap();
        assert_eq!(
            relay_connect_error_for(relay, WebSocketError::Http(Box::new(response))).kind(),
            HostErrorKind::Unavailable
        );
        assert!(check_relay_cooldown(relay).is_err());
        assert!(check_relay_cooldown("wss://other-cooldown-test.invalid").is_ok());
        let remaining = relay_cooldowns().lock().unwrap().until[relay]
            .saturating_duration_since(Instant::now());
        assert!(remaining > Duration::from_secs(130));
    }

    #[test]
    fn relay_cooldown_honors_full_retry_after_and_bounds_storage() {
        assert_eq!(retry_after_delay(Some("135"), 0), Duration::from_secs(135));
        assert_eq!(
            retry_after_delay(Some("Thu, 01 Jan 1970 00:02:15 GMT"), 0),
            Duration::from_secs(135)
        );
        assert_eq!(retry_after_delay(Some("bad"), 0), Duration::from_secs(60));
        assert_eq!(
            retry_after_delay(Some("999999999999999999999999"), 0),
            Duration::from_secs(300)
        );
        assert_eq!(retry_after_delay(Some("0"), 0), Duration::from_secs(1));
        let now = Instant::now();
        let mut state = RelayCooldowns::default();
        state.record("relay-a", now, Duration::from_secs(135));
        assert!(state.blocked("relay-a", now + Duration::from_secs(134)));
        assert!(!state.blocked("relay-b", now));
        state.record("relay-a", now, Duration::from_secs(60));
        assert!(state.blocked("relay-a", now + Duration::from_secs(134)));
        assert!(!state.blocked("relay-a", now + Duration::from_secs(135)));
        for index in 0..65 {
            state.record(&format!("relay-{index}"), now, Duration::from_secs(135));
        }
        assert_eq!(state.until.len(), 64);
        assert!(state.blocked("overflow-relay", now + Duration::from_secs(134)));
        assert!(!state.blocked("overflow-relay", now + Duration::from_secs(135)));
    }

    #[test]
    fn info_publication_preparation_owns_validation_signing_and_budget() {
        let secret = NwcSecretKey::from_bytes([7_u8; 32]).expect("secret");
        let client = PublicKey::from_hex(EVENT_ID).expect("client");
        let (relay, event_json, budget) = prepare_nwc_info_publication(
            "wss://relay.example/nwc",
            &secret,
            Some(&client),
            vec![NwcMethod::PayInvoice, NwcMethod::GetInfo],
            NwcEncryption::LegacyNip04,
            UnixTimestamp::from_secs(1_700_000_000),
            Duration::from_secs(10),
        )
        .expect("publication");

        let event: Value = serde_json::from_str(&event_json).expect("signed event JSON");
        assert_eq!(event["kind"], 13_194);
        assert_eq!(event["created_at"], 1_700_000_000_u64);
        assert_eq!(event["sig"].as_str().map(str::len), Some(128));
        assert_eq!(relay.as_str(), "wss://relay.example/nwc");
        assert_eq!(budget.timeout(), Duration::from_secs(10));

        assert!(prepare_nwc_info_publication(
            "ws://relay.example",
            &secret,
            None,
            vec![NwcMethod::GetInfo],
            NwcEncryption::LegacyNip04,
            UnixTimestamp::from_secs(1),
            Duration::from_secs(1),
        )
        .is_err());
        assert!(prepare_nwc_info_publication(
            "wss://relay.example",
            &secret,
            None,
            vec![NwcMethod::GetInfo],
            NwcEncryption::LegacyNip04,
            UnixTimestamp::from_secs(1),
            Duration::ZERO,
        )
        .is_err());
    }

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
