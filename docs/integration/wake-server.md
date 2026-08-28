# Wake-service integration

The wake service is separate infrastructure. It observes Nostr relays for
registered public connection identities and sends APNs or FCM routing payloads
to wake a wallet. It is not trusted to authorize or decrypt NWC requests.

The [`nwc-mobile-http`](../../crates/nwc-mobile-http/src/lib.rs) crate implements
the wallet-side HTTPS transport used by the current protocol. The current
reference deployment lives in the separate
[`notification-server`](https://github.com/ntheile/notification-server/tree/nwc-wake)
repository.

## Server responsibilities

A compatible service must:

1. accept authenticated, idempotent connection registration changes;
2. enforce monotonically increasing connection revisions;
3. retain only public NWC routing identifiers and provider delivery metadata;
4. subscribe to each approved secure Nostr relay;
5. match encrypted request events to active registrations;
6. deduplicate event delivery;
7. send bounded APNs or FCM routing payloads;
8. optionally schedule targeted incoming-invoice settlement wakes; and
9. expose operational health without exposing wallet activity.

The reference HTTP client resolves these paths relative to the configured
secure base URL:

- `register-nwc-push` for connection enable/disable changes; and
- `monitor-nwc-invoice` for optional targeted settlement-monitor lifecycle.

Path prefixes are preserved. For example, a base URL of
`https://wake.example.com/api/` resolves registration to
`https://wake.example.com/api/register-nwc-push`.

## Registration lifecycle

Connection approval and registration are not one distributed transaction.
`nwc-mobile` therefore commits the connection and a desired registration change
to one local transaction. A worker later sends the change and acknowledges it
only after the service durably applies it.

Every change contains a connection revision. The service must reject or ignore
an older revision after observing a newer one. This prevents a delayed enable
request from resurrecting a revoked connection.

Registration attempts are authenticated with a short-lived NIP-98 event that
binds:

- the canonical HTTPS endpoint;
- the POST method;
- the SHA-256 request-body hash; and
- an explicit expiration.

The HTTP client rejects plaintext URLs, credentials, fragments, redirects,
oversized values, private-address icon targets, and unbounded response bodies.

## Data boundary

The service may receive:

- client and wallet-service public keys;
- approved relay URLs;
- application and installation identifiers;
- APNs or FCM destination and environment;
- connection revision and enabled state; and
- bounded public identifiers for a targeted settlement monitor.

The service must never receive:

- a client or wallet-service secret;
- a complete `nostr+walletconnect` URI;
- decrypted NWC request content;
- a wallet seed;
- a payment preimage;
- wallet balance or transaction history; or
- raw wallet diagnostics.

Push payloads are routing hints. The device independently validates the relay,
event id, signature, kind, recipient, freshness, active connection, and allowed
method before any wallet operation.

## Incoming-invoice settlement

NWC clients may poll `lookup_invoice`, but mobile suspension makes client-only
polling unreliable. A wake service can optionally schedule bounded settlement
wakes for one exact invoice created by an authorized request.

Settlement wake intent must be explicit and bound to a durable local monitor.
The device must reject an arbitrary provider claim that an unrelated event is a
settlement wake. When settlement notification reaches every approved relay, the
wallet's bounded completion hook can disable the server-side monitor.

## Operational checklist

- Use TLS and disable redirects at both client and edge layers.
- Keep APNs/FCM credentials outside application logs and database exports.
- Rate-limit registration, relay subscriptions, and push delivery.
- Deduplicate by canonical Nostr event id.
- Expire registrations and settlement monitors according to explicit policy.
- Alert on relay disconnects, provider rejection, and registration backlog.
- Test sandbox and production APNs environments independently.
- Never put decrypted or payment-sensitive fields in metrics or notifications.
