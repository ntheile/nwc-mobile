# Security model

`nwc-mobile` assumes that pushes, Nostr relays, remote applications, callback
metadata, wake services, networks, and process timing are untrusted. The wallet
SDK, protected local secrets, reviewed application code, and durable local
ledger form the trusted computing base.

For private vulnerability reporting and supported versions, see
[SECURITY.md](../SECURITY.md).

## Core invariants

- One Nostr request event has at most one durable active claim across all
  application processes.
- Event id, kind, signature, recipient, freshness, and allowed relay are checked
  before decryption or wallet side effects.
- An active connection and allowed method are checked before invoking the
  Lightning node.
- Payment principal and maximum fee are reserved before payment initiation.
- Ambiguous payment outcomes remain pending until lookup proves a terminal
  result.
- Revocation tombstones outrank stale connection, registration, and worker
  completions.
- Failed and completed events remain durable for at least the accepted request
  freshness horizon.
- Wake delivery is never user consent or payment authorization.
- Deadline expiration leaves a replay-safe, recoverable durable state.

## Trust boundaries

### Nostr relay

A relay may omit, delay, duplicate, reorder, or inject events. The engine
validates the exact event and never treats relay delivery as authentication.

### Wake service

The wake service sees public routing information and push destinations. It can
wake the device but cannot authorize a method. A forged or compromised push is
rejected unless it identifies a valid, authorized Nostr event.

### Native platform code

Native code controls OS lifecycle capabilities and protected-storage access,
but it should not duplicate NWC policy. Rust accepts untrusted strings through
bounded types and returns closed outcome enums rather than raw remote errors.

### Lightning adapter

The adapter is trusted to report wallet state accurately and make payment
execution idempotent. It does not decide connection authorization or budget
policy. A successful payment result must contain the real matching preimage.

## Secret handling

Secret providers return fresh copies only for the operation that needs them.
Rust validates and zeroizes received copies. Platform implementations must not
cache or log temporary secret buffers.

Never place these values in logs, analytics, push payloads, callbacks,
notifications, crash reports, fixtures, or ordinary application persistence:

- wallet seeds or mnemonic phrases;
- Nostr secret keys;
- client secrets;
- complete NWC connection URIs;
- APNs or FCM tokens;
- decrypted NWC requests;
- invoices, amounts, counterparties, or preimages; and
- raw remote response bodies or wallet SDK errors.

## NWA invariants

- The authorization URI contains the client public key, never its secret.
- Approval is bound to a random retained request id.
- A new request cannot replace one currently being reviewed.
- Approval cannot silently expand requested methods, budget, expiration, or
  relay authority.
- Requester metadata is display-only and untrusted.
- Callback state is fresh and sufficiently random.
- Native code opens only the verified callback constructed by Rust.
- Callback failure does not roll back an already persisted connection.

## Wake registration invariants

- Connection state and its desired registration change are committed together.
- Every change has a monotonic connection revision.
- A stale enable completion cannot resurrect a newer disable tombstone.
- Registration is acknowledged only after the service durably applies it.
- NIP-98 authorization binds the canonical endpoint, HTTP method, body hash,
  and short expiration.
- The client rejects insecure endpoints and redirects.

## Payment invariants

The Lightning payment and local SQLite transaction cannot be one distributed
transaction. Safety therefore depends on this order:

1. quote without side effects;
2. reserve authorized principal and maximum fee durably;
3. call the idempotent wallet payment operation;
4. store a terminal result only when proven; and
5. reconcile ambiguous state by payment hash.

Never refund a reservation merely because a background deadline expired or a
network response was lost.

## Review checklist for host code

- Does native code contain any Nostr parsing or payment authorization?
- Can two processes open different ledgers or secret namespaces?
- Can payment retry start a second payment?
- Can stale async completion mutate a newer connection revision?
- Can untrusted text reach a notification, log, or analytics event?
- Can URL opening fall back from a verified app link to a browser or custom
  scheme?
- Does every background operation propagate cancellation and preserve cleanup
  time?
