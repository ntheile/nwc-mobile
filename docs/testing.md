# Testing an integration

Test the library, wallet adapter, native lifecycle, and deployed wake service as
separate layers before running end-to-end payment tests.

Never use production wallet seeds, Nostr secrets, push tokens, invoices, or
payment history in automated fixtures or shared logs.

## Repository checks

Run the workspace checks from the repository root:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
./scripts/check-native-contract.sh
```

Run the native package tests when their code or contract changes:

```sh
swift test --package-path apple/NwcMobileApple
./gradlew -p android/nwc-mobile test
```

## Lightning adapter tests

- Balance conversion uses spendable funds and exact millisatoshi units.
- Invoice creation preserves amount, description, expiry, and payment hash.
- Quoting is side-effect free.
- Amountless invoices require and preserve the selected amount.
- Fees above the NWC maximum are rejected before payment starts.
- Repeating the same payment hash and idempotency key starts one payment.
- Timeout after initiation returns pending or ambiguous, never definite unpaid.
- Lookup recovers outgoing success and its real preimage after adapter restart.
- Incoming lookup synchronizes and returns the settled preimage.
- History direction, amount, fee, timestamp, filtering, and pagination match the
  shared domain contract.

## NWA and connection tests

- Reject malformed, oversized, expired, duplicate-parameter, insecure-relay,
  secret-bearing, and unsupported-version requests.
- Reject approval with a different request id.
- Reject method, budget, expiration, or relay escalation.
- Prevent a second request from replacing the current approval session.
- Persist approval before returning a callback action.
- Preserve an approved connection when callback opening fails.
- Revoke idempotently and keep a permanent tombstone.
- Ignore stale enable acknowledgements after revocation.

## Wake-engine tests

- Reject a mismatched event id, kind, signature, recipient, or service key.
- Reject stale requests and unapproved relays.
- Deduplicate concurrent foreground and background execution.
- Repeat a completed read request without repeating wallet work.
- Reserve payment budget before calling `pay_invoice`.
- Keep reservations pending across cancellation, timeout, and process death.
- Republish a durable response without repeating its wallet side effect.

## Native lifecycle tests

### iOS

- APNs payload parsing is bounded and strips untrusted presentation content.
- The NSE completion handler runs exactly once.
- `serviceExtensionTimeWillExpire()` cancels Rust and returns a safe fallback.
- The main app and NSE resolve the same App Group ledger and Keychain secrets.
- App handoff preserves the settlement marker and event id.
- Queued work is safely replayed when the app foregrounds.

### Android

- FCM handling returns promptly and schedules unique work.
- WorkManager storage omits embedded ciphertext and sensitive routing details.
- Process recreation can reopen the same ledger, secrets, and wallet.
- `onStopped()` propagates cancellation.
- Only the explicit retry disposition produces WorkManager retry.
- Maintenance work is unique and contains no request payload.

## Wake-service tests

- NIP-98 signature, endpoint, method, body hash, and expiration are verified.
- Older revisions cannot overwrite newer connection state.
- Duplicate Nostr events result in at most one push per active destination.
- Disabled and expired registrations receive no pushes.
- Relay reconnect resumes observation without replay storms.
- APNs sandbox and production routing cannot be confused.
- FCM/APNs rejection does not expose tokens or event content in logs.
- Settlement monitors stop after completion, expiration, or retry budget.

## Physical-device matrix

Exercise at least these states for both a read request and a payment:

| Application state | Ordinary request | Outgoing payment | Incoming settlement |
| --- | --- | --- | --- |
| Foreground | Required | Required | Required |
| Backgrounded | Required | Required | Required |
| Terminated/process absent | Required | Required | Required |
| Device locked | Required | Required | Required |
| Network temporarily unavailable | Retry tested | Ambiguous recovery tested | Later settlement tested |
| Deadline expires mid-operation | Handoff tested | No duplicate payment | Monitor remains recoverable |

“Terminated/process absent” means a terminated iOS host or an Android process
killed and later recreated by the OS. Android deliberately does not deliver FCM
or WorkManager work after a user force-stop until the application is launched
again.

For incoming settlement, create an invoice through an independent NWC client,
pay it from a separate Lightning wallet, and verify that the client observes the
terminal invoice and `payment_received` notification without opening the host
wallet manually.

For outgoing payment, terminate the application before the wake, pay a small
test invoice, and verify one Lightning payment, one terminal NWC response, and
no repeated user-visible completion notifications.

## Log review

After each failure-path test, inspect application, NSE/worker, and server logs.
Confirm that logs contain only stable diagnostic codes and operational metadata,
not secrets, invoices, payment details, push tokens, full Nostr events, or raw
remote error bodies.
