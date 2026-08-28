# Building NWA and NWC screens

The UI owns product presentation and navigation. It should render Rust-derived
state and send typed user actions back to the application core rather than
reimplementing connection policy in Swift or Kotlin.

## Recommended screens

### Connections list

Display each `ConnectionPresentation` or generated native equivalent with:

- application name and icon when available;
- active or revoked state;
- approved methods;
- budget limit, interval, and current usage;
- expiration;
- last completed request time; and
- registration or retry state when useful to the user.

Do not load a second application-owned connection registry. The `nwc-mobile`
ledger is authoritative.

### Connection details

Provide explicit actions to:

- export a wallet-created connection URI;
- inspect approved permissions and relays;
- refresh public capability information when supported; and
- permanently revoke the connection.

Keep exported URIs transient. Do not store them in view state, clipboard
history, logs, analytics, or screenshots longer than the user-requested export
operation requires.

### Create connection

Collect a name, relay selection, methods, budget, renewal interval, expiration,
and optional Lightning address. Pass the complete selection to
`create_connection`. Rust validates it, creates and stores secret material, and
persists the connection atomically.

Never generate client secrets in Swift or Kotlin for a wallet-managed
connection.

### NWA approval

Render the `NwaRequestPresentation` produced by `open_nwa_request`. Bind the
approve action to its opaque request id. Clearly distinguish requested authority
from any user-edited reduction.

Requester names, icons, descriptions, and claimed domains are untrusted
metadata. Do not use them to decide authorization or hide effective methods,
budget, expiration, relays, or callback destination.

## UI action boundary

A useful application pattern is:

```text
View -> typed application action -> Rust application manager
     <- display-ready state or one bounded native capability request <-
```

Examples of bounded native capability requests are opening a verified URL,
copying an explicitly exported URI, showing a share sheet, or registering for
APNs. Connection creation, approval, revocation, and retry policy remain in
Rust.

## Error presentation

Map stable error categories to localized product copy. Do not display raw relay,
HTTP, wallet SDK, SQLite, or cryptographic error strings. Errors that may have
occurred after a payment began must be presented as pending or retrying until
reconciliation reaches a terminal state.

## UI test checklist

- The approval button submits the exact displayed request id.
- A second inbound NWA request cannot replace the visible request.
- Permission and budget reductions are visible before approval.
- Revocation immediately removes export and payment authority.
- A callback-open failure offers only the shared verified retry.
- Secrets and complete NWC URIs never enter persisted UI restoration state.
