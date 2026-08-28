# Protocol and background flows

These diagrams show the ownership boundaries that must survive foreground,
background, timeout, and process-restart execution.

## NWA authorization

NWA establishes a connection. The requesting application keeps its client
secret; the wallet receives a public authorization request.

```mermaid
sequenceDiagram
    autonumber
    participant C as Requesting App
    participant H as Wallet Host
    participant M as nwc-mobile
    participant U as User
    participant R as Nostr Relay

    C->>H: Open authorization URI with client public key
    H->>M: Open NWA request
    M->>M: Validate URI, authority, expiry, relays, and callback
    M-->>H: Sanitized request presentation and opaque request id
    H->>U: Display exact requested authority
    U->>H: Approve selected limits
    H->>M: Approve retained request id and selection
    M->>M: Reject escalation and persist connection
    M->>R: Publish targeted capability event
    M-->>H: Connection and verified callback action
    H-->>C: Open verified callback
```

## Ordinary NWC wake

```mermaid
sequenceDiagram
    autonumber
    participant C as NWC Client
    participant R as Nostr Relay
    participant P as Wake Service
    participant O as NSE / Android Worker
    participant M as NwcMobile
    participant L as Shared Ledger
    participant W as NwcLightningNode

    C->>R: Publish encrypted kind 23194 request
    P->>R: Observe registered public-key pair
    P->>O: Send routing-only APNs / FCM payload
    O->>M: Envelope, request wake kind, deadline, cancellation
    M->>M: Validate routing fields and request event
    M->>L: Atomically claim event id

    alt Already terminal
        L-->>M: Stored terminal result
    else Claim acquired
        M->>M: Decrypt and enforce active connection policy
        M->>W: Execute authorized operation
        W-->>M: Typed result
        M->>R: Publish encrypted kind 23195 response
        M->>L: Store terminal result and publication state
    end

    M-->>O: Completed, retry, rejected, or app handoff
    O-->>O: Complete platform lifecycle exactly once
```

The wake service does not authorize the request. The device still validates the
event id, kind, signature, recipient, freshness, connection, method, and budget.

## Outgoing payment and recovery

```mermaid
sequenceDiagram
    autonumber
    participant M as nwc-mobile
    participant L as Shared Ledger
    participant W as NwcLightningNode
    participant N as Lightning Network

    M->>W: quote_invoice (side-effect free)
    W-->>M: Payment hash, principal, fee requirement
    M->>L: Reserve principal and maximum fee by event id/hash
    M->>W: pay_invoice with idempotency key and fee limit
    W->>N: Start or resume payment

    alt Paid
        N-->>W: Preimage
        W-->>M: Succeeded
        M->>L: Finalize actual amount and fee
    else Definite failure
        N-->>W: Terminal failure
        W-->>M: Failed
        M->>L: Finalize failure and release reservation
    else Timeout, cancellation, or ambiguous transport error
        W-->>M: Pending or host error
        M->>L: Keep conservative pending reservation
        Note over M,W: Later maintenance looks up the same payment hash
        M->>W: lookup_invoice
        W-->>M: Terminal or still pending
        M->>L: Reconcile only when terminal
    end
```

The application must never interpret a timeout as proof that no payment
occurred. `pay_invoice` and wallet persistence must make retrying the same hash
idempotent.

## Incoming invoice settlement

```mermaid
sequenceDiagram
    autonumber
    participant C as NWC Client
    participant M as nwc-mobile
    participant W as NwcLightningNode
    participant N as Lightning Network
    participant P as Wake Service
    participant R as Nostr Relay

    C->>M: make_invoice request
    M->>W: create_invoice
    W-->>M: Invoice and payment hash
    M->>M: Track invoice notification state
    M-->>C: make_invoice response
    opt Targeted settlement service enabled
        M->>P: Register bounded invoice monitor
    end

    N->>W: Invoice is paid

    alt NWC client polls
        C->>M: lookup_invoice
    else Wake service schedules settlement check
        P->>M: Explicit targeted settlement wake
    end

    M->>W: lookup_invoice with bounded settlement intent
    W->>W: Synchronize and claim exact incoming invoice
    W-->>M: Settled transaction and preimage
    M->>R: Publish payment_received notification
    M->>M: Persist relay publication completion
    opt Monitor enabled
        M->>P: Disable completed monitor
    end
```

Client polling remains compatible. A targeted settlement wake improves
reliability while the mobile wallet is suspended without sending a visible push
every few seconds. Settlement intent must be explicit and validated against the
locally tracked invoice.

## Foreground handoff

When a background process runs out of time, it returns a typed retry or
application-handoff disposition and stores recoverable state. Native code may
enqueue the normalized wake for the foreground application. The foreground path
must call the same Rust engine; it must not execute a second, less restrictive
implementation.
