# Configuring `NwcMobile`

`nwc_mobile_tokio::NwcMobile` is the recommended composition root for a mobile
wallet. It owns the shared ledger, NWC engine, Lightning-node opening,
notification workers, deadline enforcement, and optional post-wake completion
work.

## Required capabilities

Construct `NwcMobileConfig` with four application-owned capabilities:

| Capability | Requirement |
| --- | --- |
| Data directory | Absolute application-owned directory shared with the background process |
| `LightningNodeProvider` | Opens the existing wallet and returns its NWC capabilities |
| `RelayTransport` | Fetches and publishes bounded Nostr events on approved secure relays |
| `SecretProvider` | Retrieves wallet-service secret material only when Rust requests it |

```rust,ignore
let config = NwcMobileConfig::new(
    shared_data_directory,
    MyLightningNodeProvider::new(wallet_config, secret_store.clone()),
    NostrRelayTransport,
    StoredNwcSecrets::new(secret_store),
);

let mut nwc = NwcMobile::open(config)?;
```

The configuration owns its capabilities so it can cross the native async
boundary and survive for the entire wake. Do not build it from references to a
foreground-only wallet object.

## Foreground application access

Use `NwcMobile::application_manager()` or
`application_manager_mut()` for connection and NWA workflows. Keep serialized
mutable access in the application's Rust actor or equivalent application core.

The application manager provides workflows for:

- listing connection presentations;
- creating and exporting wallet-managed connections;
- opening, approving, cancelling, and completing NWA sessions;
- storing non-sensitive application metadata;
- permanent connection revocation; and
- coordinating durable wake-registration passes.

Swift and Kotlin integrations use `MobileNwcEngine` presentation and lifecycle
types where the same workflow is exposed through UniFFI.

## Background execution

A background entry point passes four values into the Rust-owned executor:

1. a fresh `NwcMobileConfig`;
2. the untrusted platform wake envelope;
3. the available execution time; and
4. a request-scoped cancellation object.

`execute_native_extension_wake` validates the envelope and platform window,
opens `NwcMobile` on the shared runtime, selects ordinary request or targeted
settlement work, gathers bounded diagnostics, and returns a stable outcome.

The application should not recreate engine assembly in its NSE or Android
worker. Its Rust adapter should be limited to constructing the four application
capabilities and mapping the typed result to the native helper.

## Optional configuration

`NwcMobileConfig` also supports:

- a non-secret `WakeDiagnosticSink`;
- a bounded `NwcMobileCompletionHandler` for application-specific work after
  the standard wake flow;
- a custom `WakePolicy`; and
- a custom incoming-invoice settlement poll interval.

The completion reserve is part of the hard OS window. A completion hook must
not perform essential payment accounting that belongs in the standard engine
flow. A typical use is notifying a wake service that a tracked invoice monitor
can be disabled.

## Storage rules

- The foreground application and background process must resolve the same data
  directory.
- Do not copy the SQLite file between directories or treat it as a cache.
- Do not persist client or wallet-service secrets in application JSON.
- Serialize schema migration and application startup so two processes do not
  independently replace storage.
- Treat the `nwc-mobile` ledger as authoritative after any legacy migration.

## When to use lower-level APIs

`NwcNode` is available for an application that already owns an open
`NwcLightningNode` and deliberately wants to compose request workers itself.
`NwcWalletBackend` is the hardened internal engine boundary. Most wallet
integrations should implement `NwcLightningNode`, provide a
`LightningNodeProvider`, and let `NwcMobile` adapt them.

Next: [Implementing `NwcLightningNode`](lightning-node.md).
