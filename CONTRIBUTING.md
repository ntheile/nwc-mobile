# Contributing

`nwc-mobile` handles payment authorization and background execution. Changes
should be small, reviewable, and explicit about the security invariant they
preserve.

## Local checks

Run these commands before opening a pull request:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

The CI workflow also runs the test suite with the minimum supported Rust
version declared in the workspace manifest.

## Pull requests

- Keep generated bindings in a separate commit from authored changes.
- Include tests with every behavior change.
- Do not use live relays or real payment credentials in automated tests.
- Do not include wallet seeds, Nostr secrets, complete NWC URIs, push tokens,
  invoices, or production event payloads in fixtures or logs.
- Describe failure recovery and rollback for changes to durable state.
- Treat database migrations as security-sensitive compatibility changes.

Security findings are closed only after the library behavior and a real host
integration have both been verified.
