# Supply-chain policy

Rust build scripts and procedural macros execute code on the build machine. A
valid crates.io checksum proves which package was downloaded; it does not prove
that the package is trustworthy. This repository therefore treats dependency
resolution and compile-time code as security-sensitive changes.

## Enforced controls

- `Cargo.lock` is committed and CI uses `--locked`, so a build cannot silently
  select a newly published version.
- `cargo-deny` rejects known advisories, disallowed licenses, wildcard
  requirements, unknown registries, and all Git dependencies. Its downloaded CI
  binary is version-pinned and verified against a committed SHA-256 digest.
- `deny.toml` explicitly permits the crates that have build scripts.
- `supply-chain/approved-build-units.txt` records every resolved build script and
  procedural macro by exact version. CI fails when that execution surface
  changes.
- GitHub Actions are pinned to full commit hashes, checkout credentials are not
  persisted, and CI has read-only repository permissions.

These controls reduce risk and make dependency execution visible; they cannot
prove that allowed code is benign.

## Reviewing a dependency update

Do not run broad, unaudited dependency updates. For an intended update:

1. Wait at least seven days after a new release unless it fixes an actively
   exploitable vulnerability. This gives registries and maintainers time to yank
   or flag a compromised release.
2. Update one direct dependency at a time and inspect the complete `Cargo.lock`
   diff. Use `cargo tree --invert <crate>` to explain each new transitive crate.
3. Run `./scripts/check-build-units.sh`. If it fails, inspect the source and
   ownership history of every new build script or procedural macro. Confirm that
   the publisher and repository match the expected project.
4. If the change is approved, update both `deny.toml` and
   `supply-chain/approved-build-units.txt` with exact versions in the same PR.
5. Run the full checks with `--locked` in an isolated environment that has no
   signing keys, wallet secrets, production credentials, or writable repository
   token.

For emergency upgrades, document why the waiting period was bypassed and obtain
an independent review of the dependency source and lockfile diff.

## Local checks

```sh
cargo deny --locked --all-features check advisories bans licenses sources
./scripts/check-build-units.sh
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```
