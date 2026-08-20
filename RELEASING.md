# Release checklist

`nwc-mobile` is pre-release and its FFI and storage contracts may still change.
Use this checklist for every tagged source release; do not publish crates or
native artifacts until the project explicitly enables publishing.

1. Start from a clean, reviewed `main` commit whose required CI jobs passed.
2. Confirm the version and minimum supported Rust release in `Cargo.toml` and
   the MSRV CI job; record user-visible changes in `CHANGELOG.md`.
3. Run the locked Rust tests, strict lint, documentation, native package tests,
   dependency policy, build-unit allowlist, native contract fixture check, and
   generated binding contract check in an environment without signing keys or
   production wallet credentials.
4. Review every dependency, lockfile, Gradle verification-metadata, generated
   binding hash, and SQLite migration change since the previous tag.
5. Build Swift and Kotlin bindings from the exact reviewed commit. Hash release
   artifacts and verify them from a second clean checkout before signing.
6. Create an annotated tag only after artifact verification. GitHub release
   credentials must be scoped to that release operation and absent from build
   and test jobs.
7. After publishing, download the public artifacts, verify their hashes, and run
   the shared native wake fixture against a minimal host integration.

Baseline commands are documented in `CONTRIBUTING.md`, `SUPPLY_CHAIN.md`, and the
platform package READMEs.
