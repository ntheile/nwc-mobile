# Generated binding contract

Swift and Kotlin bindings are generated from the compiled
`nwc-mobile-uniffi` library with the workspace-pinned UniFFI generator. The
generated boilerplate is not committed. Instead, `abi.sha256` records the
complete generated content so CI detects any intentional or accidental FFI
surface change.

Check the current contract:

```sh
./scripts/check-generated-bindings.sh
```

After reviewing an intentional UniFFI API or generator change, update the
contract and inspect the diff:

```sh
./scripts/check-generated-bindings.sh --update
git diff -- bindings/abi.sha256
```

The checker also asserts that both languages expose the engine, asynchronous
wake execution, and native wallet callback interface. Generated source files
are written only to a temporary directory and removed when the check exits.
