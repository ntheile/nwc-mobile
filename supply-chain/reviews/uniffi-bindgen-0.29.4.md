# UniFFI binding generator dependency review

Reviewed on 2026-08-20 for the workspace-pinned Swift and Kotlin binding
generator. All packages resolve from crates.io with checksums committed in
`Cargo.lock`; none are yanked or use a Git dependency. Every newly approved
compile-time package was published more than seven days before this review.

## Direct generator components

| Package | Released | Publisher | Repository | Packaged VCS commit |
| --- | --- | --- | --- | --- |
| `uniffi_bindgen 0.29.4` | 2025-07-24 | `bendk` | `mozilla/uniffi-rs` | `00cd7e313cf73c78637161831ff17f8f53f7b824` |
| `uniffi_udl 0.29.4` | 2025-07-24 | `bendk` | `mozilla/uniffi-rs` | `00cd7e313cf73c78637161831ff17f8f53f7b824` |

The crates.io owner set for both packages is `badboy`, `mhammond`, `skhamis`,
and `bendk`, consistent with the existing pinned UniFFI project. The generator
is isolated in a non-publishable workspace tool and is not part of a production
`nwc-mobile-uniffi` package-only build.

## Newly approved compile-time packages

| Package | Released | Publisher / owner | Packaged VCS commit | Compile-time behavior reviewed |
| --- | --- | --- | --- | --- |
| `askama_derive 0.13.1` | 2025-04-15 | `GuillaumeGomez` / Askama maintainers | `0b1c0e4d35c38311f179b069f6a7008c9490b786` | Parses derive input and reads only manifest-relative Askama configuration/templates; no network or subprocess access. |
| `askama_parser 0.13.0` | 2025-03-27 | `Kijewski` / Askama maintainers | `697862a76c440544fd82f51a36a3c9482065bde5` | Template parser; no network or subprocess access. |
| `basic-toml 0.1.10` | 2025-03-03 | `dtolnay` | `c54c9bd3ade1a609f5da6e31cf6ee72d6c7552fb` | Pure TOML deserialization support. |
| `clap_derive 4.5.61` | 2026-03-12 | `epage` / Clap admins | `8b41d0b8497ccaa0fb0d1d8a51f91ea2f62b3aa8` | Parses derive input and reads Cargo package metadata environment variables; no filesystem, network, or subprocess access. |
| `memchr 2.8.3` | 2026-07-08 | `BurntSushi` | `5fdb40c054e1fff359a2f7bdf7f87a13b34b465d` | Byte-search implementation; no compile-time I/O. |
| `rustc-hash 2.1.3` | 2026-07-02 | `Noratrieb` / Rust compiler team | `c13e7ccca705e6255387a2ebc6dca142d6881621` | Hash implementation; no compile-time I/O. |
| `scroll_derive 0.12.1` | 2025-04-06 | `m4b` | `f27f2e3da2581234aa7c06cda65978ed08b7896c` | Pure token transformation for binary parsing derives. |
| `thiserror 2.0.20` | 2026-08-08 | `dtolnay` | `b1d5db5e039275d95bf7536a2b2192aeb4dc28bf` | Build script writes only to `OUT_DIR` and invokes Cargo's configured `rustc` for feature probes; no network access. |
| `thiserror-impl 2.0.20` | 2026-08-08 | `dtolnay` | `b1d5db5e039275d95bf7536a2b2192aeb4dc28bf` | Pure error-derive token transformation. |
| `winnow 0.7.15` | 2026-03-05 | `epage` | `eae4d4a23c400fec27a01cfb7115bc7808374f40` | Parser combinators; no compile-time filesystem, network, or subprocess access. |

`thiserror` is the only newly allowed custom build script. The remaining
entries are procedural macros or their transitive parser dependencies. Source
inspection found no network clients or credential access in any newly approved
compile-time unit.

## Minimum-Rust resolver constraints

UniFFI 0.29 permits any Clap 4.x release. The unconstrained resolver selected
Clap 4.6 and `clap_lex 1.1`, whose Edition 2024 manifests require Cargo 1.85.
The tool manifest therefore pins `clap 4.5.61` and `clap_lex 1.0.0`, both
published months before this review with Rust 1.74 minimums. It also pins
`smawk 0.3.2` (published 2023-09-17) because `smawk 0.3.3` likewise moved its
manifest to Edition 2024. The packaged commits are respectively
`8b41d0b8497ccaa0fb0d1d8a51f91ea2f62b3aa8`,
`d37483586ff582e07a3fc62b10fa98ce7d227b4f`, and
`df374f7cf7611a1026e49b72d9ed87d1cbf8d464`.
