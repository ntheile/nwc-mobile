#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
approved="${repository_root}/supply-chain/approved-build-units.txt"
observed="$(mktemp)"
trap 'rm -f "${observed}"' EXIT

cd "${repository_root}"
cargo metadata --locked --format-version 1 \
  | jq --raw-output '
      .packages[]
      | select(any(.targets[];
          (.kind | index("custom-build")) or (.kind | index("proc-macro"))))
      | [.name, .version, ([.targets[].kind[]] | unique | join(","))]
      | @tsv
    ' \
  | LC_ALL=C sort > "${observed}"

if ! diff --unified "${approved}" "${observed}"; then
  printf '%s\n' \
    'Compile-time dependencies changed.' \
    'Review the new crate source, owner, release age, and build/proc-macro code.' \
    'Update supply-chain/approved-build-units.txt only after that review.' >&2
  exit 1
fi
