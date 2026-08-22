#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
approved="${repository_root}/supply-chain/approved-build-units.txt"
classifier="${repository_root}/scripts/classify-build-units.jq"
observed="$(mktemp)"
metadata="$(mktemp)"
trap 'rm -f "${observed}" "${metadata}"' EXIT

cd "${repository_root}"
cargo metadata --locked --format-version 1 > "${metadata}"
jq --raw-output --from-file "${classifier}" "${metadata}" \
  | LC_ALL=C sort > "${observed}"

if ! diff --unified "${approved}" "${observed}"; then
  printf '%s\n' \
    'Compile-time dependencies changed.' \
    'Review the new crate source, owner, release age, and compile-time code.' \
    'Update supply-chain/approved-build-units.txt only after that review.' >&2
  exit 1
fi
