#!/usr/bin/env bash
set -euo pipefail

repository_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "${repository_root}"

case "$(uname -s)" in
  Darwin)
    library="target/debug/libnwc_mobile_uniffi.dylib"
    ;;
  Linux)
    library="target/debug/libnwc_mobile_uniffi.so"
    ;;
  *)
    printf 'unsupported binding-check host: %s\n' "$(uname -s)" >&2
    exit 1
    ;;
esac

contract_tmp="$(mktemp -d "${TMPDIR:-/tmp}/nwc-mobile-bindings.XXXXXX")"
trap 'rm -rf -- "${contract_tmp}"' EXIT

cargo build --locked --package nwc-mobile-uniffi
cargo run --locked --package nwc-mobile-uniffi-bindgen -- \
  generate --library "${library}" --language swift \
  --out-dir "${contract_tmp}/swift" --no-format
cargo run --locked --package nwc-mobile-uniffi-bindgen -- \
  generate --library "${library}" --language kotlin \
  --out-dir "${contract_tmp}/kotlin" --no-format

swift_source="${contract_tmp}/swift/NwcMobile.swift"
swift_header="${contract_tmp}/swift/NwcMobileFFI.h"
swift_modulemap="${contract_tmp}/swift/NwcMobileFFI.modulemap"
kotlin_source="${contract_tmp}/kotlin/org/nwc/mobile/nwc_mobile_uniffi.kt"

for generated_file in \
  "${swift_source}" \
  "${swift_header}" \
  "${swift_modulemap}" \
  "${kotlin_source}"
do
  test -s "${generated_file}"
done

# Keep a readable smoke contract alongside the complete content hashes.
grep -F 'open class MobileNwcEngine' "${swift_source}" >/dev/null
grep -F 'public protocol MobileWalletBackend' "${swift_source}" >/dev/null
grep -F 'func executeWake' "${swift_source}" >/dev/null
grep -F 'func openNwaRequest' "${swift_source}" >/dev/null
grep -F 'func migrateLegacyConnections' "${swift_source}" >/dev/null
grep -E 'func reconcilePayments\(.*async throws' "${swift_source}" >/dev/null
grep -E 'func processWakeRegistrations\(.*async throws' "${swift_source}" >/dev/null
grep -F 'public protocol MobileWakeRegistrationTransport' "${swift_source}" >/dev/null
grep -F 'package org.nwc.mobile' "${kotlin_source}" >/dev/null
grep -F 'open class MobileNwcEngine' "${kotlin_source}" >/dev/null
grep -F 'public interface MobileWalletBackend' "${kotlin_source}" >/dev/null
grep -F 'suspend fun `executeWake`' "${kotlin_source}" >/dev/null
grep -F 'fun `openNwaRequest`' "${kotlin_source}" >/dev/null
grep -F 'fun `migrateLegacyConnections`' "${kotlin_source}" >/dev/null
grep -F 'suspend fun `reconcilePayments`' "${kotlin_source}" >/dev/null
grep -F 'suspend fun `processWakeRegistrations`' "${kotlin_source}" >/dev/null
grep -F 'public interface MobileWakeRegistrationTransport' "${kotlin_source}" >/dev/null

checksum() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

actual_contract="${contract_tmp}/abi.sha256"
{
  printf '%s  %s\n' "$(checksum "${swift_source}")" 'swift/NwcMobile.swift'
  printf '%s  %s\n' "$(checksum "${swift_header}")" 'swift/NwcMobileFFI.h'
  printf '%s  %s\n' "$(checksum "${swift_modulemap}")" 'swift/NwcMobileFFI.modulemap'
  printf '%s  %s\n' "$(checksum "${kotlin_source}")" \
    'kotlin/org/nwc/mobile/nwc_mobile_uniffi.kt'
} >"${actual_contract}"

if [[ $# -gt 1 || ($# -eq 1 && "${1:-}" != "--update") ]]; then
  printf 'usage: %s [--update]\n' "$0" >&2
  exit 1
elif [[ $# -eq 1 ]]; then
  cp "${actual_contract}" bindings/abi.sha256
else
  diff --unified bindings/abi.sha256 "${actual_contract}"
fi
