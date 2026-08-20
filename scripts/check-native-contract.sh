#!/usr/bin/env bash
set -euo pipefail

repository_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "${repository_root}"

fixture="fixtures/mobile-wake-envelope.properties"
swift_payload="apple/NwcMobileApple/Sources/NwcMobileApple/NwcWakePayload.swift"
kotlin_payload="android/nwc-mobile/src/main/kotlin/org/nwc/mobile/android/NwcWakePayload.kt"

test -s "${fixture}"

expected_keys=(
  nwc_relay
  nwc_event_id
  nwc_wallet_service_pubkey
  nwc_event_json
)

fixture_keys="$(sed -n 's/=.*//p' "${fixture}")"
test "$(printf '%s\n' "${fixture_keys}" | wc -l | tr -d ' ')" -eq "${#expected_keys[@]}"
test -z "$(printf '%s\n' "${fixture_keys}" | sort | uniq -d)"

for key in "${expected_keys[@]}"; do
  printf '%s\n' "${fixture_keys}" | rg --fixed-strings --line-regexp "${key}" >/dev/null
  rg --fixed-strings "\"${key}\"" "${swift_payload}" >/dev/null
  rg --fixed-strings "\"${key}\"" "${kotlin_payload}" >/dev/null
done

if rg --ignore-case 'secret|invoice|preimage|payment_hash|push_token|device_token' "${fixture}"; then
  printf 'native contract fixture contains prohibited sensitive field names\n' >&2
  exit 1
fi

rg --fixed-strings 'mobile-wake-envelope.properties' \
  apple/NwcMobileApple/Tests \
  android/nwc-mobile/src/test >/dev/null
