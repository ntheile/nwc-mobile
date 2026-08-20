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

contains_fixed() {
  local needle="$1"
  local path="$2"
  if command -v rg >/dev/null 2>&1; then
    rg --fixed-strings "${needle}" "${path}" >/dev/null
  else
    grep -Fq -- "${needle}" "${path}"
  fi
}

for key in "${expected_keys[@]}"; do
  printf '%s\n' "${fixture_keys}" | awk -v expected="${key}" \
    '$0 == expected { found = 1 } END { exit !found }'
  contains_fixed "\"${key}\"" "${swift_payload}"
  contains_fixed "\"${key}\"" "${kotlin_payload}"
done

if grep -Eiq -- 'secret|invoice|preimage|payment_hash|push_token|device_token' "${fixture}"; then
  printf 'native contract fixture contains prohibited sensitive field names\n' >&2
  exit 1
fi

contains_fixed 'mobile-wake-envelope.properties' \
  apple/NwcMobileApple/Tests/NwcMobileAppleTests/NwcNativeContractFixtureTests.swift
contains_fixed 'mobile-wake-envelope.properties' \
  android/nwc-mobile/src/test/kotlin/org/nwc/mobile/android/NwcNativeContractFixtureTest.kt
