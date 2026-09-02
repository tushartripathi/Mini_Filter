#!/bin/bash
# Builds, ad-hoc signs with the Endpoint Security entitlement, and runs the
# file-access monitor as root.
#
# Local PoC: SIP must be disabled or Apple ignores this restricted entitlement.
# Production: a Developer ID + Apple-granted ES entitlement, shipped as a
# system extension — not this script.
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Compiling (release)"
swift build -c release
BIN="$(swift build -c release --show-bin-path)/MiniFilter"

echo "==> Signing with Endpoint Security entitlement"
codesign --force --sign - \
    --entitlements packaging/EndpointSecurity.entitlements \
    --identifier com.minifilter.esmonitor \
    "$BIN"

echo ""
echo "Binary: $BIN"
echo "If es_new_client fails with NOT_PERMITTED, grant Full Disk Access to this binary."
echo ""

exec sudo "$BIN" --esmonitor "$@"
