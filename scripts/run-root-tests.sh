#!/usr/bin/env bash
# Runs the real-device tests (tests/ctap_hid_fido2.rs), which create /dev/uhid devices
# and so need root. The test binary is built as the current user, so target/ stays
# yours; only the binary itself runs under sudo. Extra arguments go to the test
# harness, e.g. a test name filter or --nocapture.
set -euo pipefail
cd "$(dirname "$0")/.."

bin=$(cargo test --color never --test ctap_hid_fido2 --no-run 2>&1 |
    sed -n 's/.*Executable tests\/ctap_hid_fido2\.rs (\(.*\))/\1/p')
if [[ -z "$bin" ]]; then
    echo "could not find the ctap_hid_fido2 test binary; build output:" >&2
    cargo test --test ctap_hid_fido2 --no-run >&2
    exit 1
fi

# The uhid module is usually built in or autoloaded; load it just in case.
[[ -e /dev/uhid ]] || sudo modprobe uhid

exec sudo "$bin" "$@"
