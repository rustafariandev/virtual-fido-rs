#!/usr/bin/env bash
# End-to-end test of a running virtual-fido key with OpenSSH: creates security keys with
# ssh-keygen, then signs through a throwaway ssh-agent (ssh-add of key files, and
# resident keys loaded with ssh-add -K), verifying every signature and its UP/UV flags.
#
#   ./target/debug/virtual-fido --store memory --presence auto &   # PIN already set
#   VFIDO_PIN=123456 scripts/ssh_agent_test.sh
#
# Needs OpenSSH 8.3+ with FIDO support and python3. The virtual key must be the only FIDO
# device attached, so the PIN can't reach a real key. It leaves three resident
# credentials (ssh:vfido-test-*) on the virtual key; use --store memory to discard them.
set -euo pipefail

pin=${VFIDO_PIN:?set VFIDO_PIN to the virtual key PIN}
name=${VFIDO_NAME:-Virtual FIDO2}
scripts=$(cd "$(dirname "$0")" && pwd)

# FIDO hidraw devices: report descriptors starting with the FIDO usage page (06 d0 f1).
fido_devices=()
for d in /sys/class/hidraw/*; do
    [[ $(od -An -tx1 -N3 "$d/device/report_descriptor" 2>/dev/null | tr -d ' \n') == 06d0f1 ]] &&
        fido_devices+=("$d")
done
device=
for d in "${fido_devices[@]}"; do
    grep -qx "HID_NAME=$name" "$d/device/uevent" && device=/dev/$(basename "$d")
done
[[ -n $device ]] || { echo "no running virtual-fido device named \"$name\"" >&2; exit 1; }
if (( ${#fido_devices[@]} != 1 )); then
    echo "refusing to run: ${#fido_devices[@]} FIDO devices attached; unplug the others so the PIN" >&2
    echo "and resident-key requests can only reach the virtual key ($device)" >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"
cd "$work"
printf '#!/bin/sh\necho "%s"\n' "$pin" > askpass
chmod 700 askpass
export SSH_ASKPASS=$work/askpass SSH_ASKPASS_REQUIRE=force

run=$RANDOM
keys=(ecdsa ed25519_rk ecdsa_rk ed25519_uv)
declare -A options=(
    [ecdsa]="-t ecdsa-sk"
    [ed25519_rk]="-t ed25519-sk -O resident -O application=ssh:vfido-test-$run-ed"
    [ecdsa_rk]="-t ecdsa-sk -O resident -O application=ssh:vfido-test-$run-ec"
    [ed25519_uv]="-t ed25519-sk -O resident -O verify-required -O application=ssh:vfido-test-$run-uv"
)

echo "== $(ssh -V 2>&1 | cut -d, -f1), virtual key at $device"
echo "== ssh-keygen: creating security keys"
mkdir pub
echo "hello from virtual-fido" > msg
: > allowed_signers
for k in "${keys[@]}"; do
    # shellcheck disable=SC2086 # options are word lists
    ssh-keygen -q ${options[$k]} -O device="$device" -N '' -f "$k" -C "$k@vfido" </dev/null
    cp "$k.pub" pub/
    echo "test@vfido $(cut -d' ' -f1,2 "$k.pub")" >> allowed_signers
    echo "  $k: $(cut -d' ' -f1 "$k.pub")"
done

# Runs under `ssh-agent`, which exports SSH_AUTH_SOCK. Signs with public key files only,
# so the signature has to come from the agent.
cat > in_agent.sh <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
scripts=$1; shift
failures=0
sign() { # key expected_flags
    rm -f msg.sig
    local flags
    if timeout 60 ssh-keygen -Y sign -f "pub/$1.pub" -n file msg </dev/null >/dev/null 2>err &&
        ssh-keygen -Y verify -f allowed_signers -I test@vfido -n file -s msg.sig <msg >/dev/null 2>>err &&
        flags=$(python3 -I "$scripts/sshsig_flags.py" msg.sig) && [[ $flags == "flags=$2 "* ]]; then
        echo "  ok    $1 ($flags)"
    else
        echo "  FAIL  $1: expected flags=$2, got ${flags:-no signature}: $(tail -1 err)"
        failures=$((failures + 1))
    fi
}
echo "== ssh-add of key files"
for k in ecdsa ed25519_rk ecdsa_rk ed25519_uv; do ssh-add -q "$k" </dev/null; done
ssh-add -l | sed 's/^/  /'
sign ecdsa 0x01; sign ed25519_rk 0x01; sign ecdsa_rk 0x01; sign ed25519_uv 0x05
echo "== ssh-add -D, then ssh-add -K (resident keys from the security key)"
ssh-add -D >/dev/null 2>&1
timeout 60 ssh-add -K </dev/null 2>&1 | sed 's/^/  /'
sign ed25519_rk 0x01; sign ecdsa_rk 0x01; sign ed25519_uv 0x05
exit $(( failures > 0 ))
EOF
chmod +x in_agent.sh

if ssh-agent ./in_agent.sh "$scripts"; then
    echo "== all checks passed"
else
    echo "== FAILED" >&2
    exit 1
fi
