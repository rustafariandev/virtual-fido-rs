#!/usr/bin/env python3
"""Prints the FIDO flags byte and counter of an SSH security-key signature (SSHSIG file).

    python3 scripts/sshsig_flags.py msg.sig   ->   flags=0x05 counter=7

Flags: 0x01 user present, 0x04 user verified.
"""
import base64
import struct
import sys


def string(buf, off):
    (n,) = struct.unpack(">I", buf[off : off + 4])
    return buf[off + 4 : off + 4 + n], off + 4 + n


armored = open(sys.argv[1]).read().splitlines()
blob = base64.b64decode("".join(line for line in armored if not line.startswith("-----")))
if blob[:6] != b"SSHSIG":
    sys.exit("not an SSHSIG signature")
off = 10  # magic + version
for _ in range(4):  # public key, namespace, reserved, hash algorithm
    _, off = string(blob, off)
sig, _ = string(blob, off)
sig_type, off = string(sig, 0)
if not sig_type.startswith(b"sk-"):
    sys.exit(f"not a security-key signature: {sig_type.decode()}")
_, off = string(sig, off)  # the signature itself
flags, (counter,) = sig[off], struct.unpack(">I", sig[off + 1 : off + 5])
print(f"flags=0x{flags:02x} counter={counter}")
