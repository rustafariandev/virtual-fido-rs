#!/usr/bin/env python3
"""Live smoke test against a running virtual-fido device, using python-fido2 (0.9.x).

    sudo ./target/debug/virtual-fido --store memory --presence auto   # terminal 1
    python3 scripts/smoke_test.py                                      # terminal 2
"""
import hashlib
import os
import sys

from fido2.attestation import Attestation
from fido2.ctap2 import Ctap2
from fido2.hid import CtapHidDevice

devices = [d for d in CtapHidDevice.list_devices() if d.descriptor.product_name == "Virtual FIDO2"]
if not devices:
    sys.exit("no 'Virtual FIDO2' device found (is virtual-fido running? can you read /dev/hidraw*?)")
dev = devices[0]
print("device:", dev.descriptor.path)

ctap = Ctap2(dev)
info = ctap.get_info()
print("versions:", info.versions, "aaguid:", info.aaguid.hex(), "options:", info.options)

rp = {"id": "example.com", "name": "Example"}
user = {"id": os.urandom(8), "name": "alice", "displayName": "Alice"}
cdh = hashlib.sha256(b"register").digest()
att = ctap.make_credential(cdh, rp, user, [{"type": "public-key", "alg": -7}], options={"rk": True})
cred = att.auth_data.credential_data
Attestation.for_type(att.fmt)().verify(att.att_statement, att.auth_data, cdh)
print("registered credential", cred.credential_id.hex(), "- attestation verified")

cdh = hashlib.sha256(b"login").digest()
assertion = ctap.get_assertion(rp["id"], cdh)  # no allow list: discoverable lookup
assertion.verify(cdh, cred.public_key)
print("assertion verified; counter =", assertion.auth_data.counter, "user =", assertion.user)
print("OK")
