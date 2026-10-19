#!/usr/bin/env python3
"""Interop test against python-fido2 (0.9.x), without root or a real HID device.

Drives examples/stdio_device.rs over a pipe through python-fido2's own CTAPHID,
CTAP2 and PIN protocol implementations:

    cargo build --example stdio_device
    python3 scripts/interop_test.py [path/to/stdio_device]
"""
import hashlib
import os
import subprocess
import sys

from fido2.attestation import Attestation
from fido2.ctap import CtapError
from fido2.ctap2 import ClientPin, Ctap2
from fido2.ctap2.blob import LargeBlobs
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.extensions import (
    CredBlobExtension,
    CredProtectExtension,
    HmacSecretExtension,
    LargeBlobKeyExtension,
)
from fido2.ctap2.pin import PinProtocolV1, PinProtocolV2
from fido2.hid import CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "target/debug/examples/stdio_device")


class PipeConnection(CtapHidConnection):
    def __init__(self, proc):
        self.proc = proc

    def write_packet(self, data):
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def read_packet(self):
        data = self.proc.stdout.read(64)
        if len(data) != 64:
            raise IOError("device closed")
        return data

    def close(self):
        self.proc.kill()


def expect_error(code, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except CtapError as e:
        assert e.code == code, f"expected {code!r}, got {e.code!r}"
        return
    raise AssertionError(f"expected {code!r}, call succeeded")


proc = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
dev = CtapHidDevice(HidDescriptor("pipe", 0x1209, 0x000A, 64, 64, "Virtual FIDO2", None), PipeConnection(proc))
ctap = Ctap2(dev)
rp = {"id": "example.com", "name": "Example"}
key_params = [{"type": "public-key", "alg": -7}]

for proto_cls in (PinProtocolV1, PinProtocolV2):
    proto = proto_cls()
    name = proto_cls.__name__
    ctap.reset()
    assert ctap.get_info().options["clientPin"] is False
    assert proto.VERSION in ctap.get_info().pin_uv_protocols

    pin = ClientPin(ctap, proto)
    pin.set_pin("hunter22")
    assert ctap.get_info().options["clientPin"] is True
    assert pin.get_pin_retries()[0] == 8

    user = {"id": os.urandom(8), "name": "alice", "displayName": "Alice"}
    cdh = hashlib.sha256(b"register").digest()
    expect_error(CtapError.ERR.PUAT_REQUIRED, ctap.make_credential, cdh, rp, user, key_params)

    token = pin.get_pin_token("hunter22")
    att = ctap.make_credential(
        cdh, rp, user, key_params, options={"rk": True},
        pin_uv_param=proto.authenticate(token, cdh), pin_uv_protocol=proto.VERSION,
    )
    Attestation.for_type(att.fmt)().verify(att.att_statement, att.auth_data, cdh)
    assert att.auth_data.is_user_verified()
    cred = att.auth_data.credential_data

    cdh = hashlib.sha256(b"login").digest()
    assertion = ctap.get_assertion(
        rp["id"], cdh, pin_uv_param=proto.authenticate(token, cdh), pin_uv_protocol=proto.VERSION
    )
    assertion.verify(cdh, cred.public_key)
    assert assertion.auth_data.is_user_verified()

    expect_error(CtapError.ERR.PIN_INVALID, pin.get_pin_token, "wrong-pin")
    assert pin.get_pin_retries()[0] == 7
    pin.change_pin("hunter22", "correct horse")
    assert pin.get_pin_retries()[0] == 8
    expect_error(CtapError.ERR.PIN_INVALID, pin.get_pin_token, "hunter22")
    pin.get_pin_token("correct horse")
    print(f"{name}: set / token / makeCredential+UV / getAssertion+UV / wrong PIN / change PIN OK")

# hmac-secret: outputs depend only on the credential and salt, so both protocols agree.
ctap.reset()
assert "hmac-secret" in ctap.get_info().extensions
user = {"id": os.urandom(8), "name": "bob"}
cdh = hashlib.sha256(b"register").digest()
create = HmacSecretExtension(ctap).process_create_input({"hmacCreateSecret": True})
att = ctap.make_credential(cdh, rp, user, key_params, extensions={"hmac-secret": create}, options={"rk": True})
assert HmacSecretExtension(ctap).process_create_output(att.auth_data) == {"hmacCreateSecret": True}
cred = att.auth_data.credential_data

salt1, salt2 = os.urandom(32), os.urandom(32)
results = []
for proto_cls in (PinProtocolV1, PinProtocolV2):
    ext = HmacSecretExtension(ctap, proto_cls())
    inp = ext.process_get_input({"hmacGetSecret": {"salt1": salt1, "salt2": salt2}})
    cdh = hashlib.sha256(b"login").digest()
    assertion = ctap.get_assertion(rp["id"], cdh, extensions={"hmac-secret": inp})
    assertion.verify(cdh, cred.public_key)
    results.append(ext.process_get_output(assertion.auth_data)["hmacGetSecret"])
assert results[0] == results[1], results
assert len(results[0]["output1"]) == 32 and results[0]["output1"] != results[0]["output2"]
print("hmac-secret: create / get over PIN protocols 1 and 2 agree OK")

# credProtect level 3: invisible without the PIN, usable with it.
ctap.reset()
assert "credProtect" in ctap.get_info().extensions
level = CredProtectExtension(ctap).process_create_input(
    {"credentialProtectionPolicy": CredProtectExtension.POLICY.REQUIRED}
)
assert level == 3
proto = PinProtocolV2()
pin = ClientPin(ctap, proto)
pin.set_pin("hunter22")
token = pin.get_pin_token("hunter22")
cdh = hashlib.sha256(b"register").digest()
att = ctap.make_credential(
    cdh, rp, {"id": os.urandom(8), "name": "carol"}, key_params,
    extensions={"credProtect": level}, options={"rk": True},
    pin_uv_param=proto.authenticate(token, cdh), pin_uv_protocol=proto.VERSION,
)
assert att.auth_data.extensions == {"credProtect": 3}, att.auth_data.extensions
cred = att.auth_data.credential_data
cdh = hashlib.sha256(b"login").digest()
allow = [{"type": "public-key", "id": cred.credential_id}]
expect_error(CtapError.ERR.NO_CREDENTIALS, ctap.get_assertion, rp["id"], cdh, allow)
expect_error(CtapError.ERR.NO_CREDENTIALS, ctap.get_assertion, rp["id"], cdh)
assertion = ctap.get_assertion(
    rp["id"], cdh, allow, pin_uv_param=proto.authenticate(token, cdh), pin_uv_protocol=proto.VERSION
)
assertion.verify(cdh, cred.public_key)
print("credProtect: level 3 hidden without PIN, usable with PIN OK")

# Credential management: list, rename and delete resident credentials.
ctap.reset()
proto = PinProtocolV2()
pin = ClientPin(ctap, proto)
pin.set_pin("hunter22")
token = pin.get_pin_token("hunter22")
created = {}
for rp_id, user_name in [("b.example", "alice"), ("b.example", "bob"), ("a.example", "carol")]:
    cdh = os.urandom(32)
    att = ctap.make_credential(
        cdh, {"id": rp_id, "name": rp_id.upper()}, {"id": user_name.encode(), "name": user_name}, key_params,
        options={"rk": True}, pin_uv_param=proto.authenticate(token, cdh), pin_uv_protocol=proto.VERSION,
    )
    created[user_name] = att.auth_data.credential_data

R = CredentialManagement.RESULT
cm = CredentialManagement(ctap, proto, token)
meta = cm.get_metadata()
assert meta[R.EXISTING_CRED_COUNT] == 3, meta
rps = cm.enumerate_rps()
assert [rp[R.RP]["id"] for rp in rps] == ["a.example", "b.example"], rps
assert rps[0][R.RP]["name"] == "A.EXAMPLE"
creds = cm.enumerate_creds(rps[1][R.RP_ID_HASH])
assert [c[R.USER]["name"] for c in creds] == ["bob", "alice"], creds
for c in creds:
    assert c[R.PUBLIC_KEY] == created[c[R.USER]["name"]].public_key
cm.delete_cred(creds[0][R.CREDENTIAL_ID])
remaining = cm.enumerate_creds(rps[1][R.RP_ID_HASH])
assert [c[R.USER]["name"] for c in remaining] == ["alice"]
assert cm.get_metadata()[R.EXISTING_CRED_COUNT] == 2
print("credential management: metadata / enumerate RPs and credentials / delete OK")

# Large blobs: python-fido2 encrypts entries with the credential's largeBlobKey.
# (python-fido2 0.9 sends `length` on every fragment, which CTAP 2.1 only allows on
# the first, so keep the array within one fragment here.)
ctap.reset()
assert ctap.get_info().options["largeBlobs"] is True
lbk = LargeBlobKeyExtension(ctap).process_create_input({"largeBlobKey": True})
cdh = os.urandom(32)
att = ctap.make_credential(
    cdh, rp, {"id": b"dan", "name": "dan"}, key_params, extensions={"largeBlobKey": lbk}, options={"rk": True}
)
key = att.large_blob_key
assert key is not None and len(key) == 32
blobs = LargeBlobs(ctap)
assert blobs.read_blob_array() == []
blobs.put_blob(key, b"certificate or other per-credential data" * 5)
cdh = os.urandom(32)
assertion = ctap.get_assertion(rp["id"], cdh, extensions={"largeBlobKey": True})
assert assertion.large_blob_key == key
assert blobs.get_blob(assertion.large_blob_key) == b"certificate or other per-credential data" * 5
blobs.delete_blob(key)
assert blobs.get_blob(key) is None
print("largeBlob: key via makeCredential/getAssertion, put / get / delete blob OK")

# credBlob: a few bytes stored at creation, returned in authData on sign-in.
ctap.reset()
assert ctap.get_info().max_cred_blob_length == 32
blob = b"ssh-config:v1;" + os.urandom(8)
ext = CredBlobExtension(ctap).process_create_input({"credBlob": blob})
assert ext == blob
att = ctap.make_credential(
    os.urandom(32), rp, {"id": b"erin", "name": "erin"}, key_params, extensions={"credBlob": ext}, options={"rk": True}
)
assert att.auth_data.extensions == {"credBlob": True}, att.auth_data.extensions
assert CredBlobExtension(ctap).process_create_input({"credBlob": b"x" * 33}) is None, "client checks the limit"
get_ext = CredBlobExtension(ctap).process_get_input({"getCredBlob": True})
assertion = ctap.get_assertion(rp["id"], os.urandom(32), extensions={"credBlob": get_ext})
assert assertion.auth_data.extensions == {"credBlob": blob}, assertion.auth_data.extensions
print("credBlob: store at creation / return on sign-in OK")

dev.close()
print("OK")
