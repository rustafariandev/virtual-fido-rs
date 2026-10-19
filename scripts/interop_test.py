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

dev.close()
print("OK")
