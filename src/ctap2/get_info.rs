use ciborium::Value;

use super::cbor::{bytes, int, map, text};
use super::hmac_secret;
use super::pin_protocol::PinProtocol;
use super::CmdResult;
use crate::authenticator::{Authenticator, MAX_MSG_SIZE};
use crate::crypto::COSE_ALG_ES256;

pub(super) fn handle(auth: &Authenticator) -> CmdResult {
    Ok(Some(map(vec![
        (int(0x01), Value::Array(vec![text("U2F_V2"), text("FIDO_2_0")])),
        (int(0x02), Value::Array(vec![text(hmac_secret::NAME)])),
        (int(0x03), bytes(&auth.aaguid)),
        (
            int(0x04),
            map(vec![
                (text("rk"), Value::Bool(true)),
                (text("up"), Value::Bool(true)),
                (text("plat"), Value::Bool(false)),
                (text("clientPin"), Value::Bool(auth.store.pin()?.is_some())),
            ]),
        ),
        (int(0x05), int(MAX_MSG_SIZE as i64)),
        (int(0x06), Value::Array(PinProtocol::SUPPORTED.iter().map(|p| int(p.id())).collect())),
        (int(0x09), Value::Array(vec![text("usb")])),
        (
            int(0x0A),
            Value::Array(vec![map(vec![(text("alg"), int(COSE_ALG_ES256)), (text("type"), text("public-key"))])]),
        ),
    ])))
}
