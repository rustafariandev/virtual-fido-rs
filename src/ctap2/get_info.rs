use ciborium::Value;

use super::cbor::{bytes, int, map, text};
use super::pin_protocol::PinProtocol;
use super::{config, cred_blob, cred_mgmt, cred_protect, hmac_secret, large_blobs, CmdResult};
use crate::authenticator::{Authenticator, MAX_MSG_SIZE};
use crate::crypto::Algorithm;

/// Longest allow / exclude list processed, and longest credential ID accepted in one.
const MAX_CREDENTIAL_COUNT_IN_LIST: i64 = 16;
const MAX_CREDENTIAL_ID_LENGTH: i64 = 128;

pub(super) fn handle(auth: &Authenticator) -> CmdResult {
    let config = auth.store.config()?;
    let pin = auth.store.pin()?;
    let bool_option = |name: &str, value: bool| (text(name), Value::Bool(value));

    // U2F is turned off by alwaysUv, as it cannot verify the user.
    let mut versions = Vec::new();
    if !config.always_uv {
        versions.push(text("U2F_V2"));
    }
    versions.extend([text("FIDO_2_0"), text("FIDO_2_1_PRE"), text("FIDO_2_1")]);

    let remaining = cred_mgmt::MAX_RESIDENT_CREDENTIALS.saturating_sub(cred_mgmt::resident_count(auth)?);
    Ok(Some(map(vec![
        (int(0x01), Value::Array(versions)),
        (
            int(0x02),
            Value::Array(vec![
                text(cred_blob::NAME),
                text(cred_protect::NAME),
                text(hmac_secret::NAME),
                text(large_blobs::EXTENSION),
                text(config::MIN_PIN_LENGTH_EXTENSION),
            ]),
        ),
        (int(0x03), bytes(&auth.aaguid)),
        (
            int(0x04),
            map(vec![
                bool_option("rk", true),
                bool_option("up", true),
                bool_option("plat", false),
                bool_option("alwaysUv", config.always_uv),
                bool_option("credMgmt", true),
                bool_option("authnrCfg", true),
                bool_option("clientPin", pin.is_some()),
                bool_option("largeBlobs", true),
                bool_option("pinUvAuthToken", true),
                bool_option("setMinPINLength", true),
                bool_option("makeCredUvNotRqd", !config.always_uv),
                bool_option("credentialMgmtPreview", true),
            ]),
        ),
        (int(0x05), int(MAX_MSG_SIZE as i64)),
        (int(0x06), Value::Array(PinProtocol::SUPPORTED.iter().map(|p| int(p.id())).collect())),
        (int(0x07), int(MAX_CREDENTIAL_COUNT_IN_LIST)),
        (int(0x08), int(MAX_CREDENTIAL_ID_LENGTH)),
        (int(0x09), Value::Array(vec![text("usb")])),
        (
            int(0x0A),
            Value::Array(
                Algorithm::SUPPORTED
                    .iter()
                    .map(|a| map(vec![(text("alg"), int(a.cose_id())), (text("type"), text("public-key"))]))
                    .collect(),
            ),
        ),
        (int(0x0B), int(large_blobs::MAX_SERIALIZED_SIZE as i64)),
        (int(0x0C), Value::Bool(pin.as_ref().is_some_and(|p| p.force_change))),
        (int(0x0D), int(config.min_pin_length.into())),
        (int(0x0E), int(firmware_version())),
        (int(0x0F), int(cred_blob::MAX_LEN as i64)),
        (int(0x10), int(config::MAX_MIN_PIN_LENGTH_RP_IDS as i64)),
        (int(0x14), int(remaining as i64)),
    ])))
}

/// The crate version as a number: 0.1.0 -> 100, 1.2.3 -> 10203.
fn firmware_version() -> i64 {
    let part = |s: &str| s.parse::<i64>().unwrap_or(0);
    part(env!("CARGO_PKG_VERSION_MAJOR")) * 10_000
        + part(env!("CARGO_PKG_VERSION_MINOR")) * 100
        + part(env!("CARGO_PKG_VERSION_PATCH"))
}
