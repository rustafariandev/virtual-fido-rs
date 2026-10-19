//! authenticatorConfig (0x0D): toggleAlwaysUv and setMinPINLength. Also the
//! minPinLength extension, which reports the minimum to RPs allowed to see it.

use ciborium::Value;

use super::cbor::{self, as_array, as_bool, as_bytes, as_int, as_map, as_text, get, get_text, int, require, text};
use super::client_pin::{use_pin_token, PERM_AUTHENTICATOR_CONFIG};
use super::{CmdResult, Status};
use crate::authenticator::Authenticator;
use crate::store::DEFAULT_MIN_PIN_LENGTH;

pub(crate) const MIN_PIN_LENGTH_EXTENSION: &str = "minPinLength";
/// Most RP IDs that may be given minPinLength access.
pub(crate) const MAX_MIN_PIN_LENGTH_RP_IDS: usize = 8;
/// Longest PIN the padding allows, so the largest sensible minimum.
const MAX_MIN_PIN_LENGTH: i128 = 63;

const SUB_TOGGLE_ALWAYS_UV: i128 = 0x02;
const SUB_SET_MIN_PIN_LENGTH: i128 = 0x03;

pub(super) fn handle(auth: &mut Authenticator, params: &[u8]) -> CmdResult {
    let m = cbor::decode_map(params)?;
    let sub = as_int(require(get(&m, 0x01))?)?;
    let sub_params = get(&m, 0x02);
    // Enterprise attestation (0x01) and vendor prototype commands are not supported.
    if sub != SUB_TOGGLE_ALWAYS_UV && sub != SUB_SET_MIN_PIN_LENGTH {
        return Err(Status::INVALID_SUBCOMMAND);
    }

    // Unprotected authenticators can be configured freely; once a PIN is set:
    // pinUvAuthParam = authenticate(token, 32 x 0xff || 0x0d || subCommand || CBOR(subCommandParams)).
    if auth.store.pin()?.is_some() {
        let pin_auth = as_bytes(get(&m, 0x04).ok_or(Status::PIN_REQUIRED)?)?;
        let mut msg = vec![0xff; 32];
        msg.push(0x0d);
        msg.push(sub as u8);
        if let Some(p) = sub_params {
            msg.extend(cbor::encode(p));
        }
        use_pin_token(auth, get(&m, 0x03), &msg, pin_auth, PERM_AUTHENTICATOR_CONFIG, None)?;
    }

    let mut config = auth.store.config()?;
    if sub == SUB_TOGGLE_ALWAYS_UV {
        config.always_uv = !config.always_uv;
        log::info!("alwaysUv {}", if config.always_uv { "enabled" } else { "disabled" });
        auth.store.set_config(config)?;
        return Ok(None);
    }

    let p = match sub_params {
        Some(v) => as_map(v)?,
        None => &[],
    };
    let new_min = match get(p, 0x01) {
        Some(v) => {
            let n = as_int(v)?;
            if n < config.min_pin_length.into() || n > MAX_MIN_PIN_LENGTH {
                return Err(Status::PIN_POLICY_VIOLATION);
            }
            n as u8
        }
        None => config.min_pin_length,
    };
    let rp_ids = get(p, 0x02)
        .map(|v| as_array(v)?.iter().map(|id| as_text(id).map(str::to_owned)).collect::<Result<Vec<_>, _>>())
        .transpose()?;
    if rp_ids.as_ref().is_some_and(|ids| ids.len() > MAX_MIN_PIN_LENGTH_RP_IDS) {
        return Err(Status::INVALID_LENGTH);
    }
    let force_change = get(p, 0x03).map(as_bool).transpose()?.unwrap_or(false);
    let pin = auth.store.pin()?;
    if force_change && pin.is_none() {
        return Err(Status::PIN_NOT_SET);
    }

    config.min_pin_length = new_min;
    if let Some(ids) = rp_ids {
        config.min_pin_length_rp_ids = ids;
    }
    auth.store.set_config(config)?;
    log::info!("minimum PIN length is {new_min}");

    // A PIN shorter than the new minimum (or of unknown length, set before lengths were
    // recorded) must be changed before it can be used again.
    if let Some(mut pin) = pin {
        let too_short = pin.code_points.map_or(new_min > DEFAULT_MIN_PIN_LENGTH, |n| n < new_min);
        if force_change || too_short {
            pin.force_change = true;
            auth.store.set_pin(Some(pin))?;
        }
    }
    Ok(None)
}

/// makeCredential's minPinLength extension output entry, for RPs on the allow list.
pub(super) fn min_pin_length_output(
    auth: &Authenticator,
    extensions: Option<&Value>,
    rp_id: &str,
) -> Result<Option<(Value, Value)>, Status> {
    let requested = match extensions.map(as_map).transpose()?.and_then(|m| get_text(m, MIN_PIN_LENGTH_EXTENSION)) {
        Some(v) => as_bool(v)?,
        None => false,
    };
    let config = auth.store.config()?;
    if !requested || !config.min_pin_length_rp_ids.iter().any(|id| id == rp_id) {
        return Ok(None);
    }
    Ok(Some((text(MIN_PIN_LENGTH_EXTENSION), int(config.min_pin_length.into()))))
}
