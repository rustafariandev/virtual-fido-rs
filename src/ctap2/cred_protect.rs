//! The credProtect extension (CTAP 2.1 §12.1): a per-credential policy restricting
//! use without user verification. The policy itself is [`CredProtect::allows`];
//! this module handles the extension's wire format.

use ciborium::Value;

use super::cbor::{as_int, as_map, get_text, int, text};
use super::Status;
use crate::store::CredProtect;

pub(crate) const NAME: &str = "credProtect";

/// The level makeCredential asked for, if any. Unknown levels are ignored, as for
/// any unsupported extension input.
pub(super) fn requested(extensions: Option<&Value>) -> Result<Option<CredProtect>, Status> {
    let Some(v) = extensions.map(as_map).transpose()?.and_then(|m| get_text(m, NAME)) else {
        return Ok(None);
    };
    let level = as_int(v)?;
    let policy = u8::try_from(level).ok().and_then(|l| CredProtect::try_from(l).ok());
    if policy.is_none() {
        log::warn!("ignoring unsupported credProtect level {level}");
    }
    Ok(policy)
}

/// makeCredential's extension output entry, `"credProtect": level`.
pub(super) fn creation_output(policy: CredProtect) -> (Value, Value) {
    (text(NAME), int(u8::from(policy).into()))
}
