//! The credBlob extension (CTAP 2.1 §12.2): an RP stores a few bytes with a credential
//! at creation and gets them back, unencrypted, in authenticatorData on sign-in.

use ciborium::Value;

use super::cbor::{as_bool, as_bytes, as_map, bytes, get_text, text};
use super::Status;
use crate::store::Credential;

pub(crate) const NAME: &str = "credBlob";
/// Largest blob stored (the spec minimum).
pub(crate) const MAX_LEN: usize = 32;

/// The blob makeCredential asked to store, if any.
pub(super) fn requested_at_creation(extensions: Option<&Value>) -> Result<Option<Vec<u8>>, Status> {
    match extensions.map(as_map).transpose()?.and_then(|m| get_text(m, NAME)) {
        Some(v) => Ok(Some(as_bytes(v)?.to_vec())),
        None => Ok(None),
    }
}

/// makeCredential's extension output entry: whether the blob was stored.
pub(super) fn creation_output(stored: bool) -> (Value, Value) {
    (text(NAME), Value::Bool(stored))
}

/// Whether getAssertion asked for the blob.
pub(super) fn requested(extensions: Option<&Value>) -> Result<bool, Status> {
    match extensions.map(as_map).transpose()?.and_then(|m| get_text(m, NAME)) {
        Some(v) => as_bool(v),
        None => Ok(false),
    }
}

/// getAssertion's extension output entry: the stored blob, empty if there is none.
pub(super) fn assertion_output(cred: &Credential) -> (Value, Value) {
    (text(NAME), bytes(cred.cred_blob.as_deref().unwrap_or_default()))
}
