//! Large blobs (CTAP 2.1 §6.10): a small opaque array the authenticator stores for
//! clients, read and written in fragments with authenticatorLargeBlobs (0x0C), plus
//! the largeBlobKey extension (§12.3), which gives each resident credential a key the
//! client uses to encrypt its own entries. The authenticator never looks inside entries.

use ciborium::Value;
use zeroize::Zeroizing;

use super::cbor::{self, as_bool, as_bytes, as_int, as_map, bytes, get, get_text, int, map, require};
use super::client_pin::verify_pin_token;
use super::{CmdResult, Status};
use crate::authenticator::{Authenticator, MAX_MSG_SIZE};
use crate::crypto::{self, random_bytes};

pub(crate) const EXTENSION: &str = "largeBlobKey";

/// Largest serialized array we store (the spec minimum is 1024).
pub(crate) const MAX_SERIALIZED_SIZE: usize = 4096;
/// Largest fragment read or written per request.
const MAX_FRAGMENT: usize = MAX_MSG_SIZE - 64;
const HASH_LEN: usize = 16;

/// The empty array: CBOR `[]` followed by LEFT(SHA-256([]), 16).
const INITIAL_ARRAY: [u8; 17] = [
    0x80, 0x76, 0xbe, 0x8b, 0x52, 0x8d, 0x00, 0x75, 0xf7, 0xaa, 0xe9, 0x8d, 0x6f, 0xa5, 0x7a, 0x6d, 0x3c,
];

/// A multi-fragment write in progress.
pub(crate) struct PendingWrite {
    expected_len: usize,
    data: Vec<u8>,
}

/// Whether a request's extensions ask for a largeBlobKey. Only `true` is valid.
pub(super) fn requested(extensions: Option<&Value>) -> Result<bool, Status> {
    match extensions.map(as_map).transpose()?.and_then(|m| get_text(m, EXTENSION)) {
        Some(v) if as_bool(v)? => Ok(true),
        Some(_) => Err(Status::INVALID_OPTION),
        None => Ok(false),
    }
}

pub(super) fn new_key() -> Vec<u8> {
    random_bytes::<32>().to_vec()
}

pub(super) fn handle(auth: &mut Authenticator, params: &[u8]) -> CmdResult {
    let m = cbor::decode_map(params)?;
    let read_len = get(&m, 0x01).map(as_int).transpose()?;
    let fragment = get(&m, 0x02).map(as_bytes).transpose()?;
    let offset = usize::try_from(as_int(require(get(&m, 0x03))?)?).map_err(|_| Status::INVALID_PARAMETER)?;
    let total_len = get(&m, 0x04).map(as_int).transpose()?;

    match (read_len, fragment) {
        (Some(len), None) => {
            if total_len.is_some() {
                return Err(Status::INVALID_PARAMETER);
            }
            let len = usize::try_from(len).map_err(|_| Status::INVALID_PARAMETER)?;
            if len > MAX_FRAGMENT {
                return Err(Status::INVALID_LENGTH);
            }
            let array = stored_array(auth)?;
            if offset > array.len() {
                return Err(Status::INVALID_PARAMETER);
            }
            let end = array.len().min(offset + len);
            Ok(Some(map(vec![(int(0x01), bytes(&array[offset..end]))])))
        }
        (None, Some(fragment)) => {
            write(auth, &m, offset, total_len, fragment)?;
            Ok(None)
        }
        _ => Err(Status::INVALID_PARAMETER),
    }
}

fn stored_array(auth: &Authenticator) -> Result<Vec<u8>, Status> {
    Ok(auth.store.large_blob()?.unwrap_or_else(|| INITIAL_ARRAY.to_vec()))
}

fn write(
    auth: &mut Authenticator,
    m: &[(Value, Value)],
    offset: usize,
    total_len: Option<i128>,
    fragment: &[u8],
) -> Result<(), Status> {
    if fragment.len() > MAX_FRAGMENT {
        return Err(Status::INVALID_LENGTH);
    }
    if offset == 0 {
        let len = total_len.ok_or(Status::INVALID_PARAMETER)?;
        let len = usize::try_from(len).map_err(|_| Status::INVALID_PARAMETER)?;
        if len > MAX_SERIALIZED_SIZE {
            return Err(Status::LARGE_BLOB_STORAGE_FULL);
        }
        if len < 17 {
            return Err(Status::INVALID_PARAMETER);
        }
        auth.large_blob_write = Some(PendingWrite { expected_len: len, data: Vec::with_capacity(len) });
    } else if total_len.is_some() {
        return Err(Status::INVALID_PARAMETER);
    }
    let Some(pending) = &auth.large_blob_write else { return Err(Status::INVALID_SEQ) };
    if offset != pending.data.len() {
        return Err(Status::INVALID_SEQ);
    }

    // Writes need the PIN once one is set:
    // pinUvAuthParam = authenticate(token, 32 x 0xff || 0x0c 0x00 || u32le(offset) || SHA-256(fragment)).
    if auth.store.pin()?.is_some() {
        let pin_auth = as_bytes(get(m, 0x05).ok_or(Status::PIN_REQUIRED)?)?;
        let mut msg = Zeroizing::new(vec![0xff; 32]);
        msg.extend_from_slice(&[0x0c, 0x00]);
        msg.extend_from_slice(&(offset as u32).to_le_bytes());
        msg.extend_from_slice(&crypto::sha256(fragment));
        verify_pin_token(auth, get(m, 0x06), &msg, pin_auth)?;
    }

    let pending = auth.large_blob_write.as_mut().expect("checked above");
    if offset + fragment.len() > pending.expected_len {
        return Err(Status::INVALID_PARAMETER);
    }
    pending.data.extend_from_slice(fragment);
    if pending.data.len() < pending.expected_len {
        return Ok(());
    }

    let PendingWrite { data, .. } = auth.large_blob_write.take().expect("checked above");
    let (array, hash) = data.split_at(data.len() - HASH_LEN);
    if crypto::sha256(array)[..HASH_LEN] != *hash {
        return Err(Status::INTEGRITY_FAILURE);
    }
    log::info!("large-blob array updated ({} bytes)", array.len());
    auth.store.set_large_blob(data)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_array_is_empty_array_and_its_hash() {
        assert_eq!(INITIAL_ARRAY[0], 0x80);
        assert_eq!(INITIAL_ARRAY[1..], crypto::sha256(&[0x80])[..HASH_LEN]);
    }
}
