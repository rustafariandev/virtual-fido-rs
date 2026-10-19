//! The hmac-secret extension (CTAP 2.1 §12.5): a per-credential symmetric secret
//! that lets a client derive stable keys, e.g. for disk encryption.
//!
//! At creation the credential gets two random 32-byte keys, one used when the user
//! was verified and one when not. An assertion request carries one or two 32-byte
//! salts, encrypted under a clientPIN-style shared secret; the authenticator returns
//! HMAC-SHA-256(key, salt) for each, encrypted the same way.

use ciborium::Value;
use zeroize::Zeroizing;

use super::cbor::{as_bool, as_bytes, as_int, as_map, bytes, get, get_text, map, require, text};
use super::pin_protocol::PinProtocol;
use super::Status;
use crate::authenticator::Authenticator;
use crate::crypto::random_bytes;
use crate::store::Credential;

pub(crate) const NAME: &str = "hmac-secret";
const SALT_LEN: usize = 32;

/// New `CredRandomWithUV || CredRandomWithoutUV`.
pub(super) fn new_cred_random() -> Vec<u8> {
    random_bytes::<64>().to_vec()
}

/// Whether makeCredential asked for hmac-secret.
pub(super) fn requested_at_creation(extensions: Option<&Value>) -> Result<bool, Status> {
    match extensions.map(as_map).transpose()?.and_then(|m| get_text(m, NAME)) {
        Some(v) => as_bool(v),
        None => Ok(false),
    }
}

/// makeCredential's extension output entry, `"hmac-secret": true`.
pub(super) fn creation_output() -> (Value, Value) {
    (text(NAME), Value::Bool(true))
}

/// A decrypted and authenticated getAssertion hmac-secret request.
pub(crate) struct Request {
    protocol: PinProtocol,
    shared_secret: Zeroizing<Vec<u8>>,
    /// salt1, or salt1 || salt2.
    salts: Zeroizing<Vec<u8>>,
}

/// Parses getAssertion's hmac-secret input, if present:
/// `{1: keyAgreement, 2: saltEnc, 3: saltAuth, 4: pinUvAuthProtocol (default 1)}`.
pub(super) fn parse_request(auth: &Authenticator, extensions: Option<&Value>) -> Result<Option<Request>, Status> {
    let Some(input) = extensions.map(as_map).transpose()?.and_then(|m| get_text(m, NAME)) else {
        return Ok(None);
    };
    let input = as_map(input)?;
    let protocol = match get(input, 4) {
        Some(v) => PinProtocol::from_id(as_int(v)?).ok_or(Status::INVALID_PARAMETER)?,
        None => PinProtocol::V1,
    };
    let shared_secret = auth.pin.shared_secret(protocol, require(get(input, 1))?)?;
    let salt_enc = as_bytes(require(get(input, 2))?)?;
    let salt_auth = as_bytes(require(get(input, 3))?)?;
    if !protocol.verify_with_secret(&shared_secret, salt_enc, salt_auth) {
        return Err(Status::PIN_AUTH_INVALID);
    }
    let salts = protocol.decrypt(&shared_secret, salt_enc).ok_or(Status::INVALID_LENGTH)?;
    if salts.len() != SALT_LEN && salts.len() != 2 * SALT_LEN {
        return Err(Status::INVALID_LENGTH);
    }
    Ok(Some(Request { protocol, shared_secret, salts }))
}

impl Request {
    /// getAssertion's extension output for `cred`, `{"hmac-secret": enc(output1 [|| output2])}`.
    /// `None` if the credential was created without hmac-secret.
    pub(super) fn output(&self, cred: &Credential, user_verified: bool) -> Option<Value> {
        let cred_random = cred.hmac_secret.as_deref()?;
        let key = if user_verified { &cred_random[..32] } else { &cred_random[32..] };
        let mut outputs = Zeroizing::new(Vec::with_capacity(self.salts.len()));
        for salt in self.salts.chunks(SALT_LEN) {
            // PIN protocol two's authenticate() is the full, untruncated HMAC-SHA-256.
            outputs.extend(PinProtocol::V2.authenticate(key, salt));
        }
        let encrypted = self.protocol.encrypt(&self.shared_secret, &outputs);
        Some(map(vec![(text(NAME), bytes(&encrypted))]))
    }
}
