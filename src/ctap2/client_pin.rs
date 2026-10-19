//! authenticatorClientPIN (0x06): set, change and verify a PIN, and issue the
//! pinUvAuthToken that makeCredential / getAssertion requests are authenticated with.

use ciborium::Value;
use p256::SecretKey;
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::cbor::{self, as_bytes, as_int, bytes, get, int, map, require};
use super::pin_protocol::{cose_key_agreement, parse_cose_key, PinProtocol};
use super::{CmdResult, Status};
use crate::authenticator::{Authenticator, RequestCtx};
use crate::crypto::{self, random_bytes};
use crate::presence::PresenceRequest;
use crate::store::PinState;

pub const MAX_PIN_RETRIES: u8 = 8;
/// Wrong PINs allowed before the authenticator needs a power cycle (a restart here).
const MAX_CONSECUTIVE_FAILURES: u8 = 3;
const MIN_PIN_CODE_POINTS: usize = 4;
const PADDED_PIN_LEN: usize = 64;

const SUB_GET_PIN_RETRIES: i128 = 0x01;
const SUB_GET_KEY_AGREEMENT: i128 = 0x02;
const SUB_SET_PIN: i128 = 0x03;
const SUB_CHANGE_PIN: i128 = 0x04;
const SUB_GET_PIN_TOKEN: i128 = 0x05;

/// PIN state that only lives until the process exits ("power cycle").
pub(crate) struct PinRuntime {
    key_agreement: SecretKey,
    token: Option<Zeroizing<[u8; 32]>>,
    consecutive_failures: u8,
}

impl PinRuntime {
    pub(crate) fn new() -> Self {
        PinRuntime { key_agreement: SecretKey::random(&mut OsRng), token: None, consecutive_failures: 0 }
    }

    pub(crate) fn reset(&mut self) {
        *self = PinRuntime::new();
    }
}

pub(super) fn handle(auth: &mut Authenticator, params: &[u8]) -> CmdResult {
    let m = cbor::decode_map(params)?;
    let protocol = || -> Result<PinProtocol, Status> {
        PinProtocol::from_id(as_int(require(get(&m, 0x01))?)?).ok_or(Status::INVALID_PARAMETER)
    };
    match as_int(require(get(&m, 0x02))?)? {
        SUB_GET_PIN_RETRIES => {
            let retries = auth.store.pin()?.map_or(MAX_PIN_RETRIES, |p| p.retries);
            Ok(Some(map(vec![(int(0x03), int(retries.into()))])))
        }
        SUB_GET_KEY_AGREEMENT => {
            protocol()?;
            Ok(Some(map(vec![(int(0x01), cose_key_agreement(&auth.pin.key_agreement))])))
        }
        SUB_SET_PIN => set_pin(auth, protocol()?, &m),
        SUB_CHANGE_PIN => change_pin(auth, protocol()?, &m),
        SUB_GET_PIN_TOKEN => get_pin_token(auth, protocol()?, &m),
        _ => Err(Status::INVALID_SUBCOMMAND),
    }
}

fn shared_secret(auth: &Authenticator, protocol: PinProtocol, m: &[(Value, Value)]) -> Result<Zeroizing<Vec<u8>>, Status> {
    let peer = parse_cose_key(require(get(m, 0x03))?)?;
    Ok(protocol.shared_secret(&auth.pin.key_agreement, &peer))
}

fn set_pin(auth: &mut Authenticator, protocol: PinProtocol, m: &[(Value, Value)]) -> CmdResult {
    let secret = shared_secret(auth, protocol, m)?;
    let pin_auth = as_bytes(require(get(m, 0x04))?)?;
    let new_pin_enc = as_bytes(require(get(m, 0x05))?)?;
    if auth.store.pin()?.is_some() {
        return Err(Status::NOT_ALLOWED);
    }
    if !protocol.verify_with_secret(&secret, new_pin_enc, pin_auth) {
        return Err(Status::PIN_AUTH_INVALID);
    }
    let pin = decrypt_new_pin(protocol, &secret, new_pin_enc)?;
    auth.store.set_pin(Some(PinState { pin_hash: pin_hash(&pin), retries: MAX_PIN_RETRIES }))?;
    auth.pin.consecutive_failures = 0;
    log::info!("PIN set");
    Ok(None)
}

fn change_pin(auth: &mut Authenticator, protocol: PinProtocol, m: &[(Value, Value)]) -> CmdResult {
    let secret = shared_secret(auth, protocol, m)?;
    let pin_auth = as_bytes(require(get(m, 0x04))?)?;
    let new_pin_enc = as_bytes(require(get(m, 0x05))?)?;
    let pin_hash_enc = as_bytes(require(get(m, 0x06))?)?;
    let state = auth.store.pin()?.ok_or(Status::PIN_NOT_SET)?;
    if state.retries == 0 {
        return Err(Status::PIN_BLOCKED);
    }
    if !protocol.verify_with_secret(&secret, &[new_pin_enc, pin_hash_enc].concat(), pin_auth) {
        return Err(Status::PIN_AUTH_INVALID);
    }
    check_pin_hash(auth, protocol, &secret, pin_hash_enc)?;
    let pin = decrypt_new_pin(protocol, &secret, new_pin_enc)?;
    auth.store.set_pin(Some(PinState { pin_hash: pin_hash(&pin), retries: MAX_PIN_RETRIES }))?;
    auth.pin.token = None;
    log::info!("PIN changed");
    Ok(None)
}

fn get_pin_token(auth: &mut Authenticator, protocol: PinProtocol, m: &[(Value, Value)]) -> CmdResult {
    let secret = shared_secret(auth, protocol, m)?;
    let pin_hash_enc = as_bytes(require(get(m, 0x06))?)?;
    check_pin_hash(auth, protocol, &secret, pin_hash_enc)?;
    let token = Zeroizing::new(random_bytes::<32>());
    let encrypted = protocol.encrypt(&secret, &*token);
    auth.pin.token = Some(token);
    Ok(Some(map(vec![(int(0x02), bytes(&encrypted))])))
}

/// Checks an encrypted PIN hash against the stored one, maintaining the retry counters.
/// The persistent counter is decremented *before* comparing, so killing the process
/// mid-check cannot yield a free guess.
fn check_pin_hash(auth: &mut Authenticator, protocol: PinProtocol, secret: &[u8], pin_hash_enc: &[u8]) -> Result<(), Status> {
    let mut state = auth.store.pin()?.ok_or(Status::PIN_NOT_SET)?;
    if state.retries == 0 {
        return Err(Status::PIN_BLOCKED);
    }
    if auth.pin.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
        return Err(Status::PIN_AUTH_BLOCKED);
    }
    state.retries -= 1;
    auth.store.set_pin(Some(state.clone()))?;

    let matches = protocol
        .decrypt(secret, pin_hash_enc)
        .is_some_and(|h| h.len() == 16 && bool::from(h.ct_eq(&state.pin_hash)));
    if !matches {
        auth.pin.key_agreement = SecretKey::random(&mut OsRng);
        auth.pin.consecutive_failures += 1;
        log::warn!("wrong PIN ({} retries left)", state.retries);
        return Err(if state.retries == 0 {
            Status::PIN_BLOCKED
        } else if auth.pin.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
            Status::PIN_AUTH_BLOCKED
        } else {
            Status::PIN_INVALID
        });
    }
    state.retries = MAX_PIN_RETRIES;
    auth.store.set_pin(Some(state))?;
    auth.pin.consecutive_failures = 0;
    Ok(())
}

/// Decrypts and validates a new PIN: 64 bytes, zero-padded, UTF-8, at least 4 code points.
fn decrypt_new_pin(protocol: PinProtocol, secret: &[u8], new_pin_enc: &[u8]) -> Result<Zeroizing<Vec<u8>>, Status> {
    let padded = protocol.decrypt(secret, new_pin_enc).ok_or(Status::INVALID_PARAMETER)?;
    if padded.len() != PADDED_PIN_LEN {
        return Err(Status::PIN_POLICY_VIOLATION);
    }
    let len = padded.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    // At least one padding byte is required, so PINs are at most 63 bytes.
    if len == PADDED_PIN_LEN {
        return Err(Status::PIN_POLICY_VIOLATION);
    }
    match std::str::from_utf8(&padded[..len]) {
        Ok(pin) if pin.chars().count() >= MIN_PIN_CODE_POINTS => Ok(Zeroizing::new(padded[..len].to_vec())),
        _ => Err(Status::PIN_POLICY_VIOLATION),
    }
}

fn pin_hash(pin: &[u8]) -> [u8; 16] {
    crypto::sha256(pin)[..16].try_into().unwrap()
}

/// Checks a request's pinUvAuthParam (`pin_auth`) over `client_data_hash`. Returns
/// whether the user was verified. An empty `pin_auth` is a client probing whether a
/// PIN is set; it needs a touch and always fails.
pub(super) fn verify_pin_uv_auth(
    auth: &Authenticator,
    pin_auth: Option<&Value>,
    protocol: Option<&Value>,
    client_data_hash: &[u8],
    presence: &PresenceRequest,
    ctx: &RequestCtx,
) -> Result<bool, Status> {
    let Some(pin_auth) = pin_auth else { return Ok(false) };
    let pin_auth = as_bytes(pin_auth)?;
    let pin_set = auth.store.pin()?.is_some();
    if pin_auth.is_empty() {
        auth.require_presence(presence, ctx)?;
        return Err(if pin_set { Status::PIN_INVALID } else { Status::PIN_NOT_SET });
    }
    let protocol = PinProtocol::from_id(as_int(require(protocol)?)?).ok_or(Status::INVALID_PARAMETER)?;
    if !pin_set {
        return Err(Status::PIN_NOT_SET);
    }
    let token = auth.pin.token.as_ref().ok_or(Status::PIN_AUTH_INVALID)?;
    if !protocol.verify(&**token, client_data_hash, pin_auth) {
        return Err(Status::PIN_AUTH_INVALID);
    }
    Ok(true)
}
