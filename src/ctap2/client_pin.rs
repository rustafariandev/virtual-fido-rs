//! authenticatorClientPIN (0x06): set, change and verify a PIN, and issue the
//! pinUvAuthToken that other commands are authorized with.
//!
//! Tokens follow CTAP 2.1: each carries permissions (and optionally an RP ID it is
//! bound to), expires if unused for 30 s or 10 minutes after issue, and loses its
//! makeCredential / getAssertion permissions once used for one of them.

use std::time::{Duration, Instant};

use ciborium::Value;
use p256::SecretKey;
use rand::rngs::OsRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::cbor::{self, as_bytes, as_int, as_text, bytes, get, int, map, require};
use super::pin_protocol::{cose_key_agreement, parse_cose_key, PinProtocol};
use super::{CmdResult, Status};
use crate::authenticator::{Authenticator, RequestCtx};
use crate::crypto::{self, random_bytes};
use crate::presence::PresenceRequest;
use crate::store::PinState;

pub const MAX_PIN_RETRIES: u8 = 8;
/// Wrong PINs allowed before the authenticator needs a power cycle (a restart here).
const MAX_CONSECUTIVE_FAILURES: u8 = 3;
const PADDED_PIN_LEN: usize = 64;

/// A token must be used this soon after it is issued...
const INITIAL_USAGE_LIMIT: Duration = Duration::from_secs(30);
/// ...and stops working this long after issue regardless.
const MAX_USAGE_PERIOD: Duration = Duration::from_secs(600);

const SUB_GET_PIN_RETRIES: i128 = 0x01;
const SUB_GET_KEY_AGREEMENT: i128 = 0x02;
const SUB_SET_PIN: i128 = 0x03;
const SUB_CHANGE_PIN: i128 = 0x04;
const SUB_GET_PIN_TOKEN: i128 = 0x05;
const SUB_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS: i128 = 0x09;

/// pinUvAuthToken permissions.
pub(crate) const PERM_MAKE_CREDENTIAL: u8 = 0x01;
pub(crate) const PERM_GET_ASSERTION: u8 = 0x02;
pub(crate) const PERM_CREDENTIAL_MGMT: u8 = 0x04;
pub(crate) const PERM_BIO_ENROLLMENT: u8 = 0x08;
pub(crate) const PERM_LARGE_BLOB_WRITE: u8 = 0x10;
pub(crate) const PERM_AUTHENTICATOR_CONFIG: u8 = 0x20;
const PERM_ALL_SUPPORTED: u8 = PERM_MAKE_CREDENTIAL
    | PERM_GET_ASSERTION
    | PERM_CREDENTIAL_MGMT
    | PERM_LARGE_BLOB_WRITE
    | PERM_AUTHENTICATOR_CONFIG;

struct PinToken {
    key: Zeroizing<[u8; 32]>,
    permissions: u8,
    /// RP the token is bound to, set at issue or by its first makeCredential / getAssertion.
    rp_id: Option<String>,
    issued: Instant,
    used: bool,
}

impl PinToken {
    fn expired(&self) -> bool {
        let age = self.issued.elapsed();
        age >= MAX_USAGE_PERIOD || (!self.used && age >= INITIAL_USAGE_LIMIT)
    }
}

/// PIN state that only lives until the process exits ("power cycle").
pub(crate) struct PinRuntime {
    key_agreement: SecretKey,
    token: Option<PinToken>,
    consecutive_failures: u8,
}

impl PinRuntime {
    pub(crate) fn new() -> Self {
        PinRuntime { key_agreement: SecretKey::random(&mut OsRng), token: None, consecutive_failures: 0 }
    }

    pub(crate) fn reset(&mut self) {
        *self = PinRuntime::new();
    }

    /// Shared secret with a platform's key-agreement key (a COSE_Key).
    pub(super) fn shared_secret(&self, protocol: PinProtocol, peer: &Value) -> Result<Zeroizing<Vec<u8>>, Status> {
        Ok(protocol.shared_secret(&self.key_agreement, &parse_cose_key(peer)?))
    }

    /// Whether the current token is bound to an RP.
    pub(super) fn token_rp_bound(&self) -> bool {
        self.token.as_ref().is_some_and(|t| t.rp_id.is_some())
    }

    /// Whether the current token may act on credentials of the RP with this ID hash.
    pub(super) fn token_allows_rp(&self, rp_id_hash: &[u8; 32]) -> bool {
        match self.token.as_ref().and_then(|t| t.rp_id.as_deref()) {
            Some(rp) => crypto::sha256(rp.as_bytes()) == *rp_id_hash,
            None => true,
        }
    }

    /// After a makeCredential / getAssertion, the token keeps only its large-blob-write
    /// permission (so the platform can store a blob for the credential just used).
    pub(super) fn consume_mc_ga_permissions(&mut self) {
        if let Some(t) = &mut self.token {
            t.permissions &= PERM_LARGE_BLOB_WRITE;
        }
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
            let power_cycle_needed = auth.pin.consecutive_failures >= MAX_CONSECUTIVE_FAILURES;
            Ok(Some(map(vec![(int(0x03), int(retries.into())), (int(0x04), Value::Bool(power_cycle_needed))])))
        }
        SUB_GET_KEY_AGREEMENT => {
            protocol()?;
            Ok(Some(map(vec![(int(0x01), cose_key_agreement(&auth.pin.key_agreement))])))
        }
        SUB_SET_PIN => set_pin(auth, protocol()?, &m),
        SUB_CHANGE_PIN => change_pin(auth, protocol()?, &m),
        // The pre-2.1 command: a token for makeCredential and getAssertion only.
        SUB_GET_PIN_TOKEN => {
            if get(&m, 0x09).is_some() || get(&m, 0x0A).is_some() {
                return Err(Status::INVALID_PARAMETER);
            }
            get_token(auth, protocol()?, &m, PERM_MAKE_CREDENTIAL | PERM_GET_ASSERTION, None)
        }
        SUB_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS => {
            let protocol = protocol()?;
            let permissions = u8::try_from(as_int(require(get(&m, 0x09))?)?).map_err(|_| Status::INVALID_PARAMETER)?;
            if permissions == 0 {
                return Err(Status::INVALID_PARAMETER);
            }
            // No built-in biometrics, so no bio enrollment.
            if permissions & !PERM_ALL_SUPPORTED != 0 || permissions & PERM_BIO_ENROLLMENT != 0 {
                return Err(Status::UNAUTHORIZED_PERMISSION);
            }
            let rp_id = get(&m, 0x0A).map(as_text).transpose()?.map(str::to_owned);
            get_token(auth, protocol, &m, permissions, rp_id)
        }
        _ => Err(Status::INVALID_SUBCOMMAND),
    }
}

fn shared_secret(
    auth: &Authenticator,
    protocol: PinProtocol,
    m: &[(Value, Value)],
) -> Result<Zeroizing<Vec<u8>>, Status> {
    auth.pin.shared_secret(protocol, require(get(m, 0x03))?)
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
    let (pin, code_points) = decrypt_new_pin(auth, protocol, &secret, new_pin_enc)?;
    auth.store.set_pin(Some(new_pin_state(&pin, code_points)))?;
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
    let (pin, code_points) = decrypt_new_pin(auth, protocol, &secret, new_pin_enc)?;
    // A forced change must actually change the PIN.
    if state.force_change && pin_hash(&pin) == state.pin_hash {
        return Err(Status::PIN_POLICY_VIOLATION);
    }
    auth.store.set_pin(Some(new_pin_state(&pin, code_points)))?;
    auth.pin.token = None;
    log::info!("PIN changed");
    Ok(None)
}

fn get_token(
    auth: &mut Authenticator,
    protocol: PinProtocol,
    m: &[(Value, Value)],
    permissions: u8,
    rp_id: Option<String>,
) -> CmdResult {
    let secret = shared_secret(auth, protocol, m)?;
    let pin_hash_enc = as_bytes(require(get(m, 0x06))?)?;
    check_pin_hash(auth, protocol, &secret, pin_hash_enc)?;
    if auth.store.pin()?.is_some_and(|p| p.force_change) {
        return Err(Status::PIN_POLICY_VIOLATION);
    }
    let key = Zeroizing::new(random_bytes::<32>());
    let encrypted = protocol.encrypt(&secret, &*key);
    auth.pin.token = Some(PinToken { key, permissions, rp_id, issued: Instant::now(), used: false });
    Ok(Some(map(vec![(int(0x02), bytes(&encrypted))])))
}

fn new_pin_state(pin: &[u8], code_points: u8) -> PinState {
    PinState { pin_hash: pin_hash(pin), retries: MAX_PIN_RETRIES, code_points: Some(code_points), force_change: false }
}

/// Checks an encrypted PIN hash against the stored one, maintaining the retry counters.
/// The persistent counter is decremented *before* comparing, so killing the process
/// mid-check cannot yield a free guess.
fn check_pin_hash(
    auth: &mut Authenticator,
    protocol: PinProtocol,
    secret: &[u8],
    pin_hash_enc: &[u8],
) -> Result<(), Status> {
    let mut state = auth.store.pin()?.ok_or(Status::PIN_NOT_SET)?;
    if state.retries == 0 {
        return Err(Status::PIN_BLOCKED);
    }
    if auth.pin.consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
        return Err(Status::PIN_AUTH_BLOCKED);
    }
    state.retries -= 1;
    auth.store.set_pin(Some(state.clone()))?;

    let matches =
        protocol.decrypt(secret, pin_hash_enc).is_some_and(|h| h.len() == 16 && bool::from(h.ct_eq(&state.pin_hash)));
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

/// Decrypts and validates a new PIN: 64 bytes, zero-padded, UTF-8, at least the
/// configured minimum number of code points. Returns the PIN and its length.
fn decrypt_new_pin(
    auth: &Authenticator,
    protocol: PinProtocol,
    secret: &[u8],
    new_pin_enc: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, u8), Status> {
    let padded = protocol.decrypt(secret, new_pin_enc).ok_or(Status::INVALID_PARAMETER)?;
    if padded.len() != PADDED_PIN_LEN {
        return Err(Status::PIN_POLICY_VIOLATION);
    }
    let len = padded.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    // At least one padding byte is required, so PINs are at most 63 bytes.
    if len == PADDED_PIN_LEN {
        return Err(Status::PIN_POLICY_VIOLATION);
    }
    let min = auth.store.config()?.min_pin_length as usize;
    match std::str::from_utf8(&padded[..len]) {
        Ok(pin) if pin.chars().count() >= min => {
            Ok((Zeroizing::new(padded[..len].to_vec()), pin.chars().count() as u8))
        }
        _ => Err(Status::PIN_POLICY_VIOLATION),
    }
}

fn pin_hash(pin: &[u8]) -> [u8; 16] {
    crypto::sha256(pin)[..16].try_into().unwrap()
}

/// Checks a makeCredential / getAssertion pinUvAuthParam (`pin_auth`) over
/// `client_data_hash`, requiring `permission` and binding the token to `rp_id`.
/// Returns whether the user was verified. An empty `pin_auth` is a client probing
/// whether a PIN is set; it needs a touch and always fails.
#[allow(clippy::too_many_arguments)]
pub(super) fn verify_pin_uv_auth(
    auth: &mut Authenticator,
    pin_auth: Option<&Value>,
    protocol: Option<&Value>,
    client_data_hash: &[u8],
    permission: u8,
    rp_id: &str,
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
    use_pin_token(auth, protocol, client_data_hash, pin_auth, permission, Some(rp_id))?;
    Ok(true)
}

/// Checks that `pin_auth` is the current token's tag over `msg` and that the token has
/// `permission`. With `bind_rp`, the token must be unbound (and is then bound to it) or
/// already bound to it.
pub(super) fn use_pin_token(
    auth: &mut Authenticator,
    protocol: Option<&Value>,
    msg: &[u8],
    pin_auth: &[u8],
    permission: u8,
    bind_rp: Option<&str>,
) -> Result<(), Status> {
    let protocol = PinProtocol::from_id(as_int(require(protocol)?)?).ok_or(Status::INVALID_PARAMETER)?;
    if auth.store.pin()?.is_none() {
        return Err(Status::PIN_NOT_SET);
    }
    if auth.pin.token.as_ref().is_some_and(PinToken::expired) {
        auth.pin.token = None;
    }
    let token = auth.pin.token.as_mut().ok_or(Status::PIN_AUTH_INVALID)?;
    if !protocol.verify(&*token.key, msg, pin_auth) {
        return Err(Status::PIN_AUTH_INVALID);
    }
    if token.permissions & permission == 0 {
        return Err(Status::PIN_AUTH_INVALID);
    }
    if let Some(rp) = bind_rp {
        match &token.rp_id {
            Some(bound) if bound != rp => return Err(Status::PIN_AUTH_INVALID),
            Some(_) => {}
            None => token.rp_id = Some(rp.to_owned()),
        }
    }
    token.used = true;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(age: Duration, used: bool) -> PinToken {
        let issued = Instant::now().checked_sub(age).expect("monotonic clock far enough from boot");
        PinToken { key: Zeroizing::new([0; 32]), permissions: 0, rp_id: None, issued, used }
    }

    #[test]
    fn tokens_expire_when_unused_and_after_max_period() {
        assert!(!token(Duration::from_secs(29), false).expired());
        assert!(token(Duration::from_secs(31), false).expired(), "unused for 30 s");
        assert!(!token(Duration::from_secs(300), true).expired(), "in use");
        assert!(token(Duration::from_secs(601), true).expired(), "10 minutes after issue");
    }
}
