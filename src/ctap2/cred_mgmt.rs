//! authenticatorCredentialManagement (0x0A, and 0x41, the FIDO_2_1_PRE prototype with
//! the same layout): list, delete and rename resident credentials.
//!
//! Requests are authorized by the PIN token from clientPIN getPinToken. CTAP 2.1's
//! permission-scoped tokens are not implemented, so any current PIN token works.

use std::collections::BTreeMap;

use ciborium::Value;

use super::cbor::{self, as_bytes, as_int, as_map, bytes, get, get_text, int, map, require, text};
use super::client_pin::verify_pin_token;
use super::{CmdResult, Status};
use crate::authenticator::Authenticator;
use crate::crypto;
use crate::store::Credential;

/// Resident credential capacity reported to clients and enforced by makeCredential.
pub(crate) const MAX_RESIDENT_CREDENTIALS: usize = 1000;

const SUB_GET_CREDS_METADATA: i128 = 0x01;
const SUB_ENUMERATE_RPS_BEGIN: i128 = 0x02;
const SUB_ENUMERATE_RPS_NEXT: i128 = 0x03;
const SUB_ENUMERATE_CREDS_BEGIN: i128 = 0x04;
const SUB_ENUMERATE_CREDS_NEXT: i128 = 0x05;
const SUB_DELETE_CREDENTIAL: i128 = 0x06;
const SUB_UPDATE_USER_INFORMATION: i128 = 0x07;

/// Items left to return from an enumeration begun by a previous request.
pub(crate) enum Enumeration {
    Rps(Vec<RpEntry>),
    Credentials(Vec<Credential>),
}

pub(crate) struct RpEntry {
    id: String,
    name: Option<String>,
    hash: [u8; 32],
}

pub(super) fn handle(auth: &mut Authenticator, params: &[u8]) -> CmdResult {
    let m = cbor::decode_map(params)?;
    let sub = as_int(require(get(&m, 0x01))?)?;
    let sub_params = get(&m, 0x02);
    // Any request other than the matching "next" ends an enumeration.
    let state = auth.cred_mgmt.take();

    match sub {
        SUB_ENUMERATE_RPS_NEXT => return next_rp(auth, state),
        SUB_ENUMERATE_CREDS_NEXT => return next_credential(auth, state),
        SUB_GET_CREDS_METADATA
        | SUB_ENUMERATE_RPS_BEGIN
        | SUB_ENUMERATE_CREDS_BEGIN
        | SUB_DELETE_CREDENTIAL
        | SUB_UPDATE_USER_INFORMATION => {}
        _ => return Err(Status::INVALID_SUBCOMMAND),
    }

    // pinUvAuthParam = authenticate(token, subCommand || CBOR(subCommandParams)).
    let pin_auth = as_bytes(get(&m, 0x04).ok_or(Status::PIN_REQUIRED)?)?;
    let mut msg = vec![sub as u8];
    if let Some(p) = sub_params {
        msg.extend(cbor::encode(p));
    }
    verify_pin_token(auth, get(&m, 0x03), &msg, pin_auth)?;

    match sub {
        SUB_GET_CREDS_METADATA => {
            let count = resident_count(auth)?;
            Ok(Some(map(vec![
                (int(0x01), int(count as i64)),
                (int(0x02), int(MAX_RESIDENT_CREDENTIALS.saturating_sub(count) as i64)),
            ])))
        }
        SUB_ENUMERATE_RPS_BEGIN => {
            let mut rps = relying_parties(auth)?;
            if rps.is_empty() {
                return Err(Status::NO_CREDENTIALS);
            }
            let total = rps.len();
            let first = rps.remove(0);
            if !rps.is_empty() {
                auth.cred_mgmt = Some(Enumeration::Rps(rps));
            }
            Ok(Some(rp_response(&first, Some(total))))
        }
        SUB_ENUMERATE_CREDS_BEGIN => {
            let p = as_map(require(sub_params)?)?;
            let rp_id_hash: [u8; 32] =
                as_bytes(require(get(p, 0x01))?)?.try_into().map_err(|_| Status::INVALID_PARAMETER)?;
            let mut creds: Vec<Credential> =
                auth.store.list_by_rp(&rp_id_hash)?.into_iter().filter(|c| c.discoverable).collect();
            if creds.is_empty() {
                return Err(Status::NO_CREDENTIALS);
            }
            let total = creds.len();
            let first = creds.remove(0);
            if !creds.is_empty() {
                auth.cred_mgmt = Some(Enumeration::Credentials(creds));
            }
            Ok(Some(credential_response(&first, Some(total))?))
        }
        SUB_DELETE_CREDENTIAL => {
            let id = credential_id(sub_params)?;
            if !auth.store.delete(id)? {
                return Err(Status::NO_CREDENTIALS);
            }
            log::info!("deleted credential via credential management");
            Ok(None)
        }
        SUB_UPDATE_USER_INFORMATION => {
            let id = credential_id(sub_params)?;
            let user = as_map(require(get(as_map(require(sub_params)?)?, 0x03))?)?;
            let mut cred = auth.store.get(id)?.filter(|c| c.discoverable).ok_or(Status::NO_CREDENTIALS)?;
            if cred.user_id.as_deref() != Some(as_bytes(require(get_text(user, "id"))?)?) {
                return Err(Status::INVALID_PARAMETER);
            }
            // The new entity replaces the old one: omitted fields are removed.
            cred.user_name = cbor::opt_text(user, "name")?;
            cred.user_display_name = cbor::opt_text(user, "displayName")?;
            auth.store.put(cred)?;
            Ok(None)
        }
        _ => unreachable!("checked above"),
    }
}

/// Number of resident credentials stored.
pub(super) fn resident_count(auth: &Authenticator) -> Result<usize, Status> {
    Ok(auth.store.list_all()?.iter().filter(|c| c.discoverable).count())
}

/// RPs with resident credentials, sorted by ID. The name comes from the newest
/// credential that has one.
fn relying_parties(auth: &Authenticator) -> Result<Vec<RpEntry>, Status> {
    let mut creds: Vec<Credential> = auth.store.list_all()?.into_iter().filter(|c| c.discoverable).collect();
    creds.sort_by_key(|c| c.created);
    let mut rps: BTreeMap<String, RpEntry> = BTreeMap::new();
    for c in creds {
        let entry = rps
            .entry(c.rp_id.clone())
            .or_insert_with(|| RpEntry { id: c.rp_id.clone(), name: None, hash: c.rp_id_hash });
        if c.rp_name.is_some() {
            entry.name = c.rp_name.clone();
        }
    }
    Ok(rps.into_values().collect())
}

fn next_rp(auth: &mut Authenticator, state: Option<Enumeration>) -> CmdResult {
    let Some(Enumeration::Rps(mut rest)) = state else { return Err(Status::NOT_ALLOWED) };
    let rp = rest.remove(0);
    if !rest.is_empty() {
        auth.cred_mgmt = Some(Enumeration::Rps(rest));
    }
    Ok(Some(rp_response(&rp, None)))
}

fn next_credential(auth: &mut Authenticator, state: Option<Enumeration>) -> CmdResult {
    let Some(Enumeration::Credentials(mut rest)) = state else { return Err(Status::NOT_ALLOWED) };
    let cred = rest.remove(0);
    if !rest.is_empty() {
        auth.cred_mgmt = Some(Enumeration::Credentials(rest));
    }
    Ok(Some(credential_response(&cred, None)?))
}

fn rp_response(rp: &RpEntry, total: Option<usize>) -> Value {
    let mut entity = vec![(text("id"), text(&rp.id))];
    if let Some(name) = &rp.name {
        entity.push((text("name"), text(name)));
    }
    let mut entries = vec![(int(0x03), map(entity)), (int(0x04), bytes(&rp.hash))];
    if let Some(n) = total {
        entries.push((int(0x05), int(n as i64)));
    }
    map(entries)
}

fn credential_response(cred: &Credential, total: Option<usize>) -> Result<Value, Status> {
    let mut user = vec![(text("id"), bytes(cred.user_id.as_deref().unwrap_or_default()))];
    if let Some(name) = &cred.user_name {
        user.push((text("name"), text(name)));
    }
    if let Some(name) = &cred.user_display_name {
        user.push((text("displayName"), text(name)));
    }
    let mut entries = vec![
        (int(0x06), map(user)),
        (int(0x07), map(vec![(text("id"), bytes(&cred.id)), (text("type"), text("public-key"))])),
        (int(0x08), crypto::cose_public_key(&cred.private_key)?),
        (int(0x0A), int(u8::from(cred.cred_protect).into())),
    ];
    if let Some(n) = total {
        entries.push((int(0x09), int(n as i64)));
    }
    Ok(map(entries))
}

/// The credential ID from `subCommandParams[credentialId]`, a PublicKeyCredentialDescriptor.
fn credential_id(sub_params: Option<&Value>) -> Result<&[u8], Status> {
    let descriptor = as_map(require(get(as_map(require(sub_params)?)?, 0x02))?)?;
    as_bytes(require(get_text(descriptor, "id"))?)
}
