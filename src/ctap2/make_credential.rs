use super::cbor::{self, as_array, as_bool, as_bytes, as_int, as_map, as_text, bytes, get, get_text, int, map, require, text};
use super::client_pin::verify_pin_uv_auth;
use super::hmac_secret;
use super::{CmdResult, Status, FLAG_AT, FLAG_ED, FLAG_UP, FLAG_UV};
use crate::authenticator::{now_millis, Authenticator, RequestCtx};
use crate::crypto::{self, COSE_ALG_ES256};
use crate::presence::{PresenceKind, PresenceRequest};
use crate::store::Credential;

const MAX_USER_ID_LEN: usize = 64;
const CREDENTIAL_ID_LEN: usize = 16;

pub(super) fn handle(auth: &mut Authenticator, params: &[u8], ctx: &RequestCtx) -> CmdResult {
    let m = cbor::decode_map(params)?;
    let client_data_hash = as_bytes(require(get(&m, 0x01))?)?;
    if client_data_hash.len() != 32 {
        return Err(Status::INVALID_PARAMETER);
    }
    let rp = as_map(require(get(&m, 0x02))?)?;
    let rp_id = as_text(require(get_text(rp, "id"))?)?.to_owned();
    let user = as_map(require(get(&m, 0x03))?)?;
    let user_id = as_bytes(require(get_text(user, "id"))?)?.to_vec();
    if user_id.len() > MAX_USER_ID_LEN {
        return Err(Status::INVALID_LENGTH);
    }
    let user_name = cbor::opt_text(user, "name")?;
    let user_display_name = cbor::opt_text(user, "displayName")?;

    let mut es256 = false;
    for p in as_array(require(get(&m, 0x04))?)? {
        let p = as_map(p)?;
        let ty = as_text(require(get_text(p, "type"))?)?;
        let alg = as_int(require(get_text(p, "alg"))?)?;
        es256 |= ty == "public-key" && alg == COSE_ALG_ES256 as i128;
    }
    if !es256 {
        return Err(Status::UNSUPPORTED_ALGORITHM);
    }

    let mut rk = false;
    if let Some(opts) = get(&m, 0x07) {
        for (k, v) in as_map(opts)? {
            match as_text(k)? {
                "rk" => rk = as_bool(v)?,
                "uv" if as_bool(v)? => return Err(Status::UNSUPPORTED_OPTION),
                "up" if !as_bool(v)? => return Err(Status::INVALID_OPTION),
                _ => {}
            }
        }
    }

    let hmac_secret = hmac_secret::requested_at_creation(get(&m, 0x06))?;

    let presence = PresenceRequest {
        kind: PresenceKind::Register,
        rp_id: Some(rp_id.clone()),
        user: user_display_name.clone().or_else(|| user_name.clone()),
    };
    let uv = verify_pin_uv_auth(auth, get(&m, 0x08), get(&m, 0x09), client_data_hash, &presence, ctx)?;
    if !uv && auth.store.pin()?.is_some() {
        return Err(Status::PIN_REQUIRED);
    }

    let rp_id_hash = crypto::sha256(rp_id.as_bytes());
    if let Some(excluded) = get(&m, 0x05) {
        for d in as_array(excluded)? {
            let id = as_bytes(require(get_text(as_map(d)?, "id"))?)?;
            if auth.store.get(id)?.is_some_and(|c| c.rp_id_hash == rp_id_hash) {
                // The user must still touch the key so a site cannot silently probe it.
                auth.require_presence(&presence, ctx)?;
                return Err(Status::CREDENTIAL_EXCLUDED);
            }
        }
    }

    auth.require_presence(&presence, ctx)?;

    let private_key = crypto::generate_private_key();
    let id = crypto::random_bytes::<CREDENTIAL_ID_LEN>().to_vec();
    let cose_key = cbor::encode(&crypto::cose_public_key(&private_key)?);

    let mut auth_data = Vec::with_capacity(37 + 18 + id.len() + cose_key.len());
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(FLAG_UP | FLAG_AT | if uv { FLAG_UV } else { 0 } | if hmac_secret { FLAG_ED } else { 0 });
    auth_data.extend_from_slice(&0u32.to_be_bytes());
    auth_data.extend_from_slice(&auth.aaguid);
    auth_data.extend_from_slice(&(id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(&id);
    auth_data.extend_from_slice(&cose_key);
    if hmac_secret {
        auth_data.extend(cbor::encode(&hmac_secret::creation_output()));
    }

    // Packed self-attestation: signed by the new credential key itself.
    let signature = crypto::sign(&private_key, &[auth_data.as_slice(), client_data_hash].concat())?;

    log::info!(
        "created {} credential for {rp_id} ({})",
        if rk { "discoverable" } else { "non-discoverable" },
        user_name.as_deref().unwrap_or("unnamed user")
    );
    auth.store.put(Credential {
        id,
        rp_id,
        rp_id_hash,
        user_id: Some(user_id),
        user_name,
        user_display_name,
        private_key,
        sign_count: 0,
        discoverable: rk,
        created: now_millis(),
        hmac_secret: hmac_secret.then(hmac_secret::new_cred_random),
    })?;

    Ok(Some(map(vec![
        (int(0x01), text("packed")),
        (int(0x02), bytes(&auth_data)),
        (int(0x03), map(vec![(text("alg"), int(COSE_ALG_ES256)), (text("sig"), bytes(&signature))])),
    ])))
}
