use std::time::{Duration, Instant};

use ciborium::Value;

use super::cbor::{self, as_array, as_bool, as_bytes, as_map, as_text, bytes, get, get_text, int, map, require, text};
use super::client_pin::verify_pin_uv_auth;
use super::{hmac_secret, large_blobs};
use super::{CmdResult, Status, FLAG_ED, FLAG_UP, FLAG_UV};
use crate::authenticator::{Authenticator, RequestCtx};
use crate::crypto;
use crate::presence::{PresenceKind, PresenceRequest};
use crate::store::Credential;

/// getNextAssertion state is only valid for this long after getAssertion.
const NEXT_ASSERTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Remaining credentials from a getAssertion that matched several resident keys.
pub(crate) struct Pending {
    cid: u32,
    credentials: Vec<Credential>,
    rp_id_hash: [u8; 32],
    client_data_hash: Vec<u8>,
    flags: u8,
    extensions: Extensions,
    started: Instant,
}

/// Extensions requested by getAssertion; they apply to every credential returned.
struct Extensions {
    hmac_secret: Option<hmac_secret::Request>,
    large_blob_key: bool,
}

pub(super) fn handle(auth: &mut Authenticator, params: &[u8], ctx: &RequestCtx) -> CmdResult {
    let m = cbor::decode_map(params)?;
    let rp_id = as_text(require(get(&m, 0x01))?)?.to_owned();
    let client_data_hash = as_bytes(require(get(&m, 0x02))?)?.to_vec();
    if client_data_hash.len() != 32 {
        return Err(Status::INVALID_PARAMETER);
    }

    let mut up = true;
    if let Some(opts) = get(&m, 0x05) {
        for (k, v) in as_map(opts)? {
            match as_text(k)? {
                "up" => up = as_bool(v)?,
                "uv" if as_bool(v)? => return Err(Status::UNSUPPORTED_OPTION),
                "rk" => return Err(Status::UNSUPPORTED_OPTION),
                _ => {}
            }
        }
    }

    // User verification comes first: credProtect decides which credentials are visible.
    let mut presence = PresenceRequest { kind: PresenceKind::Authenticate, rp_id: Some(rp_id.clone()), user: None };
    let uv = verify_pin_uv_auth(auth, get(&m, 0x06), get(&m, 0x07), &client_data_hash, &presence, ctx)?;
    let extensions = Extensions {
        hmac_secret: hmac_secret::parse_request(auth, get(&m, 0x04))?,
        large_blob_key: large_blobs::requested(get(&m, 0x04))?,
    };

    let rp_id_hash = crypto::sha256(rp_id.as_bytes());
    let allow_list = match get(&m, 0x03) {
        Some(v) => as_array(v)?,
        None => &[],
    };
    let mut creds = Vec::new();
    for d in allow_list {
        let id = as_bytes(require(get_text(as_map(d)?, "id"))?)?;
        if let Some(c) = auth.store.get(id)?.filter(|c| c.rp_id_hash == rp_id_hash && c.cred_protect.allows(uv, true)) {
            creds.push(c);
            break;
        }
    }
    let discovering = allow_list.is_empty();
    if discovering {
        creds = auth
            .store
            .list_by_rp(&rp_id_hash)?
            .into_iter()
            .filter(|c| c.discoverable && c.cred_protect.allows(uv, false))
            .collect();
    }

    if let [c] = creds.as_slice() {
        presence.user = c.user_display_name.clone().or_else(|| c.user_name.clone());
    }
    if creds.is_empty() {
        return Err(Status::NO_CREDENTIALS);
    }
    if up {
        auth.require_presence(&presence, ctx)?;
    }
    let flags = if up { FLAG_UP } else { 0 } | if uv { FLAG_UV } else { 0 };

    let first = creds.remove(0);
    let total = creds.len() + 1;
    let response = assertion(
        auth,
        &first,
        &rp_id_hash,
        &client_data_hash,
        flags,
        &extensions,
        (discovering && total > 1).then_some(total),
    )?;
    if discovering && !creds.is_empty() {
        auth.pending_assertions = Some(Pending {
            cid: ctx.cid,
            credentials: creds,
            rp_id_hash,
            client_data_hash,
            flags,
            extensions,
            started: Instant::now(),
        });
    }
    log::info!("signed assertion for {rp_id}");
    Ok(Some(response))
}

pub(super) fn next(auth: &mut Authenticator, ctx: &RequestCtx) -> CmdResult {
    let mut p = auth.pending_assertions.take().ok_or(Status::NOT_ALLOWED)?;
    if p.cid != ctx.cid || p.started.elapsed() > NEXT_ASSERTION_TIMEOUT || p.credentials.is_empty() {
        return Err(Status::NOT_ALLOWED);
    }
    let cred = p.credentials.remove(0);
    let response = assertion(auth, &cred, &p.rp_id_hash, &p.client_data_hash, p.flags, &p.extensions, None)?;
    if !p.credentials.is_empty() {
        auth.pending_assertions = Some(p);
    }
    Ok(Some(response))
}

fn assertion(
    auth: &mut Authenticator,
    cred: &Credential,
    rp_id_hash: &[u8; 32],
    client_data_hash: &[u8],
    flags: u8,
    requested: &Extensions,
    number_of_credentials: Option<usize>,
) -> Result<Value, Status> {
    let extensions = requested.hmac_secret.as_ref().and_then(|h| h.output(cred, flags & FLAG_UV != 0));
    let counter = auth.store.increment_counter(&cred.id)?;
    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(rp_id_hash);
    auth_data.push(flags | if extensions.is_some() { FLAG_ED } else { 0 });
    auth_data.extend_from_slice(&counter.to_be_bytes());
    if let Some(ext) = &extensions {
        auth_data.extend(cbor::encode(ext));
    }
    let signature = crypto::sign(&cred.private_key, &[auth_data.as_slice(), client_data_hash].concat())?;

    let mut entries = vec![
        (int(0x01), map(vec![(text("id"), bytes(&cred.id)), (text("type"), text("public-key"))])),
        (int(0x02), bytes(&auth_data)),
        (int(0x03), bytes(&signature)),
    ];
    if let (true, Some(user_id)) = (cred.discoverable, &cred.user_id) {
        let mut user = vec![(text("id"), bytes(user_id))];
        if let Some(name) = &cred.user_name {
            user.push((text("name"), text(name)));
        }
        if let Some(name) = &cred.user_display_name {
            user.push((text("displayName"), text(name)));
        }
        entries.push((int(0x04), map(user)));
    }
    if let Some(n) = number_of_credentials {
        entries.push((int(0x05), int(n as i64)));
    }
    if let (true, Some(key)) = (requested.large_blob_key, &cred.large_blob_key) {
        entries.push((int(0x07), bytes(key)));
    }
    Ok(map(entries))
}
