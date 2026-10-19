//! FIDO U2F (CTAP1) raw messages carried in CTAPHID_MSG.
//!
//! U2F has no keepalives: the client polls, and the key answers
//! CONDITIONS_NOT_SATISFIED until the user has approved. So presence is requested in
//! the background and the result picked up by a later poll.

use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Duration;

use crate::authenticator::{now_millis, Authenticator};
use crate::crypto;
use crate::presence::{CancelToken, Presence, PresenceKind, PresenceRequest};
use crate::store::Credential;

pub const SW_NO_ERROR: u16 = 0x9000;
pub const SW_WRONG_LENGTH: u16 = 0x6700;
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
pub const SW_WRONG_DATA: u16 = 0x6A80;
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
pub const SW_CLA_NOT_SUPPORTED: u16 = 0x6E00;

pub const INS_REGISTER: u8 = 0x01;
pub const INS_AUTHENTICATE: u8 = 0x02;
pub const INS_VERSION: u8 = 0x03;

pub const AUTH_ENFORCE: u8 = 0x03;
pub const AUTH_CHECK_ONLY: u8 = 0x07;
pub const AUTH_DONT_ENFORCE: u8 = 0x08;

const KEY_HANDLE_LEN: usize = 16;
/// How long a poll waits for a fast presence answer (e.g. auto-approve) before returning.
const FAST_PATH: Duration = Duration::from_millis(50);

/// A presence prompt running in the background, keyed by what it was for.
pub(crate) struct PendingPresence {
    kind: PresenceKind,
    app: [u8; 32],
    result: Receiver<Presence>,
    pub(crate) cancel: CancelToken,
}

pub(crate) fn handle(auth: &mut Authenticator, apdu: &[u8]) -> Vec<u8> {
    let (mut data, sw) = match process(auth, apdu) {
        Ok(data) => (data, SW_NO_ERROR),
        Err(sw) => (Vec::new(), sw),
    };
    data.extend_from_slice(&sw.to_be_bytes());
    data
}

/// Splits an APDU (short or extended length) into header fields and command data.
fn parse(apdu: &[u8]) -> Result<(u8, u8, u8, &[u8]), u16> {
    if apdu.len() < 4 {
        return Err(SW_WRONG_LENGTH);
    }
    let (cla, ins, p1) = (apdu[0], apdu[1], apdu[2]);
    let rest = &apdu[4..];
    let data = match rest {
        [] | [_] => &[][..], // no data, or only Le
        [0, hi, lo, body @ ..] => {
            let lc = u16::from_be_bytes([*hi, *lo]) as usize;
            body.get(..lc).ok_or(SW_WRONG_LENGTH)?
        }
        [lc, body @ ..] => body.get(..*lc as usize).ok_or(SW_WRONG_LENGTH)?,
    };
    Ok((cla, ins, p1, data))
}

fn process(auth: &mut Authenticator, apdu: &[u8]) -> Result<Vec<u8>, u16> {
    let (cla, ins, p1, data) = parse(apdu)?;
    if cla != 0 {
        return Err(SW_CLA_NOT_SUPPORTED);
    }
    match ins {
        INS_REGISTER => register(auth, data),
        INS_AUTHENTICATE => authenticate(auth, p1, data),
        INS_VERSION => Ok(b"U2F_V2".to_vec()),
        _ => Err(SW_INS_NOT_SUPPORTED),
    }
}

fn internal(e: crate::Error) -> u16 {
    log::error!("internal error: {e}");
    SW_WRONG_DATA
}

fn register(auth: &mut Authenticator, data: &[u8]) -> Result<Vec<u8>, u16> {
    if data.len() != 64 {
        return Err(SW_WRONG_LENGTH);
    }
    let (challenge, app) = data.split_at(32);
    let app: [u8; 32] = app.try_into().unwrap();
    check_presence(auth, PresenceKind::Register, app)?;

    let private_key = crypto::generate_private_key();
    let public_key = crypto::public_key_uncompressed(&private_key).map_err(internal)?;
    let key_handle = crypto::random_bytes::<KEY_HANDLE_LEN>().to_vec();
    let attestation = auth.attestation().map_err(internal)?;

    let signed = [&[0x00][..], &app, challenge, &key_handle, &public_key].concat();
    let signature = crypto::sign(&attestation.private_key, &signed).map_err(internal)?;

    auth.store
        .put(Credential {
            id: key_handle.clone(),
            rp_id: String::new(),
            rp_id_hash: app,
            user_id: None,
            user_name: None,
            user_display_name: None,
            private_key,
            sign_count: 0,
            discoverable: false,
            created: now_millis(),
            hmac_secret: None,
        })
        .map_err(internal)?;
    log::info!("registered U2F credential");

    let mut out = vec![0x05];
    out.extend_from_slice(&public_key);
    out.push(key_handle.len() as u8);
    out.extend_from_slice(&key_handle);
    out.extend_from_slice(&attestation.certificate);
    out.extend_from_slice(&signature);
    Ok(out)
}

fn authenticate(auth: &mut Authenticator, mode: u8, data: &[u8]) -> Result<Vec<u8>, u16> {
    if data.len() < 65 || data.len() != 65 + data[64] as usize {
        return Err(SW_WRONG_LENGTH);
    }
    let challenge = &data[..32];
    let app: [u8; 32] = data[32..64].try_into().unwrap();
    let key_handle = &data[65..];
    let cred = auth
        .store
        .get(key_handle)
        .map_err(internal)?
        .filter(|c| c.rp_id_hash == app)
        .ok_or(SW_WRONG_DATA)?;

    let flags = match mode {
        AUTH_CHECK_ONLY => return Err(SW_CONDITIONS_NOT_SATISFIED),
        AUTH_ENFORCE => {
            check_presence(auth, PresenceKind::Authenticate, app)?;
            0x01
        }
        AUTH_DONT_ENFORCE => 0x00,
        _ => return Err(SW_WRONG_DATA),
    };
    let counter = auth.store.increment_counter(&cred.id).map_err(internal)?;
    let counter = counter.to_be_bytes();
    let signed = [&app[..], &[flags], &counter, challenge].concat();
    let signature = crypto::sign(&cred.private_key, &signed).map_err(internal)?;
    log::info!("signed U2F authentication");

    let mut out = vec![flags];
    out.extend_from_slice(&counter);
    out.extend_from_slice(&signature);
    Ok(out)
}

/// Returns Ok once the user has approved `kind` for `app`; otherwise starts (or keeps
/// waiting on) a background prompt and returns CONDITIONS_NOT_SATISFIED.
fn check_presence(auth: &mut Authenticator, kind: PresenceKind, app: [u8; 32]) -> Result<(), u16> {
    if let Some(p) = &auth.u2f_presence {
        if p.kind == kind && p.app == app {
            return match p.result.try_recv() {
                Err(TryRecvError::Empty) => Err(SW_CONDITIONS_NOT_SATISFIED),
                Ok(Presence::Approved) => {
                    auth.u2f_presence = None;
                    Ok(())
                }
                Ok(_) | Err(TryRecvError::Disconnected) => {
                    auth.u2f_presence = None;
                    Err(SW_CONDITIONS_NOT_SATISFIED)
                }
            };
        }
    }
    if let Some(old) = auth.u2f_presence.take() {
        old.cancel.cancel();
    }

    let (tx, rx) = mpsc::channel();
    let cancel = CancelToken::new();
    let provider = auth.presence.clone();
    let req = PresenceRequest { kind, rp_id: None, user: None };
    let thread_cancel = cancel.clone();
    std::thread::spawn(move || {
        let _ = tx.send(provider.request(&req, &thread_cancel));
    });
    match rx.recv_timeout(FAST_PATH) {
        Ok(Presence::Approved) => Ok(()),
        Ok(_) => Err(SW_CONDITIONS_NOT_SATISFIED),
        Err(_) => {
            auth.u2f_presence = Some(PendingPresence { kind, app, result: rx, cancel });
            Err(SW_CONDITIONS_NOT_SATISFIED)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_short_and_extended_apdus() {
        assert_eq!(parse(&[0, 3, 0, 0]).unwrap(), (0, 3, 0, &[][..]));
        assert_eq!(parse(&[0, 3, 0, 0, 0]).unwrap().3, &[][..]);
        assert_eq!(parse(&[0, 1, 0, 0, 2, 9, 8]).unwrap().3, &[9, 8][..]);
        assert_eq!(parse(&[0, 1, 0, 0, 0, 0, 2, 9, 8, 0, 0]).unwrap().3, &[9, 8][..]);
        assert_eq!(parse(&[0, 1, 0, 0, 3, 9]), Err(SW_WRONG_LENGTH));
        assert_eq!(parse(&[0, 1]), Err(SW_WRONG_LENGTH));
    }
}
