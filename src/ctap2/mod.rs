//! CTAP2 command processing (CTAPHID_CBOR payloads).

pub mod cbor;
mod client_pin;
mod cred_protect;
mod get_assertion;
mod get_info;
mod hmac_secret;
mod make_credential;
pub mod pin_protocol;

use ciborium::Value;

use crate::authenticator::{Authenticator, RequestCtx};
use crate::presence::{PresenceKind, PresenceRequest};

pub(crate) use client_pin::PinRuntime;
pub(crate) use get_assertion::Pending;

/// CTAP2 status code, the first byte of every response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status(pub u8);

impl Status {
    pub const OK: Status = Status(0x00);
    pub const INVALID_COMMAND: Status = Status(0x01);
    pub const INVALID_PARAMETER: Status = Status(0x02);
    pub const INVALID_LENGTH: Status = Status(0x03);
    pub const CBOR_UNEXPECTED_TYPE: Status = Status(0x11);
    pub const INVALID_CBOR: Status = Status(0x12);
    pub const MISSING_PARAMETER: Status = Status(0x14);
    pub const CREDENTIAL_EXCLUDED: Status = Status(0x19);
    pub const UNSUPPORTED_ALGORITHM: Status = Status(0x26);
    pub const OPERATION_DENIED: Status = Status(0x27);
    pub const UNSUPPORTED_OPTION: Status = Status(0x2B);
    pub const INVALID_OPTION: Status = Status(0x2C);
    pub const KEEPALIVE_CANCEL: Status = Status(0x2D);
    pub const NO_CREDENTIALS: Status = Status(0x2E);
    pub const USER_ACTION_TIMEOUT: Status = Status(0x2F);
    pub const NOT_ALLOWED: Status = Status(0x30);
    pub const PIN_INVALID: Status = Status(0x31);
    pub const PIN_BLOCKED: Status = Status(0x32);
    pub const PIN_AUTH_INVALID: Status = Status(0x33);
    pub const PIN_AUTH_BLOCKED: Status = Status(0x34);
    pub const PIN_NOT_SET: Status = Status(0x35);
    pub const PIN_REQUIRED: Status = Status(0x36);
    pub const PIN_POLICY_VIOLATION: Status = Status(0x37);
    pub const INVALID_SUBCOMMAND: Status = Status(0x3E);
    pub const OTHER: Status = Status(0x7F);
}

impl From<crate::Error> for Status {
    fn from(e: crate::Error) -> Self {
        log::error!("internal error: {e}");
        Status::OTHER
    }
}

pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_GET_ASSERTION: u8 = 0x02;
pub const CMD_GET_INFO: u8 = 0x04;
pub const CMD_CLIENT_PIN: u8 = 0x06;
pub const CMD_RESET: u8 = 0x07;
pub const CMD_GET_NEXT_ASSERTION: u8 = 0x08;

/// authenticatorData flags.
pub(crate) const FLAG_UP: u8 = 0x01;
pub(crate) const FLAG_UV: u8 = 0x04;
pub(crate) const FLAG_AT: u8 = 0x40;
pub(crate) const FLAG_ED: u8 = 0x80;

type CmdResult = Result<Option<Value>, Status>;

pub(crate) fn dispatch(auth: &mut Authenticator, req: &[u8], ctx: &RequestCtx) -> Vec<u8> {
    let Some((&cmd, params)) = req.split_first() else {
        return vec![Status::INVALID_LENGTH.0];
    };
    if cmd != CMD_GET_NEXT_ASSERTION {
        auth.pending_assertions = None;
    }
    let result = match cmd {
        CMD_MAKE_CREDENTIAL => make_credential::handle(auth, params, ctx),
        CMD_GET_ASSERTION => get_assertion::handle(auth, params, ctx),
        CMD_GET_INFO => get_info::handle(auth),
        CMD_CLIENT_PIN => client_pin::handle(auth, params),
        CMD_RESET => reset(auth, ctx),
        CMD_GET_NEXT_ASSERTION => get_assertion::next(auth, ctx),
        _ => Err(Status::INVALID_COMMAND),
    };
    match result {
        Ok(Some(v)) => {
            let mut out = vec![Status::OK.0];
            out.extend(cbor::encode(&v));
            out
        }
        Ok(None) => vec![Status::OK.0],
        Err(s) => {
            log::debug!("CTAP2 command {cmd:#04x} failed with status {:#04x}", s.0);
            vec![s.0]
        }
    }
}

fn reset(auth: &mut Authenticator, ctx: &RequestCtx) -> CmdResult {
    auth.require_presence(&PresenceRequest { kind: PresenceKind::Reset, rp_id: None, user: None }, ctx)?;
    auth.store.reset()?;
    auth.pin.reset();
    log::warn!("authenticator reset: all credentials deleted");
    Ok(None)
}
