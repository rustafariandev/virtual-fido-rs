use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ctap2::{self, Status};
use crate::error::Result;
use crate::presence::{CancelToken, Presence, PresenceProvider, PresenceRequest};
use crate::store::{AttestationMaterial, CredentialStore};
use crate::{crypto, u2f};

/// Largest CTAP2 message we advertise in getInfo.
pub const MAX_MSG_SIZE: usize = 1200;

/// Default AAGUID identifying this authenticator model.
pub const DEFAULT_AAGUID: [u8; 16] = [
    0x76, 0x66, 0x69, 0x64, 0x6f, 0x2d, 0x4b, 0x9a, 0x8e, 0x3c, 0x51, 0x2b, 0xd4, 0x07, 0xe1, 0x6f,
];

/// KEEPALIVE status codes.
pub const STATUS_PROCESSING: u8 = 1;
pub const STATUS_UPNEEDED: u8 = 2;

/// Per-request context shared with the transport: who is asking, cancellation, and the
/// status to report in keepalives.
#[derive(Debug)]
pub struct RequestCtx {
    pub cid: u32,
    pub cancel: CancelToken,
    status: AtomicU8,
}

impl RequestCtx {
    pub fn new(cid: u32) -> Self {
        RequestCtx { cid, cancel: CancelToken::new(), status: AtomicU8::new(STATUS_PROCESSING) }
    }

    pub fn status(&self) -> u8 {
        self.status.load(Ordering::SeqCst)
    }

    fn set_status(&self, s: u8) {
        self.status.store(s, Ordering::SeqCst);
    }
}

pub struct Authenticator {
    pub(crate) store: Box<dyn CredentialStore>,
    pub(crate) presence: Arc<dyn PresenceProvider>,
    pub(crate) aaguid: [u8; 16],
    pub(crate) pending_assertions: Option<ctap2::Pending>,
    pub(crate) pin: ctap2::PinRuntime,
    pub(crate) cred_mgmt: Option<ctap2::Enumeration>,
    pub(crate) large_blob_write: Option<ctap2::PendingWrite>,
    pub(crate) u2f_presence: Option<u2f::PendingPresence>,
}

impl Authenticator {
    pub fn new(store: Box<dyn CredentialStore>, presence: Arc<dyn PresenceProvider>, aaguid: [u8; 16]) -> Self {
        Authenticator {
            store,
            presence,
            aaguid,
            pending_assertions: None,
            pin: ctap2::PinRuntime::new(),
            cred_mgmt: None,
            large_blob_write: None,
            u2f_presence: None,
        }
    }

    /// Handles a CTAPHID_CBOR request; returns status byte + CBOR response.
    pub fn handle_cbor(&mut self, req: &[u8], ctx: &RequestCtx) -> Vec<u8> {
        if let Some(p) = self.u2f_presence.take() {
            p.cancel.cancel();
        }
        ctap2::dispatch(self, req, ctx)
    }

    /// Handles a CTAPHID_MSG request (U2F APDU); returns response data + status word.
    pub fn handle_u2f(&mut self, apdu: &[u8]) -> Vec<u8> {
        u2f::handle(self, apdu)
    }

    pub(crate) fn require_presence(&self, req: &PresenceRequest, ctx: &RequestCtx) -> std::result::Result<(), Status> {
        ctx.set_status(STATUS_UPNEEDED);
        let result = self.presence.request(req, &ctx.cancel);
        ctx.set_status(STATUS_PROCESSING);
        match result {
            Presence::Approved => Ok(()),
            Presence::Denied => Err(Status::OPERATION_DENIED),
            Presence::Timeout => Err(Status::USER_ACTION_TIMEOUT),
            Presence::Cancelled => Err(Status::KEEPALIVE_CANCEL),
        }
    }

    /// Batch attestation material, generated and stored on first use.
    pub(crate) fn attestation(&mut self) -> Result<AttestationMaterial> {
        if let Some(a) = self.store.attestation()? {
            return Ok(a);
        }
        log::info!("generating attestation certificate");
        let a = crypto::generate_attestation()?;
        self.store.set_attestation(a.clone())?;
        Ok(a)
    }
}

pub(crate) fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
