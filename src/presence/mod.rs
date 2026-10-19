//! User-presence plugins: the "touch the key" step.
//!
//! A backend implements [`PresenceProvider`]; [`from_name`] picks one by name. To add a
//! backend, write a module implementing the trait and add a match arm in [`from_name`].

mod auto;
#[cfg(feature = "notify")]
mod notify;
mod terminal;

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::error::{Error, Result};

pub use auto::AutoPresence;
#[cfg(feature = "notify")]
pub use notify::NotifyPresence;
pub use terminal::TerminalPresence;

/// Set when the client cancels the request (CTAPHID_CANCEL) or it is superseded.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Approved,
    Denied,
    Timeout,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceKind {
    Register,
    Authenticate,
    Reset,
    /// Choose this key among several (authenticatorSelection).
    Select,
}

#[derive(Debug, Clone)]
pub struct PresenceRequest {
    pub kind: PresenceKind,
    /// Relying party ID; `None` for U2F requests, which only carry its hash.
    pub rp_id: Option<String>,
    pub user: Option<String>,
}

impl fmt::Display for PresenceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let site = self.rp_id.as_deref().unwrap_or("a U2F site");
        match self.kind {
            PresenceKind::Register => write!(f, "register a new credential on {site}")?,
            PresenceKind::Authenticate => write!(f, "sign in to {site}")?,
            PresenceKind::Reset => return write!(f, "RESET the authenticator, deleting all credentials"),
            PresenceKind::Select => return write!(f, "select this security key"),
        }
        if let Some(user) = &self.user {
            write!(f, " as {user}")?;
        }
        Ok(())
    }
}

pub trait PresenceProvider: Send + Sync {
    /// Blocks until the user answers, the provider times out, or `cancel` is set.
    /// Implementations should poll `cancel` at least every ~100 ms.
    fn request(&self, req: &PresenceRequest, cancel: &CancelToken) -> Presence;
}

pub const BACKENDS: &[&str] = &[
    "auto",
    "terminal",
    #[cfg(feature = "notify")]
    "notify",
];

pub fn from_name(name: &str, timeout: Duration) -> Result<Arc<dyn PresenceProvider>> {
    match name {
        "auto" => Ok(Arc::new(AutoPresence)),
        "terminal" => Ok(Arc::new(TerminalPresence::new(timeout))),
        #[cfg(feature = "notify")]
        "notify" => Ok(Arc::new(NotifyPresence::new(timeout))),
        other => Err(Error::Config(format!("unknown presence backend {other:?} (available: {})", BACKENDS.join(", ")))),
    }
}
