use super::{CancelToken, Presence, PresenceProvider, PresenceRequest};

/// Approves every request immediately. Convenient for testing; not for real use.
pub struct AutoPresence;

impl PresenceProvider for AutoPresence {
    fn request(&self, req: &PresenceRequest, _cancel: &CancelToken) -> Presence {
        log::info!("auto-approving request to {req}");
        Presence::Approved
    }
}
