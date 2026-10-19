use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use notify_rust::{Notification, Timeout, Urgency};

use super::{CancelToken, Presence, PresenceProvider, PresenceRequest};

const POLL: Duration = Duration::from_millis(100);

/// Desktop notification with Approve / Deny buttons (freedesktop notifications over D-Bus).
/// Needs a session bus, so run the daemon as the desktop user rather than via sudo.
pub struct NotifyPresence {
    timeout: Duration,
}

impl NotifyPresence {
    pub fn new(timeout: Duration) -> Self {
        NotifyPresence { timeout }
    }
}

impl PresenceProvider for NotifyPresence {
    fn request(&self, req: &PresenceRequest, cancel: &CancelToken) -> Presence {
        let handle = match Notification::new()
            .appname("Virtual FIDO2")
            .summary("Security key request")
            .body(&format!("Allow request to {req}?"))
            .icon("security-high")
            .urgency(Urgency::Critical)
            .action("approve", "Approve")
            .action("deny", "Deny")
            .timeout(Timeout::Milliseconds(self.timeout.as_millis() as u32))
            .show()
        {
            Ok(h) => h,
            Err(e) => {
                log::error!("cannot show notification ({e}); denying request");
                return Presence::Denied;
            }
        };

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            handle.wait_for_action(|action| {
                let _ = tx.send(action == "approve");
            });
        });

        let start = Instant::now();
        loop {
            if cancel.is_cancelled() {
                return Presence::Cancelled;
            }
            match rx.recv_timeout(POLL) {
                Ok(true) => return Presence::Approved,
                // Deny button, or the notification was dismissed / expired.
                Ok(false) | Err(RecvTimeoutError::Disconnected) => {
                    return if start.elapsed() >= self.timeout { Presence::Timeout } else { Presence::Denied };
                }
                Err(RecvTimeoutError::Timeout) if start.elapsed() >= self.timeout => return Presence::Timeout,
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }
}
