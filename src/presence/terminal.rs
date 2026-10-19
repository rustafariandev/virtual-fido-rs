use std::io::BufRead;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::{CancelToken, Presence, PresenceProvider, PresenceRequest};

const POLL: Duration = Duration::from_millis(100);

/// Asks on stderr and reads `y`/`n` from stdin.
pub struct TerminalPresence {
    /// Lines from a background stdin reader. The lock also serialises prompts.
    lines: Mutex<Receiver<String>>,
    timeout: Duration,
}

impl TerminalPresence {
    pub fn new(timeout: Duration) -> Self {
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("stdin".into())
            .spawn(move || {
                for line in std::io::stdin().lock().lines() {
                    let Ok(line) = line else { break };
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            })
            .expect("spawn stdin reader");
        TerminalPresence { lines: Mutex::new(rx), timeout }
    }
}

impl PresenceProvider for TerminalPresence {
    fn request(&self, req: &PresenceRequest, cancel: &CancelToken) -> Presence {
        let lines = self.lines.lock().unwrap_or_else(|e| e.into_inner());
        // Discard anything typed before this prompt.
        while lines.try_recv().is_ok() {}
        eprintln!("\n>>> Security key request: {req}");
        eprint!(">>> Approve? [y/N] ({}s) ", self.timeout.as_secs());

        let start = Instant::now();
        loop {
            if cancel.is_cancelled() {
                eprintln!("\n>>> request cancelled by client");
                return Presence::Cancelled;
            }
            match lines.recv_timeout(POLL) {
                Ok(line) => {
                    let answer = line.trim().to_ascii_lowercase();
                    return if answer == "y" || answer == "yes" {
                        Presence::Approved
                    } else {
                        eprintln!(">>> denied");
                        Presence::Denied
                    };
                }
                Err(RecvTimeoutError::Timeout) if start.elapsed() >= self.timeout => {
                    eprintln!("\n>>> timed out");
                    return Presence::Timeout;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    log::warn!("stdin closed; denying request");
                    return Presence::Denied;
                }
            }
        }
    }
}
