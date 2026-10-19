//! Runs the authenticator over stdin/stdout instead of /dev/uhid: raw 64-byte
//! CTAPHID reports in on stdin, out on stdout. Memory store, auto-approved presence.
//! Lets client libraries be tested without root; see scripts/interop_test.py.

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

use virtual_fido::authenticator::DEFAULT_AAGUID;
use virtual_fido::ctaphid::{ReportSink, Server, REPORT_SIZE};
use virtual_fido::presence::AutoPresence;
use virtual_fido::store::MemoryStore;
use virtual_fido::Authenticator;

struct Stdout(Mutex<io::Stdout>);

impl ReportSink for Stdout {
    fn send_report(&self, report: &[u8; REPORT_SIZE]) -> io::Result<()> {
        let mut out = self.0.lock().unwrap();
        out.write_all(report)?;
        out.flush()
    }
}

fn main() -> io::Result<()> {
    let auth = Authenticator::new(Box::new(MemoryStore::default()), Arc::new(AutoPresence), DEFAULT_AAGUID);
    let mut server = Server::new(Arc::new(Stdout(Mutex::new(io::stdout()))), auth);
    let mut stdin = io::stdin().lock();
    let mut report = [0u8; REPORT_SIZE];
    loop {
        match stdin.read_exact(&mut report) {
            Ok(()) => server.handle_report(&report),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}
