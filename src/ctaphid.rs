//! CTAPHID: the framing protocol FIDO authenticators speak over 64-byte HID reports.
//!
//! Requests are reassembled here and handed to the [`Authenticator`] on a worker thread,
//! so this side can keep sending KEEPALIVEs and accept CANCEL while a request waits for
//! the user.

use std::collections::HashSet;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::authenticator::{Authenticator, RequestCtx};

pub const REPORT_SIZE: usize = 64;
const INIT_DATA: usize = REPORT_SIZE - 7;
const CONT_DATA: usize = REPORT_SIZE - 5;
/// Largest message expressible: one init packet plus 128 continuation packets.
pub const MAX_MESSAGE: usize = INIT_DATA + 128 * CONT_DATA;

pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;

pub const CMD_PING: u8 = 0x01;
pub const CMD_MSG: u8 = 0x03;
pub const CMD_LOCK: u8 = 0x04;
pub const CMD_INIT: u8 = 0x06;
pub const CMD_WINK: u8 = 0x08;
pub const CMD_CBOR: u8 = 0x10;
pub const CMD_CANCEL: u8 = 0x11;
pub const CMD_KEEPALIVE: u8 = 0x3B;
pub const CMD_ERROR: u8 = 0x3F;

pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_SEQ: u8 = 0x04;
pub const ERR_MSG_TIMEOUT: u8 = 0x05;
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
pub const ERR_INVALID_CHANNEL: u8 = 0x0B;

const CAPABILITY_WINK: u8 = 0x01;
const CAPABILITY_CBOR: u8 = 0x04;

const PROTOCOL_VERSION: u8 = 2;
const DEVICE_VERSION: [u8; 3] = [0, 1, 0];

const MESSAGE_TIMEOUT: Duration = Duration::from_millis(500);
const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(100);

/// Where outgoing input reports go: the UHID device, or a test harness.
pub trait ReportSink: Send + Sync + 'static {
    fn send_report(&self, report: &[u8; REPORT_SIZE]) -> io::Result<()>;
}

/// Fragments `data` into CTAPHID packets.
pub fn send_message(sink: &dyn ReportSink, cid: u32, cmd: u8, data: &[u8]) -> io::Result<()> {
    let mut pkt = [0u8; REPORT_SIZE];
    pkt[..4].copy_from_slice(&cid.to_be_bytes());
    pkt[4] = cmd | 0x80;
    pkt[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
    let n = data.len().min(INIT_DATA);
    pkt[7..7 + n].copy_from_slice(&data[..n]);
    sink.send_report(&pkt)?;

    for (seq, chunk) in data[n..].chunks(CONT_DATA).enumerate() {
        let mut pkt = [0u8; REPORT_SIZE];
        pkt[..4].copy_from_slice(&cid.to_be_bytes());
        pkt[4] = seq as u8;
        pkt[5..5 + chunk.len()].copy_from_slice(chunk);
        sink.send_report(&pkt)?;
    }
    Ok(())
}

/// A message being reassembled from continuation packets.
struct Partial {
    cid: u32,
    cmd: u8,
    len: usize,
    data: Vec<u8>,
    next_seq: u8,
    started: Instant,
}

/// A request running on a worker thread.
struct Job {
    ctx: Arc<RequestCtx>,
    /// Set (under the lock) just before the response is sent, so no keepalive can follow it.
    done: Mutex<bool>,
}

impl Job {
    fn is_done(&self) -> bool {
        *self.done.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub struct Server {
    sink: Arc<dyn ReportSink>,
    auth: Arc<Mutex<Authenticator>>,
    channels: HashSet<u32>,
    next_cid: u32,
    partial: Option<Partial>,
    busy: Option<Arc<Job>>,
}

impl Server {
    pub fn new(sink: Arc<dyn ReportSink>, auth: Authenticator) -> Self {
        Server {
            sink,
            auth: Arc::new(Mutex::new(auth)),
            channels: HashSet::new(),
            next_cid: 1,
            partial: None,
            busy: None,
        }
    }

    /// Processes one output report from the host.
    pub fn handle_report(&mut self, report: &[u8]) {
        let mut pkt = [0u8; REPORT_SIZE];
        let n = report.len().min(REPORT_SIZE);
        pkt[..n].copy_from_slice(&report[..n]);

        if self.partial.as_ref().is_some_and(|p| p.started.elapsed() > MESSAGE_TIMEOUT) {
            let p = self.partial.take().unwrap();
            self.error(p.cid, ERR_MSG_TIMEOUT);
        }

        let cid = u32::from_be_bytes(pkt[..4].try_into().unwrap());
        if pkt[4] & 0x80 != 0 {
            self.handle_init_packet(cid, &pkt);
        } else {
            self.handle_cont_packet(cid, &pkt);
        }
    }

    fn handle_init_packet(&mut self, cid: u32, pkt: &[u8; REPORT_SIZE]) {
        let cmd = pkt[4] & 0x7F;
        let len = u16::from_be_bytes([pkt[5], pkt[6]]) as usize;

        if cmd == CMD_CANCEL {
            if let Some(job) = self.busy.as_ref().filter(|j| j.ctx.cid == cid) {
                log::debug!("cancel on channel {cid:#010x}");
                job.ctx.cancel.cancel();
            }
            return;
        }
        if let Some(p) = &self.partial {
            if p.cid != cid {
                return self.error(cid, ERR_CHANNEL_BUSY);
            }
            // A new init packet on the same channel abandons the old message.
            self.partial = None;
        }
        if len > MAX_MESSAGE {
            return self.error(cid, ERR_INVALID_LEN);
        }

        let n = len.min(INIT_DATA);
        let partial = Partial { cid, cmd, len, data: pkt[7..7 + n].to_vec(), next_seq: 0, started: Instant::now() };
        if partial.data.len() == len {
            self.dispatch(cid, cmd, partial.data);
        } else {
            self.partial = Some(partial);
        }
    }

    fn handle_cont_packet(&mut self, cid: u32, pkt: &[u8; REPORT_SIZE]) {
        // Stray continuation packets are ignored, as the spec requires.
        let Some(p) = self.partial.as_mut().filter(|p| p.cid == cid) else { return };
        if pkt[4] != p.next_seq {
            self.partial = None;
            return self.error(cid, ERR_INVALID_SEQ);
        }
        p.next_seq += 1;
        let n = (p.len - p.data.len()).min(CONT_DATA);
        p.data.extend_from_slice(&pkt[5..5 + n]);
        if p.data.len() == p.len {
            let p = self.partial.take().unwrap();
            self.dispatch(p.cid, p.cmd, p.data);
        }
    }

    fn dispatch(&mut self, cid: u32, cmd: u8, data: Vec<u8>) {
        if self.busy.as_ref().is_some_and(|j| j.is_done()) {
            self.busy = None;
        }
        if cid == 0 {
            return self.error(cid, ERR_INVALID_CHANNEL);
        }
        if cmd == CMD_INIT {
            return self.init(cid, &data);
        }
        if cid == BROADCAST_CID || !self.channels.contains(&cid) {
            return self.error(cid, ERR_INVALID_CHANNEL);
        }
        if self.busy.is_some() {
            return self.error(cid, ERR_CHANNEL_BUSY);
        }
        match cmd {
            CMD_PING => self.reply(cid, CMD_PING, &data),
            CMD_WINK => {
                log::info!("*wink*");
                self.reply(cid, CMD_WINK, &[]);
            }
            CMD_MSG | CMD_CBOR => self.spawn_job(cid, cmd, data),
            _ => self.error(cid, ERR_INVALID_CMD),
        }
    }

    fn init(&mut self, cid: u32, nonce: &[u8]) {
        if nonce.len() != 8 {
            return self.error(cid, ERR_INVALID_LEN);
        }
        let new_cid = if cid == BROADCAST_CID {
            self.allocate_channel()
        } else {
            // Resynchronise an existing channel, aborting whatever it was doing.
            if let Some(job) = self.busy.as_ref().filter(|j| j.ctx.cid == cid) {
                job.ctx.cancel.cancel();
            }
            cid
        };
        let mut resp = Vec::with_capacity(17);
        resp.extend_from_slice(nonce);
        resp.extend_from_slice(&new_cid.to_be_bytes());
        resp.push(PROTOCOL_VERSION);
        resp.extend_from_slice(&DEVICE_VERSION);
        resp.push(CAPABILITY_WINK | CAPABILITY_CBOR);
        log::debug!("INIT on {cid:#010x} -> channel {new_cid:#010x}");
        self.reply(cid, CMD_INIT, &resp);
    }

    fn allocate_channel(&mut self) -> u32 {
        loop {
            let cid = self.next_cid;
            self.next_cid = self.next_cid.wrapping_add(1);
            if cid != 0 && cid != BROADCAST_CID && self.channels.insert(cid) {
                return cid;
            }
        }
    }

    fn spawn_job(&mut self, cid: u32, cmd: u8, data: Vec<u8>) {
        let job = Arc::new(Job { ctx: Arc::new(RequestCtx::new(cid)), done: Mutex::new(false) });
        self.busy = Some(job.clone());

        if cmd == CMD_CBOR {
            let (job, sink) = (job.clone(), self.sink.clone());
            std::thread::spawn(move || loop {
                std::thread::sleep(KEEPALIVE_INTERVAL);
                let done = job.done.lock().unwrap_or_else(|e| e.into_inner());
                if *done {
                    break;
                }
                let _ = send_message(&*sink, cid, CMD_KEEPALIVE, &[job.ctx.status()]);
            });
        }

        let (auth, sink) = (self.auth.clone(), self.sink.clone());
        std::thread::spawn(move || {
            let response = {
                let mut auth = auth.lock().unwrap_or_else(|e| e.into_inner());
                if cmd == CMD_CBOR {
                    auth.handle_cbor(&data, &job.ctx)
                } else {
                    auth.handle_u2f(&data)
                }
            };
            let mut done = job.done.lock().unwrap_or_else(|e| e.into_inner());
            *done = true;
            if let Err(e) = send_message(&*sink, cid, cmd, &response) {
                log::error!("sending response: {e}");
            }
        });
    }

    fn reply(&self, cid: u32, cmd: u8, data: &[u8]) {
        if let Err(e) = send_message(&*self.sink, cid, cmd, data) {
            log::error!("sending response: {e}");
        }
    }

    fn error(&self, cid: u32, code: u8) {
        log::debug!("CTAPHID error {code:#04x} on channel {cid:#010x}");
        self.reply(cid, CMD_ERROR, &[code]);
    }
}
