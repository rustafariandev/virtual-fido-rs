//! Minimal `/dev/uhid` client: creates a FIDO HID device and exchanges reports.
//! Struct layouts follow `<linux/uhid.h>` (all packed, native = little endian).

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

use crate::ctaphid::{ReportSink, REPORT_SIZE};

const UHID_DESTROY: u32 = 1;
const UHID_START: u32 = 2;
const UHID_STOP: u32 = 3;
const UHID_OPEN: u32 = 4;
const UHID_CLOSE: u32 = 5;
const UHID_OUTPUT: u32 = 6;
const UHID_GET_REPORT: u32 = 9;
const UHID_GET_REPORT_REPLY: u32 = 10;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;
const UHID_SET_REPORT: u32 = 13;
const UHID_SET_REPORT_REPLY: u32 = 14;

/// `sizeof(struct uhid_event)`: a u32 type plus the largest union member (uhid_create2_req).
const EVENT_SIZE: usize = 4 + 128 + 64 + 64 + 2 + 2 + 4 * 4 + 4096;
const BUS_USB: u16 = 0x03;
const EIO: u16 = 5;

/// HID report descriptor for a CTAPHID device: FIDO usage page, 64-byte in/out reports.
pub const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, //       Usage (CTAPHID)
    0xA1, 0x01, //       Collection (Application)
    0x09, 0x20, //         Usage (Input Report Data)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x81, 0x02, //         Input (Data, Var, Abs)
    0x09, 0x21, //         Usage (Output Report Data)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x91, 0x02, //         Output (Data, Var, Abs)
    0xC0, //             End Collection
];

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub name: String,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
}

impl Default for DeviceInfo {
    fn default() -> Self {
        // pid.codes test VID/PID; not a registered product.
        DeviceInfo { name: "Virtual FIDO2".into(), vendor: 0x1209, product: 0x000A, version: 0x0100 }
    }
}

#[derive(Debug)]
pub enum Event {
    Start,
    Stop,
    Open,
    Close,
    /// An output report from the host, without the report-number prefix.
    Output(Vec<u8>),
    GetReport {
        id: u32,
    },
    SetReport {
        id: u32,
    },
    Other(u32),
}

pub struct UhidDevice {
    file: File,
}

impl UhidDevice {
    pub fn create(info: &DeviceInfo) -> io::Result<Self> {
        let mut file = OpenOptions::new().read(true).write(true).open("/dev/uhid")?;
        let mut ev = event(UHID_CREATE2);
        let name = info.name.as_bytes();
        let name_len = name.len().min(127);
        ev[4..4 + name_len].copy_from_slice(&name[..name_len]);
        let uniq = b"virtual-fido";
        ev[196..196 + uniq.len()].copy_from_slice(uniq);
        ev[260..262].copy_from_slice(&(FIDO_REPORT_DESCRIPTOR.len() as u16).to_le_bytes());
        ev[262..264].copy_from_slice(&BUS_USB.to_le_bytes());
        ev[264..268].copy_from_slice(&info.vendor.to_le_bytes());
        ev[268..272].copy_from_slice(&info.product.to_le_bytes());
        ev[272..276].copy_from_slice(&info.version.to_le_bytes());
        ev[280..280 + FIDO_REPORT_DESCRIPTOR.len()].copy_from_slice(FIDO_REPORT_DESCRIPTOR);
        file.write_all(&ev)?;
        Ok(UhidDevice { file })
    }

    /// A handle for sending input reports from other threads.
    pub fn writer(&self) -> io::Result<UhidWriter> {
        Ok(UhidWriter { file: self.file.try_clone()? })
    }

    /// Blocks until the kernel delivers the next event.
    pub fn read_event(&mut self) -> io::Result<Event> {
        let mut buf = vec![0u8; EVENT_SIZE];
        let n = self.file.read(&mut buf)?;
        if n < 4 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short uhid event"));
        }
        let u32_at = |i: usize| u32::from_le_bytes(buf[i..i + 4].try_into().unwrap());
        Ok(match u32_at(0) {
            UHID_START => Event::Start,
            UHID_STOP => Event::Stop,
            UHID_OPEN => Event::Open,
            UHID_CLOSE => Event::Close,
            UHID_OUTPUT => {
                let size = (u16::from_le_bytes([buf[4100], buf[4101]]) as usize).min(4096);
                let data = &buf[4..4 + size];
                // Our descriptor has no report IDs, so hidraw writes are prefixed with a 0.
                let data = if size == REPORT_SIZE + 1 { &data[1..] } else { data };
                Event::Output(data.to_vec())
            }
            UHID_GET_REPORT => Event::GetReport { id: u32_at(4) },
            UHID_SET_REPORT => Event::SetReport { id: u32_at(4) },
            other => Event::Other(other),
        })
    }

    /// We have no feature reports; fail GET_REPORT / SET_REPORT requests.
    pub fn reject_report_request(&mut self, ev: &Event) -> io::Result<()> {
        let (ty, id) = match ev {
            Event::GetReport { id } => (UHID_GET_REPORT_REPLY, *id),
            Event::SetReport { id } => (UHID_SET_REPORT_REPLY, *id),
            _ => return Ok(()),
        };
        let mut reply = event(ty);
        reply[4..8].copy_from_slice(&id.to_le_bytes());
        reply[8..10].copy_from_slice(&EIO.to_le_bytes());
        self.file.write_all(&reply)
    }
}

impl Drop for UhidDevice {
    fn drop(&mut self) {
        let _ = self.file.write_all(&event(UHID_DESTROY));
    }
}

pub struct UhidWriter {
    file: File,
}

impl ReportSink for UhidWriter {
    fn send_report(&self, report: &[u8; REPORT_SIZE]) -> io::Result<()> {
        let mut ev = event(UHID_INPUT2);
        ev[4..6].copy_from_slice(&(REPORT_SIZE as u16).to_le_bytes());
        ev[6..6 + REPORT_SIZE].copy_from_slice(report);
        // Each write is one complete event, so concurrent writers cannot interleave.
        (&self.file).write_all(&ev)
    }
}

fn event(ty: u32) -> Vec<u8> {
    let mut ev = vec![0u8; EVENT_SIZE];
    ev[..4].copy_from_slice(&ty.to_le_bytes());
    ev
}
