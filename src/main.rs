use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use clap::Parser;

use virtual_fido::authenticator::DEFAULT_AAGUID;
use virtual_fido::ctaphid::Server;
use virtual_fido::store::StoreOptions;
use virtual_fido::uhid::{DeviceInfo, Event, UhidDevice};
use virtual_fido::{presence, store, Authenticator};

/// A virtual FIDO2 / U2F security key, exposed as a USB HID device via /dev/uhid.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Credential store backend: memory or file.
    #[arg(long, default_value = "file")]
    store: String,
    /// Path of the encrypted store (file backend).
    /// Default: $XDG_DATA_HOME/virtual-fido/store.bin
    #[arg(long)]
    store_path: Option<PathBuf>,
    /// Read the store passphrase from this file instead of $VFIDO_PASSPHRASE or a prompt.
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
    /// User-presence backend: auto, terminal or notify.
    #[arg(long, default_value = "terminal")]
    presence: String,
    /// Seconds to wait for the user to approve a request.
    #[arg(long, default_value_t = 30)]
    presence_timeout: u64,
    /// AAGUID as 32 hex digits.
    #[arg(long)]
    aaguid: Option<String>,
    /// HID device name.
    #[arg(long, default_value = "Virtual FIDO2")]
    name: String,
    /// More logging (-v debug, -vv trace). RUST_LOG also works.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    env_logger::Builder::new()
        .filter_level(match args.verbose {
            0 => log::LevelFilter::Info,
            1 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        })
        .parse_default_env()
        .init();

    let aaguid = match &args.aaguid {
        Some(hex) => parse_aaguid(hex)?,
        None => DEFAULT_AAGUID,
    };
    let store = store::open(
        &args.store,
        &StoreOptions { path: args.store_path.clone(), passphrase_file: args.passphrase_file.clone() },
    )?;
    let presence = presence::from_name(&args.presence, Duration::from_secs(args.presence_timeout))?;
    let auth = Authenticator::new(store, presence, aaguid);

    let mut device = UhidDevice::create(&DeviceInfo { name: args.name.clone(), ..Default::default() })
        .context("creating /dev/uhid device (needs write access to /dev/uhid; see README)")?;
    let mut server = Server::new(Arc::new(device.writer()?), auth);
    log::info!("virtual FIDO2 device \"{}\" created; waiting for requests (Ctrl-C to stop)", args.name);

    loop {
        match device.read_event()? {
            Event::Output(report) => server.handle_report(&report),
            ev @ (Event::GetReport { .. } | Event::SetReport { .. }) => device.reject_report_request(&ev)?,
            ev => log::debug!("uhid event: {ev:?}"),
        }
    }
}

fn parse_aaguid(hex: &str) -> anyhow::Result<[u8; 16]> {
    let hex: String = hex.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("AAGUID must be 32 hex digits");
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).context("AAGUID must be hex")?;
    }
    Ok(out)
}
