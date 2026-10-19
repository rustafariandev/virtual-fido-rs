//! A virtual FIDO2 / U2F security key exposed to Linux through `/dev/uhid`.
//!
//! Layers, bottom to top:
//! - [`uhid`]: creates the HID device and moves 64-byte reports in and out.
//! - [`ctaphid`]: CTAPHID framing, channels, keepalives and cancellation.
//! - [`authenticator`]: dispatches to [`ctap2`] (CBOR) and [`u2f`] (CTAP1 APDUs).
//! - [`store`] / [`presence`]: pluggable credential storage and user-presence backends.

pub mod authenticator;
pub mod crypto;
pub mod ctap2;
pub mod ctaphid;
pub mod error;
pub mod presence;
pub mod store;
pub mod u2f;
pub mod uhid;

pub use authenticator::Authenticator;
pub use error::{Error, Result};
