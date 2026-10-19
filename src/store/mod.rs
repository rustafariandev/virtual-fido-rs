//! Credential storage plugins.
//!
//! A backend implements [`CredentialStore`]; [`open`] picks one by name. To add a
//! backend, write a module implementing the trait and add a match arm in [`open`].

mod file;
mod memory;

use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::Algorithm;
use crate::error::{Error, Result};

pub use file::{FileStore, KdfParams};
pub use memory::{MemoryStore, StoreState};

#[derive(Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Random credential ID; doubles as the U2F key handle.
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    /// Relying party ID. Empty for credentials registered over U2F, which only know the hash.
    pub rp_id: String,
    /// Relying party display name, if the RP gave one. Absent in older stores.
    #[serde(default)]
    pub rp_name: Option<String>,
    pub rp_id_hash: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub user_id: Option<Vec<u8>>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    /// Raw 32-byte P-256 private scalar.
    #[serde(with = "serde_bytes")]
    pub private_key: Vec<u8>,
    pub sign_count: u32,
    /// Resident key: discoverable by getAssertion without an allow list.
    pub discoverable: bool,
    /// Creation time, milliseconds since the Unix epoch.
    pub created: u64,
    /// hmac-secret keys, `CredRandomWithUV || CredRandomWithoutUV` (2 x 32 bytes), if the
    /// credential was created with the extension. Absent in stores from older versions.
    #[serde(default, with = "serde_bytes")]
    pub hmac_secret: Option<Vec<u8>>,
    /// credProtect level. Absent in stores from older versions (= no protection).
    #[serde(default)]
    pub cred_protect: CredProtect,
    /// 32-byte largeBlobKey, if created with the largeBlobKey extension.
    #[serde(default, with = "serde_bytes")]
    pub large_blob_key: Option<Vec<u8>>,
    /// Small RP-supplied blob from the credBlob extension.
    #[serde(default, with = "serde_bytes")]
    pub cred_blob: Option<Vec<u8>>,
    /// Signature algorithm of `private_key`. Absent in older stores, which were ES256 only.
    #[serde(default)]
    pub algorithm: Algorithm,
}

/// credProtect policy: when a credential may be used without user verification (PIN).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
pub enum CredProtect {
    /// Level 1: always usable.
    #[default]
    UvOptional,
    /// Level 2: without UV, only usable when the client names it (allow list / key
    /// handle); it is not discoverable.
    UvOptionalWithCredentialIdList,
    /// Level 3: only usable with UV.
    UvRequired,
}

impl CredProtect {
    /// Whether the credential may be used, given whether the user was verified and
    /// whether the client named the credential ID.
    pub fn allows(self, user_verified: bool, id_listed: bool) -> bool {
        match self {
            CredProtect::UvOptional => true,
            CredProtect::UvOptionalWithCredentialIdList => user_verified || id_listed,
            CredProtect::UvRequired => user_verified,
        }
    }
}

impl From<CredProtect> for u8 {
    fn from(p: CredProtect) -> u8 {
        match p {
            CredProtect::UvOptional => 1,
            CredProtect::UvOptionalWithCredentialIdList => 2,
            CredProtect::UvRequired => 3,
        }
    }
}

impl TryFrom<u8> for CredProtect {
    type Error = String;

    fn try_from(level: u8) -> std::result::Result<Self, String> {
        match level {
            1 => Ok(CredProtect::UvOptional),
            2 => Ok(CredProtect::UvOptionalWithCredentialIdList),
            3 => Ok(CredProtect::UvRequired),
            other => Err(format!("invalid credProtect level {other}")),
        }
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.private_key.zeroize();
        if let Some(s) = &mut self.hmac_secret {
            s.zeroize();
        }
        if let Some(k) = &mut self.large_blob_key {
            k.zeroize();
        }
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("id", &self.id)
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("sign_count", &self.sign_count)
            .field("discoverable", &self.discoverable)
            .field("cred_protect", &self.cred_protect)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Batch attestation key and its self-signed certificate (DER).
#[derive(Clone, Serialize, Deserialize)]
pub struct AttestationMaterial {
    #[serde(with = "serde_bytes")]
    pub private_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub certificate: Vec<u8>,
}

impl Drop for AttestationMaterial {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

/// Persistent client-PIN state. Only a hash of the PIN is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinState {
    /// LEFT(SHA-256(PIN), 16), as CTAP specifies.
    pub pin_hash: [u8; 16],
    /// Wrong guesses left before the PIN is blocked until reset.
    pub retries: u8,
    /// Length in Unicode code points, to check against a raised minimum. Unknown for
    /// PINs set before this was recorded.
    #[serde(default)]
    pub code_points: Option<u8>,
    /// Set by authenticatorConfig: the PIN must be changed before it can be used.
    #[serde(default)]
    pub force_change: bool,
}

/// Default minimum PIN length, in code points.
pub const DEFAULT_MIN_PIN_LENGTH: u8 = 4;

/// Settings changed with authenticatorConfig. Reset restores the defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatorConfig {
    /// Minimum PIN length in code points; it can only be raised.
    pub min_pin_length: u8,
    /// RPs allowed to learn `min_pin_length` through the minPinLength extension.
    pub min_pin_length_rp_ids: Vec<String>,
    /// Require user verification for every makeCredential / getAssertion, and disable U2F.
    pub always_uv: bool,
}

impl Default for AuthenticatorConfig {
    fn default() -> Self {
        AuthenticatorConfig {
            min_pin_length: DEFAULT_MIN_PIN_LENGTH,
            min_pin_length_rp_ids: Vec::new(),
            always_uv: false,
        }
    }
}

pub trait CredentialStore: Send {
    /// Stores a credential. A discoverable credential replaces any existing discoverable
    /// credential for the same RP and user ID.
    fn put(&mut self, cred: Credential) -> Result<()>;
    fn get(&self, id: &[u8]) -> Result<Option<Credential>>;
    /// All credentials for an RP, newest first.
    fn list_by_rp(&self, rp_id_hash: &[u8; 32]) -> Result<Vec<Credential>>;
    /// Every stored credential.
    fn list_all(&self) -> Result<Vec<Credential>>;
    /// Deletes a credential; returns whether it existed.
    fn delete(&mut self, id: &[u8]) -> Result<bool>;
    /// Increments and returns the credential's signature counter.
    fn increment_counter(&mut self, id: &[u8]) -> Result<u32>;
    /// Deletes all credentials, the PIN and the large-blob array, and restores the
    /// default configuration. Attestation material is kept.
    fn reset(&mut self) -> Result<()>;
    fn attestation(&self) -> Result<Option<AttestationMaterial>>;
    fn set_attestation(&mut self, attestation: AttestationMaterial) -> Result<()>;
    /// The client PIN, if one is set.
    fn pin(&self) -> Result<Option<PinState>>;
    /// Must be durable before returning: retry counters depend on it.
    fn set_pin(&mut self, pin: Option<PinState>) -> Result<()>;
    /// The serialized large-blob array (CBOR array || truncated hash); `None` if never written.
    fn large_blob(&self) -> Result<Option<Vec<u8>>>;
    fn set_large_blob(&mut self, data: Vec<u8>) -> Result<()>;
    fn config(&self) -> Result<AuthenticatorConfig>;
    fn set_config(&mut self, config: AuthenticatorConfig) -> Result<()>;
}

#[derive(Debug, Default, Clone)]
pub struct StoreOptions {
    pub path: Option<PathBuf>,
    pub passphrase_file: Option<PathBuf>,
}

pub const BACKENDS: &[&str] = &["memory", "file"];

pub fn open(name: &str, opts: &StoreOptions) -> Result<Box<dyn CredentialStore>> {
    match name {
        "memory" => Ok(Box::new(MemoryStore::default())),
        "file" => {
            let path = match &opts.path {
                Some(p) => p.clone(),
                None => default_store_path()?,
            };
            let passphrase = read_passphrase(opts, !path.exists())?;
            log::info!("using credential store {}", path.display());
            Ok(Box::new(FileStore::open(&path, &passphrase)?))
        }
        other => Err(Error::Config(format!("unknown store backend {other:?} (available: {})", BACKENDS.join(", ")))),
    }
}

fn default_store_path() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .ok_or_else(|| Error::Config("cannot determine data directory; pass --store-path".into()))?;
    Ok(base.join("virtual-fido").join("store.bin"))
}

/// Passphrase from `--passphrase-file`, then `$VFIDO_PASSPHRASE`, then an interactive prompt.
fn read_passphrase(opts: &StoreOptions, creating: bool) -> Result<Zeroizing<String>> {
    if let Some(path) = &opts.passphrase_file {
        let mut s = Zeroizing::new(std::fs::read_to_string(path)?);
        let trimmed = s.trim_end_matches(['\r', '\n']).len();
        s.truncate(trimmed);
        return Ok(s);
    }
    if let Ok(s) = std::env::var("VFIDO_PASSPHRASE") {
        return Ok(Zeroizing::new(s));
    }
    let pass = Zeroizing::new(rpassword::prompt_password("Credential store passphrase: ")?);
    if creating {
        let confirm = Zeroizing::new(rpassword::prompt_password("Confirm new passphrase: ")?);
        if *pass != *confirm {
            return Err(Error::Config("passphrases do not match".into()));
        }
    }
    if pass.is_empty() {
        return Err(Error::Config("empty passphrase".into()));
    }
    Ok(pass)
}
