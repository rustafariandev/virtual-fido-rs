//! Passphrase-encrypted file store.
//!
//! Layout: `MAGIC | m_cost u32 | t_cost u32 | p_cost u32 | salt[16] | nonce[12] | ciphertext`,
//! integers little-endian. The key is Argon2id(passphrase, salt); the ciphertext is
//! AES-256-GCM over the CBOR-encoded [`StoreState`], with the header as associated data.
//! Every mutation rewrites the file atomically.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroizing;

use super::{AttestationMaterial, Credential, CredentialStore, PinState, StoreState};
use crate::crypto::random_bytes;
use crate::error::{Error, Result};

const MAGIC: &[u8; 8] = b"VFIDOST1";
const HEADER_LEN: usize = 8 + 12 + 16;
const NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams { m_cost: 64 * 1024, t_cost: 3, p_cost: 1 }
    }
}

pub struct FileStore {
    path: PathBuf,
    header: [u8; HEADER_LEN],
    key: Zeroizing<[u8; 32]>,
    state: StoreState,
}

impl FileStore {
    /// Opens `path`, or creates a new empty store there if it does not exist.
    pub fn open(path: &Path, passphrase: &str) -> Result<Self> {
        Self::open_with_params(path, passphrase, KdfParams::default())
    }

    /// Like [`FileStore::open`]; `params` only applies when creating a new store.
    pub fn open_with_params(path: &Path, passphrase: &str, params: KdfParams) -> Result<Self> {
        if path.exists() {
            Self::load(path, passphrase)
        } else {
            let header = make_header(params, random_bytes::<16>());
            let key = derive_key(passphrase, &header)?;
            let store = FileStore { path: path.to_owned(), header, key, state: StoreState::default() };
            store.save()?;
            Ok(store)
        }
    }

    fn load(path: &Path, passphrase: &str) -> Result<Self> {
        let data = fs::read(path)?;
        if data.len() < HEADER_LEN + NONCE_LEN || &data[..8] != MAGIC {
            return Err(Error::Store(format!("{} is not a virtual-fido store", path.display())));
        }
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&data[..HEADER_LEN]);
        let key = derive_key(passphrase, &header)?;
        let nonce: [u8; NONCE_LEN] = data[HEADER_LEN..HEADER_LEN + NONCE_LEN].try_into().unwrap();
        let plaintext = Zeroizing::new(
            cipher(&key)
                .decrypt(&Nonce::from(nonce), Payload { msg: &data[HEADER_LEN + NONCE_LEN..], aad: &header })
                .map_err(|_| Error::Store("wrong passphrase or corrupted store".into()))?,
        );
        let state: StoreState = ciborium::de::from_reader(plaintext.as_slice())
            .map_err(|e| Error::Store(format!("corrupted store contents: {e}")))?;
        Ok(FileStore { path: path.to_owned(), header, key, state })
    }

    fn save(&self) -> Result<()> {
        let mut plaintext = Zeroizing::new(Vec::new());
        ciborium::ser::into_writer(&self.state, &mut *plaintext)
            .map_err(|e| Error::Store(format!("serialising store: {e}")))?;
        let nonce = random_bytes::<NONCE_LEN>();
        let ciphertext = cipher(&self.key)
            .encrypt(&Nonce::from(nonce), Payload { msg: &plaintext, aad: &self.header })
            .map_err(|_| Error::Crypto("store encryption failed".into()))?;

        if let Some(dir) = self.path.parent() {
            fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        let tmp = self.path.with_extension("tmp");
        let mut file = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        file.write_all(&self.header)?;
        file.write_all(&nonce)?;
        file.write_all(&ciphertext)?;
        file.sync_all()?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Applies `f` to the state and persists it; the in-memory state is rolled back
    /// if the write fails.
    fn mutate<T>(&mut self, f: impl FnOnce(&mut StoreState) -> Result<T>) -> Result<T> {
        let backup = self.state.clone();
        let out = f(&mut self.state)?;
        if let Err(e) = self.save() {
            self.state = backup;
            return Err(e);
        }
        Ok(out)
    }
}

fn make_header(params: KdfParams, salt: [u8; 16]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(MAGIC);
    h[8..12].copy_from_slice(&params.m_cost.to_le_bytes());
    h[12..16].copy_from_slice(&params.t_cost.to_le_bytes());
    h[16..20].copy_from_slice(&params.p_cost.to_le_bytes());
    h[20..36].copy_from_slice(&salt);
    h
}

fn derive_key(passphrase: &str, header: &[u8; HEADER_LEN]) -> Result<Zeroizing<[u8; 32]>> {
    let u32_at = |i: usize| u32::from_le_bytes(header[i..i + 4].try_into().unwrap());
    let params = argon2::Params::new(u32_at(8), u32_at(12), u32_at(16), Some(32))
        .map_err(|e| Error::Store(format!("invalid KDF parameters: {e}")))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), &header[20..36], &mut *key)
        .map_err(|e| Error::Crypto(format!("key derivation: {e}")))?;
    Ok(key)
}

fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(key.into())
}

impl CredentialStore for FileStore {
    fn put(&mut self, cred: Credential) -> Result<()> {
        self.mutate(|s| {
            s.put(cred);
            Ok(())
        })
    }

    fn get(&self, id: &[u8]) -> Result<Option<Credential>> {
        Ok(self.state.get(id))
    }

    fn list_by_rp(&self, rp_id_hash: &[u8; 32]) -> Result<Vec<Credential>> {
        Ok(self.state.list_by_rp(rp_id_hash))
    }

    fn list_all(&self) -> Result<Vec<Credential>> {
        Ok(self.state.credentials.clone())
    }

    fn delete(&mut self, id: &[u8]) -> Result<bool> {
        self.mutate(|s| Ok(s.delete(id)))
    }

    fn increment_counter(&mut self, id: &[u8]) -> Result<u32> {
        self.mutate(|s| s.increment_counter(id))
    }

    fn reset(&mut self) -> Result<()> {
        self.mutate(|s| {
            s.reset();
            Ok(())
        })
    }

    fn attestation(&self) -> Result<Option<AttestationMaterial>> {
        Ok(self.state.attestation.clone())
    }

    fn set_attestation(&mut self, attestation: AttestationMaterial) -> Result<()> {
        self.mutate(|s| {
            s.attestation = Some(attestation);
            Ok(())
        })
    }

    fn pin(&self) -> Result<Option<PinState>> {
        Ok(self.state.pin.clone())
    }

    fn set_pin(&mut self, pin: Option<PinState>) -> Result<()> {
        self.mutate(|s| {
            s.pin = pin;
            Ok(())
        })
    }
}
