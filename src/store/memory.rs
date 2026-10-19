use serde::{Deserialize, Serialize};

use super::{AttestationMaterial, Credential, CredentialStore, PinState};
use crate::error::{Error, Result};

/// Complete store contents. Shared by the memory backend and the file backend,
/// which serialises it.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct StoreState {
    pub credentials: Vec<Credential>,
    pub attestation: Option<AttestationMaterial>,
    /// Absent in stores written before PIN support.
    #[serde(default)]
    pub pin: Option<PinState>,
}

impl StoreState {
    pub fn put(&mut self, cred: Credential) {
        self.credentials.retain(|c| {
            let same_user = cred.discoverable
                && c.discoverable
                && c.rp_id_hash == cred.rp_id_hash
                && c.user_id.is_some()
                && c.user_id == cred.user_id;
            !same_user && c.id != cred.id
        });
        self.credentials.push(cred);
    }

    pub fn get(&self, id: &[u8]) -> Option<Credential> {
        self.credentials.iter().find(|c| c.id == id).cloned()
    }

    pub fn list_by_rp(&self, rp_id_hash: &[u8; 32]) -> Vec<Credential> {
        // Insertion order breaks ties between credentials created in the same millisecond.
        let mut out: Vec<Credential> =
            self.credentials.iter().rev().filter(|c| &c.rp_id_hash == rp_id_hash).cloned().collect();
        out.sort_by_key(|c| std::cmp::Reverse(c.created));
        out
    }

    pub fn reset(&mut self) {
        self.credentials.clear();
        self.pin = None;
    }

    pub fn increment_counter(&mut self, id: &[u8]) -> Result<u32> {
        let cred = self
            .credentials
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or_else(|| Error::Store("unknown credential".into()))?;
        cred.sign_count = cred.sign_count.saturating_add(1);
        Ok(cred.sign_count)
    }
}

/// Volatile store: everything is lost when the process exits.
#[derive(Default)]
pub struct MemoryStore {
    state: StoreState,
}

impl CredentialStore for MemoryStore {
    fn put(&mut self, cred: Credential) -> Result<()> {
        self.state.put(cred);
        Ok(())
    }

    fn get(&self, id: &[u8]) -> Result<Option<Credential>> {
        Ok(self.state.get(id))
    }

    fn list_by_rp(&self, rp_id_hash: &[u8; 32]) -> Result<Vec<Credential>> {
        Ok(self.state.list_by_rp(rp_id_hash))
    }

    fn increment_counter(&mut self, id: &[u8]) -> Result<u32> {
        self.state.increment_counter(id)
    }

    fn reset(&mut self) -> Result<()> {
        self.state.reset();
        Ok(())
    }

    fn attestation(&self) -> Result<Option<AttestationMaterial>> {
        Ok(self.state.attestation.clone())
    }

    fn set_attestation(&mut self, attestation: AttestationMaterial) -> Result<()> {
        self.state.attestation = Some(attestation);
        Ok(())
    }

    fn pin(&self) -> Result<Option<PinState>> {
        Ok(self.state.pin.clone())
    }

    fn set_pin(&mut self, pin: Option<PinState>) -> Result<()> {
        self.state.pin = pin;
        Ok(())
    }
}
