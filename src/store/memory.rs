use serde::{Deserialize, Serialize};

use super::{AttestationMaterial, AuthenticatorConfig, Credential, CredentialStore, PinState};
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
    /// Absent in stores written before largeBlob support.
    #[serde(default, with = "serde_bytes")]
    pub large_blob: Option<Vec<u8>>,
    /// Absent in stores written before authenticatorConfig support.
    #[serde(default)]
    pub config: AuthenticatorConfig,
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

    pub fn delete(&mut self, id: &[u8]) -> bool {
        let before = self.credentials.len();
        self.credentials.retain(|c| c.id != id);
        self.credentials.len() != before
    }

    pub fn reset(&mut self) {
        self.credentials.clear();
        self.pin = None;
        self.large_blob = None;
        self.config = AuthenticatorConfig::default();
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

    fn list_all(&self) -> Result<Vec<Credential>> {
        Ok(self.state.credentials.clone())
    }

    fn delete(&mut self, id: &[u8]) -> Result<bool> {
        Ok(self.state.delete(id))
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

    fn large_blob(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.state.large_blob.clone())
    }

    fn set_large_blob(&mut self, data: Vec<u8>) -> Result<()> {
        self.state.large_blob = Some(data);
        Ok(())
    }

    fn config(&self) -> Result<AuthenticatorConfig> {
        Ok(self.state.config.clone())
    }

    fn set_config(&mut self, config: AuthenticatorConfig) -> Result<()> {
        self.state.config = config;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::Algorithm;
    use crate::store::CredProtect;

    pub(crate) fn cred(id: u8, rp: u8, user: Option<&[u8]>, discoverable: bool, created: u64) -> Credential {
        Credential {
            id: vec![id; 16],
            rp_id: String::new(),
            rp_name: None,
            rp_id_hash: [rp; 32],
            user_id: user.map(<[u8]>::to_vec),
            user_name: None,
            user_display_name: None,
            private_key: vec![1; 32],
            sign_count: 0,
            discoverable,
            created,
            hmac_secret: None,
            cred_protect: CredProtect::UvOptional,
            large_blob_key: None,
            cred_blob: None,
            algorithm: Algorithm::Es256,
        }
    }

    fn ids(creds: &[Credential]) -> Vec<u8> {
        creds.iter().map(|c| c.id[0]).collect()
    }

    #[test]
    fn discoverable_credential_replaces_same_rp_and_user() {
        let mut s = StoreState::default();
        s.put(cred(1, 0xA, Some(b"u"), true, 1));
        s.put(cred(2, 0xA, Some(b"u"), false, 2)); // not discoverable: kept alongside
        s.put(cred(3, 0xB, Some(b"u"), true, 3)); // other RP
        s.put(cred(4, 0xA, Some(b"v"), true, 4)); // other user
        assert_eq!(s.credentials.len(), 4);
        s.put(cred(5, 0xA, Some(b"u"), true, 5));
        assert_eq!(ids(&s.credentials), [2, 3, 4, 5]);
        // Re-putting an ID replaces it.
        s.put(cred(2, 0xA, Some(b"u"), false, 6));
        assert_eq!(ids(&s.credentials), [3, 4, 5, 2]);
    }

    #[test]
    fn list_by_rp_is_newest_first_with_insertion_order_tiebreak() {
        let mut s = StoreState::default();
        s.put(cred(1, 0xA, None, false, 10));
        s.put(cred(2, 0xA, None, false, 30));
        s.put(cred(3, 0xB, None, false, 40));
        s.put(cred(4, 0xA, None, false, 20));
        s.put(cred(5, 0xA, None, false, 20));
        assert_eq!(ids(&s.list_by_rp(&[0xA; 32])), [2, 5, 4, 1]);
        assert!(s.list_by_rp(&[0xC; 32]).is_empty());
    }

    #[test]
    fn counters_delete_and_reset() {
        let mut s = StoreState::default();
        s.put(cred(1, 0xA, None, false, 0));
        assert_eq!(s.increment_counter(&[1; 16]).unwrap(), 1);
        assert_eq!(s.increment_counter(&[1; 16]).unwrap(), 2);
        assert!(s.increment_counter(&[9; 16]).is_err());
        s.credentials[0].sign_count = u32::MAX;
        assert_eq!(s.increment_counter(&[1; 16]).unwrap(), u32::MAX, "saturates");

        assert!(!s.delete(&[9; 16]));
        assert!(s.delete(&[1; 16]));
        assert!(s.get(&[1; 16]).is_none());

        s.put(cred(2, 0xA, None, false, 0));
        s.attestation = Some(AttestationMaterial { private_key: vec![1], certificate: vec![2] });
        s.pin = Some(PinState { pin_hash: [0; 16], retries: 8, code_points: Some(4), force_change: false });
        s.large_blob = Some(vec![0x80]);
        s.config.always_uv = true;
        s.reset();
        assert!(s.credentials.is_empty() && s.pin.is_none() && s.large_blob.is_none());
        assert_eq!(s.config, AuthenticatorConfig::default());
        assert!(s.attestation.is_some(), "reset keeps the attestation key");
    }
}
