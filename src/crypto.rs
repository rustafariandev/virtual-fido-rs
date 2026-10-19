//! Credential signature algorithms (ES256, Ed25519), SHA-256, and attestation
//! certificate generation.

use ciborium::Value;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ctap2::cbor::{bytes, int, map};
use crate::error::{Error, Result};
use crate::store::AttestationMaterial;

/// COSE algorithm identifier for ES256.
pub const COSE_ALG_ES256: i64 = -7;
/// COSE algorithm identifier for EdDSA (here always Ed25519).
pub const COSE_ALG_EDDSA: i64 = -8;

/// A credential's signature algorithm. Both use a 32-byte private key: a P-256
/// scalar for ES256, a seed for Ed25519.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "i64", try_from = "i64")]
pub enum Algorithm {
    /// ECDSA P-256 with SHA-256; signatures are DER encoded.
    #[default]
    Es256,
    /// Ed25519 (PureEdDSA); signatures are the raw 64 bytes.
    Ed25519,
}

impl Algorithm {
    /// Supported algorithms, in the order advertised by getInfo.
    pub const SUPPORTED: [Algorithm; 2] = [Algorithm::Es256, Algorithm::Ed25519];

    pub fn from_cose(id: i128) -> Option<Self> {
        match id {
            x if x == COSE_ALG_ES256 as i128 => Some(Algorithm::Es256),
            x if x == COSE_ALG_EDDSA as i128 => Some(Algorithm::Ed25519),
            _ => None,
        }
    }

    pub fn cose_id(self) -> i64 {
        match self {
            Algorithm::Es256 => COSE_ALG_ES256,
            Algorithm::Ed25519 => COSE_ALG_EDDSA,
        }
    }

    pub fn generate_private_key(self) -> Vec<u8> {
        match self {
            Algorithm::Es256 => SigningKey::random(&mut OsRng).to_bytes().to_vec(),
            Algorithm::Ed25519 => ed25519_dalek::SigningKey::generate(&mut OsRng).to_bytes().to_vec(),
        }
    }

    pub fn sign(self, private_key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            Algorithm::Es256 => {
                let sig: Signature = signing_key(private_key)?.sign(msg);
                Ok(sig.to_der().as_bytes().to_vec())
            }
            Algorithm::Ed25519 => Ok(ed25519_key(private_key)?.sign(msg).to_bytes().to_vec()),
        }
    }

    /// COSE_Key for the public half of `private_key`.
    pub fn cose_public_key(self, private_key: &[u8]) -> Result<Value> {
        match self {
            Algorithm::Es256 => {
                let p = public_key_uncompressed(private_key)?;
                Ok(map(vec![
                    (int(1), int(2)),              // kty: EC2
                    (int(3), int(COSE_ALG_ES256)), // alg
                    (int(-1), int(1)),             // crv: P-256
                    (int(-2), bytes(&p[1..33])),   // x
                    (int(-3), bytes(&p[33..65])),  // y
                ]))
            }
            Algorithm::Ed25519 => {
                let public = ed25519_key(private_key)?.verifying_key().to_bytes();
                Ok(map(vec![
                    (int(1), int(1)),              // kty: OKP
                    (int(3), int(COSE_ALG_EDDSA)), // alg
                    (int(-1), int(6)),             // crv: Ed25519
                    (int(-2), bytes(&public)),     // x
                ]))
            }
        }
    }
}

impl From<Algorithm> for i64 {
    fn from(alg: Algorithm) -> i64 {
        alg.cose_id()
    }
}

impl TryFrom<i64> for Algorithm {
    type Error = String;

    fn try_from(id: i64) -> std::result::Result<Self, String> {
        Algorithm::from_cose(id.into()).ok_or_else(|| format!("unsupported COSE algorithm {id}"))
    }
}

fn ed25519_key(private_key: &[u8]) -> Result<ed25519_dalek::SigningKey> {
    let seed: [u8; 32] = private_key.try_into().map_err(|_| Error::Crypto("invalid Ed25519 private key".into()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

fn signing_key(private_key: &[u8]) -> Result<SigningKey> {
    SigningKey::from_slice(private_key).map_err(|e| Error::Crypto(format!("invalid private key: {e}")))
}

/// SEC1 uncompressed P-256 public key: `0x04 || x || y`.
pub fn public_key_uncompressed(private_key: &[u8]) -> Result<[u8; 65]> {
    let point = signing_key(private_key)?.verifying_key().to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(point.as_bytes());
    Ok(out)
}

/// Generates a self-signed batch attestation key and certificate (used by U2F registration).
pub fn generate_attestation() -> Result<AttestationMaterial> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};
    let err = |e: rcgen::Error| Error::Crypto(format!("attestation certificate: {e}"));

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(err)?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "Virtual FIDO");
    dn.push(DnType::OrganizationalUnitName, "Authenticator Attestation");
    dn.push(DnType::CommonName, "Virtual FIDO2 Batch Certificate");
    params.distinguished_name = dn;
    params.is_ca = IsCa::ExplicitNoCa;
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2049, 12, 31);
    let cert = params.self_signed(&key_pair).map_err(err)?;

    let secret = p256::SecretKey::from_pkcs8_der(&key_pair.serialize_der())
        .map_err(|e| Error::Crypto(format!("attestation key: {e}")))?;
    Ok(AttestationMaterial {
        private_key: secret.to_bytes().to_vec(),
        certificate: cert.der().to_vec(),
    })
}
