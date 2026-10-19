//! ECDSA P-256 / SHA-256 primitives and attestation certificate generation.

use ciborium::Value;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::ctap2::cbor::{bytes, int, map};
use crate::error::{Error, Result};
use crate::store::AttestationMaterial;

/// COSE algorithm identifier for ES256.
pub const COSE_ALG_ES256: i64 = -7;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Returns a new raw 32-byte P-256 private scalar.
pub fn generate_private_key() -> Vec<u8> {
    SigningKey::random(&mut OsRng).to_bytes().to_vec()
}

fn signing_key(private_key: &[u8]) -> Result<SigningKey> {
    SigningKey::from_slice(private_key).map_err(|e| Error::Crypto(format!("invalid private key: {e}")))
}

/// ECDSA-SHA256 signature over `msg`, DER encoded.
pub fn sign(private_key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let sig: Signature = signing_key(private_key)?.sign(msg);
    Ok(sig.to_der().as_bytes().to_vec())
}

/// SEC1 uncompressed public key: `0x04 || x || y`.
pub fn public_key_uncompressed(private_key: &[u8]) -> Result<[u8; 65]> {
    let point = signing_key(private_key)?.verifying_key().to_encoded_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(point.as_bytes());
    Ok(out)
}

/// COSE_Key (EC2, P-256, ES256) for the public half of `private_key`.
pub fn cose_public_key(private_key: &[u8]) -> Result<Value> {
    let p = public_key_uncompressed(private_key)?;
    Ok(map(vec![
        (int(1), int(2)),               // kty: EC2
        (int(3), int(COSE_ALG_ES256)),  // alg
        (int(-1), int(1)),              // crv: P-256
        (int(-2), bytes(&p[1..33])),    // x
        (int(-3), bytes(&p[33..65])),   // y
    ]))
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
