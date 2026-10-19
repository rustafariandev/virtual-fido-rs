//! PIN/UV auth protocols one and two (CTAP 2.1 §6.5): ECDH key agreement, then
//! AES-256-CBC for confidentiality and HMAC-SHA-256 for authentication.
//!
//! Both sides are implemented here; the platform half ([`PinProtocol::encapsulate`],
//! [`PinProtocol::authenticate`]) is what a client needs to talk to the authenticator.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes256, Block};
use ciborium::Value;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::cbor::{as_bytes, as_map, bytes, get, int, map, require};
use super::Status;
use crate::crypto::{self, random_bytes};

type HmacSha256 = Hmac<Sha256>;

/// COSE algorithm "ECDH-ES + HKDF-256", used to tag key-agreement keys.
const COSE_ALG_ECDH_ES_HKDF_256: i64 = -25;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinProtocol {
    V1,
    V2,
}

impl PinProtocol {
    /// Protocols we support, most preferred first (as advertised in getInfo).
    pub const SUPPORTED: [PinProtocol; 2] = [PinProtocol::V2, PinProtocol::V1];

    pub fn from_id(id: i128) -> Option<Self> {
        match id {
            1 => Some(PinProtocol::V1),
            2 => Some(PinProtocol::V2),
            _ => None,
        }
    }

    pub fn id(self) -> i64 {
        match self {
            PinProtocol::V1 => 1,
            PinProtocol::V2 => 2,
        }
    }

    /// Derives the shared secret from our private key and the peer's public key.
    /// V1: SHA-256(Z), 32 bytes. V2: HKDF-derived HMAC key || AES key, 64 bytes.
    pub fn shared_secret(self, ours: &SecretKey, peer: &PublicKey) -> Zeroizing<Vec<u8>> {
        let z = p256::ecdh::diffie_hellman(ours.to_nonzero_scalar(), peer.as_affine());
        let z = z.raw_secret_bytes();
        match self {
            PinProtocol::V1 => Zeroizing::new(crypto::sha256(z).to_vec()),
            PinProtocol::V2 => {
                let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), z);
                let mut out = Zeroizing::new(vec![0u8; 64]);
                hk.expand(b"CTAP2 HMAC key", &mut out[..32]).expect("valid HKDF length");
                hk.expand(b"CTAP2 AES key", &mut out[32..]).expect("valid HKDF length");
                out
            }
        }
    }

    /// Platform side of key agreement: a fresh key pair, the COSE key to send, and the
    /// shared secret.
    pub fn encapsulate(self, peer: &PublicKey) -> (Value, Zeroizing<Vec<u8>>) {
        let ours = SecretKey::random(&mut OsRng);
        (cose_key_agreement(&ours), self.shared_secret(&ours, peer))
    }

    fn hmac_key(self, shared_secret: &[u8]) -> &[u8] {
        match self {
            PinProtocol::V1 => shared_secret,
            PinProtocol::V2 => &shared_secret[..32],
        }
    }

    fn aes_key(self, shared_secret: &[u8]) -> &[u8] {
        match self {
            PinProtocol::V1 => shared_secret,
            PinProtocol::V2 => &shared_secret[32..],
        }
    }

    /// Encrypts `plaintext` (a multiple of 16 bytes). V2 prefixes a random IV.
    pub fn encrypt(self, shared_secret: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let key = self.aes_key(shared_secret);
        match self {
            PinProtocol::V1 => cbc_encrypt(key, &[0; 16], plaintext),
            PinProtocol::V2 => {
                let iv = random_bytes::<16>();
                [&iv[..], &cbc_encrypt(key, &iv, plaintext)].concat()
            }
        }
    }

    /// Decrypts; `None` if the ciphertext is not a whole number of blocks.
    pub fn decrypt(self, shared_secret: &[u8], ciphertext: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let key = self.aes_key(shared_secret);
        let (iv, ct) = match self {
            PinProtocol::V1 => ([0u8; 16], ciphertext),
            PinProtocol::V2 if ciphertext.len() >= 16 => (ciphertext[..16].try_into().unwrap(), &ciphertext[16..]),
            PinProtocol::V2 => return None,
        };
        (ct.len() % 16 == 0).then(|| cbc_decrypt(key, &iv, ct))
    }

    /// HMAC over `msg` with a shared secret: V1 truncates to 16 bytes.
    pub fn authenticate_with_secret(self, shared_secret: &[u8], msg: &[u8]) -> Vec<u8> {
        self.authenticate(self.hmac_key(shared_secret), msg)
    }

    /// HMAC over `msg` with `key` (a pinUvAuthToken, or an HMAC key).
    pub fn authenticate(self, key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(msg);
        let tag = mac.finalize().into_bytes();
        match self {
            PinProtocol::V1 => tag[..16].to_vec(),
            PinProtocol::V2 => tag.to_vec(),
        }
    }

    pub fn verify_with_secret(self, shared_secret: &[u8], msg: &[u8], signature: &[u8]) -> bool {
        self.verify(self.hmac_key(shared_secret), msg, signature)
    }

    /// Constant-time check of an [`authenticate`](Self::authenticate) tag.
    pub fn verify(self, key: &[u8], msg: &[u8], signature: &[u8]) -> bool {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(msg);
        match self {
            PinProtocol::V1 => signature.len() == 16 && mac.verify_truncated_left(signature).is_ok(),
            PinProtocol::V2 => mac.verify_slice(signature).is_ok(),
        }
    }
}

/// COSE_Key for a key-agreement public key.
pub fn cose_key_agreement(key: &SecretKey) -> Value {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let point = key.public_key().to_encoded_point(false);
    let p = point.as_bytes();
    map(vec![
        (int(1), int(2)),
        (int(3), int(COSE_ALG_ECDH_ES_HKDF_256)),
        (int(-1), int(1)),
        (int(-2), bytes(&p[1..33])),
        (int(-3), bytes(&p[33..65])),
    ])
}

/// Parses a peer's COSE_Key into a P-256 public key.
pub fn parse_cose_key(v: &Value) -> Result<PublicKey, Status> {
    let m = as_map(v)?;
    let x = as_bytes(require(get(m, -2))?)?;
    let y = as_bytes(require(get(m, -3))?)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(Status::INVALID_PARAMETER);
    }
    PublicKey::from_sec1_bytes(&[&[0x04][..], x, y].concat()).map_err(|_| Status::INVALID_PARAMETER)
}

fn cbc_encrypt(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new_from_slice(key).expect("32-byte AES key");
    let mut prev = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.as_chunks::<16>().0 {
        let mut block = Block::from(std::array::from_fn::<u8, 16, _>(|i| chunk[i] ^ prev[i]));
        cipher.encrypt_block(&mut block);
        prev = block.into();
        out.extend_from_slice(&prev);
    }
    out
}

fn cbc_decrypt(key: &[u8], iv: &[u8; 16], data: &[u8]) -> Zeroizing<Vec<u8>> {
    let cipher = Aes256::new_from_slice(key).expect("32-byte AES key");
    let mut prev = *iv;
    let mut out = Zeroizing::new(Vec::with_capacity(data.len()));
    for &ct in data.as_chunks::<16>().0 {
        let mut block = Block::from(ct);
        cipher.decrypt_block(&mut block);
        out.extend(block.iter().zip(prev).map(|(b, p)| b ^ p));
        prev = ct;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_cbc_matches_nist_vector() {
        // NIST SP 800-38A F.2.5 (CBC-AES256.Encrypt), first two blocks.
        let key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
        let pt = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let ct = hex("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d");
        assert_eq!(cbc_encrypt(&key, &iv, &pt), ct);
        assert_eq!(*cbc_decrypt(&key, &iv, &ct), pt);
    }

    #[test]
    fn both_sides_agree() {
        let authenticator = SecretKey::random(&mut OsRng);
        for protocol in PinProtocol::SUPPORTED {
            let (platform_cose, platform_secret) = protocol.encapsulate(&authenticator.public_key());
            let peer = parse_cose_key(&platform_cose).unwrap();
            let secret = protocol.shared_secret(&authenticator, &peer);
            assert_eq!(*secret, *platform_secret);

            let ct = protocol.encrypt(&secret, &[7u8; 64]);
            assert_eq!(*protocol.decrypt(&platform_secret, &ct).unwrap(), vec![7u8; 64]);
            let tag = protocol.authenticate_with_secret(&platform_secret, b"msg");
            assert!(protocol.verify_with_secret(&secret, b"msg", &tag));
            assert!(!protocol.verify_with_secret(&secret, b"other", &tag));
            assert!(!protocol.verify_with_secret(&secret, b"msg", &tag[..8]));
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
