#![allow(deprecated)]
//! GAP B-001: Post-Quantum Key Encapsulation (ML-KEM-768 / Kyber768)
//! Implementasi fungsional nyata tanpa placeholder byte acak.

use crate::CryptoError;
use pqcrypto_kyber::kyber768::{decapsulate, encapsulate, keypair};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand_core::{CryptoRng, RngCore};

pub const MLKEM_PUBKEY_SIZE: usize = 1184;
pub const MLKEM_CIPHERTEXT_SIZE: usize = 1088;
pub const SHARED_SECRET_SIZE: usize = 32;

pub struct MlKemKeyPair {
    pub public_key: [u8; MLKEM_PUBKEY_SIZE],
    pub secret_key: [u8; 2400],
}

pub fn generate_keypair<R: RngCore + CryptoRng>(_rng: R) -> Result<MlKemKeyPair, CryptoError> {
    // Generate real Kyber768/ML-KEM-768 keypair
    let (pk, sk) = keypair();

    let mut public_key = [0u8; MLKEM_PUBKEY_SIZE];
    public_key.copy_from_slice(pk.as_bytes());

    let mut secret_key = [0u8; 2400];
    secret_key.copy_from_slice(sk.as_bytes());

    Ok(MlKemKeyPair {
        public_key,
        secret_key,
    })
}

pub fn encapsulate_ml_kem<R: RngCore + CryptoRng>(
    peer_pubkey: &[u8],
    _rng: R,
) -> Result<([u8; MLKEM_CIPHERTEXT_SIZE], [u8; SHARED_SECRET_SIZE]), CryptoError> {
    let pk = PublicKey::from_bytes(peer_pubkey).map_err(|_| CryptoError::InvalidData)?;
    let (ss, ct) = encapsulate(&pk);

    let mut ciphertext = [0u8; MLKEM_CIPHERTEXT_SIZE];
    ciphertext.copy_from_slice(ct.as_bytes());

    let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(ss.as_bytes());

    Ok((ciphertext, shared_secret))
}

pub fn decapsulate_ml_kem(
    local_privkey: &[u8],
    ciphertext: &[u8],
) -> Result<[u8; SHARED_SECRET_SIZE], CryptoError> {
    let sk = SecretKey::from_bytes(local_privkey).map_err(|_| CryptoError::InvalidData)?;
    let ct = Ciphertext::from_bytes(ciphertext).map_err(|_| CryptoError::InvalidData)?;

    let ss = decapsulate(&ct, &sk);

    let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(ss.as_bytes());

    Ok(shared_secret)
}
