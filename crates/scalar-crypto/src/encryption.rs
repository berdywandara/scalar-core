#![allow(deprecated)]
//! GAP-C2-001: Encryption Layer (ChaCha20-Poly1305)
//! Berkolaborasi dengan ML-KEM untuk sesi yang aman.

use crate::CryptoError;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand_core::{CryptoRng, RngCore};

pub fn encrypt_payload<R: RngCore + CryptoRng>(
    shared_secret: &[u8; 32],
    plaintext: &[u8],
    mut rng: R,
) -> Result<Vec<u8>, CryptoError> {
    let key = Key::from_slice(shared_secret);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::SigningFailed)?; // Placeholder error

    let mut result = nonce_bytes.to_vec();
    result.append(&mut ciphertext);
    Ok(result)
}
