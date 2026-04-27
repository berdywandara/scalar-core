#![allow(deprecated)]
//! GAP B-002: Encrypted Channel (ChaCha20-Poly1305)
//! Semua koneksi antar node WAJIB melalui channel ini.

use crate::CryptoError;
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand_core::{CryptoRng, RngCore};

pub struct EncryptedChannel {
    cipher: ChaCha20Poly1305,
}

impl EncryptedChannel {
    /// Inisialisasi channel setelah ML-KEM Key Exchange
    pub fn establish(shared_secret: &[u8; 32]) -> Self {
        let key = Key::from_slice(shared_secret);
        Self {
            cipher: ChaCha20Poly1305::new(key),
        }
    }

    /// Enkripsi data dengan random nonce
    pub fn send<R: RngCore + CryptoRng>(
        &self,
        data: &[u8],
        mut rng: R,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut ciphertext = self
            .cipher
            .encrypt(nonce, data)
            .map_err(|_| CryptoError::SigningFailed)?;

        let mut payload = nonce_bytes.to_vec();
        payload.append(&mut ciphertext);
        Ok(payload)
    }

    /// Dekripsi data masuk
    pub fn receive(&self, encrypted_payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if encrypted_payload.len() < 12 {
            return Err(CryptoError::InvalidData);
        }
        let nonce = Nonce::from_slice(&encrypted_payload[..12]);
        let ciphertext = &encrypted_payload[12..];

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}
