//! GAP B-001: Post-Quantum Key Encapsulation (ML-KEM-768 / Kyber768)
//! Implementasi fungsional nyata tanpa placeholder byte acak.

use crate::CryptoError;
use pqcrypto_kyber::kyber768::{decapsulate, encapsulate, keypair};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

pub const MLKEM_PUBKEY_SIZE: usize = 1184;
pub const MLKEM_CIPHERTEXT_SIZE: usize = 1088;
pub const SHARED_SECRET_SIZE: usize = 32;

pub struct MlKemKeyPair {
    pub public_key: [u8; MLKEM_PUBKEY_SIZE],
    pub secret_key: [u8; 2400],
}

// Tidak perlu parameter RNG, pqcrypto sudah menggunakan OS Entropy secara native dan aman!
pub fn generate_keypair() -> Result<MlKemKeyPair, CryptoError> {
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

// Parameter RNG juga dibuang dari enkapsulasi
pub fn encapsulate_ml_kem(
    peer_pubkey: &[u8],
) -> Result<([u8; MLKEM_CIPHERTEXT_SIZE], [u8; SHARED_SECRET_SIZE]), CryptoError> {
    let pk = PublicKey::from_bytes(peer_pubkey).map_err(|_| CryptoError::InvalidKey)?;
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
    let sk = SecretKey::from_bytes(local_privkey).map_err(|_| CryptoError::InvalidKey)?;
    let ct = Ciphertext::from_bytes(ciphertext).map_err(|_| CryptoError::InvalidData)?;

    let ss = decapsulate(&ct, &sk);

    let mut shared_secret = [0u8; SHARED_SECRET_SIZE];
    shared_secret.copy_from_slice(ss.as_bytes());

    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_keypair_generation() {
        let keypair = generate_keypair().expect("Gagal meng-generate ML-KEM keypair");

        assert_ne!(keypair.public_key, [0u8; MLKEM_PUBKEY_SIZE]);
        assert_ne!(keypair.secret_key, [0u8; 2400]);
    }

    #[test]
    fn test_ml_kem_encapsulate_decapsulate_success() {
        let keypair_a = generate_keypair().unwrap();

        let (ciphertext, shared_secret_b) = encapsulate_ml_kem(&keypair_a.public_key).expect("Gagal enkapsulasi");

        let shared_secret_a = decapsulate_ml_kem(&keypair_a.secret_key, &ciphertext).expect("Gagal dekapsulasi");

        assert_eq!(shared_secret_a, shared_secret_b, "GAP-B001: Shared secret mismatch!");
    }

    #[test]
    fn test_ml_kem_wrong_private_key_implicit_rejection() {
        let keypair_alice = generate_keypair().unwrap();
        let keypair_eve = generate_keypair().unwrap(); // Penyerang

        let (ciphertext, shared_secret_bob) = encapsulate_ml_kem(&keypair_alice.public_key).unwrap();

        let shared_secret_eve = decapsulate_ml_kem(&keypair_eve.secret_key, &ciphertext).unwrap();

        assert_ne!(shared_secret_bob, shared_secret_eve, "FATAL: Eve berhasil mendapatkan shared secret yang sama dengan kunci yang salah!");
    }

    #[test]
    fn test_ml_kem_invalid_inputs() {
        let bad_pubkey = vec![0u8; 10]; 
        let bad_ciphertext = vec![0u8; 10]; 
        let keypair = generate_keypair().unwrap();

        let enc_res = encapsulate_ml_kem(&bad_pubkey);
        assert!(enc_res.is_err(), "Harus menolak invalid public key");

        let dec_res = decapsulate_ml_kem(&keypair.secret_key, &bad_ciphertext);
        assert!(dec_res.is_err(), "Harus menolak invalid ciphertext");
    }
}