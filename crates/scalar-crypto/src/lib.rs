pub mod channel;

#[derive(Debug)]
pub enum CryptoError {
    KeyGenerationFailed,
    SigningFailed,
    VerificationFailed,
    InvalidData,
    InvalidKey, // <-- Varian baru yang dibutuhkan oleh SPHINCS+
}

pub mod encryption;
pub mod hybrid_hash;
pub mod ml_kem;
pub mod poseidon2;
pub mod sphincs;

pub use blake3;
pub use encryption::encrypt_payload;
pub use hybrid_hash::{compute_circuit_nullifier, compute_network_nullifier};
pub use ml_kem::{decapsulate_ml_kem, encapsulate_ml_kem, MlKemKeyPair};
pub use poseidon2::hash_2_to_1;
pub use sphincs::{generate_keypair, sign_message, verify_signature, ScalarKeyPair};
