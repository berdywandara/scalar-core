pub mod channel;
#[derive(Debug)]
pub enum CryptoError {
    KeyGenerationFailed, SigningFailed, VerificationFailed, InvalidData,
}

pub mod sphincs;
pub mod hybrid_hash;
pub mod poseidon2;
pub mod ml_kem;
pub mod encryption;

pub use blake3;
pub use sphincs::{ScalarKeyPair, generate_keypair, sign_message, verify_signature};
pub use hybrid_hash::{compute_circuit_nullifier, compute_network_nullifier};
pub use poseidon2::hash_2_to_1;
pub use ml_kem::{MlKemKeyPair, encapsulate_ml_kem, decapsulate_ml_kem};
pub use encryption::encrypt_payload;
