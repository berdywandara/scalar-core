//! Cryptographic primitives for Scalar Network.
//! 
//! Implements post-quantum secure signatures, KEMs, and ZK-friendly hash functions.

pub mod blake3;
pub mod ml_kem;
pub mod poseidon2;
pub mod sphincs;

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("Signature verification failed")]
    InvalidSignature,
    #[error("Key encapsulation/decapsulation failed")]
    KemError,
    #[error("Invalid parameter length")]
    InvalidLength,
}