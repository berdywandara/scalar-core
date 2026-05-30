//! scalar-crypto — Post-Quantum Cryptography Primitives
//!
//! Spec §2.1: Stack kriptografi Scalar Network.
//! Hash discipline: Poseidon2 in-circuit ONLY. BLAKE3 out-circuit ONLY.
//!
//! Modules:
//! - blake3       — BLAKE3 out-circuit hashing (spec §2.1)
//! - poseidon2    — Poseidon2 in-circuit hashing (spec §2.1)
//! - sphincs      — SPHINCS+-SHAKE-256s signatures (spec §2.1, §2.4)
//! - ml_kem       — ML-KEM-768 key encapsulation (spec §2.1)
//! - encryption   — ChaCha20-Poly1305 encryption (spec §2.1)
//! - channel      — Encrypted channel over ML-KEM (spec §2.1)
//! - hybrid_hash  — Hybrid hash utilities
//! - version      — crypto version constant (spec §2.4)

pub mod blake3;
pub mod channel;
pub mod crypto_agility;
pub mod domain;
pub mod encryption;
pub mod hybrid_hash;
pub mod hybrid_kem;
pub mod imt;
pub mod ml_kem;
pub mod poseidon2;
pub mod poseidon2_t8;
pub mod privacy;
pub mod sphincs;
pub mod version;

// Re-export SPHINCS constants for convenient access
pub use sphincs::{
    generate_keypair, public_key_from_secret, sign_message, verify_signature, ScalarKeyPair,
    SPHINCS_PK_BYTES, SPHINCS_SIG_BYTES, SPHINCS_SK_BYTES,
};

/// Unified error type untuk semua operasi kriptografi scalar-crypto.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    #[error("Kunci tidak valid atau format salah")]
    InvalidKey,

    #[error("Data tidak valid atau format salah")]
    InvalidData,

    #[error("Operasi signing gagal")]
    SigningFailed,

    /// Spec §2.4: post-sign verify gagal — kemungkinan hardware fault.
    #[error("Post-sign verification gagal — kemungkinan hardware fault (spec §2.4)")]
    SignatureVerificationFailed,

    #[error("Verification gagal")]
    VerificationFailed,

    #[error("Enkripsi gagal")]
    EncryptionFailed,

    #[error("Dekripsi gagal")]
    DecryptionFailed,

    #[error("Overflow aritmetik")]
    Overflow,
}
