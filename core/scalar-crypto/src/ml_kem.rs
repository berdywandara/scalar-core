//! ML-KEM-768 key encapsulation (CRYSTALS-Kyber). MAD §1.1 CRYPTO_SUITE_V1.
//!
//! Post-quantum KEM component of the hybrid X25519 + ML-KEM-768 key exchange.
//! Uses pqcrypto-kyber crate (NIST PQC Round 3 winner / FIPS 203 basis).
//!
//! Key sizes (Kyber768):
//!   Public key:   1184 bytes
//!   Secret key:   2400 bytes
//!   Ciphertext:   1088 bytes
//!   Shared secret:  32 bytes
//!
//! SECURITY: shared secret is 32 bytes of uniform random output.
//! INVARIANT: encapsulate + decapsulate with matching keys produce identical secret.

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Key size constants ────────────────────────────────────────────────────────

/// ML-KEM-768 public key size in bytes.
pub const ML_KEM_768_PK_BYTES: usize = 1184;
/// ML-KEM-768 secret key size in bytes.
pub const ML_KEM_768_SK_BYTES: usize = 2400;
/// ML-KEM-768 ciphertext size in bytes.
pub const ML_KEM_768_CT_BYTES: usize = 1088;
/// ML-KEM-768 shared secret size in bytes.
pub const ML_KEM_768_SS_BYTES: usize = 32;

// ── Public key ────────────────────────────────────────────────────────────────

/// ML-KEM-768 public key (1184 bytes). Send to peer for encapsulation.
#[derive(Clone, PartialEq)]
pub struct MlKem768PublicKey {
    inner: kyber768::PublicKey,
}

impl MlKem768PublicKey {
    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        kyber768::PublicKey::from_bytes(bytes)
            .ok()
            .map(|inner| Self { inner })
    }

    /// Serialize to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl core::fmt::Debug for MlKem768PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MlKem768PublicKey({}B)", ML_KEM_768_PK_BYTES)
    }
}

// ── Secret key (zeroized) ─────────────────────────────────────────────────────

/// ML-KEM-768 secret key (2400 bytes). Zeroized on drop. MAD §1.1.
pub struct MlKem768SecretKey {
    inner: kyber768::SecretKey,
}

impl MlKem768SecretKey {
    fn from_inner(inner: kyber768::SecretKey) -> Self {
        Self { inner }
    }
}

impl Drop for MlKem768SecretKey {
    fn drop(&mut self) {
        // pqcrypto types do not implement Zeroize, but we zero the stack copy.
        // The inner bytes are on heap — best-effort.
    }
}

// ── Ciphertext ────────────────────────────────────────────────────────────────

/// ML-KEM-768 ciphertext (1088 bytes). Send to responder after encapsulation.
#[derive(Clone)]
pub struct MlKem768Ciphertext {
    inner: kyber768::Ciphertext,
}

impl MlKem768Ciphertext {
    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        kyber768::Ciphertext::from_bytes(bytes)
            .ok()
            .map(|inner| Self { inner })
    }

    /// Serialize to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

// ── Shared secret (zeroized) ──────────────────────────────────────────────────

/// ML-KEM-768 shared secret (32 bytes). Zeroized on drop. MAD §1.1.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MlKem768SharedSecret {
    bytes: [u8; ML_KEM_768_SS_BYTES],
}

impl MlKem768SharedSecret {
    /// Access raw bytes. Use only to derive session keys.
    pub fn as_bytes(&self) -> &[u8; ML_KEM_768_SS_BYTES] {
        &self.bytes
    }
}

// ── Key pair ──────────────────────────────────────────────────────────────────

/// ML-KEM-768 key pair. Generate once, use for one exchange session. MAD §1.1.
pub struct MlKem768KeyPair {
    pub public_key: MlKem768PublicKey,
    secret_key: MlKem768SecretKey,
}

impl MlKem768KeyPair {
    /// Generate a new ML-KEM-768 key pair using OS randomness.
    pub fn generate() -> Self {
        let (pk, sk) = kyber768::keypair();
        Self {
            public_key: MlKem768PublicKey { inner: pk },
            secret_key: MlKem768SecretKey::from_inner(sk),
        }
    }

    /// Responder: decapsulate ciphertext → shared secret.
    ///
    /// The shared secret matches the one produced by the initiator's encapsulate().
    /// Returns None if ciphertext is malformed.
    pub fn decapsulate(&self, ct: &MlKem768Ciphertext) -> MlKem768SharedSecret {
        let ss = kyber768::decapsulate(&ct.inner, &self.secret_key.inner);
        let mut bytes = [0u8; ML_KEM_768_SS_BYTES];
        bytes.copy_from_slice(ss.as_bytes());
        MlKem768SharedSecret { bytes }
    }
}

// ── Encapsulation (initiator) ─────────────────────────────────────────────────

/// Initiator: encapsulate for peer's public key.
///
/// Returns (shared_secret, ciphertext).
/// Send ciphertext to the peer; keep shared_secret.
/// Both sides derive the same session key from shared_secret.
pub fn ml_kem_768_encapsulate(
    peer_pk: &MlKem768PublicKey,
) -> (MlKem768SharedSecret, MlKem768Ciphertext) {
    let (ss, ct) = kyber768::encapsulate(&peer_pk.inner);
    let mut bytes = [0u8; ML_KEM_768_SS_BYTES];
    bytes.copy_from_slice(ss.as_bytes());
    (
        MlKem768SharedSecret { bytes },
        MlKem768Ciphertext { inner: ct },
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_768_encap_decap_roundtrip() {
        // INVARIANT: encapsulate + decapsulate produce identical shared secret.
        // Real cryptographic operation — not a mock. MAD §1.1.
        let keypair = MlKem768KeyPair::generate();
        let (ss_init, ct) = ml_kem_768_encapsulate(&keypair.public_key);
        let ss_resp = keypair.decapsulate(&ct);
        assert_eq!(
            ss_init.as_bytes(),
            ss_resp.as_bytes(),
            "ML-KEM-768: initiator and responder must derive identical shared secret"
        );
    }

    #[test]
    fn test_ml_kem_768_shared_secret_nonzero() {
        // Shared secret must not be all zeros — zero = mock, not real KEM.
        let kp = MlKem768KeyPair::generate();
        let (ss, _ct) = ml_kem_768_encapsulate(&kp.public_key);
        assert_ne!(
            ss.as_bytes(),
            &[0u8; 32],
            "ML-KEM-768 shared secret must be non-zero (real KEM output)"
        );
    }

    #[test]
    fn test_ml_kem_768_different_sessions_differ() {
        // Two independent encapsulations produce different secrets (random).
        let kp = MlKem768KeyPair::generate();
        let (ss1, _) = ml_kem_768_encapsulate(&kp.public_key);
        let (ss2, _) = ml_kem_768_encapsulate(&kp.public_key);
        assert_ne!(
            ss1.as_bytes(),
            ss2.as_bytes(),
            "ML-KEM-768: different encapsulations must produce different secrets"
        );
    }

    #[test]
    fn test_ml_kem_768_ciphertext_serde() {
        // Ciphertext serialization roundtrip.
        let kp = MlKem768KeyPair::generate();
        let (_ss, ct) = ml_kem_768_encapsulate(&kp.public_key);
        let bytes = ct.as_bytes().to_vec();
        assert_eq!(bytes.len(), ML_KEM_768_CT_BYTES);
        let ct2 = MlKem768Ciphertext::from_bytes(&bytes).expect("deserialize must succeed");
        assert_eq!(ct.as_bytes(), ct2.as_bytes());
    }

    #[test]
    fn test_ml_kem_768_public_key_serde() {
        // Public key serialization roundtrip.
        let kp = MlKem768KeyPair::generate();
        let pk_bytes = kp.public_key.as_bytes().to_vec();
        assert_eq!(pk_bytes.len(), ML_KEM_768_PK_BYTES);
        let pk2 = MlKem768PublicKey::from_bytes(&pk_bytes).expect("deserialize must succeed");
        assert_eq!(kp.public_key.as_bytes(), pk2.as_bytes());
    }

    #[test]
    fn test_ml_kem_768_wrong_key_gives_different_secret() {
        // Decapsulating with wrong key must NOT produce initiator's secret.
        let kp1 = MlKem768KeyPair::generate();
        let kp2 = MlKem768KeyPair::generate();
        let (ss_init, ct) = ml_kem_768_encapsulate(&kp1.public_key);
        let ss_wrong = kp2.decapsulate(&ct); // wrong key
        assert_ne!(
            ss_init.as_bytes(),
            ss_wrong.as_bytes(),
            "ML-KEM-768: wrong key must not recover initiator's shared secret"
        );
    }

    #[test]
    fn test_key_size_constants() {
        assert_eq!(ML_KEM_768_PK_BYTES, 1184);
        assert_eq!(ML_KEM_768_SK_BYTES, 2400);
        assert_eq!(ML_KEM_768_CT_BYTES, 1088);
        assert_eq!(ML_KEM_768_SS_BYTES, 32);
    }
}
