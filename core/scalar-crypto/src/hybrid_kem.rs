//! Hybrid Key Exchange: X25519 + ML-KEM-768. MAD §1.1 CRYPTO_SUITE_V1.
//!
//! Combines classical (X25519) and post-quantum (ML-KEM-768) key exchange.
//! Combined shared secret = BLAKE3("scalar_hybrid_kem" || ss_x25519 || ss_mlkem).
//!
//! Security: breaking the hybrid requires breaking BOTH schemes.
//! If ML-KEM-768 is broken by quantum → X25519 still protects (classical).
//! If X25519 is broken classically → ML-KEM-768 still protects (PQ).
//!
//! Protocol (initiator → responder):
//!   1. Both generate X25519 + ML-KEM keypairs.
//!   2. Exchange public keys out-of-band (via existing transport).
//!   3. Initiator: X25519 DH + ML-KEM encapsulate → send ML-KEM ciphertext.
//!   4. Responder: X25519 DH + ML-KEM decapsulate → same combined secret.
//!   5. Both derive session key from combined secret.

use crate::ml_kem::{
    ml_kem_768_encapsulate, MlKem768Ciphertext, MlKem768KeyPair, MlKem768PublicKey,
};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separator for hybrid KEM combining step. MAD §1.4.
const HYBRID_KEM_DOMAIN: &[u8] = b"scalar_hybrid_kem";

// ── Combined shared secret ────────────────────────────────────────────────────

/// Combined shared secret from X25519 + ML-KEM-768. Zeroized on drop. MAD §1.1.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret {
    bytes: [u8; 32],
}

impl HybridSharedSecret {
    /// Access raw 32-byte secret. Use only to derive session keys via KDF.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// Combine X25519 and ML-KEM shared secrets via BLAKE3. MAD §1.1.
/// combined = BLAKE3(HYBRID_KEM_DOMAIN || ss_x25519 || ss_mlkem)
fn combine_secrets(ss_x25519: &[u8; 32], ss_mlkem: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HYBRID_KEM_DOMAIN);
    hasher.update(ss_x25519);
    hasher.update(ss_mlkem);
    *hasher.finalize().as_bytes()
}

// ── Initiator ─────────────────────────────────────────────────────────────────

/// Initiator output from hybrid_initiate(). Send ciphertext + x25519_pk to responder.
pub struct HybridInitiatorOutput {
    /// ML-KEM-768 ciphertext for responder to decapsulate.
    pub mlkem_ciphertext: MlKem768Ciphertext,
    /// Initiator's X25519 public key for responder's DH.
    pub x25519_public_key: X25519PublicKey,
    /// Combined shared secret (keep, do not send).
    pub shared_secret: HybridSharedSecret,
}

/// Initiator: perform hybrid key exchange with responder's public keys.
///
/// Returns: (shared_secret, mlkem_ciphertext, x25519_pk_to_send).
/// Send mlkem_ciphertext + x25519_public_key to responder.
pub fn hybrid_initiate(
    responder_x25519_pk: &X25519PublicKey,
    responder_mlkem_pk: &MlKem768PublicKey,
) -> HybridInitiatorOutput {
    // X25519: ephemeral key exchange
    let x25519_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let x25519_pk = X25519PublicKey::from(&x25519_secret);
    let ss_x25519 = x25519_secret.diffie_hellman(responder_x25519_pk);

    // ML-KEM-768: encapsulate for responder
    let (ss_mlkem, mlkem_ct) = ml_kem_768_encapsulate(responder_mlkem_pk);

    // Combine: BLAKE3(domain || ss_x25519 || ss_mlkem)
    let combined = combine_secrets(ss_x25519.as_bytes(), ss_mlkem.as_bytes());

    HybridInitiatorOutput {
        mlkem_ciphertext: mlkem_ct,
        x25519_public_key: x25519_pk,
        shared_secret: HybridSharedSecret { bytes: combined },
    }
}

// ── Responder ─────────────────────────────────────────────────────────────────

/// Responder: recover combined secret from initiator's public keys + ciphertext.
///
/// Inputs come from the initiator's HybridInitiatorOutput.
pub fn hybrid_respond(
    responder_x25519_secret: &StaticSecret,
    responder_mlkem_keypair: &MlKem768KeyPair,
    initiator_x25519_pk: &X25519PublicKey,
    mlkem_ciphertext: &MlKem768Ciphertext,
) -> HybridSharedSecret {
    // X25519: DH with initiator's ephemeral key
    let ss_x25519 = responder_x25519_secret.diffie_hellman(initiator_x25519_pk);

    // ML-KEM-768: decapsulate
    let ss_mlkem = responder_mlkem_keypair.decapsulate(mlkem_ciphertext);

    // Combine: BLAKE3(domain || ss_x25519 || ss_mlkem)
    let combined = combine_secrets(ss_x25519.as_bytes(), ss_mlkem.as_bytes());

    HybridSharedSecret { bytes: combined }
}

// ── Responder key pair ────────────────────────────────────────────────────────

/// Responder's long-term hybrid public keys. Send to initiator before exchange.
pub struct HybridPublicKeys {
    pub x25519: X25519PublicKey,
    pub mlkem: MlKem768PublicKey,
}

/// Responder's hybrid key pair for one or more sessions.
pub struct HybridKeyPair {
    pub public_keys: HybridPublicKeys,
    x25519_secret: StaticSecret,
    mlkem_keypair: MlKem768KeyPair,
}

impl HybridKeyPair {
    /// Generate a new hybrid key pair.
    pub fn generate() -> Self {
        let x25519_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let x25519_pk = X25519PublicKey::from(&x25519_secret);
        let mlkem_kp = MlKem768KeyPair::generate();
        let mlkem_pk = mlkem_kp.public_key.clone();
        Self {
            public_keys: HybridPublicKeys {
                x25519: x25519_pk,
                mlkem: mlkem_pk,
            },
            x25519_secret,
            mlkem_keypair: mlkem_kp,
        }
    }

    /// Respond to an initiator's hybrid exchange.
    pub fn respond(
        &self,
        initiator_x25519_pk: &X25519PublicKey,
        mlkem_ciphertext: &MlKem768Ciphertext,
    ) -> HybridSharedSecret {
        hybrid_respond(
            &self.x25519_secret,
            &self.mlkem_keypair,
            initiator_x25519_pk,
            mlkem_ciphertext,
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_roundtrip() {
        // MAD §1.1: initiator and responder derive identical combined secret.
        let responder = HybridKeyPair::generate();

        let init_out = hybrid_initiate(&responder.public_keys.x25519, &responder.public_keys.mlkem);

        let resp_secret =
            responder.respond(&init_out.x25519_public_key, &init_out.mlkem_ciphertext);

        assert_eq!(
            init_out.shared_secret.as_bytes(),
            resp_secret.as_bytes(),
            "Hybrid KEM: initiator and responder must derive identical combined secret"
        );
    }

    #[test]
    fn test_hybrid_kem_secret_nonzero() {
        let responder = HybridKeyPair::generate();
        let out = hybrid_initiate(&responder.public_keys.x25519, &responder.public_keys.mlkem);
        assert_ne!(
            out.shared_secret.as_bytes(),
            &[0u8; 32],
            "Hybrid KEM secret must not be all-zeros"
        );
    }

    #[test]
    fn test_hybrid_kem_two_sessions_differ() {
        // Different sessions → different combined secrets (random X25519 ephemeral).
        let responder = HybridKeyPair::generate();
        let out1 = hybrid_initiate(&responder.public_keys.x25519, &responder.public_keys.mlkem);
        let out2 = hybrid_initiate(&responder.public_keys.x25519, &responder.public_keys.mlkem);
        assert_ne!(
            out1.shared_secret.as_bytes(),
            out2.shared_secret.as_bytes(),
            "Different sessions must produce different secrets"
        );
    }

    #[test]
    fn test_hybrid_kem_wrong_responder_fails() {
        // Wrong responder key → different combined secret.
        let responder1 = HybridKeyPair::generate();
        let responder2 = HybridKeyPair::generate();

        let out = hybrid_initiate(
            &responder1.public_keys.x25519,
            &responder1.public_keys.mlkem,
        );

        let wrong_secret = responder2.respond(&out.x25519_public_key, &out.mlkem_ciphertext);

        assert_ne!(
            out.shared_secret.as_bytes(),
            wrong_secret.as_bytes(),
            "Wrong responder must not recover initiator's secret"
        );
    }

    #[test]
    fn test_hybrid_domain_separation() {
        // combine_secrets with different inputs → different outputs.
        let a = combine_secrets(&[0x01u8; 32], &[0x02u8; 32]);
        let b = combine_secrets(&[0x02u8; 32], &[0x01u8; 32]);
        assert_ne!(a, b, "Domain separation: order matters");
    }
}
