//! SPHINCS+ Post-Quantum Signatures — Spec §2.1, §2.4
//!
//! Menggunakan SLH-DSA-SHAKE-128s (NIST FIPS 205). OSSIFIED — spec §2.1.
//!
//! Parameter 128s:
//!   SK = 64 bytes, PK = 32 bytes, Signature = 7,856 bytes.
//!   73% lebih kecil dari SHAKE-256s, keamanan setara (128-bit post-quantum).
//!
//! Spec §2.4 — Fault Detection:
//!   Setiap sign_message() WAJIB diikuti immediate verify.
//!   Jika verify gagal → return Err(CryptoError::SignatureVerificationFailed).
//!   Tujuan: deteksi hardware fault, memory corruption, atau implementasi bug
//!   sebelum signature disebarkan ke jaringan.

use crate::CryptoError;

// SLH-DSA-SHAKE-128s — OSSIFIED spec §2.1 (NIST FIPS 205 via fips205 crate).
use fips205::slh_dsa_shake_128s;
use fips205::traits::{SerDes, Signer, Verifier};

/// Ukuran public key SLH-DSA-SHAKE-128s: 32 bytes. OSSIFIED — spec §2.1.
pub const SPHINCS_PK_BYTES: usize = 32;
/// Ukuran secret key SLH-DSA-SHAKE-128s: 64 bytes. OSSIFIED — spec §2.1.
pub const SPHINCS_SK_BYTES: usize = 64;
/// Ukuran signature SLH-DSA-SHAKE-128s: 7,856 bytes. OSSIFIED — spec §2.1.
pub const SPHINCS_SIG_BYTES: usize = 7_856;

/// Pasangan kunci SLH-DSA-SHAKE-128s.
pub struct ScalarKeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

/// Generate pasangan kunci SLH-DSA-SHAKE-128s baru. Spec §2.1.
pub fn generate_keypair() -> Result<ScalarKeyPair, CryptoError> {
    // fips205 try_keygen() uses OsRng (default-rng feature). Fallible on RNG error.
    let (pk, sk) = slh_dsa_shake_128s::try_keygen().map_err(|_| CryptoError::SigningFailed)?;
    Ok(ScalarKeyPair {
        public: pk.into_bytes().to_vec(),
        secret: sk.into_bytes().to_vec(),
    })
}

/// Tandatangani pesan dengan SLH-DSA-SHAKE-128s secret key.
///
/// Spec §2.4 — Fault Detection:
/// Setelah sign, langsung verify. Jika verify gagal →
/// return Err(CryptoError::SignatureVerificationFailed).
/// Ini memastikan signature yang disebarkan ke jaringan selalu valid.
pub fn sign_message(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sk_arr: [u8; SPHINCS_SK_BYTES] =
        secret_key.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let sk = slh_dsa_shake_128s::PrivateKey::try_from_bytes(&sk_arr)
        .map_err(|_| CryptoError::InvalidKey)?;

    // Deterministic signing (hedged = false), empty context. Faithful to the prior
    // SPHINCS+ "simple" determinism; signature format/interop unchanged (FIPS 205).
    let sig = sk
        .try_sign(message, &[], false)
        .map_err(|_| CryptoError::SigningFailed)?;
    let sig_bytes = sig.to_vec();

    // Post-sign verify — spec §2.4 fault detection.
    let pk_bytes = public_key_from_secret(secret_key)?;
    if !verify_signature(message, &sig_bytes, &pk_bytes)? {
        return Err(CryptoError::SignatureVerificationFailed);
    }

    Ok(sig_bytes)
}

/// Verifikasi signature SLH-DSA-SHAKE-128s.
pub fn verify_signature(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, CryptoError> {
    let pk_arr: [u8; SPHINCS_PK_BYTES] = match public_key.try_into() {
        Ok(a) => a,
        Err(_) => return Ok(false),
    };
    let pk = match slh_dsa_shake_128s::PublicKey::try_from_bytes(&pk_arr) {
        Ok(k) => k,
        Err(_) => return Ok(false),
    };
    let sig_arr: [u8; SPHINCS_SIG_BYTES] = match signature.try_into() {
        Ok(a) => a,
        Err(_) => return Ok(false),
    };
    Ok(pk.verify(message, &sig_arr, &[]))
}

/// Ekstrak public key dari secret key SLH-DSA-SHAKE-128s.
///
/// SLH-DSA-SHAKE-128s: SK = 64 bytes, PK = 32 bytes (last 32 bytes of SK).
/// Spec §2.1.
pub fn public_key_from_secret(secret_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // SLH-DSA-SHAKE-128s SK layout (FIPS 205): [SK.seed||SK.prf||PK.seed||PK.root].
    // PublicKey = PK.seed||PK.root = last 32 bytes of the 64-byte SK.
    let sk_len = secret_key.len();
    if sk_len < SPHINCS_PK_BYTES {
        return Err(CryptoError::InvalidKey);
    }
    Ok(secret_key[sk_len - SPHINCS_PK_BYTES..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincs_algorithm_is_shake128s() {
        // OSSIFIED spec §2.1: SLH-DSA-SHAKE-128s.
        // PK=32, SK=64, Sig=7856 bytes.
        let kp = generate_keypair().unwrap();
        assert_eq!(kp.public.len(), SPHINCS_PK_BYTES, "PK harus 32 bytes");
        assert_eq!(kp.secret.len(), SPHINCS_SK_BYTES, "SK harus 64 bytes");
        let sig = sign_message(b"test", &kp.secret).unwrap();
        assert_eq!(sig.len(), SPHINCS_SIG_BYTES, "Sig harus 7856 bytes");
    }

    #[test]
    fn test_sphincs_keypair_generation() {
        let kp = generate_keypair().expect("Gagal generate keypair");
        assert!(!kp.public.is_empty());
        assert!(!kp.secret.is_empty());
        assert_ne!(kp.public, vec![0u8; kp.public.len()]);
        assert_ne!(kp.secret, vec![0u8; kp.secret.len()]);
    }

    #[test]
    fn test_sphincs_sign_and_verify_success() {
        let kp = generate_keypair().unwrap();
        let message = b"Scalar Network: Truth by Mathematics";
        let sig = sign_message(message, &kp.secret).expect("Gagal sign");
        let valid = verify_signature(message, &sig, &kp.public).unwrap();
        assert!(valid, "Signature valid harus return true");
    }

    #[test]
    fn test_sphincs_post_sign_verify_runs() {
        // Spec §2.4: sign_message harus melakukan post-sign verify.
        let kp = generate_keypair().unwrap();
        let result = sign_message(b"post-sign fault detection test", &kp.secret);
        assert!(
            result.is_ok(),
            "Post-sign verify harus lolos untuk key valid"
        );
    }

    #[test]
    fn test_sphincs_verify_tampered_message() {
        let kp = generate_keypair().unwrap();
        let sig = sign_message(b"Transfer 100 SCL to Alice", &kp.secret).unwrap();
        let valid = verify_signature(b"Transfer 100 SCL to Bob", &sig, &kp.public).unwrap();
        assert!(!valid, "Signature harus invalid pada pesan yang diubah");
    }

    #[test]
    fn test_sphincs_verify_wrong_public_key() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();
        let sig = sign_message(b"Confidential transaction", &kp1.secret).unwrap();
        let valid = verify_signature(b"Confidential transaction", &sig, &kp2.public).unwrap();
        assert!(!valid, "Signature harus invalid dengan public key berbeda");
    }

    #[test]
    fn test_sphincs_malformed_inputs() {
        let kp = generate_keypair().unwrap();
        let valid = verify_signature(b"test", &[0u8; 10], &kp.public).unwrap();
        assert!(!valid, "Signature malformed harus return false");
    }

    #[test]
    fn test_public_key_from_secret_matches_generated() {
        // Spec §2.1: PK dari SK harus identik dengan PK asli.
        let kp = generate_keypair().unwrap();
        let derived_pk = public_key_from_secret(&kp.secret).unwrap();
        assert_eq!(
            derived_pk, kp.public,
            "PK dari SK harus sama dengan PK asli"
        );
    }

    #[test]
    fn test_sign_invalid_secret_key_returns_error() {
        let result = sign_message(b"test", &[0u8; 10]);
        assert!(result.is_err(), "Secret key invalid harus return error");
    }
}
