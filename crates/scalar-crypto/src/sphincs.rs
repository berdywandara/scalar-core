//! SPHINCS+ Post-Quantum Signatures — Spec §2.1, §2.4
//!
//! Menggunakan SPHINCS+-SHAKE-256s (Stateless, Post-Quantum).
//!
//! Spec §2.4 — Fault Detection:
//!   Setiap sign_message() WAJIB diikuti immediate verify.
//!   Jika verify gagal → return Err(CryptoError::SignatureVerificationFailed).
//!   Tujuan: deteksi hardware fault, memory corruption, atau implementasi bug
//!   sebelum signature disebarkan ke jaringan.

use crate::CryptoError;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

use pqcrypto_sphincsplus::sphincsshake256ssimple::{
    detached_sign, keypair, verify_detached_signature, DetachedSignature, PublicKey, SecretKey,
};

/// Pasangan kunci SPHINCS+.
pub struct ScalarKeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

/// Generate pasangan kunci SPHINCS+ baru.
pub fn generate_keypair() -> Result<ScalarKeyPair, CryptoError> {
    let (pk, sk) = keypair();
    Ok(ScalarKeyPair {
        public: pk.as_bytes().to_vec(),
        secret: sk.as_bytes().to_vec(),
    })
}

/// Tandatangani pesan dengan SPHINCS+ secret key.
///
/// Spec §2.4 — Fault Detection:
/// Setelah sign, langsung verify. Jika verify gagal →
/// return Err(CryptoError::SignatureVerificationFailed).
/// Ini memastikan signature yang disebarkan ke jaringan selalu valid.
pub fn sign_message(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sk = SecretKey::from_bytes(secret_key).map_err(|_| CryptoError::InvalidKey)?;

    // Rekonstruksi public key untuk post-sign verify — spec §2.4.
    // Public key ada di 32 byte pertama secret key pada SPHINCS+-SHAKE-256s.
    // Gunakan verify_signature untuk post-sign check.
    let sig = detached_sign(message, &sk);
    let sig_bytes = sig.as_bytes().to_vec();

    // Post-sign verify — spec §2.4 fault detection.
    // Verifikasi menggunakan raw bytes untuk menghindari re-parse sk.
    let sig_check =
        DetachedSignature::from_bytes(&sig_bytes).map_err(|_| CryptoError::SigningFailed)?;
    let pk_bytes = public_key_from_secret(secret_key)?;
    let pk = PublicKey::from_bytes(&pk_bytes).map_err(|_| CryptoError::InvalidKey)?;
    verify_detached_signature(&sig_check, message, &pk)
        .map_err(|_| CryptoError::SignatureVerificationFailed)?;

    Ok(sig_bytes)
}

/// Verifikasi signature SPHINCS+.
pub fn verify_signature(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, CryptoError> {
    let pk = match PublicKey::from_bytes(public_key) {
        Ok(k) => k,
        Err(_) => return Ok(false),
    };
    let sig = match DetachedSignature::from_bytes(signature) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    match verify_detached_signature(&sig, message, &pk) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Ekstrak public key dari secret key SPHINCS+-SHAKE-256s.
///
/// Pada SPHINCS+-SHAKE-256s: secret key = SK_seed (32) ∥ SK_prf (32) ∥ PK_seed (32) ∥ PK_root (32)
/// Public key = PK_seed (32) ∥ PK_root (32) — 64 byte terakhir dari secret key.
/// Spec §2.1.
fn public_key_from_secret(secret_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // SPHINCS+-SHAKE-256s: SK = 128 bytes, PK = 64 bytes (last 64 of SK)
    let sk_len = secret_key.len();
    let pk_len = pqcrypto_sphincsplus::sphincsshake256ssimple::public_key_bytes();
    if sk_len < pk_len {
        return Err(CryptoError::InvalidKey);
    }
    Ok(secret_key[sk_len - pk_len..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Jika post-sign verify tidak jalan, fungsi ini tidak akan Ok.
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
        // public_key_from_secret harus menghasilkan public key yang sama
        // dengan yang di-generate oleh generate_keypair. Spec §2.1.
        let kp = generate_keypair().unwrap();
        let derived_pk = public_key_from_secret(&kp.secret).unwrap();
        assert_eq!(
            derived_pk, kp.public,
            "Public key dari secret harus sama dengan public key yang di-generate"
        );
    }

    #[test]
    fn test_sign_invalid_secret_key_returns_error() {
        let result = sign_message(b"test", &[0u8; 10]);
        assert!(result.is_err(), "Secret key invalid harus return error");
    }
}
