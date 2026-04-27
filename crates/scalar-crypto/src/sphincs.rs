use crate::CryptoError;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

// Menggunakan SPHINCS+ varian SHAKE-256s (Stateless, Post-Quantum)
// Sesuai dengan spesifikasi Scalar Network "SPHINCS+-SHAKE-256s"
use pqcrypto_sphincsplus::sphincsshake256ssimple::{
    detached_sign, keypair, verify_detached_signature, DetachedSignature, PublicKey, SecretKey,
};

/// Pasangan Kunci SPHINCS+ (Post-Quantum)
pub struct ScalarKeyPair {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

/// Menghasilkan pasangan kunci SPHINCS+ baru
pub fn generate_keypair() -> Result<ScalarKeyPair, CryptoError> {
    let (pk, sk) = keypair();
    Ok(ScalarKeyPair {
        public: pk.as_bytes().to_vec(),
        secret: sk.as_bytes().to_vec(),
    })
}

/// Menandatangani pesan dengan Private Key SPHINCS+
pub fn sign_message(message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    // Memparsing secret key dari byte array
    let sk = SecretKey::from_bytes(secret_key).map_err(|_| CryptoError::InvalidKey)?;

    // Menghasilkan signature terpisah (detached signature) murni dari pesan
    let sig = detached_sign(message, &sk);
    Ok(sig.as_bytes().to_vec())
}

/// Memverifikasi tanda tangan menggunakan Public Key
pub fn verify_signature(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, CryptoError> {
    // Jika format kunci publik salah, secara matematis signature tidak valid
    let pk = match PublicKey::from_bytes(public_key) {
        Ok(k) => k,
        Err(_) => return Ok(false),
    };

    // Jika format signature salah/terpotong, otomatis tidak valid
    let sig = match DetachedSignature::from_bytes(signature) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };

    // Verifikasi matematis absolut SPHINCS+
    match verify_detached_signature(&sig, message, &pk) {
        Ok(_) => Ok(true),   // Valid
        Err(_) => Ok(false), // Signature palsu atau pesan telah dimanipulasi
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sphincs_keypair_generation() {
        let keypair = generate_keypair().expect("Gagal meng-generate SPHINCS+ keypair");

        assert!(!keypair.public.is_empty());
        assert!(!keypair.secret.is_empty());
        assert_ne!(keypair.public, vec![0u8; keypair.public.len()]);
        assert_ne!(keypair.secret, vec![0u8; keypair.secret.len()]);
    }

    #[test]
    fn test_sphincs_sign_and_verify_success() {
        let keypair = generate_keypair().unwrap();
        let message = b"Scalar Network: Truth by Mathematics";

        let signature = sign_message(message, &keypair.secret).expect("Gagal menandatangani pesan");

        let is_valid = verify_signature(message, &signature, &keypair.public)
            .expect("Gagal mengeksekusi verifikasi");
        assert!(
            is_valid,
            "GAP-T02: Signature SPHINCS+ valid harus me-return true!"
        );
    }

    #[test]
    fn test_sphincs_verify_tampered_message() {
        let keypair = generate_keypair().unwrap();
        let original_message = b"Transfer 100 SCL to Alice";
        let tampered_message = b"Transfer 100 SCL to Bob";

        let signature = sign_message(original_message, &keypair.secret).unwrap();

        let is_valid = verify_signature(tampered_message, &signature, &keypair.public).unwrap();
        assert!(
            !is_valid,
            "GAP-T02 FATAL: Signature tetap valid pada pesan yang diubah!"
        );
    }

    #[test]
    fn test_sphincs_verify_wrong_public_key() {
        let keypair1 = generate_keypair().unwrap();
        let keypair2 = generate_keypair().unwrap();
        let message = b"Confidential transaction";

        let signature = sign_message(message, &keypair1.secret).unwrap();

        let is_valid = verify_signature(message, &signature, &keypair2.public).unwrap();
        assert!(
            !is_valid,
            "GAP-T02 FATAL: Signature valid dengan kunci publik yang salah!"
        );
    }

    #[test]
    fn test_sphincs_malformed_inputs() {
        let keypair = generate_keypair().unwrap();
        let message = b"Test message";
        let bad_signature = vec![0u8; 10]; // Signature terpotong

        let is_valid = verify_signature(message, &bad_signature, &keypair.public).unwrap();
        assert!(!is_valid, "Signature malformed harus me-return false");
    }
}
