// File: crates/scalar-crypto/src/ml_kem.rs

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Private Key ML-KEM v5.0
/// WAJIB dihapus dari RAM setelah digunakan (Keamanan Memori STARK)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKemPrivateKey {
    pub(crate) secret_bytes: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemPublicKey {
    pub pub_bytes: [u8; 32],
}

impl MlKemPrivateKey {
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret_bytes: secret,
        }
    }

    pub fn encapsulate(&self, _pub_key: &MlKemPublicKey) -> [u8; 32] {
        // Mock eksekusi ML-KEM
        [0u8; 32]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_instantiation_and_zeroize_trait() {
        let pk = MlKemPrivateKey::new([1u8; 32]);
        assert_eq!(pk.secret_bytes[0], 1);
        // Trait ZeroizeOnDrop akan otomatis membersihkan memori saat `pk` keluar dari scope
    }
}
