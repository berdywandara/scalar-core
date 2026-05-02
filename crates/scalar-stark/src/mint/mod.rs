// File: crates/scalar-stark/src/mint/mod.rs

use zeroize::{Zeroize, ZeroizeOnDrop};

pub const VALID_MINT_CRYPTO_VERSIONS: [u8; 1] = [0x01];

/// Public Input untuk Mint Claim Circuit v5.0
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintClaimPublicInput {
    pub crypto_version: u8, // V5.0 Requirement (MC1)
    pub node_id: [u8; 32],
    pub epoch_id: u64,
    pub claim_hash: [u8; 32],
}

/// Witness WAJIB dihapus dari RAM setelah digunakan untuk keamanan memori
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MintClaimWitness {
    pub(crate) secret_key: [u8; 32],
}

/// MC1: Verifikasi crypto_version
pub fn verify_mc1_crypto_version(version: u8) -> Result<(), &'static str> {
    if VALID_MINT_CRYPTO_VERSIONS.contains(&version) {
        Ok(())
    } else {
        Err("Constraint MC1 Failed: Invalid crypto version")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mint_claim_circuit_includes_crypto_version() {
        let pi = MintClaimPublicInput {
            crypto_version: 0x01,
            node_id: [0; 32],
            epoch_id: 1,
            claim_hash: [0; 32],
        };
        assert_eq!(pi.crypto_version, 0x01);
        assert!(verify_mc1_crypto_version(pi.crypto_version).is_ok());
    }

    #[test]
    fn test_mint_claim_rejects_invalid_crypto_version() {
        assert!(verify_mc1_crypto_version(0xFF).is_err());
    }
}
