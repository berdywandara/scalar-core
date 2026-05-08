// File: crates/scalar-stark/src/mint/air.rs

#[derive(Clone, Debug, PartialEq)]
pub struct MintClaimPublicInput {
    pub epoch_id: u64,
    pub reward_root: [u8; 32],
    pub emission_accumulator_root: [u8; 32],
    pub mint_nullifier: [u8; 32],
    pub output_commitments: Vec<[u8; 32]>,
    pub crypto_version: u8, // BARU — v5.0 (Konsisten dengan C9)
}

#[allow(dead_code)] // Mencegah clippy warning saat fase mock
pub struct MintClaimAir {
    pub_inputs: MintClaimPublicInput,
}

impl MintClaimAir {
    pub fn new_mock() -> Self {
        Self {
            pub_inputs: build_test_mint_public_input(),
        }
    }
}

pub fn prove_mint_claim(
    _witness: &(),
    public_input: &MintClaimPublicInput,
) -> Result<Vec<u8>, &'static str> {
    let valid_versions = [0x01]; // Diambil dari CryptoVersion Registry
    if !valid_versions.contains(&public_input.crypto_version) {
        return Err("Invalid crypto version (MC failure)");
    }

    // Mock valid proof
    Ok(vec![1, 2, 3])
}

pub fn verify_mint_claim(_proof: &[u8], public_input: &MintClaimPublicInput) -> bool {
    public_input.crypto_version == 0x01
}

pub fn build_test_mint_public_input() -> MintClaimPublicInput {
    MintClaimPublicInput {
        epoch_id: 1,
        reward_root: [1u8; 32],
        emission_accumulator_root: [2u8; 32],
        mint_nullifier: [3u8; 32],
        output_commitments: vec![[4u8; 32]],
        crypto_version: 0x01, // BARU
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_mint_witness() {}

    #[test]
    fn test_mint_claim_circuit_includes_crypto_version() {
        let public_input = MintClaimPublicInput {
            epoch_id: 1,
            reward_root: [1u8; 32],
            emission_accumulator_root: [2u8; 32],
            mint_nullifier: [3u8; 32],
            output_commitments: vec![[4u8; 32]],
            crypto_version: 0x01, // BARU
        };

        // Prove + verify dengan crypto_version field
        let witness = build_test_mint_witness();
        let proof = prove_mint_claim(&witness, &public_input).unwrap();
        assert!(verify_mint_claim(&proof, &public_input));
    }

    #[test]
    fn test_mint_claim_rejects_invalid_crypto_version() {
        let public_input = MintClaimPublicInput {
            crypto_version: 0xFF, // tidak valid
            ..build_test_mint_public_input()
        };
        let result = prove_mint_claim(&build_test_mint_witness(), &public_input);
        assert!(result.is_err());
    }
}
