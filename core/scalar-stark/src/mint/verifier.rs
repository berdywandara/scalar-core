// Mint Claim Circuit — verifier interface. Spec §5.2.
//
// Pre-mainnet: mock verifier. Production: Winterfell STARK verifier.

use crate::mint::air::{verify_mint_claim, MintClaimPublicInput};

/// Verify a mint claim proof against public inputs and MC5 signature.
/// Spec §5.2.
pub fn verify_mint(proof: &[u8], pub_input: &MintClaimPublicInput, signature: &[u8]) -> bool {
    verify_mint_claim(proof, pub_input, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::air::build_test_mint_public_input;
    use crate::mint::prover::prove_mint;
    use crate::mint::MintClaimWitness;
    use scalar_crypto::{generate_keypair, sign_message, SPHINCS_PK_BYTES};

    #[test]
    fn test_verify_mint_valid_proof() {
        let kp = generate_keypair().unwrap();
        let witness = MintClaimWitness::new(kp.secret.clone());

        let node_id = {
            let mut id = [0u8; 32];
            id[0] = 0x09;
            id
        };
        let mut pubkey_arr = [0u8; SPHINCS_PK_BYTES];
        pubkey_arr.copy_from_slice(&kp.public[..SPHINCS_PK_BYTES]);

        let pub_input = build_test_mint_public_input(node_id, 2, 1_000_000, pubkey_arr);
        let proof = prove_mint(&witness, &pub_input).unwrap();

        // Reconstruct signature for verification
        use crate::mint::air::compute_claim_message;
        let claim_msg =
            compute_claim_message(&node_id, pub_input.epoch_id, pub_input.reward_amount_sscl);
        let sig = sign_message(&claim_msg, &kp.secret).unwrap();

        assert!(verify_mint(&proof, &pub_input, &sig));
    }

    #[test]
    fn test_verify_mint_empty_proof_fails() {
        let kp = generate_keypair().unwrap();
        let node_id = [0u8; 32];
        let mut pubkey_arr = [0u8; SPHINCS_PK_BYTES];
        pubkey_arr.copy_from_slice(&kp.public[..SPHINCS_PK_BYTES]);

        let pub_input = build_test_mint_public_input(node_id, 1, 100, pubkey_arr);
        use crate::mint::air::compute_claim_message;
        let claim_msg = compute_claim_message(&node_id, 1, 100);
        let sig = sign_message(&claim_msg, &kp.secret).unwrap();

        assert!(!verify_mint(&[], &pub_input, &sig));
    }
}
