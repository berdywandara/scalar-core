// Mint Claim Circuit — verifier interface. Spec §5.2.
//
// Delegates to verify_mint_proof (Winterfell-based) from mint_air.rs.
// The legacy mock (verify_mint_claim with 0x5c sentinel) has been removed. K5-03.

use crate::mint::air::MintClaimPublicInput;
use crate::mint_air::{verify_mint_proof, MintPublicInputs};

/// Verify a mint claim proof against public inputs. Spec §5.2, K5-03.
///
/// Converts legacy MintClaimPublicInput to MintPublicInputs and delegates
/// to the real Winterfell STARK verifier.
pub fn verify_mint(
    proof: &[u8],
    pub_input: &MintClaimPublicInput,
    _signature: &[u8], // MC5 is encoded in node_auth_valid via prover
) -> bool {
    let mint_pi = MintPublicInputs {
        crypto_version: pub_input.crypto_version,
        mint_nullifier_nonzero: pub_input.mint_nullifier != [0u8; 32],
        total_pou_minted_sscl: 0,
        reward_amount_sscl: pub_input.reward_amount_sscl,
        reward_nonzero: pub_input.reward_amount_sscl > 0,
        node_auth_valid: true,
    };
    verify_mint_proof(proof, &mint_pi).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::air::build_test_mint_public_input_legacy;
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

        let pub_input = build_test_mint_public_input_legacy(node_id, 2, 1_000_000, pubkey_arr);
        let proof = prove_mint(&witness, &pub_input).unwrap();

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

        let pub_input = build_test_mint_public_input_legacy(node_id, 1, 100, pubkey_arr);
        use crate::mint::air::compute_claim_message;
        let claim_msg = compute_claim_message(&node_id, 1, 100);
        let sig = sign_message(&claim_msg, &kp.secret).unwrap();

        assert!(!verify_mint(&[], &pub_input, &sig));
    }
}
