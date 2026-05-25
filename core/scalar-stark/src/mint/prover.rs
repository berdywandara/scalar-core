// Mint Claim Circuit — prover interface. Spec §5.2.
//
// Delegates to MintProver (Winterfell-based) from mint_air.rs.
// The legacy mock (prove_mint_claim with 0x5c sentinel) has been removed. K5-03.

use crate::mint::air::{verify_mc5_node_authorization, MintClaimPublicInput};
use crate::mint::MintClaimWitness;
use crate::mint_air::{MintProver, MintPublicInputs};

/// Prove a mint claim using the real Winterfell STARK prover. Spec §5.2, K5-03.
///
/// `witness`: contains NodeKey secret key for MC5 signature verification.
/// `pub_input`: legacy MintClaimPublicInput (MC1-MC5 fields).
///
/// Converts to MintPublicInputs and delegates to MintProver.
pub fn prove_mint(
    witness: &MintClaimWitness,
    pub_input: &MintClaimPublicInput,
) -> Result<Vec<u8>, &'static str> {
    // MC5: verify signature before proving
    let sig = witness.sign_claim(
        &pub_input.node_id_full,
        pub_input.epoch_id,
        pub_input.reward_amount_sscl,
    )?;
    verify_mc5_node_authorization(
        &pub_input.node_id_full,
        pub_input.epoch_id,
        pub_input.reward_amount_sscl,
        &pub_input.node_key_pubkey,
        &sig,
    )?;

    // Convert to MintPublicInputs for real AIR
    let mint_pi = MintPublicInputs {
        crypto_version: pub_input.crypto_version,
        mint_nullifier_nonzero: pub_input.mint_nullifier != [0u8; 32],
        total_pou_minted_sscl: 0, // MC3 enforced externally by EmissionAccumulator
        reward_amount_sscl: pub_input.reward_amount_sscl,
        reward_nonzero: pub_input.reward_amount_sscl > 0,
        node_auth_valid: true, // MC5 verified above
    };

    let prover = MintProver::new();
    prover
        .prove_mint(&mint_pi)
        .map_err(|_| "MintProver: proving failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::air::build_test_mint_public_input_legacy;
    use scalar_crypto::{generate_keypair, SPHINCS_PK_BYTES};

    #[test]
    fn test_prove_mint_end_to_end() {
        let kp = generate_keypair().unwrap();
        let witness = MintClaimWitness::new(kp.secret.clone());

        let node_id = {
            let mut id = [0u8; 32];
            id[0] = 0x05;
            id
        };
        let mut pubkey_arr = [0u8; SPHINCS_PK_BYTES];
        pubkey_arr.copy_from_slice(&kp.public[..SPHINCS_PK_BYTES]);

        let pub_input = build_test_mint_public_input_legacy(node_id, 1, 500_000, pubkey_arr);
        let proof = prove_mint(&witness, &pub_input);
        assert!(
            proof.is_ok(),
            "prove_mint must succeed with valid inputs: {:?}",
            proof
        );
        assert!(!proof.unwrap().is_empty());
    }
}
