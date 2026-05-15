// Mint Claim Circuit — prover interface. Spec §5.2.
//
// Pre-mainnet: mock prover. Production: Winterfell STARK prover.

use crate::mint::air::{prove_mint_claim, MintClaimPublicInput};
use crate::mint::MintClaimWitness;

/// Prove a mint claim using MC1+MC5 constraints. Spec §5.2.
///
/// `witness`: contains NodeKey secret key for MC5 signature.
/// `pub_input`: public inputs for the circuit.
///
/// Returns proof bytes on success.
pub fn prove_mint(
    witness: &MintClaimWitness,
    pub_input: &MintClaimPublicInput,
) -> Result<Vec<u8>, &'static str> {
    let sig = witness.sign_claim(
        &pub_input.node_id_full,
        pub_input.epoch_id,
        pub_input.reward_amount_sscl,
    )?;
    prove_mint_claim(pub_input, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mint::air::build_test_mint_public_input;
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

        let pub_input = build_test_mint_public_input(node_id, 1, 500_000, pubkey_arr);
        let proof = prove_mint(&witness, &pub_input);
        assert!(proof.is_ok(), "prove_mint must succeed with valid inputs");
        assert!(!proof.unwrap().is_empty());
    }
}
