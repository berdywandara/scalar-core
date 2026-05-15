// Mint Claim Circuit — public interface. Spec §5.2 v11.1-FINAL.

pub mod air;
pub mod prover;
pub mod verifier;

pub use crate::mint::air::{
    build_test_mint_public_input, compute_claim_message, prove_mint_claim,
    verify_mc1_crypto_version, verify_mc5_node_authorization, verify_mint_claim,
    verify_mint_constraints_mc1_mc5, MintClaimPublicInput, VALID_MINT_CRYPTO_VERSIONS,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Private witness for Mint Claim Circuit. Zeroized on drop. Spec §5.2.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MintClaimWitness {
    /// NodeKey secret key (SLH-DSA-SHAKE-128s, 64 bytes). Spec §5.2 MC5.
    pub(crate) node_key_secret: Vec<u8>,
}

impl MintClaimWitness {
    /// Create witness from NodeKey secret key bytes.
    pub fn new(node_key_secret: Vec<u8>) -> Self {
        Self { node_key_secret }
    }

    /// Produce the MC5 signature over claim_message. Spec §5.2 MC5.
    pub fn sign_claim(
        &self,
        node_id_full: &[u8; 32],
        epoch_id: u64,
        reward_amount_sscl: u64,
    ) -> Result<Vec<u8>, &'static str> {
        let claim_msg = compute_claim_message(node_id_full, epoch_id, reward_amount_sscl);
        scalar_crypto::sign_message(&claim_msg, &self.node_key_secret)
            .map_err(|_| "MC5: failed to sign claim_message")
    }
}

#[cfg(test)]
mod witness_tests {
    use super::*;
    use scalar_crypto::{generate_keypair, SPHINCS_PK_BYTES};

    #[test]
    fn test_witness_sign_claim_produces_valid_signature() {
        let kp = generate_keypair().unwrap();
        let witness = MintClaimWitness::new(kp.secret.clone());

        let node_id = {
            let mut id = [0u8; 32];
            id[0] = 0x07;
            id
        };
        let epoch_id = 2u64;
        let reward = 750_000u64;
        let sig = witness.sign_claim(&node_id, epoch_id, reward).unwrap();

        let mut pubkey_arr = [0u8; SPHINCS_PK_BYTES];
        pubkey_arr.copy_from_slice(&kp.public[..SPHINCS_PK_BYTES]);

        let result = verify_mc5_node_authorization(&node_id, epoch_id, reward, &pubkey_arr, &sig);
        assert!(result.is_ok(), "Witness-produced signature must pass MC5");
    }

    #[test]
    fn test_witness_zeroize_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<MintClaimWitness>();
    }
}
