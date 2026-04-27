//! mint — MINT_CLAIM_CIRCUIT module
//! Spesifikasi: Scalar_Master_Technical_Spec.docx §B.2

pub mod air;
pub mod prover;
pub mod verifier;

pub use air::MintClaimPublicInputs;
pub use prover::{
    compute_mint_nullifier, generate_mint_proof, validate_mint_inputs, MintClaimPrivateInputs,
};
pub use verifier::verify_mint_proof;

#[cfg(test)]
mod tests {
    use super::*;

    fn node(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    fn make_pub(
        epoch_id: u64,
        node_id: &[u8; 32],
        reward_root: u64,
        total_minted: u64,
        output_count: u64,
    ) -> MintClaimPublicInputs {
        MintClaimPublicInputs {
            epoch_id,
            reward_root,
            emission_accumulator_root: total_minted,
            mint_nullifier: compute_mint_nullifier(node_id, epoch_id),
            output_count,
        }
    }

    fn make_priv(
        node_id: [u8; 32],
        reward_amount: u64,
        output_values: Vec<u64>,
    ) -> MintClaimPrivateInputs {
        MintClaimPrivateInputs {
            node_id,
            node_key: [0u8; 32],
            reward_amount,
            reward_merkle_path: vec![[0u8; 32]; 32],
            output_secrets: output_values.iter().map(|_| 42u64).collect(),
            output_values,
        }
    }

    // ── MC2: Nullifier ────────────────────────────────────────────────

    #[test]
    fn test_nullifier_deterministic() {
        let n = node(1);
        assert_eq!(compute_mint_nullifier(&n, 0), compute_mint_nullifier(&n, 0));
    }

    #[test]
    fn test_nullifier_unique_per_epoch() {
        let n = node(1);
        assert_ne!(compute_mint_nullifier(&n, 0), compute_mint_nullifier(&n, 1));
    }

    #[test]
    fn test_nullifier_unique_per_node() {
        assert_ne!(
            compute_mint_nullifier(&node(1), 0),
            compute_mint_nullifier(&node(2), 0)
        );
    }

    // ── Validasi MC1–MC5 ──────────────────────────────────────────────

    #[test]
    fn test_validate_ok() {
        let n = node(1);
        let pub_i = make_pub(0, &n, 999, 0, 1);
        let prv_i = make_priv(n, 1_000_000, vec![1_000_000]);
        assert!(validate_mint_inputs(&prv_i, &pub_i, 0).is_ok());
    }

    #[test]
    fn test_mc2_nullifier_mismatch() {
        let n = node(1);
        let mut pub_i = make_pub(0, &n, 999, 0, 1);
        pub_i.mint_nullifier = 0xDEADBEEF;
        let prv_i = make_priv(n, 1_000_000, vec![500_000]);
        assert!(validate_mint_inputs(&prv_i, &pub_i, 0).is_err());
    }

    #[test]
    fn test_mc3_supply_cap_exceeded() {
        use scalar_emission::accumulator::S_E_SSCL;
        let n = node(2);
        let pub_i = make_pub(0, &n, 999, S_E_SSCL - 100, 1);
        let prv_i = make_priv(n, 200, vec![200]);
        assert!(validate_mint_inputs(&prv_i, &pub_i, S_E_SSCL - 100).is_err());
    }

    #[test]
    fn test_mc5_output_exceeds_reward() {
        let n = node(3);
        let pub_i = make_pub(0, &n, 999, 0, 1);
        let prv_i = make_priv(n, 1_000, vec![1_001]);
        assert!(validate_mint_inputs(&prv_i, &pub_i, 0).is_err());
    }

    #[test]
    fn test_mc5_output_equal_reward_ok() {
        let n = node(4);
        let pub_i = make_pub(0, &n, 999, 0, 2);
        let prv_i = make_priv(n, 1_000, vec![600, 400]);
        assert!(validate_mint_inputs(&prv_i, &pub_i, 0).is_ok());
    }

    #[test]
    fn test_mc4_no_outputs_rejected() {
        let n = node(5);
        let pub_i = make_pub(0, &n, 999, 0, 0);
        let prv_i = make_priv(n, 1_000, vec![]);
        assert!(validate_mint_inputs(&prv_i, &pub_i, 0).is_err());
    }

    // ── Prove + Verify roundtrip ──────────────────────────────────────

    #[test]
    fn test_prove_and_verify_roundtrip() {
        let n = node(10);
        let pub_i = make_pub(0, &n, 12345, 0, 1);
        let prv_i = make_priv(n, 10_000_000, vec![10_000_000]);

        let proof =
            generate_mint_proof(&prv_i, pub_i.clone(), 0).expect("Proof generation harus berhasil");
        assert!(!proof.is_empty());

        let result = verify_mint_proof(&proof, pub_i);
        assert!(result.is_ok(), "Verifikasi harus berhasil: {:?}", result);
    }

    #[test]
    fn test_verify_rejects_tampered_public_input() {
        let n = node(11);
        let pub_i = make_pub(0, &n, 12345, 0, 1);
        let prv_i = make_priv(n, 5_000, vec![5_000]);

        // Generate proof dengan pub_inputs VALID untuk node 11
        let proof = generate_mint_proof(&prv_i, pub_i, 0).expect("Proof generation harus berhasil");

        // Verifikasi dengan pub_inputs node BERBEDA (nullifier berbeda)
        let n2 = node(99);
        let tampered = make_pub(0, &n2, 12345, 0, 1);

        let result = verify_mint_proof(&proof, tampered);
        assert!(
            result.is_err(),
            "Verifikasi harus gagal dengan public input yang diubah"
        );
    }
}
