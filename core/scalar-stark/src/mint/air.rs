// Mint Claim Circuit — MC1 through MC5. Spec §5.2 v11.1-FINAL.
//
// MC1 — crypto_version verification
// MC2 — anti double-claim via mint_nullifier (enforced by MintNullifierSet)
// MC3 — supply cap enforcement (enforced by EmissionAccumulator)
// MC4 — reward validity formula (enforced by EmissionAccumulator)
// MC5 — node authorization: SLH-DSA signature verification. Spec §5.2 MC5.
//
// MC5 spec:
//   claim_message = BLAKE3(node_id_full || epoch_id_le64 || reward_amount_le64)
//   SLH_DSA_verify(NodeKey_pubkey, claim_message, sig) == TRUE
//
// Hash discipline: BLAKE3 out-circuit — spec §2.1.

use blake3::Hasher;
use scalar_crypto::verify_signature;

// ── Constants — spec §5.2 ─────────────────────────────────────────────────────

/// Valid crypto versions for Mint Claim Circuit. OSSIFIED — spec §5.2 MC1.
pub const VALID_MINT_CRYPTO_VERSIONS: [u8; 1] = [0x03];

// ── MintClaimPublicInput — spec §5.2 ─────────────────────────────────────────

/// Public inputs for Mint Claim Circuit MC1–MC5. Spec §5.2.
#[derive(Clone, Debug, PartialEq)]
pub struct MintClaimPublicInput {
    /// MC1: crypto version must be in VALID_MINT_CRYPTO_VERSIONS. Spec §5.2 MC1.
    pub crypto_version: u8,
    /// MC2: identifies which node is claiming. Spec §5.2 MC2.
    pub node_id_full: [u8; 32],
    /// MC2: epoch being claimed. Spec §5.2 MC2.
    pub epoch_id: u64,
    /// MC1/MC4: reward root from committed manifest. Spec §5.2 MC1, MC4.
    pub reward_root: [u8; 32],
    /// MC3: emission accumulator root for supply cap check. Spec §5.2 MC3.
    pub emission_accumulator_root: [u8; 32],
    /// MC2: mint nullifier = Poseidon2(Poseidon2(node_id_lo, epoch_id), domain).
    pub mint_nullifier: [u8; 32],
    /// MC4: reward amount in sSCL. Spec §5.2 MC4.
    pub reward_amount_sscl: u64,
    /// Output UTXO commitments produced by this mint. Spec §5.2.
    pub output_commitments: Vec<[u8; 32]>,
    /// MC5: NodeKey public key (SLH-DSA-SHAKE-128s, 32 bytes). Spec §5.2 MC5.
    pub node_key_pubkey: [u8; 32],
}

// ── MC5 claim_message construction — spec §5.2 MC5 ───────────────────────────

/// Compute claim_message for MC5 node authorization. Spec §5.2 MC5.
///
/// claim_message = BLAKE3(node_id_full || epoch_id_le64 || reward_amount_le64)
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.
pub fn compute_claim_message(
    node_id_full: &[u8; 32],
    epoch_id: u64,
    reward_amount_sscl: u64,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(node_id_full);
    hasher.update(&epoch_id.to_le_bytes());
    hasher.update(&reward_amount_sscl.to_le_bytes());
    *hasher.finalize().as_bytes()
}

// ── MC5 verification — spec §5.2 MC5 ─────────────────────────────────────────

/// MC5 node authorization: verify SLH-DSA signature over claim_message.
/// Spec §5.2 MC5.
///
/// Returns Ok(()) if signature is valid, Err otherwise.
pub fn verify_mc5_node_authorization(
    node_id_full: &[u8; 32],
    epoch_id: u64,
    reward_amount_sscl: u64,
    node_key_pubkey: &[u8; 32],
    signature: &[u8],
) -> Result<(), &'static str> {
    let claim_message = compute_claim_message(node_id_full, epoch_id, reward_amount_sscl);
    let valid = verify_signature(&claim_message, signature, node_key_pubkey)
        .map_err(|_| "MC5: SLH-DSA verification error")?;
    if valid {
        Ok(())
    } else {
        Err("MC5: node authorization failed — invalid SLH-DSA signature")
    }
}

// ── MC1 verification — spec §5.2 MC1 ─────────────────────────────────────────

/// MC1: verify crypto_version is valid. Spec §5.2 MC1.
pub fn verify_mc1_crypto_version(version: u8) -> Result<(), &'static str> {
    if VALID_MINT_CRYPTO_VERSIONS.contains(&version) {
        Ok(())
    } else {
        Err("MC1: invalid crypto version")
    }
}

// ── Full circuit verification MC1 + MC5 ──────────────────────────────────────

/// Verify MC1 (crypto_version) and MC5 (node authorization) constraints.
/// MC2, MC3, MC4 are enforced externally by MintNullifierSet and EmissionAccumulator.
///
/// Returns Ok(()) if all checked constraints pass.
pub fn verify_mint_constraints_mc1_mc5(
    public_input: &MintClaimPublicInput,
    signature: &[u8],
) -> Result<(), &'static str> {
    // MC1: crypto version
    verify_mc1_crypto_version(public_input.crypto_version)?;

    // MC5: node authorization
    verify_mc5_node_authorization(
        &public_input.node_id_full,
        public_input.epoch_id,
        public_input.reward_amount_sscl,
        &public_input.node_key_pubkey,
        signature,
    )?;

    Ok(())
}

// ── Mock prover/verifier (pre-mainnet placeholder) ────────────────────────────

/// Mock STARK prover for Mint Claim Circuit. Spec §5.2.
/// Production: replace with Winterfell-based proof generation.
pub fn prove_mint_claim(
    public_input: &MintClaimPublicInput,
    signature: &[u8],
) -> Result<Vec<u8>, &'static str> {
    verify_mint_constraints_mc1_mc5(public_input, signature)?;
    // Mock proof: real proof will be Winterfell STARK bytes.
    let mut proof = vec![0x5cu8; 32]; // sentinel byte 0x5c = "Scalar"
    proof.extend_from_slice(&public_input.epoch_id.to_le_bytes());
    proof.extend_from_slice(&public_input.node_id_full);
    Ok(proof)
}

/// Mock STARK verifier for Mint Claim Circuit. Spec §5.2.
/// Production: replace with Winterfell-based proof verification.
pub fn verify_mint_claim(
    proof: &[u8],
    public_input: &MintClaimPublicInput,
    signature: &[u8],
) -> bool {
    if proof.len() < 32 {
        return false;
    }
    // Check sentinel and MC1/MC5
    proof[0] == 0x5cu8 && verify_mint_constraints_mc1_mc5(public_input, signature).is_ok()
}

/// Build a test public input with valid crypto_version. For tests only.
pub fn build_test_mint_public_input(
    node_id: [u8; 32],
    epoch_id: u64,
    reward_amount_sscl: u64,
    node_key_pubkey: [u8; 32],
) -> MintClaimPublicInput {
    MintClaimPublicInput {
        crypto_version: 0x03,
        node_id_full: node_id,
        epoch_id,
        reward_root: [0xAAu8; 32],
        emission_accumulator_root: [0xBBu8; 32],
        mint_nullifier: [0xCCu8; 32],
        reward_amount_sscl,
        output_commitments: vec![[0xDDu8; 32]],
        node_key_pubkey,
    }
}

// ── MintClaimAir (kept for compatibility) ────────────────────────────────────

#[allow(dead_code)]
pub struct MintClaimAir {
    pub_inputs: MintClaimPublicInput,
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalar_crypto::{generate_keypair, sign_message, SPHINCS_PK_BYTES};

    fn make_node_id(seed: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = seed;
        id
    }

    fn make_pubkey_array(pk_vec: &[u8]) -> [u8; 32] {
        let mut arr = [0u8; SPHINCS_PK_BYTES];
        arr.copy_from_slice(&pk_vec[..SPHINCS_PK_BYTES]);
        arr
    }

    // ── MC1 tests ─────────────────────────────────────────────────────────────

    #[test]
    fn test_mc1_valid_crypto_version() {
        assert!(verify_mc1_crypto_version(0x03).is_ok());
    }

    #[test]
    fn test_mc1_invalid_crypto_version_rejected() {
        assert!(verify_mc1_crypto_version(0x01).is_err());
        assert!(verify_mc1_crypto_version(0xFF).is_err());
        assert!(verify_mc1_crypto_version(0x00).is_err());
    }

    #[test]
    fn test_mc1_version_constant_ossified() {
        // VALID_MINT_CRYPTO_VERSIONS must contain 0x03. Spec §5.2 MC1.
        assert!(VALID_MINT_CRYPTO_VERSIONS.contains(&0x03u8));
    }

    // ── MC5 claim_message tests ───────────────────────────────────────────────

    #[test]
    fn test_claim_message_deterministic() {
        let node_id = make_node_id(0x42);
        let m1 = compute_claim_message(&node_id, 5, 1_000_000);
        let m2 = compute_claim_message(&node_id, 5, 1_000_000);
        assert_eq!(m1, m2);
    }

    #[test]
    fn test_claim_message_different_epoch() {
        let node_id = make_node_id(0x42);
        let m1 = compute_claim_message(&node_id, 5, 1_000_000);
        let m2 = compute_claim_message(&node_id, 6, 1_000_000);
        assert_ne!(m1, m2);
    }

    #[test]
    fn test_claim_message_different_reward() {
        let node_id = make_node_id(0x42);
        let m1 = compute_claim_message(&node_id, 5, 1_000_000);
        let m2 = compute_claim_message(&node_id, 5, 2_000_000);
        assert_ne!(m1, m2);
    }

    #[test]
    fn test_claim_message_different_node() {
        let m1 = compute_claim_message(&make_node_id(0x01), 5, 1_000_000);
        let m2 = compute_claim_message(&make_node_id(0x02), 5, 1_000_000);
        assert_ne!(m1, m2);
    }

    #[test]
    fn test_claim_message_nonzero() {
        let m = compute_claim_message(&[0u8; 32], 0, 0);
        assert_ne!(m, [0u8; 32]);
    }

    // ── MC5 authorization tests ───────────────────────────────────────────────

    #[test]
    fn test_mc5_valid_signature_accepted() {
        // Generate real SLH-DSA keypair and sign claim_message.
        let kp = generate_keypair().unwrap();
        let node_id = make_node_id(0x01);
        let epoch_id = 3u64;
        let reward = 500_000u64;

        let claim_msg = compute_claim_message(&node_id, epoch_id, reward);
        let sig = sign_message(&claim_msg, &kp.secret).unwrap();
        let pubkey = make_pubkey_array(&kp.public);

        let result = verify_mc5_node_authorization(&node_id, epoch_id, reward, &pubkey, &sig);
        assert!(result.is_ok(), "Valid SLH-DSA signature must pass MC5");
    }

    #[test]
    fn test_mc5_wrong_signature_rejected() {
        let kp = generate_keypair().unwrap();
        let node_id = make_node_id(0x01);

        // Sign with correct message, then verify against different params
        let claim_msg = compute_claim_message(&node_id, 3, 500_000);
        let sig = sign_message(&claim_msg, &kp.secret).unwrap();
        let pubkey = make_pubkey_array(&kp.public);

        // Wrong epoch_id
        let result = verify_mc5_node_authorization(&node_id, 99, 500_000, &pubkey, &sig);
        assert!(result.is_err(), "Wrong epoch must fail MC5");
    }

    #[test]
    fn test_mc5_wrong_pubkey_rejected() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();
        let node_id = make_node_id(0x01);
        let epoch_id = 3u64;
        let reward = 500_000u64;

        let claim_msg = compute_claim_message(&node_id, epoch_id, reward);
        let sig = sign_message(&claim_msg, &kp1.secret).unwrap();
        // Wrong pubkey
        let wrong_pubkey = make_pubkey_array(&kp2.public);

        let result = verify_mc5_node_authorization(&node_id, epoch_id, reward, &wrong_pubkey, &sig);
        assert!(result.is_err(), "Wrong pubkey must fail MC5");
    }

    #[test]
    fn test_mc5_tampered_reward_rejected() {
        let kp = generate_keypair().unwrap();
        let node_id = make_node_id(0x01);
        let epoch_id = 3u64;

        // Sign with reward=500_000, verify with reward=999_999
        let claim_msg = compute_claim_message(&node_id, epoch_id, 500_000);
        let sig = sign_message(&claim_msg, &kp.secret).unwrap();
        let pubkey = make_pubkey_array(&kp.public);

        let result = verify_mc5_node_authorization(&node_id, epoch_id, 999_999, &pubkey, &sig);
        assert!(result.is_err(), "Tampered reward must fail MC5");
    }

    // ── Full circuit MC1+MC5 tests ─────────────────────────────────────────────

    #[test]
    fn test_full_circuit_mc1_mc5_valid() {
        let kp = generate_keypair().unwrap();
        let node_id = make_node_id(0x01);
        let epoch_id = 1u64;
        let reward = 1_000_000u64;

        let pubkey_arr = make_pubkey_array(&kp.public);
        let pub_input = build_test_mint_public_input(node_id, epoch_id, reward, pubkey_arr);

        let claim_msg = compute_claim_message(&node_id, epoch_id, reward);
        let sig = sign_message(&claim_msg, &kp.secret).unwrap();

        assert!(
            verify_mint_constraints_mc1_mc5(&pub_input, &sig).is_ok(),
            "Valid MC1+MC5 must pass"
        );
    }

    #[test]
    fn test_full_circuit_bad_crypto_version_fails() {
        let kp = generate_keypair().unwrap();
        let node_id = make_node_id(0x01);
        let pubkey_arr = make_pubkey_array(&kp.public);

        let mut pub_input = build_test_mint_public_input(node_id, 1, 1_000_000, pubkey_arr);
        pub_input.crypto_version = 0xFF; // bad version

        let claim_msg = compute_claim_message(&node_id, 1, 1_000_000);
        let sig = sign_message(&claim_msg, &kp.secret).unwrap();

        assert!(
            verify_mint_constraints_mc1_mc5(&pub_input, &sig).is_err(),
            "Bad crypto version must fail MC1"
        );
    }

    // ── Mock prove/verify roundtrip ───────────────────────────────────────────

    #[test]
    fn test_prove_verify_roundtrip() {
        let kp = generate_keypair().unwrap();
        let node_id = make_node_id(0x02);
        let epoch_id = 5u64;
        let reward = 250_000u64;

        let pubkey_arr = make_pubkey_array(&kp.public);
        let pub_input = build_test_mint_public_input(node_id, epoch_id, reward, pubkey_arr);
        let claim_msg = compute_claim_message(&node_id, epoch_id, reward);
        let sig = sign_message(&claim_msg, &kp.secret).unwrap();

        let proof = prove_mint_claim(&pub_input, &sig).unwrap();
        assert!(
            verify_mint_claim(&proof, &pub_input, &sig),
            "Proof must verify after prove"
        );
    }

    #[test]
    fn test_empty_proof_rejected() {
        let kp = generate_keypair().unwrap();
        let node_id = make_node_id(0x01);
        let pubkey_arr = make_pubkey_array(&kp.public);
        let pub_input = build_test_mint_public_input(node_id, 1, 1_000_000, pubkey_arr);
        let claim_msg = compute_claim_message(&node_id, 1, 1_000_000);
        let sig = sign_message(&claim_msg, &kp.secret).unwrap();

        assert!(
            !verify_mint_claim(&[], &pub_input, &sig),
            "Empty proof must be rejected"
        );
    }
}
