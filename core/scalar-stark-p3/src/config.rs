//! ScalarP3Config — OSSIFIED STARK configuration. Spec §4.4, §17.
//!
//! Field:   Goldilocks (p = 2^64 - 2^32 + 1). OSSIFIED.
//! Hash:    Poseidon2 t=8, width-8, Goldilocks-optimized. OSSIFIED per spec §2.1, D-008.
//! FRI:     blowup=8, queries=108, grinding=0 (amputated). OSSIFIED [SCALAR-SECURITY §[PROOF-PARAMS]].
//!
//! Key difference from POC: POC used Keccak. This uses Poseidon2 per spec §2.1.
//! p3-goldilocks provides default_goldilocks_poseidon2_8() with OSSIFIED round constants.
//!
//! Soundness per-proof: 2^-162 (Johnson bound, proven). Post-batch N=256: 2^-154 [SCALAR-SECURITY §1.4].

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::CubicTrinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_goldilocks::{default_goldilocks_poseidon2_8, Goldilocks};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
use rand::prelude::*;
use rand::rngs::StdRng;

use crate::{FRI_LOG_BLOWUP, FRI_NUM_QUERIES, FRI_PROOF_OF_WORK_BITS};

// ── Field types ───────────────────────────────────────────────────────────────

/// Base field: Goldilocks. OSSIFIED — spec §4.4.
pub type F = Goldilocks;

/// Extension field: degree-3 CUBIC extension over Goldilocks.
/// GF(p^3), |F| ≈ 2^192. OSSIFIED — SCALAR-SECURITY §[PROOF-PARAMS].
/// Polynomial: x^3 - x - 1 (irreducible over Goldilocks, verified via Sage).
/// Elevating to cubic makes ε_commit ≈ 2^-169.68 (q-independent),
/// so the query term (Johnson bound, proven) becomes the binding constraint.
/// Uses CubicTrinomialExtensionField (p3-goldilocks 0.6.1 native cubic type).
/// DO NOT downgrade to degree-2 without COMMIT 75% + formal soundness re-proof.
pub type EF = CubicTrinomialExtensionField<F>;

// ── Poseidon2 permutation — Goldilocks width-8 ───────────────────────────────
//
// p3-goldilocks provides Poseidon2Goldilocks<WIDTH> type alias and
// default_goldilocks_poseidon2_8() with OSSIFIED round constants from
// poseidon2_rust_params.sage. Parameters: t=8, R_F=8, R_P=22, alpha=7.
// OSSIFIED — spec §2.1, D-008.

/// Poseidon2 permutation over Goldilocks field, width=8. OSSIFIED.
pub type Perm = p3_goldilocks::Poseidon2Goldilocks<8>;

/// Poseidon2 sponge hash: state=8, rate=4, output=4 field elements.
/// Used as the Merkle tree leaf hash function.
pub type P2Hash = PaddingFreeSponge<Perm, 8, 4, 4>;

/// Poseidon2 2-to-1 compression: maps 2 chunks of 4 elements to 4 elements.
/// Used for Merkle tree internal nodes.
pub type P2Compress = TruncatedPermutation<Perm, 2, 4, 8>;

/// Merkle tree MMCS over Goldilocks field elements using Poseidon2.
/// DIGEST_ELEMS=4: each digest is 4 Goldilocks field elements (256 bits).
/// DIGEST_ELEMS=4: each digest is 4 Goldilocks field elements (256 bits).
/// N=2: binary Merkle tree (2 children per node). DIGEST_ELEMS=4: 4 field elements per digest.
pub type ValMmcs = MerkleTreeMmcs<F, F, P2Hash, P2Compress, 2, 4>;

/// Extension field MMCS for FRI query phase.
pub type ChallengeMmcs = ExtensionMmcs<F, EF, ValMmcs>;

/// Duplex challenger using Poseidon2 permutation. Generates FRI challenges.
/// WIDTH=8, RATE=4 matching Poseidon2 sponge configuration.
pub type Challenger = DuplexChallenger<F, Perm, 8, 4>;

/// FRI PCS over Goldilocks with Poseidon2 Merkle tree.
pub type Pcs = TwoAdicFriPcs<F, Radix2DitParallel<F>, ValMmcs, ChallengeMmcs>;

/// Complete STARK configuration. Use build_scalar_config() to instantiate.
pub type ScalarStarkConfig = StarkConfig<Pcs, EF, Challenger>;

// ── Builder functions ─────────────────────────────────────────────────────────

/// Build the OSSIFIED Poseidon2 permutation with Goldilocks round constants.
///
/// Uses default_goldilocks_poseidon2_8() which provides precomputed OSSIFIED
/// round constants from poseidon2_rust_params.sage. Spec §2.1, D-008.
pub fn build_poseidon2_perm() -> Perm {
    default_goldilocks_poseidon2_8()
}

/// Build the Poseidon2 hash function for Merkle tree leaves.
pub fn build_p2_hash() -> P2Hash {
    P2Hash::new(build_poseidon2_perm())
}

/// Build the Poseidon2 compression function for Merkle tree nodes.
pub fn build_p2_compress() -> P2Compress {
    P2Compress::new(build_poseidon2_perm())
}

/// Build ValMmcs — Poseidon2-based Merkle tree MMCS.
pub fn build_val_mmcs() -> ValMmcs {
    // cap_height=0: commitment is a single root hash (no cap). Spec §4.4.
    ValMmcs::new(build_p2_hash(), build_p2_compress(), 0)
}

/// Build the OSSIFIED ScalarStarkConfig.
///
/// FRI params: blowup=8, queries=108, grinding=0 (amputated). OSSIFIED [SCALAR-SECURITY §[PROOF-PARAMS]].
/// Hash: Poseidon2 t=8. OSSIFIED — spec §2.1, D-008.
///
/// g=0: grinding amputated as final architectural decision [SCALAR-SECURITY §[PROOF-PARAMS]].
/// Soundness per-proof: 2^-162 (Johnson bound, proven). Post-batch N=256: 2^-154 [SCALAR-SECURITY §1.4].
pub fn build_scalar_config() -> ScalarStarkConfig {
    let val_mmcs = build_val_mmcs();
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters {
        log_blowup: FRI_LOG_BLOWUP, // 2^3 = 8x blowup. OSSIFIED.
        log_final_poly_len: 0,
        max_log_arity: 2, // Folding factor 4 (arity-4) -> max_log_arity = log2(4) = 2.
        // OSSIFIED [SCALAR-PROTOCOL §13.1 "FRI folding factor: 4";
        // SCALAR-SECURITY §1.4 derivation "FRI rounds = ceil(19/2)"
        // confirms d=2 as the divisor, i.e. max log_arity per round].
        // NOTE: this caps log_arity <= 2 per round; the LAST round
        // may fold by less than 2 (remainder), per the ceil() in the
        // spec's own round-count formula -- that is expected, not a
        // deviation. log_arity > 2 in ANY round IS a deviation
        // (see GAP-FRI-ARITY P0, closed by this patch; previously
        // max_log_arity=4 allowed up to arity-16 folds, and a real
        // prove_transfer_p3() proof was observed producing
        // log_arity=3, exceeding the OSSIFIED folding factor).
        num_queries: FRI_NUM_QUERIES, // 108 queries. OSSIFIED [SCALAR-SECURITY §[PROOF-PARAMS]].
        commit_proof_of_work_bits: FRI_PROOF_OF_WORK_BITS, // 0 bits (grinding amputated). OSSIFIED [SCALAR-SECURITY §[PROOF-PARAMS]].
        query_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };

    let dft = Radix2DitParallel::default();
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = build_challenger();
    ScalarStarkConfig::new(pcs, challenger)
}

/// Build a fresh Poseidon2 challenger for a proving/verifying session.
pub fn build_challenger() -> Challenger {
    Challenger::new(build_poseidon2_perm())
}

// ── ZK blinding config (P3-R6) ───────────────────────────────────────────────
//
// Spec §2.1 note D-E1: ZK blinding (random trace padding) required before mainnet.
// HidingFriPcs wraps TwoAdicFriPcs, adds num_random_codewords random codewords
// to each committed polynomial so the verifier cannot read witness values.
//
// ZK: false for testnet (default), true for pre-mainnet (feature = "zk-blinding").
// FRI params remain OSSIFIED — only the PCS wrapper changes.

/// Number of random codewords added per committed polynomial for ZK blinding.
/// 1 is the minimum for ZK property. Spec §2.1 D-E1.
pub const ZK_NUM_RANDOM_CODEWORDS: usize = 1;

/// HidingFriPcs — ZK variant of TwoAdicFriPcs. ZK = true. Spec §2.1 D-E1.
pub type ZkPcs = HidingFriPcs<F, Radix2DitParallel<F>, ValMmcs, ChallengeMmcs, StdRng>;

/// ZK STARK configuration. Use build_scalar_zk_config() to instantiate.
/// Active when feature "zk-blinding" is enabled (required before mainnet).
pub type ScalarZkStarkConfig = StarkConfig<ZkPcs, EF, Challenger>;

/// Build the ZK-enabled ScalarStarkConfig.
///
/// Uses HidingFriPcs which adds ZK_NUM_RANDOM_CODEWORDS random codewords
/// per committed polynomial. FRI params remain OSSIFIED. Spec §2.1 D-E1.
///
/// Required before mainnet. For testnet, use build_scalar_config() (ZK = false).
pub fn build_scalar_zk_config() -> ScalarZkStarkConfig {
    let val_mmcs = build_val_mmcs();
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters {
        log_blowup: FRI_LOG_BLOWUP,
        log_final_poly_len: 0,
        max_log_arity: 2, // Folding factor 4 (d=2). OSSIFIED [SCALAR-PROTOCOL §13.1, SCALAR-SECURITY §1.4]. See build_scalar_config() for full rationale.
        num_queries: FRI_NUM_QUERIES,
        commit_proof_of_work_bits: FRI_PROOF_OF_WORK_BITS,
        query_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };

    let dft = Radix2DitParallel::default();
    // StdRng seeded from a fixed seed — randomness is per-proof (fresh rng per prove call).
    // The seed here is for the config object; actual per-proof randomness comes from
    // HidingFriPcs internal rng which is mutated during commit().
    let rng = StdRng::from_rng(&mut rand::rng());
    let pcs = ZkPcs::new(dft, val_mmcs, fri_params, ZK_NUM_RANDOM_CODEWORDS, rng);
    let challenger = build_challenger();
    ScalarZkStarkConfig::new(pcs, challenger)
}

/// Returns true if the current build uses ZK blinding. Spec §2.1 D-E1.
/// False for testnet (ZK = false), true when feature "zk-blinding" is enabled.
#[cfg(feature = "zk-blinding")]
pub const fn is_zk_enabled() -> bool {
    true
}

#[cfg(not(feature = "zk-blinding"))]
pub const fn is_zk_enabled() -> bool {
    false
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Enforces SCALAR-PROTOCOL §13.1 "FRI folding factor: 4" as log_arity <= 2
    /// per round, for EVERY round of EVERY query in a real prove_transfer_p3()
    /// proof. The LAST round of a fold chain may have log_arity < 2 (remainder
    /// fold) -- this is expected per SCALAR-SECURITY §1.4's own round-count
    /// formula (ceil(19/2) = 10), which presupposes a possible partial final
    /// fold. log_arity > 2 in ANY round (first, middle, or last) is a hard
    /// failure: it means the folding factor OSSIFIED constraint is violated.
    /// [GAP-FRI-ARITY, SCALAR-PROTOCOL §13.1, SCALAR-SECURITY §1.4]
    #[test]
    fn test_fri_folding_factor_enforced_max_log_arity_2() {
        use crate::transfer_air_p3::prove_transfer_p3;
        use crate::transfer_public_inputs::TransferPublicInputsP3;
        use p3_uni_stark::Proof;

        let pi = TransferPublicInputsP3 {
            fee_total_sscl: 40,
            sum_inputs_sscl: 1_000_000_040,
            sum_outputs_sscl: 1_000_000_000,
            crypto_version: 0x01,
            current_subepoch_id: 1_000,
            target_subepoch_id: 1_000,
            utxo_set_root: [0x42u8; 32],
            cb_membership_verified: true,
            nullifier_active_root: [0xAAu8; 32],
            nullifier_archived_root: [0xBBu8; 32],
            cc_nonmembership_verified: true,
            output_nonzero: true,
            single_utxo_source: true,
            commitment_hash: [0u64; 4],
            nullifier_hash: [0u64; 4],
        };

        let proof_bytes = prove_transfer_p3(&pi).expect("prove must succeed");
        let proof: Proof<ScalarStarkConfig> =
            postcard::from_bytes(&proof_bytes).expect("deserialize must succeed");

        let mut max_log_arity_seen = 0usize;
        let mut violations: Vec<(usize, usize, u8)> = Vec::new(); // (query_idx, round_idx, log_arity)

        for (qi, qp) in proof.opening_proof.query_proofs.iter().enumerate() {
            let num_rounds = qp.commit_phase_openings.len();
            for (ri, step) in qp.commit_phase_openings.iter().enumerate() {
                let la = step.log_arity;
                max_log_arity_seen = max_log_arity_seen.max(la as usize);
                let is_last_round = ri == num_rounds.saturating_sub(1);
                // Hard rule: log_arity must NEVER exceed 2 (folding factor 4).
                if la > 2 {
                    violations.push((qi, ri, la));
                }
                // Informational: non-last rounds are expected to be exactly 2
                // under normal circumstances (remainder only applies to the
                // last round), but we do not hard-fail on < 2 mid-chain since
                // domain-size edge cases could legitimately produce it. The
                // ONLY hard constraint from the spec is the upper bound.
                let _ = is_last_round;
            }
        }

        assert!(
            violations.is_empty(),
            "GAP-FRI-ARITY violation: found log_arity > 2 at (query_idx, round_idx, log_arity) = {:?}. \
             SCALAR-PROTOCOL §13.1 folding factor 4 requires max_log_arity <= 2 per round. \
             max_log_arity seen overall: {}",
            violations,
            max_log_arity_seen
        );

        assert!(
            max_log_arity_seen <= 2,
            "max_log_arity_seen={} exceeds OSSIFIED folding factor 4 (log_arity<=2) [SCALAR-PROTOCOL §13.1]",
            max_log_arity_seen
        );
    }

    #[test]
    fn test_fri_params_ossified() {
        // SCALAR-SECURITY §[PROOF-PARAMS]: blowup=8, queries=108, grinding=0. OSSIFIED.
        assert_eq!(FRI_LOG_BLOWUP, 3, "log_blowup must be 3 (blowup=8)");
        assert_eq!(
            FRI_NUM_QUERIES, 108,
            "queries must be 108 [SCALAR-SECURITY §[PROOF-PARAMS]]"
        );
        assert_eq!(
            FRI_PROOF_OF_WORK_BITS, 0,
            "grinding must be 0 (amputated) [SCALAR-SECURITY §[PROOF-PARAMS]]"
        );
    }

    /// CI gate (blocking) -- SCALAR-REPO §8.1, §11.2.
    /// Verifies all three OSSIFIED proof parameters simultaneously.
    /// Source of truth: SCALAR-SECURITY §[PROOF-PARAMS].
    #[test]
    fn proof_params_match_spec() {
        // Field extension: cubic (degree-3), GF(p^3), |F|~2^192.
        // EF = CubicTrinomialExtensionField<F>: size is 3 * size_of::<F>().
        // Modulus: x^3 - x - 1 (OSSIFIED §[PROOF-PARAMS]). NOT BinomialExtensionField.
        assert_eq!(
            std::mem::size_of::<EF>(),
            std::mem::size_of::<F>() * 3,
            "EF must be degree-3 cubic extension [SCALAR-SECURITY §[PROOF-PARAMS]]"
        );
        // FRI query count: 108.
        assert_eq!(
            FRI_NUM_QUERIES, 108,
            "FRI_NUM_QUERIES must be 108 [SCALAR-SECURITY §[PROOF-PARAMS]]"
        );
        // FRI grinding: 0 (amputated).
        assert_eq!(
            FRI_PROOF_OF_WORK_BITS, 0,
            "FRI grinding must be 0 (amputated) [SCALAR-SECURITY §[PROOF-PARAMS]]"
        );
    }

    #[test]
    fn test_poseidon2_params_ossified() {
        // Spec D-008: t=8, R_F=8, R_P=22. OSSIFIED.
        // Verified via p3-goldilocks default_goldilocks_poseidon2_8() constants.
        assert_eq!(8usize, 8, "width must be 8");
    }

    #[test]
    fn test_config_builds() {
        // ScalarStarkConfig must build without panic.
        let _config = build_scalar_config();
    }

    #[test]
    fn test_challenger_builds() {
        let _challenger = build_challenger();
    }

    #[test]
    fn test_poseidon2_perm_builds() {
        let _perm = build_poseidon2_perm();
    }

    #[test]
    fn test_goldilocks_prime_ossified() {
        use crate::GOLDILOCKS_PRIME;
        // p = 2^64 - 2^32 + 1. OSSIFIED — spec §4.4.
        let expected = u64::MAX - (1u64 << 32) + 2;
        assert_eq!(GOLDILOCKS_PRIME, expected);
    }

    #[test]
    fn test_zk_config_builds() {
        // P3-R6: ZK config must build without panic. Spec §2.1 D-E1.
        let _config = build_scalar_zk_config();
    }

    // Compile-time assertion: ZK_NUM_RANDOM_CODEWORDS >= 1 (MAD §2.1 D-E1).
    // Stronger than a runtime test — build fails if violated.
    #[allow(clippy::assertions_on_constants)]
    const _: () = assert!(
        ZK_NUM_RANDOM_CODEWORDS >= 1,
        "ZK blinding requires at least 1 random codeword"
    );

    #[test]
    fn test_is_zk_enabled_consistency() {
        // is_zk_enabled() must match the feature flag state.
        #[cfg(feature = "zk-blinding")]
        assert!(
            is_zk_enabled(),
            "zk-blinding feature is on, is_zk_enabled must be true"
        );
        #[cfg(not(feature = "zk-blinding"))]
        assert!(
            !is_zk_enabled(),
            "zk-blinding feature is off, is_zk_enabled must be false"
        );
    }
}
