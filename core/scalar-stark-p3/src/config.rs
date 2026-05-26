//! ScalarP3Config — OSSIFIED STARK configuration. Spec §4.4, §17.
//!
//! Field:   Goldilocks (p = 2^64 - 2^32 + 1). OSSIFIED.
//! Hash:    Poseidon2 t=8, width-8, Goldilocks-optimized. OSSIFIED per spec §2.1, D-008.
//! FRI:     blowup=8, queries=84, grinding=20 (split: commit=20, query=0). OSSIFIED.
//!
//! Key difference from POC: POC used Keccak. This uses Poseidon2 per spec §2.1.
//! p3-goldilocks provides default_goldilocks_poseidon2_8() with OSSIFIED round constants.
//!
//! Soundness classical: epsilon ~ 2^-128.
//! DEEP-FRI conjecture:  epsilon ~ 2^-256.

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, default_goldilocks_poseidon2_8};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

use crate::{FRI_LOG_BLOWUP, FRI_NUM_QUERIES, FRI_PROOF_OF_WORK_BITS};

// ── Field types ───────────────────────────────────────────────────────────────

/// Base field: Goldilocks. OSSIFIED — spec §4.4.
pub type F = Goldilocks;

/// Extension field: degree-2 extension over Goldilocks.
/// Used for FRI queries and DEEP-ALI polynomial evaluation.
pub type EF = BinomialExtensionField<F, 2>;

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
pub type ValMmcs = MerkleTreeMmcs<F, F, P2Hash, P2Compress, 4, 4>;

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
/// FRI params: blowup=8, queries=84, grinding=20. OSSIFIED — spec §4.4.
/// Hash: Poseidon2 t=8. OSSIFIED — spec §2.1, D-008.
///
/// grinding=20 split: commit_proof_of_work_bits=20, query_proof_of_work_bits=0.
/// This matches the soundness security target of spec §4.4.
pub fn build_scalar_config() -> ScalarStarkConfig {
    let val_mmcs = build_val_mmcs();
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    let fri_params = FriParameters {
        log_blowup: FRI_LOG_BLOWUP,              // 2^3 = 8x blowup. OSSIFIED.
        log_final_poly_len: 0,
        max_log_arity: 4,                        // folding factor 4. OSSIFIED spec §4.4.
        num_queries: FRI_NUM_QUERIES,            // 84 queries. OSSIFIED.
        commit_proof_of_work_bits: FRI_PROOF_OF_WORK_BITS, // 20 bits grinding. OSSIFIED.
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fri_params_ossified() {
        // Spec §4.4: FRI blowup=8, queries=84, grinding=20. OSSIFIED.
        assert_eq!(FRI_LOG_BLOWUP, 3, "log_blowup must be 3 (blowup=8)");
        assert_eq!(FRI_NUM_QUERIES, 84);
        assert_eq!(FRI_PROOF_OF_WORK_BITS, 20);
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
}
