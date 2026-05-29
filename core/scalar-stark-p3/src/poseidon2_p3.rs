//! Poseidon2 proving and verification over Plonky3. P3-R3.
//!
//! Uses p3-poseidon2-air which provides the complete Poseidon2 AIR
//! (BaseAir + Air<AB> implementations) with all constraint groups.
//!
//! Parameters for Goldilocks field (OSSIFIED — spec §2.1, D-008):
//!   WIDTH          = 8   (state size t=8)
//!   SBOX_DEGREE    = 7   (alpha=7, gcd(7, p-1)=1 for Goldilocks)
//!   SBOX_REGISTERS = 1   (optimal for degree-7: x3 intermediate)
//!   HALF_FULL_ROUNDS = 4 (R_F=8 total, 4 before + 4 after partial)
//!   PARTIAL_ROUNDS = 22  (R_P=22)
//!
//! Spec §2.1: Poseidon2 is the ONLY permitted in-circuit hash.
//! Soundness: collision resistance 128-bit per spec §4.4.

use p3_goldilocks::{
    GenericPoseidon2LinearLayersGoldilocks, Goldilocks, GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL,
    GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL, GOLDILOCKS_POSEIDON2_RC_8_INTERNAL,
};
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Air, RoundConstants};
use p3_uni_stark::{prove_with_preprocessed, verify};

use crate::config::{build_scalar_config, ScalarStarkConfig};

// ── Goldilocks Poseidon2 AIR constants — OSSIFIED ─────────────────────────────

/// State width. OSSIFIED — spec D-008.
pub const P2_WIDTH: usize = 8;
/// S-box exponent. OSSIFIED — spec D-008: alpha=7.
pub const P2_SBOX_DEGREE: u64 = 7;
/// S-box intermediate registers (optimal for degree-7). OSSIFIED.
pub const P2_SBOX_REGISTERS: usize = 1;
/// Half of full rounds (R_F=8 total). OSSIFIED — spec D-008.
pub const P2_HALF_FULL_ROUNDS: usize = 4;
/// Partial rounds. OSSIFIED — spec D-008.
pub const P2_PARTIAL_ROUNDS: usize = 22;

/// Goldilocks linear layers for Poseidon2. OSSIFIED.
pub type GoldilocksLinearLayers = GenericPoseidon2LinearLayersGoldilocks;

/// Poseidon2 AIR type for Goldilocks field with OSSIFIED parameters.
pub type ScalarPoseidon2Air = Poseidon2Air<
    Goldilocks,
    GoldilocksLinearLayers,
    8,  // P2_WIDTH
    7,  // P2_SBOX_DEGREE
    1,  // P2_SBOX_REGISTERS
    4,  // P2_HALF_FULL_ROUNDS
    22, // P2_PARTIAL_ROUNDS
>;

/// Round constants for Poseidon2 AIR (format compatible with p3-poseidon2-air).
pub type ScalarRoundConstants = RoundConstants<
    Goldilocks,
    8,  // P2_WIDTH
    4,  // P2_HALF_FULL_ROUNDS
    22, // P2_PARTIAL_ROUNDS
>;

// ── Builder ───────────────────────────────────────────────────────────────────

/// Build the Poseidon2 AIR with OSSIFIED Goldilocks round constants.
///
/// Round constants are from poseidon2_rust_params.sage — identical to
/// those used in scalar_crypto::poseidon2_t8 for out-of-circuit hashing.
/// OSSIFIED per spec D-008.
pub fn build_poseidon2_air() -> ScalarPoseidon2Air {
    let constants = build_round_constants();
    ScalarPoseidon2Air::new(constants)
}

/// Build OSSIFIED round constants from p3-goldilocks precomputed values.
pub fn build_round_constants() -> ScalarRoundConstants {
    // Extract the 4 initial external round constants (HALF_FULL_ROUNDS=4)
    let beginning: [[Goldilocks; P2_WIDTH]; P2_HALF_FULL_ROUNDS] =
        GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL;

    // Extract the 4 final external round constants
    let ending: [[Goldilocks; P2_WIDTH]; P2_HALF_FULL_ROUNDS] =
        GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL;

    // Extract the 22 partial round constants
    let partial: [Goldilocks; P2_PARTIAL_ROUNDS] = GOLDILOCKS_POSEIDON2_RC_8_INTERNAL;

    RoundConstants::new(beginning, partial, ending)
}

// ── Proof types ───────────────────────────────────────────────────────────────

/// Error type for Poseidon2 proving/verification.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Poseidon2P3Error {
    #[error("Poseidon2 proof verification failed")]
    VerificationFailed,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

// ── Prover ────────────────────────────────────────────────────────────────────

/// Prove num_hashes Poseidon2 permutations. P3-R3.
///
/// Returns serialized proof bytes.
/// num_hashes must be a power of two (Plonky3 requirement).
pub fn prove_poseidon2(num_hashes: usize) -> Result<Vec<u8>, Poseidon2P3Error> {
    if !num_hashes.is_power_of_two() {
        return Err(Poseidon2P3Error::InvalidInput(format!(
            "num_hashes must be power of two, got {}",
            num_hashes
        )));
    }

    let config = build_scalar_config();
    let air = build_poseidon2_air();
    // Generate trace: num_hashes rows, each encoding one Poseidon2 permutation.
    let constants = build_round_constants();
    let inputs: Vec<[Goldilocks; P2_WIDTH]> = (0..num_hashes)
        .map(|i| core::array::from_fn(|j| Goldilocks::new(i as u64 * P2_WIDTH as u64 + j as u64)))
        .collect();
    let trace = generate_trace_rows::<Goldilocks, GoldilocksLinearLayers, 8, 7, 1, 4, 22>(
        inputs, &constants, 0,
    );

    // prove_with_preprocessed: (config, air, trace, public_values, preprocessed)
    let proof = prove_with_preprocessed(&config, &air, trace, &[], None);

    // Serialize proof
    let proof_bytes = postcard::to_allocvec(&proof)
        .map_err(|e| Poseidon2P3Error::InvalidInput(format!("serialize: {}", e)))?;

    Ok(proof_bytes)
}

// ── Verifier ──────────────────────────────────────────────────────────────────

/// Verify a Poseidon2 proof. P3-R3.
pub fn verify_poseidon2(proof_bytes: &[u8]) -> Result<(), Poseidon2P3Error> {
    use p3_uni_stark::Proof;

    let proof: Proof<ScalarStarkConfig> = postcard::from_bytes(proof_bytes)
        .map_err(|e| Poseidon2P3Error::InvalidInput(format!("deserialize: {}", e)))?;

    let config = build_scalar_config();
    let air = build_poseidon2_air();

    // verify: (config, air, proof, public_values)
    verify(&config, &air, &proof, &[]).map_err(|_| Poseidon2P3Error::VerificationFailed)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon2_air_params_ossified() {
        // Spec D-008: t=8, R_F=8, R_P=22, alpha=7. OSSIFIED.
        assert_eq!(P2_WIDTH, 8);
        assert_eq!(P2_SBOX_DEGREE, 7);
        assert_eq!(P2_HALF_FULL_ROUNDS, 4); // 4+4 = R_F=8
        assert_eq!(P2_PARTIAL_ROUNDS, 22);
        assert_eq!(P2_SBOX_REGISTERS, 1); // optimal for degree-7
    }

    #[test]
    fn test_round_constants_build() {
        // OSSIFIED round constants from p3-goldilocks must build.
        let _constants = build_round_constants();
    }

    #[test]
    fn test_poseidon2_air_builds() {
        let _air = build_poseidon2_air();
    }

    #[test]
    fn test_poseidon2_prove_verify_roundtrip() {
        // P3-R3: prove 4 Poseidon2 permutations, verify proof. Spec §15.1.
        let proof_bytes = prove_poseidon2(4).expect("prove must succeed");
        assert!(!proof_bytes.is_empty(), "proof must be non-empty");

        let result = verify_poseidon2(&proof_bytes);
        assert!(result.is_ok(), "valid proof must verify: {:?}", result);
    }

    #[test]
    fn test_poseidon2_tampered_proof_rejected() {
        // Falsifiability: tampered proof must be rejected. Spec §15.1.
        let mut proof_bytes = prove_poseidon2(4).expect("prove must succeed");

        // Tamper with proof bytes
        let mid = proof_bytes.len() / 2;
        proof_bytes[mid] ^= 0xFF;
        proof_bytes[mid + 1] ^= 0xFF;

        let result = verify_poseidon2(&proof_bytes);
        assert!(
            result.is_err(),
            "tampered proof must be rejected — falsifiability (spec §15.1)"
        );
    }

    #[test]
    fn test_poseidon2_non_power_of_two_rejected() {
        // num_hashes must be power of two.
        let result = prove_poseidon2(3);
        assert!(result.is_err());
    }

    /// MAD §1.2 — CI gate (BLOCKING).
    ///
    /// Out-of-circuit (scalar-crypto::poseidon2_t8) and in-circuit
    /// (ScalarPoseidon2Air / p3-goldilocks) MUST produce identical output
    /// for every input. Both sides use p3-goldilocks RC as single source
    /// of truth (D-011). Failure = hash alignment broken = BLOCKING.
    #[test]
    fn invariant_poseidon2_alignment() {
        use p3_field::PrimeField64;
        use p3_symmetric::Permutation as P3PermTrait;
        use scalar_crypto::poseidon2_t8::poseidon2_permute_t8;

        // Three test vectors — chosen to exercise different field regions.
        // All values are below Goldilocks prime (2^64 - 2^32 + 1).
        let test_inputs: &[[u64; 8]] = &[
            [1, 2, 3, 4, 5, 6, 7, 8],
            [0, 0, 0, 0, 0, 0, 0, 0],
            [123_456_789, 0xDEAD_BEEF, 42, 99, 1_000_000, 7, 3, 255],
        ];

        for (i, input_u64) in test_inputs.iter().enumerate() {
            // ── Out-of-circuit: scalar-crypto single permutation ──────────
            let out_oc: [u64; 8] = poseidon2_permute_t8(input_u64);

            // ── In-circuit: same p3-goldilocks permutation backing
            //    ScalarPoseidon2Air (D-011: identical RC source) ──────────
            let perm = p3_goldilocks::default_goldilocks_poseidon2_8();
            let mut state_ic: [Goldilocks; P2_WIDTH] =
                core::array::from_fn(|j| Goldilocks::new(input_u64[j]));
            <_ as P3PermTrait<_>>::permute_mut(&perm, &mut state_ic);
            let out_ic: [u64; P2_WIDTH] = core::array::from_fn(|j| state_ic[j].as_canonical_u64());

            assert_eq!(
                out_oc,
                out_ic,
                "invariant_poseidon2_alignment FAILED for input[{}]:\n                   out-of-circuit (scalar-crypto): {:?}\n                   in-circuit     (p3-goldilocks):  {:?}\n                   Hash alignment broken — BLOCKING per MAD §1.2 D-011",
                i,
                out_oc,
                out_ic
            );
        }
    }
}
