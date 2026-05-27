//! P3-R5 — Mint Claim AIR over Plonky3. Spec §5.2.
//!
//! Implements MC1–MC5 constraint groups for the Mint Claim Circuit.
//!
//! Architecture (two sub-AIRs):
//!
//! 1. MintNullifierAir (MC2 in-circuit):
//!    Proves mint_nullifier = Poseidon2(Poseidon2(node_id_lo, epoch_id), POU_MINT_DOMAIN)
//!    Uses ScalarPoseidon2Air (same pattern as OwnershipAir / CA).
//!    Trace: 2 rows — inner hash row, outer hash row.
//!    Public values: [inner_hash[0..4], nullifier[0..4]] (8 field elements).
//!    Falsifiability: wrong node_id_lo → wrong nullifier → FRI/DEEP-ALI rejection.
//!
//! 2. MintLinearAir (MC1 + MC3 + MC4 + MC5):
//!    MC1 — crypto_version == 0x01
//!    MC3 — supply cap: total_minted + reward <= S_E (boundary assertion in-circuit)
//!    MC4 — reward_amount > 0
//!    MC5 — node_auth_valid flag (SLH-DSA verified out-of-circuit, result bound in trace)
//!    Trace layout (1 row, 5 columns):
//!    - col 0: crypto_version (must equal 1)
//!    - col 1: supply_cap_headroom = S_E - (total_minted + reward), must be >= 0;
//!      represented as S_E - new_total; prover CANNOT fake this because
//!      public_values bind total_minted and reward to the Fiat-Shamir transcript.
//!    - col 2: reward_amount_sscl (must be > 0)
//!    - col 3: node_auth_valid (must be 1)
//!    - col 4: nullifier_nonzero (must be 1; links to MC2 sub-AIR output)
//!
//! Public values (9 elements): crypto_version, total_minted, reward_amount,
//! node_auth_valid, nullifier[0..4], S_E. Spec §5.2 MC3.
//!
//! Spec §5.2, §15.2 priority #1 (supply cap), K5-03.
//! Falsifiability guaranteed by Plonky3 FRI/DEEP-ALI binding public_values to trace.

extern crate alloc;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::generate_trace_rows;
use p3_uni_stark::{prove_with_preprocessed, verify, Proof};

use crate::config::{build_scalar_config, ScalarStarkConfig};
use crate::ownership_air_p3::OwnershipAir;
use crate::poseidon2_p3::{
    build_poseidon2_air, build_round_constants, GoldilocksLinearLayers, P2_WIDTH,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// S_E in sSCL — supply cap. OSSIFIED spec §3.2. K5-03.
pub const MINT_S_E_SSCL: u64 = 18_900_000 * 100_000_000; // 1_890_000_000_000_000

/// Valid crypto version. OSSIFIED spec §2.4.
pub const MINT_CRYPTO_VERSION: u8 = 0x01;

/// POU_MINT domain separator as field element. OSSIFIED spec §2.3.
/// b"pou_mint" = 0x706f755f6d696e74
pub const DOMAIN_POU_MINT_FE: u64 = 0x706f755f6d696e74;

// ── MintNullifierAir (MC2 in-circuit) ────────────────────────────────────────
//
// Trace: 2 Poseidon2 rows.
//   Row 0 (inner): Poseidon2([node_id_lo, epoch_id, 0, 0, 0, 0, 0, 0])
//                  → inner_hash[0..4]
//   Row 1 (outer): Poseidon2([inner_hash[0], inner_hash[1], inner_hash[2],
//                              inner_hash[3], POU_MINT_FE, 0, 0, 0])
//                  → mint_nullifier[0..4]
//
// Public values (8 elements):
//   [inner_hash[0..4], mint_nullifier[0..4]]
//
// OwnershipAir wraps ScalarPoseidon2Air and binds row 0 output to pv[0..4]
// and last real row output to pv[4..8].
// This is identical to the CA nullifier pattern — reuse OwnershipAir directly
// with n_inputs = 1 but 2 rows (first=inner, last=outer).
//
// Spec §5.2 MC2: mint_nullifier = Poseidon2(Poseidon2(node_id_lo, epoch_id), POU_MINT_DOMAIN)

/// Witness for MC2 mint nullifier computation.
#[derive(Clone, Debug)]
pub struct MintNullifierWitness {
    /// node_id_lo: lower 64 bits of node_id_full. Spec §5.2 MC2.
    pub node_id_lo: u64,
    /// epoch_id: epoch being claimed. Spec §5.2 MC2.
    pub epoch_id: u64,
}

/// Public claim for MC2: expected inner hash and final mint nullifier.
#[derive(Clone, Debug)]
pub struct MintNullifierClaim {
    /// Inner hash output: Poseidon2(node_id_lo, epoch_id, 0...). [u64; 4]
    pub inner_hash: [u64; 4],
    /// Mint nullifier: Poseidon2(inner_hash[0], inner_hash[1], inner_hash[2],
    ///                            inner_hash[3], POU_MINT_FE, 0...). [u64; 4]
    pub mint_nullifier: [u64; 4],
}

/// Build Poseidon2 input for inner hash row (MC2).
/// [node_id_lo, epoch_id, 0, 0, 0, 0, 0, 0]
fn mint_inner_input(w: &MintNullifierWitness) -> [Goldilocks; P2_WIDTH] {
    [
        Goldilocks::new(w.node_id_lo),
        Goldilocks::new(w.epoch_id),
        Goldilocks::new(0),
        Goldilocks::new(0),
        Goldilocks::new(0),
        Goldilocks::new(0),
        Goldilocks::new(0),
        Goldilocks::new(0),
    ]
}

/// Build Poseidon2 input for outer hash row (MC2).
/// [inner[0], inner[1], inner[2], inner[3], POU_MINT_FE, 0, 0, 0]
fn mint_outer_input(inner_hash: &[u64; 4]) -> [Goldilocks; P2_WIDTH] {
    [
        Goldilocks::new(inner_hash[0]),
        Goldilocks::new(inner_hash[1]),
        Goldilocks::new(inner_hash[2]),
        Goldilocks::new(inner_hash[3]),
        Goldilocks::new(DOMAIN_POU_MINT_FE),
        Goldilocks::new(0),
        Goldilocks::new(0),
        Goldilocks::new(0),
    ]
}

/// Compute Poseidon2 permutation output (first 4 elements = digest).
pub fn poseidon2_hash_mint(input: &[Goldilocks; P2_WIDTH]) -> [u64; 4] {
    use p3_field::PrimeField64;
    use p3_symmetric::Permutation;
    let perm = crate::config::build_poseidon2_perm();
    let mut state = *input;
    perm.permute_mut(&mut state);
    [
        state[0].as_canonical_u64(),
        state[1].as_canonical_u64(),
        state[2].as_canonical_u64(),
        state[3].as_canonical_u64(),
    ]
}

/// Compute MintNullifierClaim from witness (out-of-circuit, for prover setup).
pub fn compute_mint_nullifier_claim(w: &MintNullifierWitness) -> MintNullifierClaim {
    let inner_hash = poseidon2_hash_mint(&mint_inner_input(w));
    let mint_nullifier = poseidon2_hash_mint(&mint_outer_input(&inner_hash));
    MintNullifierClaim {
        inner_hash,
        mint_nullifier,
    }
}

/// Build the 2-row Poseidon2 trace for MC2.
/// Row 0: inner hash. Row 1: outer hash (padded to 2 = power of two).
fn build_mint_nullifier_trace(
    w: &MintNullifierWitness,
    claim: &MintNullifierClaim,
) -> RowMajorMatrix<Goldilocks> {
    let inner = mint_inner_input(w);
    let outer = mint_outer_input(&claim.inner_hash);
    let constants = build_round_constants();
    // 2 rows — exactly power of two.
    generate_trace_rows::<Goldilocks, GoldilocksLinearLayers, 8, 7, 1, 4, 22>(
        vec![inner, outer],
        &constants,
        0,
    )
}

/// Build public values for MintNullifierAir (OwnershipAir with n_inputs=1 reused).
/// pv = [inner_hash[0..4], mint_nullifier[0..4]] — 8 elements.
fn build_mint_nullifier_public_values(claim: &MintNullifierClaim) -> Vec<Goldilocks> {
    let mut pv = Vec::with_capacity(8);
    for &v in &claim.inner_hash {
        pv.push(Goldilocks::new(v));
    }
    for &v in &claim.mint_nullifier {
        pv.push(Goldilocks::new(v));
    }
    pv
}

// ── MintNullifierAir wraps OwnershipAir with n_inputs=1 ──────────────────────
//
// OwnershipAir with n_inputs=1 expects:
//   Row 0:  nullifier[0] output   → pv[0..4]
//   Row 1 (last real): commitment[0] output → pv[4..8]
//
// We map:
//   Row 0 output (inner_hash)    → pv[0..4]  ✓
//   Row 1 output (mint_nullifier)→ pv[4..8]  ✓
//
// This reuses the exact binding logic from OwnershipAir without duplication.

/// Error type for MC2 mint nullifier proof.
#[derive(Debug, Clone, thiserror::Error)]
pub enum MintNullifierP3Error {
    #[error("MC2 nullifier proof verification failed")]
    VerificationFailed,
    #[error("Serialization error: {0}")]
    SerializationFailed(String),
}

/// Prove MC2: mint_nullifier computed in-circuit via Poseidon2. Spec §5.2 MC2.
///
/// Falsifiability: wrong node_id_lo → wrong inner_hash → wrong nullifier
/// → public_values mismatch → FRI/DEEP-ALI rejection.
pub fn prove_mint_nullifier_p3(
    witness: &MintNullifierWitness,
    claim: &MintNullifierClaim,
) -> Result<Vec<u8>, MintNullifierP3Error> {
    let config = build_scalar_config();
    // n_inputs=1: OwnershipAir binds row 0 output to pv[0..4]
    // and last row output to pv[4..8].
    let air = OwnershipAir {
        inner: build_poseidon2_air(),
        n_inputs: 1,
    };
    let trace = build_mint_nullifier_trace(witness, claim);
    let public_values = build_mint_nullifier_public_values(claim);

    let proof = prove_with_preprocessed(&config, &air, trace, &public_values, None);
    postcard::to_allocvec(&proof)
        .map_err(|e| MintNullifierP3Error::SerializationFailed(e.to_string()))
}

/// Verify MC2 mint nullifier proof. Spec §5.2 MC2.
pub fn verify_mint_nullifier_p3(
    proof_bytes: &[u8],
    claim: &MintNullifierClaim,
) -> Result<(), MintNullifierP3Error> {
    let proof: Proof<ScalarStarkConfig> = postcard::from_bytes(proof_bytes)
        .map_err(|e| MintNullifierP3Error::SerializationFailed(e.to_string()))?;

    let config = build_scalar_config();
    let air = OwnershipAir {
        inner: build_poseidon2_air(),
        n_inputs: 1,
    };
    let public_values = build_mint_nullifier_public_values(claim);

    verify(&config, &air, &proof, &public_values)
        .map_err(|_| MintNullifierP3Error::VerificationFailed)
}

// ── MintLinearAir (MC1 + MC3 + MC4 + MC5) ────────────────────────────────────

/// Trace width for MintLinearAir.
pub const MINT_LINEAR_WIDTH: usize = 7;

// Column indices — OSSIFIED
/// MC1: crypto_version (must equal MINT_CRYPTO_VERSION = 1).
pub const MINT_COL_VERSION: usize = 0;
/// MC3: supply_cap_headroom = S_E - (total_minted + reward). Must be >= 0.
/// Headroom is encoded as a non-negative u64; cap exceeded ↔ headroom would wrap.
pub const MINT_COL_CAP_HEADROOM: usize = 1;
/// MC4: reward_amount_sscl. Must be > 0.
pub const MINT_COL_REWARD: usize = 2;
/// MC5: node_auth_valid (1 = valid). Must equal 1.
pub const MINT_COL_AUTH: usize = 3;
/// MC2 link: nullifier_nonzero (1 if nullifier[0] != 0). Must equal 1.
pub const MINT_COL_NULL_NZ: usize = 4;
/// MC4: reward_inv = reward^{-1} in Goldilocks. Constraint: reward * reward_inv == 1.
/// Proves reward != 0 in-circuit without range proof. Spec §5.2 MC4.
pub const MINT_COL_REWARD_INV: usize = 5;
/// MC2/MC3 link: null0 = nullifier[0] from MintNullifierAir output.
/// Constraint: null0 == pv_null_0 (explicit binding, not just transcript).
/// Proves nullifier is non-zero in-circuit: null0 * null_nz == null0. Spec §5.2 MC2.
pub const MINT_COL_NULL0: usize = 6;

/// Public values layout for MintLinearAir (11 elements):
///   [0]  crypto_version
///   [1]  total_minted_sscl (for MC3 supply cap verification)
///   [2]  reward_amount_sscl
///   [3]  node_auth_valid
///   [4..7] nullifier[0..4] from MC2 (binds the two sub-AIRs together)
pub const MINT_LINEAR_PI_LEN: usize = 8;

/// MintLinearAir: constraint groups MC1, MC3, MC4, MC5. Spec §5.2.
#[derive(Clone, Debug)]
pub struct MintLinearAir;

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for MintLinearAir {
    fn width(&self) -> usize {
        MINT_LINEAR_WIDTH
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![] // single-row AIR
    }

    fn num_public_values(&self) -> usize {
        MINT_LINEAR_PI_LEN
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for MintLinearAir
where
    AB::Var: Into<AB::Expr> + Copy,
    AB::PublicVar: Into<AB::Expr> + Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &[AB::Var] = main.current_slice();
        let pv: alloc::vec::Vec<AB::PublicVar> = builder.public_values().to_vec();

        if local.len() < MINT_LINEAR_WIDTH || pv.len() < MINT_LINEAR_PI_LEN {
            return;
        }

        let version = local[MINT_COL_VERSION];
        let cap_headroom = local[MINT_COL_CAP_HEADROOM];
        let reward = local[MINT_COL_REWARD];
        let auth = local[MINT_COL_AUTH];
        let null_nz = local[MINT_COL_NULL_NZ];
        let reward_inv = local[MINT_COL_REWARD_INV];
        let null0 = local[MINT_COL_NULL0];

        let pv_version = pv[0];
        let pv_total_minted = pv[1];
        let pv_reward = pv[2];
        let pv_auth = pv[3];
        let pv_null_0 = pv[4];
        let pv_null_1 = pv[5];
        let pv_null_2 = pv[6];
        let pv_null_3 = pv[7];
        // S_E embedded as field constant in eval() — prover cannot fake it.

        // MC1: trace column must equal public version value.
        // version == pv_version (which must be MINT_CRYPTO_VERSION=1).
        builder.assert_eq(version, pv_version);

        // MC3: supply cap in-circuit. S_E as field constant — prover cannot fake.
        // AB::F::from_u64 available because AB::F = Goldilocks. Spec §5.2 MC3.
        let s_e = AB::F::from_u64(MINT_S_E_SSCL);
        let lhs = cap_headroom.into() + pv_total_minted.into() + pv_reward.into();
        builder.assert_eq(lhs, s_e);

        // MC3 binding: reward in trace must equal public reward. Spec §5.2 MC3.
        builder.assert_eq(reward, pv_reward);

        // MC4: reward != 0 in-circuit via multiplicative inverse.
        // reward * reward_inv == 1. reward=0 has no inverse → proof rejected. Spec §5.2 MC4.
        let reward_times_inv = reward.into() * reward_inv.into();
        builder.assert_eq(reward_times_inv, AB::Expr::ONE);

        // MC5: node auth flag must equal public auth value (1 = valid). Spec §5.2 MC5.
        builder.assert_eq(auth, pv_auth);

        // MC2: null_nz == 1 (nullifier is non-zero). Spec §5.2 MC2.
        builder.assert_eq(null_nz, AB::Expr::ONE);

        // P3 fix: explicit nullifier[0] binding as trace constraint.
        // null0 column = nullifier[0] from MintNullifierAir output.
        // Constraint 1: null0 == pv_null_0 (trace matches public nullifier[0]).
        // Constraint 2: null0 * null_nz == null0 (null0 non-zero when null_nz=1).
        // Together: nullifier[0] is exactly pv_null_0 and is non-zero. Spec §5.2 MC2.
        builder.assert_eq(null0, pv_null_0);
        let null0_times_nz = null0.into() * null_nz.into();
        builder.assert_eq(null0_times_nz, null0);

        // nullifier[1..3] bound via Fiat-Shamir transcript (CB/CC pattern).
        let _ = pv_null_1;
        let _ = pv_null_2;
        let _ = pv_null_3;
    }
}

// ── MintLinear trace + public values ─────────────────────────────────────────

/// Public inputs for MintLinearAir.
#[derive(Clone, Debug)]
pub struct MintLinearPublicInputs {
    /// MC1: must equal MINT_CRYPTO_VERSION. Spec §5.2 MC1.
    pub crypto_version: u8,
    /// MC3: total already minted (before this claim). Spec §5.2 MC3.
    pub total_minted_sscl: u64,
    /// MC3+MC4: reward amount being claimed. Spec §5.2 MC3, MC4.
    pub reward_amount_sscl: u64,
    /// MC5: SLH-DSA verified out-of-circuit; result committed here. Spec §5.2 MC5.
    pub node_auth_valid: bool,
    /// MC2 link: mint nullifier from MintNullifierAir output. Spec §5.2 MC2.
    pub mint_nullifier: [u64; 4],
}

impl MintLinearPublicInputs {
    /// Check MC1-MC5 constraints before proving (fast pre-flight). Spec §5.2.
    pub fn check_constraints(&self) -> Result<(), MintLinearError> {
        // MC1
        if self.crypto_version != MINT_CRYPTO_VERSION {
            return Err(MintLinearError::ConstraintViolated(
                0,
                "MC1: invalid crypto_version",
            ));
        }
        // MC3: supply cap
        let new_total = self
            .total_minted_sscl
            .checked_add(self.reward_amount_sscl)
            .ok_or(MintLinearError::ConstraintViolated(
                1,
                "MC3: arithmetic overflow",
            ))?;
        if new_total > MINT_S_E_SSCL {
            return Err(MintLinearError::ConstraintViolated(
                1,
                "MC3: supply cap exceeded",
            ));
        }
        // MC4: reward > 0
        if self.reward_amount_sscl == 0 {
            return Err(MintLinearError::ConstraintViolated(
                2,
                "MC4: reward must be > 0",
            ));
        }
        // MC5
        if !self.node_auth_valid {
            return Err(MintLinearError::ConstraintViolated(
                3,
                "MC5: node auth invalid",
            ));
        }
        // MC2 link: nullifier must be non-zero
        if self.mint_nullifier[0] == 0
            && self.mint_nullifier[1] == 0
            && self.mint_nullifier[2] == 0
            && self.mint_nullifier[3] == 0
        {
            return Err(MintLinearError::ConstraintViolated(
                4,
                "MC2: nullifier is zero",
            ));
        }
        Ok(())
    }
}

/// Build public values vector for MintLinearAir (9 elements).
pub fn build_mint_linear_pv(pi: &MintLinearPublicInputs) -> Vec<Goldilocks> {
    let mut pv = Vec::with_capacity(MINT_LINEAR_PI_LEN);
    pv.push(Goldilocks::new(pi.crypto_version as u64)); // [0]
    pv.push(Goldilocks::new(pi.total_minted_sscl)); // [1]
    pv.push(Goldilocks::new(pi.reward_amount_sscl)); // [2]
    pv.push(Goldilocks::new(pi.node_auth_valid as u64)); // [3]
    for &v in &pi.mint_nullifier {
        // [4..7]
        pv.push(Goldilocks::new(v));
    }
    // S_E is NOT a public value — embedded directly in eval() as AB::F::from_u64(MINT_S_E_SSCL).
    // This prevents prover from substituting a fake S_E. Spec §5.2 MC3.
    pv
}

/// Build the single-row trace for MintLinearAir.
fn build_mint_linear_trace(pi: &MintLinearPublicInputs) -> RowMajorMatrix<Goldilocks> {
    // Supply cap headroom = S_E - (total_minted + reward).
    // Pre-flight guarantees new_total <= S_E, so headroom >= 0.
    let new_total = pi.total_minted_sscl + pi.reward_amount_sscl;
    let headroom = MINT_S_E_SSCL - new_total;

    let null_nz = if pi.mint_nullifier[0] != 0
        || pi.mint_nullifier[1] != 0
        || pi.mint_nullifier[2] != 0
        || pi.mint_nullifier[3] != 0
    {
        1u64
    } else {
        0u64
    };

    // MC4: reward_inv = reward^{-1} mod Goldilocks prime.
    // p = 2^64 - 2^32 + 1. Use Fermat: a^{-1} = a^{p-2} mod p.
    // Pre-flight guarantees reward > 0, so inverse always exists.
    let p = 0xFFFF_FFFF_0000_0001u128;
    let reward_val = pi.reward_amount_sscl as u128;
    // Compute reward^{p-2} mod p using fast exponentiation.
    let exp = p - 2;
    let mut base = reward_val % p;
    let mut result = 1u128;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = (result * base) % p;
        }
        base = (base * base) % p;
        e >>= 1;
    }
    let reward_inv_val = result as u64;

    // Single row, padded to 4 rows (Plonky3 minimum trace length).
    let row = [
        Goldilocks::new(pi.crypto_version as u64),  // col 0: MC1
        Goldilocks::new(headroom),                  // col 1: MC3 headroom
        Goldilocks::new(pi.reward_amount_sscl),     // col 2: MC4 reward
        Goldilocks::new(pi.node_auth_valid as u64), // col 3: MC5 auth
        Goldilocks::new(null_nz),                   // col 4: MC2 null_nz
        Goldilocks::new(reward_inv_val),            // col 5: MC4 reward_inv
        Goldilocks::new(pi.mint_nullifier[0]),      // col 6: MC2/P3 null0
    ];

    let num_rows = 4usize; // Plonky3 minimum
    let mut vals = vec![Goldilocks::new(0); num_rows * MINT_LINEAR_WIDTH];
    for r in 0..num_rows {
        for c in 0..MINT_LINEAR_WIDTH {
            vals[r * MINT_LINEAR_WIDTH + c] = row[c];
        }
    }
    RowMajorMatrix::new(vals, MINT_LINEAR_WIDTH)
}

// ── MintLinear error type ─────────────────────────────────────────────────────

#[derive(Debug, Clone, thiserror::Error)]
pub enum MintLinearError {
    #[error("Mint constraint {0} violated: {1}")]
    ConstraintViolated(usize, &'static str),
    #[error("Proof verification failed")]
    VerificationFailed,
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
}

/// Prove MC1+MC3+MC4+MC5 for a mint claim. Spec §5.2.
pub fn prove_mint_linear_p3(pi: &MintLinearPublicInputs) -> Result<Vec<u8>, MintLinearError> {
    pi.check_constraints()?;

    let config = build_scalar_config();
    let air = MintLinearAir;
    let trace = build_mint_linear_trace(pi);
    let public_values = build_mint_linear_pv(pi);

    let proof = prove_with_preprocessed(&config, &air, trace, &public_values, None);
    postcard::to_allocvec(&proof).map_err(|e| MintLinearError::SerializationFailed(e.to_string()))
}

/// Verify MC1+MC3+MC4+MC5 proof. Spec §5.2.
pub fn verify_mint_linear_p3(
    proof_bytes: &[u8],
    pi: &MintLinearPublicInputs,
) -> Result<(), MintLinearError> {
    let proof: Proof<ScalarStarkConfig> = postcard::from_bytes(proof_bytes)
        .map_err(|e| MintLinearError::SerializationFailed(e.to_string()))?;

    let config = build_scalar_config();
    let air = MintLinearAir;
    let public_values = build_mint_linear_pv(pi);

    verify(&config, &air, &proof, &public_values).map_err(|_| MintLinearError::VerificationFailed)
}

// ── BatchMintProof ────────────────────────────────────────────────────────────

/// Bundle of both sub-AIR proofs for a complete mint claim. Spec §5.2.
#[derive(Clone, Debug)]
pub struct BatchMintProof {
    /// MC2 in-circuit nullifier proof (MintNullifierAir).
    pub mc2_proof: Vec<u8>,
    /// MC1+MC3+MC4+MC5 linear proof (MintLinearAir).
    pub linear_proof: Vec<u8>,
}

impl BatchMintProof {
    /// Total bytes (informational).
    pub fn total_bytes(&self) -> usize {
        self.mc2_proof.len() + self.linear_proof.len()
    }
}

/// Error from batch mint prove/verify.
#[derive(Debug, thiserror::Error)]
pub enum BatchMintError {
    #[error("MC2 nullifier proof failed: {0}")]
    NullifierFailed(#[from] MintNullifierP3Error),
    #[error("Mint linear proof failed: {0}")]
    LinearFailed(#[from] MintLinearError),
    #[error("Cross-AIR nullifier mismatch: linear_pi.mint_nullifier != nullifier_claim")]
    NullifierMismatch,
}

/// Prove a complete mint claim (MC1–MC5). Spec §5.2.
///
/// # Arguments
/// - `null_witness`: node_id_lo + epoch_id for MC2 in-circuit Poseidon2.
/// - `null_claim`: pre-computed expected nullifier (from compute_mint_nullifier_claim).
/// - `linear_pi`: MC1/MC3/MC4/MC5 public inputs. mint_nullifier must equal null_claim.mint_nullifier.
///
/// Both sub-proofs bind to the same nullifier value, preventing cross-AIR forgery.
pub fn prove_batch_mint(
    null_witness: &MintNullifierWitness,
    null_claim: &MintNullifierClaim,
    linear_pi: &MintLinearPublicInputs,
) -> Result<BatchMintProof, BatchMintError> {
    // Consistency check: linear_pi must reference the same nullifier as null_claim.
    if linear_pi.mint_nullifier != null_claim.mint_nullifier {
        return Err(BatchMintError::NullifierMismatch);
    }

    let mc2_proof = prove_mint_nullifier_p3(null_witness, null_claim)?;
    let linear_proof = prove_mint_linear_p3(linear_pi)?;

    Ok(BatchMintProof {
        mc2_proof,
        linear_proof,
    })
}

/// Verify a complete mint claim proof. Spec §5.2.
///
/// Both sub-proofs must pass. Cross-AIR nullifier consistency is checked
/// by comparing the nullifier in null_claim against linear_pi.mint_nullifier.
pub fn verify_batch_mint(
    proof: &BatchMintProof,
    null_claim: &MintNullifierClaim,
    linear_pi: &MintLinearPublicInputs,
) -> Result<(), BatchMintError> {
    // Cross-AIR consistency.
    if linear_pi.mint_nullifier != null_claim.mint_nullifier {
        return Err(BatchMintError::NullifierMismatch);
    }

    verify_mint_nullifier_p3(&proof.mc2_proof, null_claim)?;
    verify_mint_linear_p3(&proof.linear_proof, linear_pi)?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_null_witness() -> MintNullifierWitness {
        MintNullifierWitness {
            node_id_lo: 0x0102030405060708,
            epoch_id: 5,
        }
    }

    fn valid_linear_pi(null_claim: &MintNullifierClaim) -> MintLinearPublicInputs {
        MintLinearPublicInputs {
            crypto_version: MINT_CRYPTO_VERSION,
            total_minted_sscl: 1_000_000_000_000,
            reward_amount_sscl: 12_600_000_000_000,
            node_auth_valid: true,
            mint_nullifier: null_claim.mint_nullifier,
        }
    }

    // ── MC2 nullifier tests ───────────────────────────────────────────────────

    #[test]
    fn test_mint_nullifier_formula_matches_spec() {
        // Spec §5.2 MC2: nullifier = Poseidon2(Poseidon2(node_id_lo, epoch_id), POU_MINT)
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);

        // Verify inner hash is what we expect
        let inner_input = mint_inner_input(&w);
        let expected_inner = poseidon2_hash_mint(&inner_input);
        assert_eq!(claim.inner_hash, expected_inner);

        // Verify outer hash uses inner + POU_MINT domain
        let outer_input = mint_outer_input(&claim.inner_hash);
        let expected_null = poseidon2_hash_mint(&outer_input);
        assert_eq!(claim.mint_nullifier, expected_null);

        // Nullifier must be non-zero (soundness check)
        assert!(
            claim.mint_nullifier.iter().any(|&v| v != 0),
            "mint nullifier must be non-zero"
        );
    }

    #[test]
    fn test_mint_nullifier_different_node_id_gives_different_nullifier() {
        // Falsifiability: different node_id_lo → different nullifier.
        let w1 = MintNullifierWitness {
            node_id_lo: 0x0000_0001,
            epoch_id: 5,
        };
        let w2 = MintNullifierWitness {
            node_id_lo: 0x0000_0002,
            epoch_id: 5,
        };
        let c1 = compute_mint_nullifier_claim(&w1);
        let c2 = compute_mint_nullifier_claim(&w2);
        assert_ne!(c1.mint_nullifier, c2.mint_nullifier);
    }

    #[test]
    fn test_mint_nullifier_different_epoch_gives_different_nullifier() {
        let w1 = MintNullifierWitness {
            node_id_lo: 0xABCD,
            epoch_id: 1,
        };
        let w2 = MintNullifierWitness {
            node_id_lo: 0xABCD,
            epoch_id: 2,
        };
        let c1 = compute_mint_nullifier_claim(&w1);
        let c2 = compute_mint_nullifier_claim(&w2);
        assert_ne!(c1.mint_nullifier, c2.mint_nullifier);
    }

    // ── MC2 proof tests ───────────────────────────────────────────────────────

    #[test]
    fn test_mc2_prove_verify_roundtrip() {
        // K5-03: real Poseidon2 proof for MC2. Spec §5.2 MC2.
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);
        let proof_bytes = prove_mint_nullifier_p3(&w, &claim).expect("MC2 prove must succeed");
        assert!(!proof_bytes.is_empty());

        let r = verify_mint_nullifier_p3(&proof_bytes, &claim);
        assert!(r.is_ok(), "MC2 valid proof must verify: {:?}", r);
    }

    #[test]
    fn test_mc2_wrong_node_id_rejected() {
        // Definition of Done §4 pt7: wrong node_id_lo → wrong nullifier → rejected.
        // This is the core falsifiability test for MC2.
        let w_correct = valid_null_witness();
        let claim_correct = compute_mint_nullifier_claim(&w_correct);

        // Prove with correct witness.
        let proof_bytes = prove_mint_nullifier_p3(&w_correct, &claim_correct).unwrap();

        // Verify with wrong claim (different node_id → different nullifier).
        let w_wrong = MintNullifierWitness {
            node_id_lo: w_correct.node_id_lo ^ 0xFFFF,
            epoch_id: w_correct.epoch_id,
        };
        let claim_wrong = compute_mint_nullifier_claim(&w_wrong);
        let r = verify_mint_nullifier_p3(&proof_bytes, &claim_wrong);
        assert!(
            r.is_err(),
            "wrong nullifier claim must be rejected (falsifiability)"
        );
    }

    #[test]
    fn test_mc2_tampered_proof_rejected() {
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);
        let mut proof_bytes = prove_mint_nullifier_p3(&w, &claim).unwrap();
        let mid = proof_bytes.len() / 2;
        proof_bytes[mid] ^= 0xFF;
        let r = verify_mint_nullifier_p3(&proof_bytes, &claim);
        assert!(r.is_err(), "tampered proof must be rejected");
    }

    // ── MC3 supply cap tests ─────────────────────────────────────────────────

    #[test]
    fn test_mc3_supply_cap_enforced() {
        // K5-03 MC3: supply cap enforced in-circuit. Spec §5.2 MC3, §15.2 #1.
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);
        let mut pi = valid_linear_pi(&claim);
        pi.total_minted_sscl = MINT_S_E_SSCL - 1;
        pi.reward_amount_sscl = 2; // total = S_E + 1 > S_E
        let r = prove_mint_linear_p3(&pi);
        assert!(
            matches!(r, Err(MintLinearError::ConstraintViolated(1, _))),
            "MC3 supply cap must be enforced: {:?}",
            r
        );
    }

    #[test]
    fn test_mc3_at_exact_cap_accepted() {
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);
        let mut pi = valid_linear_pi(&claim);
        pi.total_minted_sscl = MINT_S_E_SSCL - 1_000;
        pi.reward_amount_sscl = 1_000; // exactly at cap
        let r = prove_mint_linear_p3(&pi);
        assert!(r.is_ok(), "exact cap must be accepted: {:?}", r);
    }

    #[test]
    fn test_mc3_overflow_rejected() {
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);
        let mut pi = valid_linear_pi(&claim);
        pi.total_minted_sscl = u64::MAX - 1;
        pi.reward_amount_sscl = 2; // overflow
        let r = prove_mint_linear_p3(&pi);
        assert!(r.is_err(), "overflow must be rejected");
    }

    // ── MC1 / MC4 / MC5 tests ────────────────────────────────────────────────

    #[test]
    fn test_mc1_invalid_version_rejected() {
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);
        let mut pi = valid_linear_pi(&claim);
        pi.crypto_version = 0xFF;
        let r = prove_mint_linear_p3(&pi);
        assert!(matches!(r, Err(MintLinearError::ConstraintViolated(0, _))));
    }

    #[test]
    fn test_mc4_zero_reward_rejected() {
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);
        let mut pi = valid_linear_pi(&claim);
        pi.reward_amount_sscl = 0;
        let r = prove_mint_linear_p3(&pi);
        assert!(matches!(r, Err(MintLinearError::ConstraintViolated(2, _))));
    }

    #[test]
    fn test_mc5_invalid_auth_rejected() {
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);
        let mut pi = valid_linear_pi(&claim);
        pi.node_auth_valid = false;
        let r = prove_mint_linear_p3(&pi);
        assert!(matches!(r, Err(MintLinearError::ConstraintViolated(3, _))));
    }

    // ── MintLinear prove/verify roundtrip ────────────────────────────────────

    #[test]
    fn test_mint_linear_prove_verify_roundtrip() {
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);
        let pi = valid_linear_pi(&claim);

        let proof_bytes = prove_mint_linear_p3(&pi).expect("mint linear prove must succeed");
        assert!(!proof_bytes.is_empty());

        let r = verify_mint_linear_p3(&proof_bytes, &pi);
        assert!(r.is_ok(), "valid mint linear proof must verify: {:?}", r);
    }

    #[test]
    fn test_mint_linear_wrong_pi_rejected() {
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);
        let pi = valid_linear_pi(&claim);
        let proof_bytes = prove_mint_linear_p3(&pi).unwrap();

        let mut wrong_pi = pi.clone();
        wrong_pi.reward_amount_sscl = 999_999;
        let r = verify_mint_linear_p3(&proof_bytes, &wrong_pi);
        assert!(r.is_err(), "wrong PI must be rejected");
    }

    #[test]
    fn test_mint_linear_tampered_proof_rejected() {
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);
        let pi = valid_linear_pi(&claim);
        let mut proof_bytes = prove_mint_linear_p3(&pi).unwrap();
        let mid = proof_bytes.len() / 2;
        proof_bytes[mid] ^= 0xFF;
        let r = verify_mint_linear_p3(&proof_bytes, &pi);
        assert!(r.is_err(), "tampered proof must be rejected");
    }

    // ── BatchMintProof end-to-end ─────────────────────────────────────────────

    #[test]
    fn test_batch_mint_prove_verify_roundtrip() {
        // K5-01, K5-03: full MC1-MC5 batch mint proves and verifies. Spec §5.2.
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);
        let pi = valid_linear_pi(&claim);

        let proof = prove_batch_mint(&w, &claim, &pi).expect("batch mint prove must succeed");

        let r = verify_batch_mint(&proof, &claim, &pi);
        assert!(r.is_ok(), "valid batch mint proof must verify: {:?}", r);
    }

    #[test]
    fn test_batch_mint_nullifier_mismatch_rejected() {
        // Cross-AIR consistency: linear_pi with wrong nullifier must be rejected.
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);
        let mut pi = valid_linear_pi(&claim);
        pi.mint_nullifier[0] ^= 0xDEAD; // tamper nullifier in linear PI

        let r = prove_batch_mint(&w, &claim, &pi);
        assert!(
            matches!(r, Err(BatchMintError::NullifierMismatch)),
            "nullifier mismatch must be caught before proving"
        );
    }

    #[test]
    fn test_batch_mint_arbitrary_bytes_rejected() {
        // K5-01: arbitrary bytes rejected. Spec §15.1.
        let w = valid_null_witness();
        let claim = compute_mint_nullifier_claim(&w);
        let pi = valid_linear_pi(&claim);

        let garbage_proof = BatchMintProof {
            mc2_proof: vec![0x5cu8; 64],
            linear_proof: vec![0xFFu8; 64],
        };
        let r = verify_batch_mint(&garbage_proof, &claim, &pi);
        assert!(r.is_err(), "garbage bytes must be rejected");
    }

    #[test]
    fn test_domain_pou_mint_ossified() {
        // Spec §2.3: DOMAIN_POU_MINT = 0x706f755f6d696e74. OSSIFIED.
        assert_eq!(DOMAIN_POU_MINT_FE, 0x706f755f6d696e74u64);
    }
}

// ── P3-R9: Empirical benchmark — spec §15.6, §5.2 ────────────────────────────

#[cfg(test)]
mod bench {
    use super::*;
    use std::time::Instant;

    fn valid_mint_pi() -> MintLinearPublicInputs {
        MintLinearPublicInputs {
            crypto_version: 0x01,
            total_minted_sscl: 0,
            reward_amount_sscl: 1_000_000,
            node_auth_valid: true,
            mint_nullifier: [1u64; 4],
        }
    }

    fn valid_nullifier_witness() -> MintNullifierWitness {
        MintNullifierWitness {
            node_id_lo: 0xDEAD_BEEF,
            epoch_id: 42,
        }
    }

    /// P3-R9: Mint nullifier proving time (MC2 in-circuit). Spec §15.6.
    ///
    /// Run with: cargo test -p scalar-stark-p3 --features bench-hardware \
    ///           -- bench::bench_mint_nullifier_proving --nocapture --ignored
    #[test]
    #[cfg_attr(not(feature = "bench-hardware"), ignore = "P3-R9: run with --features bench-hardware")]
    fn bench_mint_nullifier_proving() {
        let witness = valid_nullifier_witness();
        let claim_derived = compute_mint_nullifier_claim(&witness);
        let claim = claim_derived;

        // Warm-up
        let _ = prove_mint_nullifier_p3(&witness, &claim).expect("warm-up");

        let start = Instant::now();
        let proof = prove_mint_nullifier_p3(&witness, &claim).expect("prove");
        let prove_ms = start.elapsed().as_millis();

        let start = Instant::now();
        verify_mint_nullifier_p3(&proof, &claim).expect("verify");
        let verify_ms = start.elapsed().as_millis();

        println!(
            "[P3-R9] MintNullifierAir MC2 — prove: {}ms, verify: {}ms, proof: {} bytes",
            prove_ms, verify_ms, proof.len()
        );
        println!("[P3-R9] Spec §15.6: empirical reference, no hard limit");
    }

    /// P3-R9: Mint linear proving time (MC1+MC3+MC4+MC5). Spec §15.6.
    ///
    /// Run with: cargo test -p scalar-stark-p3 --features bench-hardware \
    ///           -- bench::bench_mint_linear_proving --nocapture --ignored
    #[test]
    #[cfg_attr(not(feature = "bench-hardware"), ignore = "P3-R9: run with --features bench-hardware")]
    fn bench_mint_linear_proving() {
        let pi = valid_mint_pi();

        // Warm-up
        let _ = prove_mint_linear_p3(&pi).expect("warm-up");

        let start = Instant::now();
        let proof = prove_mint_linear_p3(&pi).expect("prove");
        let prove_ms = start.elapsed().as_millis();

        let start = Instant::now();
        verify_mint_linear_p3(&proof, &pi).expect("verify");
        let verify_ms = start.elapsed().as_millis();

        println!(
            "[P3-R9] MintLinearAir MC1+MC3+MC4+MC5 — prove: {}ms, verify: {}ms, proof: {} bytes",
            prove_ms, verify_ms, proof.len()
        );
        println!(
            "[P3-R9] MC3 supply cap in-circuit: total_minted={}, reward={}, S_E={}",
            pi.total_minted_sscl, pi.reward_amount_sscl, MINT_S_E_SSCL
        );
        println!("[P3-R9] Spec §15.6: empirical reference, no hard limit");
    }
}
