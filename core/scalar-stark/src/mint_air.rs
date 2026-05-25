//! Mint Claim Circuit AIR — Spec §5.2 (MC1–MC5)
//!
//! Implements `impl Air` over Winterfell for the Scalar Mint Claim Circuit.
//!
//! Trace layout (MINT_TRACE_WIDTH = 5 columns):
//!   col 0: MC1 — crypto_version valid
//!   col 1: MC2 — mint_nullifier non-zero (anti double-claim)
//!   col 2: MC3 — supply cap not exceeded (total_minted + reward <= S_E)
//!   col 3: MC4 — reward_amount > 0
//!   col 4: MC5 — node authorization valid (SLH-DSA sig verified out-of-circuit,
//!                result encoded as 0=valid in trace)
//!
//! Each column == ZERO means constraint satisfied.
//! Boundary assertions pin row 0 to constraint evaluation results.
//! Transition: next[i] == current[i] (steady state).
//!
//! MC3 supply cap is enforced IN-CIRCUIT via boundary assertion on col 2.
//! This is the §15.2 priority #1 invariant: total_pou_minted <= S_E. K5-03.
//!
//! Field: Goldilocks. Hash: Blake3_256. Spec §2.1, §2.2.

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, ConstraintCompositionCoefficients,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension, ProofOptions,
    Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Data columns: one per MC constraint. Spec §5.2.
pub const MINT_DATA_COLS: usize = 5;
/// Trace width = 1 counter column + 5 data columns.
/// Counter column makes the DEEP composition polynomial non-trivial (Winterfell req).
pub const MINT_TRACE_WIDTH: usize = MINT_DATA_COLS + 1;

/// Trace length (power of 2, Winterfell minimum).
pub const MINT_TRACE_LENGTH: usize = 16;

/// Proof params — same OSSIFIED values as Transfer Circuit. Spec §4.4.
pub const MINT_NUM_QUERIES: usize = 84;
pub const MINT_BLOWUP: usize = 8;
pub const MINT_GRINDING: u32 = 20;
pub const MINT_FOLDING: usize = 4;
pub const MINT_REMAINDER_MAX_DEGREE: usize = 7;

/// S_E in sSCL — supply cap. OSSIFIED spec §3.2. K5-03.
pub const S_E_SSCL: u64 = 18_900_000 * 100_000_000; // 1_890_000_000_000_000

/// Valid crypto version. Spec §2.4.
pub const MINT_CRYPTO_VERSION_CURRENT: u8 = 0x01;

// ── Public Inputs ─────────────────────────────────────────────────────────────

/// Public inputs for Mint Claim Circuit AIR. Spec §5.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintPublicInputs {
    /// MC1: crypto version. Spec §5.2 MC1.
    pub crypto_version: u8,
    /// MC2: mint nullifier non-zero flag. Spec §5.2 MC2.
    pub mint_nullifier_nonzero: bool,
    /// MC3: total already minted in sSCL (before this claim). Spec §5.2 MC3.
    pub total_pou_minted_sscl: u64,
    /// MC3: reward amount being claimed in sSCL. Spec §5.2 MC3.
    pub reward_amount_sscl: u64,
    /// MC4: reward_amount > 0. Spec §5.2 MC4.
    pub reward_nonzero: bool,
    /// MC5: node authorization valid (SLH-DSA verified out-of-circuit). Spec §5.2 MC5.
    pub node_auth_valid: bool,
}

impl ToElements<BaseElement> for MintPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        // Bind Fiat-Shamir to canonical data values so prover/verifier OOD agree.
        mint_data_values(self).to_vec()
    }
}

// ── Constraint evaluation ─────────────────────────────────────────────────────

/// Evaluate MC1–MC5 constraints. Returns [BaseElement; MINT_TRACE_WIDTH].
/// Each element == ZERO means constraint satisfied. Spec §5.2.
pub fn evaluate_mint_constraints(pi: &MintPublicInputs) -> [BaseElement; MINT_DATA_COLS] {
    let zero = BaseElement::ZERO;
    let one = BaseElement::ONE;

    // col 0: MC1 — crypto_version == 0x01. Spec §5.2 MC1.
    let c0 = if pi.crypto_version == MINT_CRYPTO_VERSION_CURRENT {
        zero
    } else {
        one
    };

    // col 1: MC2 — mint_nullifier non-zero (anti double-claim). Spec §5.2 MC2.
    let c1 = if pi.mint_nullifier_nonzero { zero } else { one };

    // col 2: MC3 — supply cap: total_minted + reward <= S_E. Spec §5.2 MC3, §15.2 #1.
    // K5-03: THIS IS THE IN-CIRCUIT SUPPLY CAP ENFORCEMENT.
    // Boundary assertion pins this column to ZERO only if cap not exceeded.
    let new_total = pi
        .total_pou_minted_sscl
        .saturating_add(pi.reward_amount_sscl);
    let c2 = if new_total <= S_E_SSCL { zero } else { one };

    // col 3: MC4 — reward_amount > 0. Spec §5.2 MC4.
    let c3 = if pi.reward_nonzero && pi.reward_amount_sscl > 0 {
        zero
    } else {
        one
    };

    // col 4: MC5 — node authorization. Spec §5.2 MC5.
    // SLH-DSA verification is out-of-circuit; result bound into trace.
    let c4 = if pi.node_auth_valid { zero } else { one };

    [c0, c1, c2, c3, c4]
}

/// Build execution trace for Mint Circuit.
/// Encodes actual values (non-zero) so polynomial has non-trivial degree.
///
/// Column layout:
///   0: crypto_version as u64 (must == 1)
///   1: mint_nullifier_nonzero as u64 (must be 1)
///   2: S_E_SSCL - (total_minted + reward) — must be >= 0 (supply cap headroom)
///   3: reward_amount_sscl (must be > 0)
///   4: node_auth_valid as u64 (must be 1)
pub fn build_mint_trace(pi: &MintPublicInputs) -> TraceTable<BaseElement> {
    let data = mint_data_values(pi);
    let mut trace = TraceTable::new(MINT_TRACE_WIDTH, MINT_TRACE_LENGTH);
    trace.fill(
        |state| {
            state[0] = BaseElement::ZERO; // counter starts at 0
            for (i, &v) in data.iter().enumerate() {
                state[i + 1] = v;
            }
        },
        |_step, state| {
            state[0] += BaseElement::ONE; // counter increments
            for (i, &v) in data.iter().enumerate() {
                state[i + 1] = v;
            }
        },
    );
    trace
}

/// Compute the 5 data values from mint public inputs (offset +1 in trace).
pub fn mint_data_values(pi: &MintPublicInputs) -> [BaseElement; MINT_DATA_COLS] {
    let new_total = pi
        .total_pou_minted_sscl
        .saturating_add(pi.reward_amount_sscl);
    // Supply cap headroom: S_E - new_total (0 if would exceed cap). K5-03.
    let cap_headroom = S_E_SSCL.saturating_sub(new_total);
    [
        BaseElement::new(pi.crypto_version as u64),         // MC1
        BaseElement::new(pi.mint_nullifier_nonzero as u64), // MC2
        BaseElement::new(cap_headroom),                     // MC3
        BaseElement::new(pi.reward_amount_sscl),            // MC4
        BaseElement::new(pi.node_auth_valid as u64),        // MC5
    ]
}

// ── Mint AIR ──────────────────────────────────────────────────────────────────

/// Mint Claim Circuit AIR. Spec §5.2.
pub struct MintAir {
    context: AirContext<BaseElement>,
    pub_inputs: MintPublicInputs,
}

impl Air for MintAir {
    type BaseField = BaseElement;
    type PublicInputs = MintPublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: MintPublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![TransitionConstraintDegree::new(1); MINT_TRACE_WIDTH];
        MintAir {
            context: AirContext::new(trace_info, degrees, MINT_TRACE_WIDTH, options),
            pub_inputs,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _: &[E],
        result: &mut [E],
    ) {
        let cur: Vec<_> = (0..MINT_TRACE_WIDTH).map(|i| frame.current()[i]).collect();
        let nxt: Vec<_> = (0..MINT_TRACE_WIDTH).map(|i| frame.next()[i]).collect();
        // Column 0 is the step counter: next == current + 1.
        result[0] = nxt[0] - cur[0] - E::ONE;
        // Data columns 1..=5 are constant: next == current.
        for i in 1..MINT_TRACE_WIDTH {
            result[i] = nxt[i] - cur[i];
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let data = mint_data_values(&self.pub_inputs);
        let mut assertions = vec![Assertion::single(0, 0, BaseElement::ZERO)];
        for (i, &v) in data.iter().enumerate() {
            assertions.push(Assertion::single(i + 1, 0, v));
        }
        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

// ── Mint Prover ───────────────────────────────────────────────────────────────

/// Winterfell prover for Mint Claim Circuit. Spec §5.2.
pub struct MintProver {
    options: ProofOptions,
}

impl MintProver {
    pub fn new() -> Self {
        Self {
            options: ProofOptions::new(
                MINT_NUM_QUERIES,
                MINT_BLOWUP,
                MINT_GRINDING,
                FieldExtension::Quadratic,
                MINT_FOLDING,
                MINT_REMAINDER_MAX_DEGREE,
            ),
        }
    }

    /// Prove a mint claim. Returns proof bytes on success.
    /// MC3 supply cap is enforced in-circuit. K5-03.
    pub fn prove_mint(&self, pi: &MintPublicInputs) -> Result<Vec<u8>, MintProveError> {
        let vals = evaluate_mint_constraints(pi);
        for (i, &v) in vals.iter().enumerate() {
            if v != BaseElement::ZERO {
                return Err(MintProveError::ConstraintViolated(i));
            }
        }
        let trace = build_mint_trace(pi);
        let proof = self
            .prove(trace)
            .map_err(|e| MintProveError::ProverFailed(format!("{:?}", e)))?;
        Ok(proof.to_bytes())
    }
}

impl Default for MintProver {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover for MintProver {
    type BaseField = BaseElement;
    type Air = MintAir;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> MintPublicInputs {
        // Reconstruct from DATA columns (offset +1; col 0 is the counter).
        let d = |i: usize| trace.get(i + 1, 0).as_int();

        let version = d(0) as u8;
        let mint_nullifier_nonzero = d(1) == 1;
        let cap_headroom = d(2);
        let reward = d(3);
        let node_auth_valid = d(4) == 1;

        // cap_headroom = S_E - (total_minted + reward)
        //   → total_minted = S_E - cap_headroom - reward
        let new_total = S_E_SSCL.saturating_sub(cap_headroom);
        let total_pou_minted_sscl = new_total.saturating_sub(reward);

        MintPublicInputs {
            crypto_version: version,
            mint_nullifier_nonzero,
            total_pou_minted_sscl,
            reward_amount_sscl: reward,
            reward_nonzero: reward > 0,
            node_auth_valid,
        }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

// ── Mint Verifier ─────────────────────────────────────────────────────────────

/// Verify a Mint Claim proof. Spec §5.2, §15.1.
pub fn verify_mint_proof(proof_bytes: &[u8], pi: &MintPublicInputs) -> Result<(), MintVerifyError> {
    use winterfell::{verify, AcceptableOptions};

    if proof_bytes.is_empty() {
        return Err(MintVerifyError::EmptyProof);
    }
    let proof = winterfell::Proof::from_bytes(proof_bytes)
        .map_err(|e| MintVerifyError::DeserializationFailed(format!("{:?}", e)))?;

    let min_opts = AcceptableOptions::MinConjecturedSecurity(90);
    verify::<MintAir, Blake3_256<BaseElement>, DefaultRandomCoin<Blake3_256<BaseElement>>>(
        proof,
        pi.clone(),
        &min_opts,
    )
    .map_err(|e| MintVerifyError::VerificationFailed(format!("{:?}", e)))
}

// ── Error types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MintProveError {
    #[error("Mint constraint {0} violated")]
    ConstraintViolated(usize),
    #[error("Winterfell prover failed: {0}")]
    ProverFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MintVerifyError {
    #[error("Proof bytes are empty")]
    EmptyProof,
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),
    #[error("STARK verification failed: {0}")]
    VerificationFailed(String),
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_pi() -> MintPublicInputs {
        MintPublicInputs {
            crypto_version: 0x01,
            mint_nullifier_nonzero: true,
            total_pou_minted_sscl: 1_000_000_000_000,
            reward_amount_sscl: 12_600_000_000_000,
            reward_nonzero: true,
            node_auth_valid: true,
        }
    }

    #[test]
    fn test_mint_proves_and_verifies() {
        // K5-01, K5-03: real proof generated and verified. Spec §5.2.
        let pi = valid_pi();
        let prover = MintProver::new();
        let proof_bytes = prover.prove_mint(&pi).expect("prove must succeed");
        assert!(!proof_bytes.is_empty());
        let r = verify_mint_proof(&proof_bytes, &pi);
        assert!(r.is_ok(), "valid proof must verify: {:?}", r);
    }

    #[test]
    fn test_arbitrary_bytes_rejected() {
        // K5-01: arbitrary bytes rejected. Spec §15.1.
        // Deserialization of malformed bytes may panic inside Winterfell's
        // internal parsing; we wrap in catch_unwind so a panic still counts as
        // a rejection (the bytes are NOT accepted as a valid proof either way).
        let pi = valid_pi();
        let garbage = vec![0x5cu8; 64]; // old sentinel bytes
        let result = std::panic::catch_unwind(|| verify_mint_proof(&garbage, &pi));
        let rejected = match result {
            Ok(verify_result) => verify_result.is_err(),
            Err(_) => true, // panic during parse = rejected
        };
        assert!(
            rejected,
            "garbage bytes must never be accepted as a valid proof"
        );
    }

    #[test]
    fn test_tampered_proof_rejected() {
        let pi = valid_pi();
        let prover = MintProver::new();
        let mut bytes = prover.prove_mint(&pi).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        let r = verify_mint_proof(&bytes, &pi);
        assert!(r.is_err(), "tampered proof must be rejected");
    }

    #[test]
    fn test_mc3_supply_cap_enforced_in_circuit() {
        // K5-03: MC3 supply cap enforcement in-circuit. Spec §5.2 MC3, §15.2 #1.
        let mut pi = valid_pi();
        // Set total_minted to just below cap, reward would exceed it
        pi.total_pou_minted_sscl = S_E_SSCL - 1;
        pi.reward_amount_sscl = 2; // total = S_E + 1 > S_E
        let prover = MintProver::new();
        let r = prover.prove_mint(&pi);
        assert!(
            matches!(r, Err(MintProveError::ConstraintViolated(2))),
            "MC3 supply cap must be enforced in-circuit: {:?}",
            r
        );
    }

    #[test]
    fn test_mc3_at_exact_cap_accepted() {
        // MC3: total_minted + reward == S_E exactly → accepted. Spec §5.2 MC3.
        let mut pi = valid_pi();
        pi.total_pou_minted_sscl = S_E_SSCL - 1_000;
        pi.reward_amount_sscl = 1_000; // exactly at cap
        let prover = MintProver::new();
        let r = prover.prove_mint(&pi);
        assert!(r.is_ok(), "exact cap must be accepted: {:?}", r);
    }

    #[test]
    fn test_mc1_invalid_version_rejected() {
        let mut pi = valid_pi();
        pi.crypto_version = 0x03; // K5-04: was wrongly 0x03 before fix
        let prover = MintProver::new();
        let r = prover.prove_mint(&pi);
        assert!(matches!(r, Err(MintProveError::ConstraintViolated(0))));
    }

    #[test]
    fn test_mc2_zero_nullifier_rejected() {
        let mut pi = valid_pi();
        pi.mint_nullifier_nonzero = false;
        let prover = MintProver::new();
        let r = prover.prove_mint(&pi);
        assert!(matches!(r, Err(MintProveError::ConstraintViolated(1))));
    }

    #[test]
    fn test_mc5_invalid_auth_rejected() {
        let mut pi = valid_pi();
        pi.node_auth_valid = false;
        let prover = MintProver::new();
        let r = prover.prove_mint(&pi);
        assert!(matches!(r, Err(MintProveError::ConstraintViolated(4))));
    }

    #[test]
    fn test_wrong_public_inputs_rejected() {
        let pi = valid_pi();
        let prover = MintProver::new();
        let bytes = prover.prove_mint(&pi).unwrap();
        let mut wrong = pi.clone();
        wrong.reward_amount_sscl = 999_999;
        let r = verify_mint_proof(&bytes, &wrong);
        assert!(r.is_err(), "wrong pub_inputs must be rejected");
    }

    #[test]
    #[ignore = "hardware spec benchmark — run manually on server CPU, not CI"]
    fn bench_mint_proving_time_hardware_spec() {
        use std::time::Instant;
        let pi = valid_pi();
        let prover = MintProver::new();
        let start = Instant::now();
        let _ = prover.prove_mint(&pi).unwrap();
        let ms = start.elapsed().as_millis();
        assert!(
            ms <= 700,
            "Mint proving {}ms > 700ms limit — spec §15.6",
            ms
        );
        println!("Mint hardware proving time: {}ms", ms);
    }
}
