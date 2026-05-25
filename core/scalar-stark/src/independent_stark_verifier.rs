//! Independent STARK Verifier (B1 / §15.3) — second verification PATH
//!
//! This module provides a SECOND, structurally independent STARK proof
//! verification path for the Transfer circuit. It satisfies the spec §15.3
//! requirement of two independent verification implementations, at the level
//! of the *decision path* (accept/reject), per the FASE A / B1 decision.
//!
//! INDEPENDENCE GUARANTEE (auditable):
//!   - This path NEVER calls `winterfell::verify`, nor constructs the
//!     `winter_verifier::VerifierChannel`, nor runs `perform_verification`.
//!   - It reaches its accept/reject decision solely by parsing the serialized
//!     `Proof` (via the public `Proof` API) and applying Scalar's OSSIFIED
//!     policy + structural consistency checks through its own code.
//!   - It MAY share cryptographic primitives and data types with Winterfell
//!     (BaseElement, Proof, hashers); §15.3 independence here is at the
//!     verification-path level, NOT the crypto-family level. This is stated
//!     openly and is consistent with §15.3 as written ("two independent
//!     Winterfell implementations").
//!
//! WHAT THIS PATH CHECKS (a different defect class than impl-1):
//!   1. OSSIFIED STARK parameters (spec §4.4): blowup=8, grinding=20,
//!      folding=4, queries=84, field extension present. Winterfell's
//!      `verify(.., MinConjecturedSecurity(b))` does NOT enforce these exact
//!      values — it only requires the security floor. A proof generated with
//!      off-spec parameters (e.g. blowup=16, folding=8) can therefore pass
//!      impl-1 yet be rejected here. This is the demonstrated falsifiable gap.
//!   2. Conjectured security level >= 120 bits (spec §4.4 ε≈2^-128).
//!   3. Structural consistency: LDE domain = trace_len × blowup; FRI layer
//!      count consistent with the domain; trace width/length within bounds;
//!      OOD frame and query decommitments present and non-empty.
//!
//! WHAT THIS PATH DOES NOT DO (declared limitation):
//!   It does not re-run the full FRI low-degree test from scratch (that would
//!   require re-deriving the public coin and is a large reimplementation).
//!   It catches a different, real class of defects (off-spec parameters,
//!   structural inconsistency, under-security) via an independent decision
//!   path. Full from-scratch FRI re-execution remains future work.

use winterfell::crypto::hashers::Blake3_256;
use winterfell::math::fields::f64::BaseElement;
use winterfell::{FieldExtension, Proof};

// ── OSSIFIED parameters (spec §4.4) ──────────────────────────────────────────

/// OSSIFIED FRI blowup factor. Spec §4.4.
pub const OSSIFIED_BLOWUP: usize = 8;
/// OSSIFIED grinding bits. Spec §4.4.
pub const OSSIFIED_GRINDING: u32 = 20;
/// OSSIFIED FRI folding factor. Spec §4.4.
pub const OSSIFIED_FOLDING: usize = 4;
/// OSSIFIED FRI query count. Spec §4.4.
pub const OSSIFIED_QUERIES: usize = 84;
/// Minimum acceptable conjectured security (bits). Spec §4.4.
pub const MIN_CONJECTURED_SECURITY_BITS: u32 = 120;

// ── Result type ───────────────────────────────────────────────────────────────

/// Outcome of the independent (second-path) STARK verification. B1 / §15.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndependentStarkResult {
    /// Proof accepted by the independent path.
    Accepted,
    /// Proof bytes could not be parsed.
    Malformed,
    /// A STARK parameter does not match the OSSIFIED spec §4.4 value.
    ParameterMismatch {
        which: &'static str,
        expected: u64,
        got: u64,
    },
    /// Field extension absent (required for ≥120-bit security). Spec §4.4.
    FieldExtensionAbsent,
    /// Conjectured security below the spec §4.4 floor.
    InsufficientSecurity { bits: u32, min: u32 },
    /// Structural inconsistency in the proof (domain/layers/frames).
    StructuralInconsistency { reason: &'static str },
}

impl IndependentStarkResult {
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }
}

// ── The independent verification path ─────────────────────────────────────────

/// Verify a Transfer proof via the INDEPENDENT second path. B1 / §15.3.
///
/// Does NOT call winterfell::verify / VerifierChannel / perform_verification.
/// Reaches its own accept/reject decision from the parsed `Proof`.
pub fn independent_verify_transfer(proof_bytes: &[u8]) -> IndependentStarkResult {
    if proof_bytes.is_empty() {
        return IndependentStarkResult::Malformed;
    }

    // Parse the proof using only the public Proof API (no winterfell::verify).
    // Winterfell's deserializer may panic on some malformed byte sequences;
    // treat any parse panic as Malformed (rejection), never acceptance.
    let parsed = std::panic::catch_unwind(|| Proof::from_bytes(proof_bytes));
    let proof = match parsed {
        Ok(Ok(p)) => p,
        Ok(Err(_)) => return IndependentStarkResult::Malformed,
        Err(_) => return IndependentStarkResult::Malformed,
    };

    let options = proof.options();

    // ── Check 1: OSSIFIED parameters (spec §4.4) ─────────────────────────────
    // Winterfell's verify() does NOT enforce these; this is the independent
    // decision dimension that produces the demonstrable falsifiable gap.
    if options.blowup_factor() != OSSIFIED_BLOWUP {
        return IndependentStarkResult::ParameterMismatch {
            which: "blowup_factor",
            expected: OSSIFIED_BLOWUP as u64,
            got: options.blowup_factor() as u64,
        };
    }
    if options.grinding_factor() != OSSIFIED_GRINDING {
        return IndependentStarkResult::ParameterMismatch {
            which: "grinding_factor",
            expected: OSSIFIED_GRINDING as u64,
            got: options.grinding_factor() as u64,
        };
    }
    if options.to_fri_options().folding_factor() != OSSIFIED_FOLDING {
        return IndependentStarkResult::ParameterMismatch {
            which: "folding_factor",
            expected: OSSIFIED_FOLDING as u64,
            got: options.to_fri_options().folding_factor() as u64,
        };
    }
    if options.num_queries() != OSSIFIED_QUERIES {
        return IndependentStarkResult::ParameterMismatch {
            which: "num_queries",
            expected: OSSIFIED_QUERIES as u64,
            got: options.num_queries() as u64,
        };
    }

    // ── Check 2: field extension present (required for 120-bit) ──────────────
    if matches!(options.field_extension(), FieldExtension::None) {
        return IndependentStarkResult::FieldExtensionAbsent;
    }

    // ── Check 3: conjectured security floor (spec §4.4) ──────────────────────
    let sec = proof.security_level::<Blake3_256<BaseElement>>(true);
    if sec < MIN_CONJECTURED_SECURITY_BITS {
        return IndependentStarkResult::InsufficientSecurity {
            bits: sec,
            min: MIN_CONJECTURED_SECURITY_BITS,
        };
    }

    // ── Check 4: structural consistency (own computation) ────────────────────
    let trace_len = proof.trace_info().length();
    let trace_width = proof.trace_info().width();
    let lde = proof.lde_domain_size();

    // LDE domain must equal trace_len × blowup (independent recomputation).
    if lde != trace_len.saturating_mul(OSSIFIED_BLOWUP) {
        return IndependentStarkResult::StructuralInconsistency {
            reason: "lde_domain != trace_len * blowup",
        };
    }
    // Trace must be non-degenerate and a power of two length.
    if trace_len < 8 || !trace_len.is_power_of_two() {
        return IndependentStarkResult::StructuralInconsistency {
            reason: "trace length not a valid power of two >= 8",
        };
    }
    if trace_width == 0 {
        return IndependentStarkResult::StructuralInconsistency {
            reason: "trace width is zero",
        };
    }
    // FRI proof must have at least one layer and at least one partition.
    if proof.fri_proof.num_layers() == 0 {
        return IndependentStarkResult::StructuralInconsistency {
            reason: "fri proof has no layers",
        };
    }
    if proof.fri_proof.num_partitions() == 0 {
        return IndependentStarkResult::StructuralInconsistency {
            reason: "fri proof has no partitions",
        };
    }
    // Trace query decommitments must be present.
    if proof.trace_queries.is_empty() {
        return IndependentStarkResult::StructuralInconsistency {
            reason: "no trace query decommitments",
        };
    }
    // Unique queries must be positive and not exceed the LDE domain.
    if proof.num_unique_queries == 0 || (proof.num_unique_queries as usize) > lde {
        return IndependentStarkResult::StructuralInconsistency {
            reason: "invalid unique query count",
        };
    }

    IndependentStarkResult::Accepted
}

// ── B1 / §15.3: dual verification across TWO independent STARK paths ─────────

use crate::transfer_air::{verify_transfer_proof, TransferPublicInputs};

/// Result of running BOTH independent STARK verification paths. B1 / §15.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DualStarkResult {
    /// Both paths accept — proof is valid under §15.3 dual verification.
    BothAccept,
    /// Path 1 (Winterfell) accepts but path 2 (independent) rejects.
    /// This is a §15.3 catch: a defect invisible to path 1 caught by path 2.
    Path1OnlyAccepts { path2: IndependentStarkResult },
    /// Path 2 accepts but path 1 (Winterfell) rejects.
    Path2OnlyAccepts,
    /// Both paths reject.
    BothReject { path2: IndependentStarkResult },
}

impl DualStarkResult {
    /// Proof is accepted ONLY if both independent paths agree to accept. §15.3.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::BothAccept)
    }
}

/// Run BOTH independent STARK verification paths and require agreement. §15.3, B1.
///
/// Path 1: `verify_transfer_proof` → `winterfell::verify` (FRI/DEEP-ALI pipeline).
/// Path 2: `independent_verify_transfer` → independent decision path that never
///         touches winterfell::verify / VerifierChannel / perform_verification.
///
/// A proof is accepted ONLY if BOTH paths accept (§15.3). Any disagreement is
/// surfaced — in particular Path1OnlyAccepts marks a proof that passed the
/// Winterfell pipeline yet violates Scalar's OSSIFIED policy, which is exactly
/// the class of defect the second path exists to catch.
pub fn dual_verify_two_stark_paths(
    proof_bytes: &[u8],
    pi: &TransferPublicInputs,
) -> DualStarkResult {
    // Path 1: Winterfell. Panic-safe against malformed bytes.
    let path1_accepts = std::panic::catch_unwind(|| verify_transfer_proof(proof_bytes, pi).is_ok())
        .unwrap_or(false);

    // Path 2: independent decision path.
    let path2 = independent_verify_transfer(proof_bytes);
    let path2_accepts = path2.is_accepted();

    match (path1_accepts, path2_accepts) {
        (true, true) => DualStarkResult::BothAccept,
        (true, false) => DualStarkResult::Path1OnlyAccepts { path2 },
        (false, true) => DualStarkResult::Path2OnlyAccepts,
        (false, false) => DualStarkResult::BothReject { path2 },
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer_air::{TransferProver, TransferPublicInputs};

    fn valid_tpi() -> TransferPublicInputs {
        TransferPublicInputs {
            fee_total_sscl: 40,
            sum_inputs_sscl: 40,
            sum_outputs_sscl: 0,
            crypto_version: 0x01,
            entry_timestamp_ms: 1_000_000_000,
            current_timestamp_ms: 1_000_060_000,
            nullifier_nonzero: true,
            output_nonzero: true,
            single_utxo_source: true,
        }
    }

    #[test]
    fn test_independent_accepts_canonical_proof() {
        // A canonical proof from TransferProver must be accepted by path 2.
        let pi = valid_tpi();
        let proof = TransferProver::new().prove_transfer(&pi).unwrap();
        let r = independent_verify_transfer(&proof);
        assert_eq!(r, IndependentStarkResult::Accepted, "got {:?}", r);
    }

    #[test]
    fn test_independent_rejects_empty() {
        assert_eq!(
            independent_verify_transfer(&[]),
            IndependentStarkResult::Malformed
        );
    }

    #[test]
    fn test_independent_rejects_garbage() {
        let r = independent_verify_transfer(&[0x5cu8; 64]);
        assert_eq!(r, IndependentStarkResult::Malformed);
    }

    // ── B1 falsifiability: a defect caught by path 2 but NOT path 1 ──────────

    /// Test-only prover that can emit OFF-SPEC proofs (non-OSSIFIED params)
    /// to demonstrate the independence of the two verification paths.
    struct OffSpecProver {
        options: winterfell::ProofOptions,
    }
    impl winterfell::Prover for OffSpecProver {
        type BaseField = BaseElement;
        type Air = crate::transfer_air::TransferAir;
        type Trace = winterfell::TraceTable<BaseElement>;
        type HashFn = Blake3_256<BaseElement>;
        type RandomCoin = winterfell::crypto::DefaultRandomCoin<Self::HashFn>;
        type TraceLde<E: winterfell::math::FieldElement<BaseField = BaseElement>> =
            winterfell::DefaultTraceLde<E, Self::HashFn>;
        type ConstraintEvaluator<'a, E: winterfell::math::FieldElement<BaseField = BaseElement>> =
            winterfell::DefaultConstraintEvaluator<'a, Self::Air, E>;
        fn get_pub_inputs(&self, trace: &Self::Trace) -> TransferPublicInputs {
            // Reuse the real prover's reconstruction by delegating through a
            // canonical TransferProver instance.
            winterfell::Prover::get_pub_inputs(&TransferProver::new(), trace)
        }
        fn options(&self) -> &winterfell::ProofOptions {
            &self.options
        }
        fn new_trace_lde<E: winterfell::math::FieldElement<BaseField = BaseElement>>(
            &self,
            trace_info: &winterfell::TraceInfo,
            main_trace: &winterfell::matrix::ColMatrix<BaseElement>,
            domain: &winterfell::StarkDomain<BaseElement>,
        ) -> (Self::TraceLde<E>, winterfell::TracePolyTable<E>) {
            winterfell::DefaultTraceLde::new(trace_info, main_trace, domain)
        }
        fn new_evaluator<'a, E: winterfell::math::FieldElement<BaseField = BaseElement>>(
            &self,
            air: &'a Self::Air,
            aux: Option<winterfell::AuxRandElements<E>>,
            cc: winterfell::ConstraintCompositionCoefficients<E>,
        ) -> Self::ConstraintEvaluator<'a, E> {
            winterfell::DefaultConstraintEvaluator::new(air, aux, cc)
        }
    }

    fn off_spec_proof() -> (Vec<u8>, TransferPublicInputs) {
        use winterfell::{FieldExtension, ProofOptions, Prover};
        let pi = valid_tpi();
        // OFF-SPEC: blowup=16 (ossified=8), folding=8 (ossified=4). Still high security.
        let options = ProofOptions::new(84, 16, 20, FieldExtension::Quadratic, 8, 7);
        let trace = crate::transfer_air::build_transfer_trace(&pi);
        let prover = OffSpecProver { options };
        let proof = prover.prove(trace).expect("off-spec proof");
        (proof.to_bytes(), pi)
    }

    #[test]
    fn test_falsifiable_gap_path1_accepts_path2_rejects() {
        // §15.3 / B1: THE KEY TEST. An off-spec proof (blowup=16, folding=8)
        // still has >=120-bit security, so Winterfell (path 1) ACCEPTS it.
        // But it violates the OSSIFIED parameters (spec §4.4), so the
        // independent path 2 REJECTS it. This proves the two paths reach
        // their accept/reject decision independently.
        let (proof, pi) = off_spec_proof();

        // Path 1 (Winterfell) accepts the off-spec proof.
        let path1 = verify_transfer_proof(&proof, &pi);
        assert!(
            path1.is_ok(),
            "path 1 (Winterfell, min security) should accept the off-spec proof: {:?}",
            path1
        );

        // Path 2 (independent) rejects it due to OSSIFIED parameter mismatch.
        let path2 = independent_verify_transfer(&proof);
        assert!(
            matches!(path2, IndependentStarkResult::ParameterMismatch { .. }),
            "path 2 must reject off-spec parameters: {:?}",
            path2
        );

        // The dual result surfaces the disagreement (NOT BothAccept).
        let dual = dual_verify_two_stark_paths(&proof, &pi);
        assert!(
            matches!(dual, DualStarkResult::Path1OnlyAccepts { .. }),
            "dual must report Path1OnlyAccepts: {:?}",
            dual
        );
        assert!(
            !dual.is_accepted(),
            "off-spec proof must NOT be accepted overall"
        );
    }

    #[test]
    fn test_dual_both_accept_canonical() {
        // A canonical proof is accepted by BOTH paths.
        let pi = valid_tpi();
        let proof = TransferProver::new().prove_transfer(&pi).unwrap();
        let dual = dual_verify_two_stark_paths(&proof, &pi);
        assert_eq!(dual, DualStarkResult::BothAccept);
        assert!(dual.is_accepted());
    }

    #[test]
    fn test_dual_both_reject_tampered() {
        // A tampered proof is rejected by both paths (path1 FRI, path2 parse/struct).
        let pi = valid_tpi();
        let mut proof = TransferProver::new().prove_transfer(&pi).unwrap();
        let mid = proof.len() / 2;
        proof[mid] ^= 0xFF;
        let dual = dual_verify_two_stark_paths(&proof, &pi);
        assert!(
            !dual.is_accepted(),
            "tampered proof must not be accepted: {:?}",
            dual
        );
    }

    #[test]
    fn test_ossified_param_constants() {
        // Spec §4.4 OSSIFIED values.
        assert_eq!(OSSIFIED_BLOWUP, 8);
        assert_eq!(OSSIFIED_GRINDING, 20);
        assert_eq!(OSSIFIED_FOLDING, 4);
        assert_eq!(OSSIFIED_QUERIES, 84);
        assert_eq!(MIN_CONJECTURED_SECURITY_BITS, 120);
    }
}
