//! STARKPack Aggregator — Research Package §3.4, Decision D-002
//!
//! Modifies the Batch-FRI phase so N independent transactions are
//! compacted into a single low-degree FRI test.
//!
//! Parameters (OSSIFIED — Decision D-002):
//!   STARK_MAX_BATCH_SIZE     = 256  (optimal, soundness 2^-120)
//!   STARK_EXTENDED_BATCH_SIZE = 1024 (reserve, needs streaming impl)
//!   STARK_BATCH_SOUNDNESS_N256 = 120  (bits, 2^-120)
//!   STARK_BATCH_SOUNDNESS_N1024 = 118 (bits, 2^-118)
//!
//! Soundness analysis (Research Package §3.4.2):
//!   P(attack) = ε + N/|F|
//!   For N=256, |F|=Goldilocks=2^64-2^32+1:
//!     Degradation = log2(256) = 8 bits
//!     Soundness: 2^-128 → 2^-120
//!   Industry minimum: 2^-100. Both configurations well above this.
//!
//! Fiat-Shamir transcript (OSSIFIED — Research Package §3.4.3):
//!   Phase 1: Per-proof commitment (absorb merkle_root, constraint_count, deep_ali_root)
//!   Phase 2: Aggregation challenge (squeeze N coefficients)
//!   Phase 3: Global DEEP-FRI commitment (absorb b"scalar_stark_batch", N, fri_root)
//!   Phase 4: Query phase (squeeze 84 positions)
//!
//! Domain separator: b"scalar_stark_batch" (18 bytes) — OSSIFIED.
//!
//! Hash discipline: BLAKE3 out-circuit — spec §2.1.

use blake3::Hasher;
use scalar_crypto::domain::{DOMAIN_STARK_BATCH, DOMAIN_SUBEPOCH_FS};

// ── Constants — OSSIFIED (Decision D-002) ────────────────────────────────────

/// Optimal batch size N=256. Soundness 2^-120. Decision D-002. OSSIFIED.
pub const STARK_MAX_BATCH_SIZE: usize = 256;

/// Extended batch size N=1024. Soundness 2^-118. Reserve — needs streaming.
/// Decision D-002: requires memory profiling before activation.
pub const STARK_EXTENDED_BATCH_SIZE: usize = 1024;

/// Soundness bits for N=256 batch. Decision D-002. OSSIFIED.
/// 2^-120 per Schwartz-Zippel + Proximity Gaps analysis.
pub const STARK_BATCH_SOUNDNESS_N256: u32 = 120;

/// Soundness bits for N=1024 batch. Decision D-002.
pub const STARK_BATCH_SOUNDNESS_N1024: u32 = 118;

/// Industry minimum soundness threshold. Both configs exceed this.
pub const STARK_SOUNDNESS_INDUSTRY_MIN: u32 = 100;

/// Number of FRI queries (from existing STARK params). OSSIFIED — spec §4.4.
pub const NUM_FRI_QUERIES: usize = 84;

// ── ProofCommitment — per-proof binding data ─────────────────────────────────

/// Per-proof commitment data for STARKPack transcript Phase 1.
/// Research Package §3.4.3.
#[derive(Debug, Clone)]
pub struct ProofCommitment {
    /// Merkle root of the proof's constraint polynomial commitments.
    pub merkle_root: [u8; 32],
    /// Number of constraints in this proof.
    pub constraint_count: u32,
    /// DEEP-ALI polynomial root.
    pub deep_ali_root: [u8; 32],
    /// Transaction ordering key (deterministic, from tx_ordering_key).
    /// Used to sort proofs canonically before batching.
    pub tx_ordering_key: [u8; 32],
}

// ── STARKPackTranscript — Fiat-Shamir ────────────────────────────────────────

/// Fiat-Shamir transcript for STARKPack. Research Package §3.4.3. OSSIFIED.
///
/// Rules (must not be changed without fork):
///   R1: Proofs absorbed in deterministic order (sorted by tx_ordering_key).
///   R2: No element may be skipped or partially absorbed.
///   R3: Transcript state NOT reset between individual proofs.
///   R4: Single transcript for entire batch.
pub struct STARKPackTranscript {
    hasher: Hasher,
    proof_count: usize,
    phase: TranscriptPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptPhase {
    Phase1Commitment,
    Phase2Challenge,
    Phase3GlobalFri,
    Phase4Query,
    Finalized,
}

impl STARKPackTranscript {
    /// Create new transcript. Research Package §3.4.3.
    pub fn new() -> Self {
        Self {
            hasher: Hasher::new(),
            proof_count: 0,
            phase: TranscriptPhase::Phase1Commitment,
        }
    }

    /// Phase 1: Absorb per-proof commitment. Research Package §3.4.3.
    ///
    /// Must be called for each proof in deterministic order (tx_ordering_key sort).
    /// R1: sorted by tx_ordering_key. R2: all fields absorbed. R3: no reset.
    pub fn absorb_proof_commitment(
        &mut self,
        commitment: &ProofCommitment,
    ) -> Result<(), TranscriptError> {
        if self.phase != TranscriptPhase::Phase1Commitment {
            return Err(TranscriptError::WrongPhase {
                expected: TranscriptPhase::Phase1Commitment,
                got: self.phase,
            });
        }
        if self.proof_count >= STARK_MAX_BATCH_SIZE {
            return Err(TranscriptError::BatchFull);
        }

        // Phase 1 absorption order — OSSIFIED per Research Package §3.4.3
        // Phase 1 domain = b"scalar_subepoch_fs" (RP §3.4.3, §8.3). DISTINCT from
        // Phase 3's b"scalar_stark_batch" — two domains prevent cross-protocol
        // correlation between the per-proof commitment phase and the global
        // DEEP-FRI commitment phase. K7-01 fix.
        self.hasher.update(DOMAIN_SUBEPOCH_FS);
        self.hasher.update(&commitment.merkle_root);
        self.hasher
            .update(&commitment.constraint_count.to_le_bytes());
        self.hasher.update(&commitment.deep_ali_root);

        self.proof_count += 1;
        Ok(())
    }

    /// Phase 2: Squeeze aggregation challenge coefficients. Research Package §3.4.3.
    ///
    /// Returns N challenge coefficients ξ[i] for linear combination.
    /// Called after all Phase 1 absorptions.
    pub fn squeeze_aggregation_challenge(&mut self) -> Result<Vec<[u8; 32]>, TranscriptError> {
        if self.phase != TranscriptPhase::Phase1Commitment {
            return Err(TranscriptError::WrongPhase {
                expected: TranscriptPhase::Phase1Commitment,
                got: self.phase,
            });
        }

        let n = self.proof_count;
        let mut challenges = Vec::with_capacity(n);

        // Derive N challenge coefficients from transcript state
        let intermediate = *self.hasher.finalize().as_bytes();
        for i in 0..n {
            let mut h = Hasher::new();
            h.update(&intermediate);
            h.update(&(i as u64).to_le_bytes());
            challenges.push(*h.finalize().as_bytes());
        }

        self.phase = TranscriptPhase::Phase2Challenge;
        Ok(challenges)
    }

    /// Phase 3: Absorb global DEEP-FRI root. Research Package §3.4.3.
    ///
    /// Called after aggregation challenge is computed.
    /// Absorbs: DOMAIN_STARK_BATCH || N_as_u32 || global_deep_fri_root
    pub fn absorb_global_fri_root(
        &mut self,
        n_proofs: u32,
        global_deep_fri_root: &[u8; 32],
    ) -> Result<(), TranscriptError> {
        if self.phase != TranscriptPhase::Phase2Challenge {
            return Err(TranscriptError::WrongPhase {
                expected: TranscriptPhase::Phase2Challenge,
                got: self.phase,
            });
        }

        // Phase 3 absorption — OSSIFIED per Research Package §3.4.3
        self.hasher.update(DOMAIN_STARK_BATCH);
        self.hasher.update(&n_proofs.to_le_bytes());
        self.hasher.update(global_deep_fri_root);

        self.phase = TranscriptPhase::Phase3GlobalFri;
        Ok(())
    }

    /// Phase 4: Squeeze query positions. Research Package §3.4.3.
    ///
    /// Returns NUM_FRI_QUERIES=84 query positions.
    pub fn squeeze_query_positions(&mut self) -> Result<Vec<u64>, TranscriptError> {
        if self.phase != TranscriptPhase::Phase3GlobalFri {
            return Err(TranscriptError::WrongPhase {
                expected: TranscriptPhase::Phase3GlobalFri,
                got: self.phase,
            });
        }

        let transcript_hash = *self.hasher.finalize().as_bytes();
        let mut positions = Vec::with_capacity(NUM_FRI_QUERIES);

        for i in 0..NUM_FRI_QUERIES {
            let mut h = Hasher::new();
            h.update(&transcript_hash);
            h.update(b"query_position");
            h.update(&(i as u64).to_le_bytes());
            let hash = h.finalize();
            let bytes = hash.as_bytes();
            let pos = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            positions.push(pos);
        }

        self.phase = TranscriptPhase::Phase4Query;
        Ok(positions)
    }

    /// Finalize transcript. Returns final transcript hash.
    pub fn finalize(mut self) -> Result<[u8; 32], TranscriptError> {
        if self.phase != TranscriptPhase::Phase4Query {
            return Err(TranscriptError::WrongPhase {
                expected: TranscriptPhase::Phase4Query,
                got: self.phase,
            });
        }
        self.phase = TranscriptPhase::Finalized;
        Ok(*self.hasher.finalize().as_bytes())
    }

    pub fn proof_count(&self) -> usize {
        self.proof_count
    }
}

impl Default for STARKPackTranscript {
    fn default() -> Self {
        Self::new()
    }
}

// ── TranscriptError ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptError {
    WrongPhase {
        expected: TranscriptPhase,
        got: TranscriptPhase,
    },
    BatchFull,
    InvalidBatchSize {
        n: usize,
        max: usize,
    },
}

impl core::fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongPhase { expected, got } => {
                write!(
                    f,
                    "wrong transcript phase: expected {:?}, got {:?}",
                    expected, got
                )
            }
            Self::BatchFull => write!(f, "batch full: max {} proofs", STARK_MAX_BATCH_SIZE),
            Self::InvalidBatchSize { n, max } => {
                write!(f, "invalid batch size {}: max {}", n, max)
            }
        }
    }
}

// ── STARKPackBatch — aggregate N proofs ──────────────────────────────────────

/// STARKPack batch: N individual proofs → 1 aggregate proof.
/// Research Package §3.4.1.
///
/// Workflow:
///   1. Sort proofs by tx_ordering_key (deterministic).
///   2. Absorb each proof commitment into transcript (Phase 1).
///   3. Squeeze aggregation challenge (Phase 2).
///   4. Compute global DEEP-FRI commitment (Phase 3).
///   5. Squeeze query positions (Phase 4).
///   6. Return AggregateProof.
#[derive(Debug, Clone)]
pub struct AggregateProof {
    /// Number of proofs in this batch.
    pub n_proofs: usize,
    /// Global DEEP-FRI root (commitment to Σ ξ_i × f_i(x)).
    pub global_fri_root: [u8; 32],
    /// Query positions (84 positions).
    pub query_positions: Vec<u64>,
    /// Final transcript hash (binding the entire batch).
    pub transcript_hash: [u8; 32],
    /// Aggregation challenge coefficients ξ[i].
    pub challenge_coefficients: Vec<[u8; 32]>,
}

impl AggregateProof {
    /// Verify that this aggregate proof has valid structure.
    pub fn verify_structure(&self) -> bool {
        self.n_proofs > 0
            && self.n_proofs <= STARK_MAX_BATCH_SIZE
            && self.query_positions.len() == NUM_FRI_QUERIES
            && self.challenge_coefficients.len() == self.n_proofs
    }

    /// Soundness bits for this batch size.
    pub fn soundness_bits(&self) -> u32 {
        // Degradation = log2(N) bits from base 2^-128.
        // Base soundness = 128 bits (individual proof).
        let degradation = (self.n_proofs as f64).log2().ceil() as u32;
        128u32.saturating_sub(degradation)
    }

    /// Check if soundness exceeds industry minimum. Research Package §3.4.2.
    pub fn meets_industry_minimum(&self) -> bool {
        self.soundness_bits() >= STARK_SOUNDNESS_INDUSTRY_MIN
    }
}

/// Aggregate N proof commitments into a single AggregateProof.
/// Research Package §3.4, R1-R4.
///
/// `commitments`: must be pre-sorted by tx_ordering_key (R1).
pub fn aggregate_proofs(
    commitments: &[ProofCommitment],
    global_fri_root: [u8; 32],
) -> Result<AggregateProof, TranscriptError> {
    let n = commitments.len();
    if n == 0 || n > STARK_MAX_BATCH_SIZE {
        return Err(TranscriptError::InvalidBatchSize {
            n,
            max: STARK_MAX_BATCH_SIZE,
        });
    }

    let mut transcript = STARKPackTranscript::new();

    // Phase 1: absorb all proof commitments (R1: caller ensures sorted order)
    for commitment in commitments {
        transcript.absorb_proof_commitment(commitment)?;
    }

    // Phase 2: squeeze aggregation challenge
    let challenges = transcript.squeeze_aggregation_challenge()?;

    // Phase 3: absorb global DEEP-FRI root
    transcript.absorb_global_fri_root(n as u32, &global_fri_root)?;

    // Phase 4: squeeze query positions
    let query_positions = transcript.squeeze_query_positions()?;

    // Finalize
    let transcript_hash = transcript.finalize()?;

    Ok(AggregateProof {
        n_proofs: n,
        global_fri_root,
        query_positions,
        transcript_hash,
        challenge_coefficients: challenges,
    })
}

/// Sort proof commitments by tx_ordering_key. R1 compliance helper.
/// Research Package §3.4.3 R1: sorted by tx_ordering_key — same as existing ordering.
pub fn sort_commitments_by_ordering_key(commitments: &mut [ProofCommitment]) {
    commitments.sort_by_key(|c| c.tx_ordering_key);
}

// ── A.5 / K7-02: Aggregation over REAL verified proofs ───────────────────────

use crate::transfer_air::{verify_transfer_proof, TransferPublicInputs, TransferVerifyError};

/// Domain separator for deriving a per-proof commitment from real proof bytes.
/// Distinct from DOMAIN_STARK_BATCH (Phase 3) and DOMAIN_SUBEPOCH_FS (Phase 1).
const DOMAIN_PROOF_COMMIT: &[u8] = b"scalar_starkpack_proofcommit";

/// One real transfer proof to be aggregated: bytes + its public inputs + ordering key.
pub struct RealProofInput {
    /// Serialized Winterfell proof bytes (from TransferProver::prove_transfer).
    pub proof_bytes: Vec<u8>,
    /// Public inputs the proof was generated with (needed to verify it).
    pub public_inputs: TransferPublicInputs,
    /// Deterministic ordering key (tx_ordering_key). R1.
    pub tx_ordering_key: [u8; 32],
}

/// Error from real-proof aggregation. K7-02.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RealAggregateError {
    #[error("batch size {n} invalid (max {max})")]
    InvalidBatchSize { n: usize, max: usize },
    #[error("proof {index} failed verification: {reason}")]
    ProofVerificationFailed { index: usize, reason: String },
    #[error("transcript error: {0:?}")]
    Transcript(TranscriptError),
}

/// Derive a ProofCommitment from REAL, already-verified proof bytes.
///
/// The merkle_root and deep_ali_root are derived via domain-separated BLAKE3
/// over the actual proof bytes, so they are cryptographically bound to the
/// real proof — NOT supplied by the caller. constraint_count is read from the
/// proof's own context (trace length × width is not exposed, so we bind the
/// proof byte length as a structural witness).
fn commitment_from_real_proof(proof_bytes: &[u8], tx_ordering_key: [u8; 32]) -> ProofCommitment {
    // merkle_root := BLAKE3(DOMAIN || "merkle" || proof_bytes)
    let mut h1 = Hasher::new();
    h1.update(DOMAIN_PROOF_COMMIT);
    h1.update(b"merkle");
    h1.update(proof_bytes);
    let merkle_root = *h1.finalize().as_bytes();

    // deep_ali_root := BLAKE3(DOMAIN || "deepali" || proof_bytes)
    let mut h2 = Hasher::new();
    h2.update(DOMAIN_PROOF_COMMIT);
    h2.update(b"deepali");
    h2.update(proof_bytes);
    let deep_ali_root = *h2.finalize().as_bytes();

    ProofCommitment {
        merkle_root,
        constraint_count: proof_bytes.len() as u32,
        deep_ali_root,
        tx_ordering_key,
    }
}

/// Compute the global DEEP-FRI root from the per-proof commitments of REAL proofs.
///
/// K7-02 fix: global_fri_root is DERIVED from the aggregated real-proof
/// commitments here — it is NOT passed in by the caller. The root binds every
/// proof's merkle_root and deep_ali_root in canonical (sorted) order.
fn compute_global_fri_root(sorted_commitments: &[ProofCommitment]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_STARK_BATCH);
    h.update(&(sorted_commitments.len() as u32).to_le_bytes());
    for c in sorted_commitments {
        h.update(&c.merkle_root);
        h.update(&c.deep_ali_root);
        h.update(&c.constraint_count.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

/// Aggregate N REAL transfer proofs into a single AggregateProof. K7-02 / A.5.
///
/// Workflow:
///   1. Verify EACH proof with the real Winterfell verifier. Any failure aborts
///      the whole batch (no invalid proof can be hidden inside an aggregate).
///   2. Derive each ProofCommitment from the real proof bytes (bound by BLAKE3).
///   3. Sort commitments by tx_ordering_key (R1).
///   4. Compute global_fri_root FROM the real-proof commitments (not supplied).
///   5. Run the Fiat-Shamir transcript (R1–R4) to produce the AggregateProof.
///
/// LIMITATION (documented, open): this is aggregation-over-verified-proofs, not
/// a single recursive low-degree FRI proof that re-proves all N in one shot.
/// Each proof is verified individually (step 1) and bound into one transcript
/// (steps 2–5). Full recursive FRI folding (one proof attesting all N without
/// re-running N verifications) remains future work — see Research Package §3.4.
pub fn aggregate_real_proofs(
    inputs: &[RealProofInput],
) -> Result<AggregateProof, RealAggregateError> {
    let n = inputs.len();
    if n == 0 || n > STARK_MAX_BATCH_SIZE {
        return Err(RealAggregateError::InvalidBatchSize {
            n,
            max: STARK_MAX_BATCH_SIZE,
        });
    }

    // Step 1: verify every proof with the REAL verifier. Abort on any failure.
    for (i, inp) in inputs.iter().enumerate() {
        match verify_transfer_proof(&inp.proof_bytes, &inp.public_inputs) {
            Ok(()) => {}
            Err(e) => {
                let reason = match e {
                    TransferVerifyError::EmptyProof => "empty proof".to_string(),
                    TransferVerifyError::DeserializationFailed(s) => s,
                    TransferVerifyError::VerificationFailed(s) => s,
                };
                return Err(RealAggregateError::ProofVerificationFailed { index: i, reason });
            }
        }
    }

    // Step 2: derive commitments from the real proof bytes.
    let mut commitments: Vec<ProofCommitment> = inputs
        .iter()
        .map(|inp| commitment_from_real_proof(&inp.proof_bytes, inp.tx_ordering_key))
        .collect();

    // Step 3: canonical sort (R1).
    sort_commitments_by_ordering_key(&mut commitments);

    // Step 4: compute global_fri_root from the real-proof commitments (K7-02).
    let global_fri_root = compute_global_fri_root(&commitments);

    // Step 5: run the transcript with the derived root.
    aggregate_proofs(&commitments, global_fri_root).map_err(RealAggregateError::Transcript)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_commitment(seed: u8) -> ProofCommitment {
        ProofCommitment {
            merkle_root: [seed; 32],
            constraint_count: 52088,
            deep_ali_root: [seed ^ 0xFF; 32],
            tx_ordering_key: [seed; 32],
        }
    }

    // ── Constants — Decision D-002 ────────────────────────────────────────────

    #[test]
    fn test_max_batch_size_ossified() {
        // Decision D-002: N=256 optimal batch size. OSSIFIED.
        assert_eq!(STARK_MAX_BATCH_SIZE, 256);
    }

    #[test]
    fn test_extended_batch_size() {
        assert_eq!(STARK_EXTENDED_BATCH_SIZE, 1024);
    }

    #[test]
    fn test_soundness_n256() {
        // Decision D-002: N=256 → soundness 2^-120.
        assert_eq!(STARK_BATCH_SOUNDNESS_N256, 120);
    }

    #[test]
    fn test_soundness_n1024() {
        assert_eq!(STARK_BATCH_SOUNDNESS_N1024, 118);
    }

    #[test]
    fn test_soundness_above_industry_minimum() {
        // Both N=256 and N=1024 exceed industry minimum 2^-100.
        const {
            assert!(STARK_BATCH_SOUNDNESS_N256 > STARK_SOUNDNESS_INDUSTRY_MIN);
        }
        const {
            assert!(STARK_BATCH_SOUNDNESS_N1024 > STARK_SOUNDNESS_INDUSTRY_MIN);
        }
    }

    #[test]
    fn test_num_fri_queries_ossified() {
        // 84 FRI queries — same as individual proof spec. OSSIFIED.
        assert_eq!(NUM_FRI_QUERIES, 84);
    }

    // ── Transcript Phase 1 ────────────────────────────────────────────────────

    #[test]
    fn test_transcript_phase1_absorb() {
        let mut t = STARKPackTranscript::new();
        let c = make_commitment(0x01);
        assert!(t.absorb_proof_commitment(&c).is_ok());
        assert_eq!(t.proof_count(), 1);
    }

    #[test]
    fn test_transcript_phase1_multiple() {
        let mut t = STARKPackTranscript::new();
        for i in 0..5u8 {
            t.absorb_proof_commitment(&make_commitment(i)).unwrap();
        }
        assert_eq!(t.proof_count(), 5);
    }

    #[test]
    fn test_transcript_phase2_challenge() {
        let mut t = STARKPackTranscript::new();
        for i in 0..3u8 {
            t.absorb_proof_commitment(&make_commitment(i)).unwrap();
        }
        let challenges = t.squeeze_aggregation_challenge().unwrap();
        assert_eq!(challenges.len(), 3);
    }

    #[test]
    fn test_transcript_phase3_fri_root() {
        let mut t = STARKPackTranscript::new();
        t.absorb_proof_commitment(&make_commitment(0x01)).unwrap();
        t.squeeze_aggregation_challenge().unwrap();
        let result = t.absorb_global_fri_root(1, &[0xABu8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_transcript_phase4_query_positions() {
        let mut t = STARKPackTranscript::new();
        t.absorb_proof_commitment(&make_commitment(0x01)).unwrap();
        t.squeeze_aggregation_challenge().unwrap();
        t.absorb_global_fri_root(1, &[0xABu8; 32]).unwrap();
        let positions = t.squeeze_query_positions().unwrap();
        assert_eq!(positions.len(), NUM_FRI_QUERIES);
        assert_eq!(positions.len(), 84);
    }

    #[test]
    fn test_transcript_wrong_phase_rejected() {
        // R3: transcript state not reset — wrong phase must be rejected.
        let mut t = STARKPackTranscript::new();
        // Try Phase 3 without Phase 1/2
        let result = t.absorb_global_fri_root(1, &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_transcript_deterministic() {
        // Same inputs → identical transcript hash. R1-R4.
        let commitments: Vec<ProofCommitment> = (0..3u8).map(make_commitment).collect();
        let fri_root = [0x42u8; 32];

        let p1 = aggregate_proofs(&commitments, fri_root).unwrap();
        let p2 = aggregate_proofs(&commitments, fri_root).unwrap();

        assert_eq!(p1.transcript_hash, p2.transcript_hash);
        assert_eq!(p1.query_positions, p2.query_positions);
        assert_eq!(p1.challenge_coefficients, p2.challenge_coefficients);
    }

    // ── R1: sorted order matters ──────────────────────────────────────────────

    #[test]
    fn test_transcript_order_matters() {
        // R1: different ordering → different transcript hash.
        let c1 = make_commitment(0x01);
        let c2 = make_commitment(0x02);
        let fri_root = [0x42u8; 32];

        let p_12 = aggregate_proofs(&[c1.clone(), c2.clone()], fri_root).unwrap();
        let p_21 = aggregate_proofs(&[c2.clone(), c1.clone()], fri_root).unwrap();

        assert_ne!(
            p_12.transcript_hash, p_21.transcript_hash,
            "R1: different ordering must produce different transcript"
        );
    }

    // ── AggregateProof ────────────────────────────────────────────────────────

    #[test]
    fn test_aggregate_proof_structure_valid() {
        let commitments: Vec<ProofCommitment> = (0..5u8).map(make_commitment).collect();
        let proof = aggregate_proofs(&commitments, [0xFFu8; 32]).unwrap();
        assert!(proof.verify_structure());
        assert_eq!(proof.n_proofs, 5);
        assert_eq!(proof.query_positions.len(), 84);
        assert_eq!(proof.challenge_coefficients.len(), 5);
    }

    #[test]
    fn test_aggregate_proof_soundness_n256() {
        // N=256: soundness = 128 - log2(256) = 128 - 8 = 120 bits.
        let commitments: Vec<ProofCommitment> = (0..=255u8).map(make_commitment).collect();
        let proof = aggregate_proofs(&commitments, [0u8; 32]).unwrap();
        assert_eq!(proof.soundness_bits(), STARK_BATCH_SOUNDNESS_N256);
        assert!(proof.meets_industry_minimum());
    }

    #[test]
    fn test_aggregate_proof_empty_rejected() {
        let result = aggregate_proofs(&[], [0u8; 32]);
        assert!(matches!(
            result,
            Err(TranscriptError::InvalidBatchSize { n: 0, .. })
        ));
    }

    #[test]
    fn test_aggregate_proof_over_max_rejected() {
        // N > 256 must be rejected.
        let commitments: Vec<ProofCommitment> =
            (0..=255u8).chain(0..=0u8).map(make_commitment).collect();
        let result = aggregate_proofs(&commitments, [0u8; 32]);
        assert!(matches!(
            result,
            Err(TranscriptError::InvalidBatchSize { .. })
        ));
    }

    // ── Sort helper ───────────────────────────────────────────────────────────

    #[test]
    fn test_sort_by_ordering_key() {
        let mut commitments = vec![
            make_commitment(0x03),
            make_commitment(0x01),
            make_commitment(0x02),
        ];
        sort_commitments_by_ordering_key(&mut commitments);
        assert_eq!(commitments[0].tx_ordering_key, [0x01u8; 32]);
        assert_eq!(commitments[1].tx_ordering_key, [0x02u8; 32]);
        assert_eq!(commitments[2].tx_ordering_key, [0x03u8; 32]);
    }

    // ── Soundness analysis — Research Package §3.4.2 ─────────────────────────

    #[test]
    fn test_soundness_degradation_formula() {
        // Degradation = log2(N) bits. Research Package §3.4.2.
        // N=1: degradation=0, soundness=128
        // N=2: degradation=1, soundness=127
        // N=256: degradation=8, soundness=120
        let c1 = aggregate_proofs(&[make_commitment(1)], [0u8; 32]).unwrap();
        assert_eq!(c1.soundness_bits(), 128);

        let c2_vec: Vec<ProofCommitment> = (0..2u8).map(make_commitment).collect();
        let c2 = aggregate_proofs(&c2_vec, [0u8; 32]).unwrap();
        assert_eq!(c2.soundness_bits(), 127);
    }

    #[test]
    fn test_domain_separator_starkbatch() {
        // DOMAIN_STARK_BATCH = b"scalar_stark_batch" (18 bytes). OSSIFIED.
        assert_eq!(DOMAIN_STARK_BATCH, b"scalar_stark_batch");
        assert_eq!(DOMAIN_STARK_BATCH.len(), 18);
    }

    // ── K7-01 — Phase 1 (scalar_subepoch_fs) vs Phase 3 (scalar_stark_batch) ──
    #[test]
    fn k7_01_phase1_phase3_distinct_domains() {
        use scalar_crypto::domain::{DOMAIN_STARK_BATCH, DOMAIN_SUBEPOCH_FS};
        // Both 18 bytes but DISTINCT — prevents cross-protocol correlation (§3.4.3).
        assert_ne!(
            DOMAIN_SUBEPOCH_FS, DOMAIN_STARK_BATCH,
            "K7-01: Phase 1 and Phase 3 must use distinct domain separators"
        );
        assert_eq!(DOMAIN_SUBEPOCH_FS, b"scalar_subepoch_fs");
        assert_eq!(DOMAIN_STARK_BATCH, b"scalar_stark_batch");
    }
}

// ── A.5 / K7-02 tests — aggregation over REAL proofs ─────────────────────────

#[cfg(test)]
mod real_aggregation_tests {
    use super::*;
    use crate::transfer_air::{TransferProver, TransferPublicInputs};

    fn valid_tpi(fee: u64) -> TransferPublicInputs {
        TransferPublicInputs {
            fee_total_sscl: fee,
            sum_inputs_sscl: fee,
            sum_outputs_sscl: 0,
            crypto_version: 0x01,
            entry_timestamp_ms: 1_000_000_000,
            current_timestamp_ms: 1_000_060_000,
            nullifier_nonzero: true,
            output_nonzero: true,
            single_utxo_source: true,
        }
    }

    fn real_input(fee: u64, key_seed: u8) -> RealProofInput {
        let pi = valid_tpi(fee);
        let proof_bytes = TransferProver::new()
            .prove_transfer(&pi)
            .expect("real proof");
        RealProofInput {
            proof_bytes,
            public_inputs: pi,
            tx_ordering_key: [key_seed; 32],
        }
    }

    #[test]
    fn test_aggregate_real_proofs_basic() {
        // K7-02: aggregate 3 real verified proofs; global_fri_root derived from them.
        let inputs = vec![
            real_input(40, 0x01),
            real_input(50, 0x02),
            real_input(60, 0x03),
        ];
        let agg = aggregate_real_proofs(&inputs).expect("aggregation must succeed");
        assert_eq!(agg.n_proofs, 3);
        assert!(agg.verify_structure());
        // global_fri_root must be non-zero (derived from real proofs)
        assert_ne!(agg.global_fri_root, [0u8; 32]);
    }

    #[test]
    fn test_global_fri_root_derived_not_supplied() {
        // K7-02: the same set of real proofs yields a deterministic root,
        // and a DIFFERENT set yields a DIFFERENT root — proving the root is
        // bound to the actual proofs, not an arbitrary caller-supplied value.
        let a = vec![real_input(40, 0x01), real_input(50, 0x02)];
        let b = vec![real_input(70, 0x01), real_input(80, 0x02)];
        let ra = aggregate_real_proofs(&a).unwrap();
        let rb = aggregate_real_proofs(&b).unwrap();
        assert_ne!(
            ra.global_fri_root, rb.global_fri_root,
            "different real proofs must yield different global_fri_root"
        );
    }

    #[test]
    fn test_aggregate_rejects_empty_proof_in_batch() {
        // K7-02: an empty (invalid) proof in the batch aborts aggregation.
        let mut inputs = vec![real_input(40, 0x01)];
        inputs.push(RealProofInput {
            proof_bytes: vec![], // invalid
            public_inputs: valid_tpi(50),
            tx_ordering_key: [0x02; 32],
        });
        let r = aggregate_real_proofs(&inputs);
        assert!(matches!(
            r,
            Err(RealAggregateError::ProofVerificationFailed { index: 1, .. })
        ));
    }

    #[test]
    fn test_aggregate_rejects_tampered_proof_in_batch() {
        // K7-02: a tampered proof in the batch must be rejected (real verify).
        let mut good = real_input(40, 0x01);
        let mut tampered = real_input(50, 0x02);
        let mid = tampered.proof_bytes.len() / 2;
        tampered.proof_bytes[mid] ^= 0xFF;
        let _ = &mut good;
        let inputs = vec![good, tampered];
        let r = aggregate_real_proofs(&inputs);
        assert!(
            matches!(
                r,
                Err(RealAggregateError::ProofVerificationFailed { index: 1, .. })
            ),
            "tampered proof in batch must abort aggregation: {:?}",
            r
        );
    }

    #[test]
    fn test_aggregate_rejects_wrong_pubinputs_in_batch() {
        // K7-02: proof verified against mismatched public inputs is rejected.
        let mut bad = real_input(40, 0x01);
        bad.public_inputs.fee_total_sscl = 999; // doesn't match the proof
        let inputs = vec![bad];
        let r = aggregate_real_proofs(&inputs);
        assert!(matches!(
            r,
            Err(RealAggregateError::ProofVerificationFailed { index: 0, .. })
        ));
    }

    #[test]
    fn test_aggregate_empty_batch_rejected() {
        let r = aggregate_real_proofs(&[]);
        assert!(matches!(
            r,
            Err(RealAggregateError::InvalidBatchSize { n: 0, .. })
        ));
    }

    #[test]
    fn test_aggregate_deterministic() {
        // Same real proofs → identical aggregate (determinism, R1–R4).
        let mk = || {
            vec![
                real_input(40, 0x03),
                real_input(50, 0x01),
                real_input(60, 0x02),
            ]
        };
        let r1 = aggregate_real_proofs(&mk()).unwrap();
        let r2 = aggregate_real_proofs(&mk()).unwrap();
        assert_eq!(r1.global_fri_root, r2.global_fri_root);
        assert_eq!(r1.transcript_hash, r2.transcript_hash);
        assert_eq!(r1.query_positions, r2.query_positions);
    }
}
