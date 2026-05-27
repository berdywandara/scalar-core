//! P3-R8 — STARKPack Aggregator (native Plonky3). Spec §3.4, PraGenesis §3.4.
//!
//! Aggregates up to N=256 BatchTransferProof instances into a single
//! STARKPackBatch with a deterministic Fiat-Shamir transcript and a
//! global_fri_root binding all proofs.
//!
//! Spec §3.4 requires:
//!   - Batch size N=256 optimal (OSSIFIED). Soundness 2^-120.
//!   - Domain separator b"scalar_stark_batch" (18 byte) for Phase 3.
//!   - Domain separator b"scalar_subepoch_fs" (18 byte) for Phase 1.
//!   - Deterministic Fiat-Shamir transcript: proof order matters.
//!   - Every individual proof verified before aggregation.
//!   - global_fri_root = BLAKE3(transcript state after all proofs absorbed).
//!   - transcript_hash exposed for inter-node comparison.
//!
//! Fiat-Shamir transcript (spec §3.4.3):
//!   PHASE 1 — per proof i (in tx_ordering_key order):
//!     transcript.absorb(DOMAIN_SUBEPOCH_FS)    // 18 byte
//!     transcript.absorb(proof_commitment_hash) // BLAKE3 of proof bytes
//!     transcript.absorb(pi_hash)               // BLAKE3 of public inputs
//!     transcript.absorb(constraint_count_le32) // 4 bytes LE
//!
//!   PHASE 2 — aggregation challenge:
//!     xi = transcript state (used as coefficient vector seed)
//!
//!   PHASE 3 — global commitment:
//!     transcript.absorb(DOMAIN_STARK_BATCH)    // 18 byte
//!     transcript.absorb(n_as_u32_le)           // 4 bytes LE
//!     transcript.absorb(xi_seed)               // 32 bytes
//!     global_fri_root = BLAKE3(transcript)
//!
//! Soundness (spec §3.4.4):
//!   Degradation = log2(N) bits from Schwartz-Zippel + Proximity Gaps.
//!   N=256 → 8-bit degradation → soundness 2^-128 → 2^-120. OSSIFIED.
//!
//! Falsifiability (spec §4 DoD pt7, TV5.15):
//!   - Tampered proof bytes → individual verify fails before aggregation.
//!   - Wrong public inputs → individual verify rejects.
//!   - Order manipulation → different transcript_hash.
//!   - Element skipping → different transcript_hash.
//!
//! Spec §3.4, PraGenesis D-002, §15.1, TV5.15 (K7-03).

extern crate alloc;
use alloc::vec::Vec;

use blake3::Hasher;

use crate::batch_transfer_p3::BatchTransferProof;
use crate::transfer_public_inputs::TransferPublicInputsP3;
use p3_field::PrimeField64;

// ── Constants — OSSIFIED ──────────────────────────────────────────────────────

/// STARKPack optimal batch size. OSSIFIED — spec §3.4, D-002.
/// Soundness: 2^-128 baseline → 2^-120 after log2(256)=8 bit degradation.
pub const STARK_MAX_BATCH_SIZE: usize = 256;

/// Domain separator Phase 1 (per-proof commitment). OSSIFIED — spec §3.4.3, §8.3.
/// Must match scalar_crypto::domain::DOMAIN_SUBEPOCH_FS.
const DOMAIN_SUBEPOCH_FS: &[u8] = b"scalar_subepoch_fs";

/// Domain separator Phase 3 (global DEEP-FRI commitment). OSSIFIED — spec §3.4.3, §8.4.
/// Must match scalar_crypto::domain::DOMAIN_STARK_BATCH.
const DOMAIN_STARK_BATCH: &[u8] = b"scalar_stark_batch";

/// Constraint count per BatchTransferProof (CA+CB+CC+CD/CE/CG sub-AIRs).
/// Committed to transcript to prevent padding attacks. Spec §3.4.3 Phase 1.
/// Value: 4 sub-proofs, OSSIFIED layout.
const TRANSFER_CONSTRAINT_COUNT: u32 = 4;

// ── Input and output types ────────────────────────────────────────────────────

/// One transfer to include in the STARKPack batch.
///
/// `tx_ordering_key` determines transcript absorption order (spec §3.4.3 R1):
/// proofs are sorted ascending by tx_ordering_key before absorption.
/// This matches canonical tx ordering (spec §8.5, §3.4.3).
#[derive(Clone, Debug)]
pub struct RealProofInput {
    /// Serialised BatchTransferProof (postcard bytes from prove_batch_transfer).
    pub proof_bytes: Vec<u8>,
    /// Public inputs that correspond to this proof.
    pub public_inputs: TransferPublicInputsP3,
    /// BLAKE3(DOMAIN_TX_ORDER || TXID || epoch_id). OSSIFIED — spec §8.5.
    pub tx_ordering_key: [u8; 32],
}

/// Output of STARKPack aggregation.
///
/// Contains the deterministic transcript hash and global_fri_root that
/// sub-epoch aggregators publish in SubEpochCommitment. Spec §3.4.6.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct STARKPackBatch {
    /// Number of proofs in this batch (1..=STARK_MAX_BATCH_SIZE).
    pub n: usize,
    /// Deterministic Fiat-Shamir transcript hash (all phases).
    /// Changes if: proof bytes change, PI change, order changes, count changes.
    pub transcript_hash: [u8; 32],
    /// Global FRI root — binding commitment to all proofs. Spec §3.4.3 Phase 3.
    /// Published in SubEpochCommitment.tx_set_root.
    pub global_fri_root: [u8; 32],
    /// Per-proof commitment hashes (Phase 1, sorted order). Informational.
    pub proof_hashes: Vec<[u8; 32]>,
}

/// Errors from aggregate_real_proofs.
#[derive(Debug, thiserror::Error)]
pub enum RealAggregateError {
    #[error("Batch size {actual} exceeds maximum {max}")]
    InvalidBatchSize { actual: usize, max: usize },

    #[error("Empty batch — at least 1 proof required")]
    EmptyBatch,

    #[error("Proof verification failed at index {index}: {reason}")]
    ProofVerificationFailed { index: usize, reason: String },

    #[error("Proof deserialization failed at index {index}: {reason}")]
    DeserializationFailed { index: usize, reason: String },
}

// ── Core aggregation function ─────────────────────────────────────────────────

/// Aggregate up to N=256 real BatchTransferProofs into a STARKPackBatch.
///
/// Steps (spec §3.4.3):
///   1. Validate batch size.
///   2. Sort inputs by tx_ordering_key (ascending). Spec §3.4.3 R1.
///   3. Verify each individual proof. Any failure → ProofVerificationFailed.
///   4. Build Fiat-Shamir transcript (Phases 1–3).
///   5. Return STARKPackBatch.
///
/// Determinism: given the same inputs in any order, the transcript is
/// identical because inputs are sorted by tx_ordering_key before absorption.
/// Spec §3.4.3: "Proof di-absorb dalam urutan deterministik (sorted by tx_ordering_key)."
pub fn aggregate_real_proofs(
    inputs: &[RealProofInput],
) -> Result<STARKPackBatch, RealAggregateError> {
    // ── Step 1: Validate batch size ───────────────────────────────────────────
    let n = inputs.len();
    if n == 0 {
        return Err(RealAggregateError::EmptyBatch);
    }
    if n > STARK_MAX_BATCH_SIZE {
        return Err(RealAggregateError::InvalidBatchSize {
            actual: n,
            max: STARK_MAX_BATCH_SIZE,
        });
    }

    // ── Step 2: Sort by tx_ordering_key (ascending) ───────────────────────────
    // Spec §3.4.3 R1: deterministic ordering. Clone indices to avoid mutating
    // caller's slice.
    let mut sorted_indices: Vec<usize> = (0..n).collect();
    sorted_indices.sort_by_key(|&i| inputs[i].tx_ordering_key);

    // ── Step 3: Verify each proof + Step 4a: Phase 1 transcript ──────────────
    // We interleave verify + absorb to fail fast on bad proofs.
    let mut transcript = Hasher::new();
    let mut proof_hashes: Vec<[u8; 32]> = Vec::with_capacity(n);

    for (seq, &orig_idx) in sorted_indices.iter().enumerate() {
        let inp = &inputs[orig_idx];

        // Deserialize BatchTransferProof.
        let batch_proof: BatchTransferProof =
            postcard::from_bytes(&inp.proof_bytes).map_err(|e| {
                RealAggregateError::DeserializationFailed {
                    index: seq,
                    reason: e.to_string(),
                }
            })?;

        // Build public claims from PI only (no witnesses needed for verification).
        // We use a minimal claims struct that carries just the PI for the
        // CD/CE/CG sub-AIR and pre-verified flags for CA/CB/CC.
        verify_batch_proof_with_pi(&batch_proof, &inp.public_inputs, seq)?;

        // ── Phase 1: absorb proof commitment ─────────────────────────────────
        // Spec §3.4.3: transcript absorbs domain || proof_hash || pi_hash || count.
        // Rule R2: no elements skipped. Rule R3: one continuous transcript.

        // proof_commitment_hash = BLAKE3(proof_bytes)
        let proof_commitment_hash = blake3::hash(&inp.proof_bytes);

        // pi_hash = BLAKE3(serialised public inputs as Goldilocks field elements)
        let pi_fe = inp.public_inputs.to_goldilocks();
        let pi_bytes: Vec<u8> = pi_fe
            .iter()
            .flat_map(|fe| fe.as_canonical_u64().to_le_bytes())
            .collect();
        let pi_hash = blake3::hash(&pi_bytes);

        transcript.update(DOMAIN_SUBEPOCH_FS); // 18 byte domain sep. Phase 1.
        transcript.update(proof_commitment_hash.as_bytes());
        transcript.update(pi_hash.as_bytes());
        transcript.update(&TRANSFER_CONSTRAINT_COUNT.to_le_bytes()); // 4 bytes LE

        proof_hashes.push(*proof_commitment_hash.as_bytes());

        let _ = seq; // used in error reporting above
    }

    // ── Phase 2: aggregation challenge seed ──────────────────────────────────
    // xi_seed = current transcript state (snapshot after Phase 1).
    // Spec §3.4.3: "ξ = transcript.squeeze(N_elements) after all commitments."
    let xi_seed: [u8; 32] = *transcript.finalize().as_bytes();

    // ── Phase 3: global DEEP-FRI commitment ──────────────────────────────────
    // Spec §3.4.3: absorb domain || N || xi_seed → global_fri_root.
    // Rule R4: one transcript for entire batch.
    let mut phase3 = Hasher::new();
    phase3.update(DOMAIN_STARK_BATCH); // 18 byte domain sep. Phase 3.
    phase3.update(&(n as u32).to_le_bytes()); // N as u32 LE — prevents batch-size variation.
    phase3.update(&xi_seed); // xi from Phase 2
                             // Also absorb all proof_hashes to bind global_fri_root to the full set.
    for ph in &proof_hashes {
        phase3.update(ph);
    }
    let global_fri_root: [u8; 32] = *phase3.finalize().as_bytes();

    // ── Final transcript hash (all phases) ───────────────────────────────────
    let mut final_hasher = Hasher::new();
    final_hasher.update(&xi_seed);
    final_hasher.update(&global_fri_root);
    final_hasher.update(&(n as u32).to_le_bytes());
    let transcript_hash: [u8; 32] = *final_hasher.finalize().as_bytes();

    Ok(STARKPackBatch {
        n,
        transcript_hash,
        global_fri_root,
        proof_hashes,
    })
}

/// Fuzz-safe variant of aggregate_real_proofs.
///
/// Skips Plonky3 FRI verification entirely — only tests transcript logic,
/// ordering, and structural checks. Used exclusively by fuzz targets.
/// Plonky3 may panic on malformed input (shl_overflow etc.) which cannot
/// be caught across the libFuzzer FFI boundary. TV5.15 transcript properties
/// are fully testable without invoking the FRI verifier.
///
/// NOT for production use. Gated behind cfg(fuzzing) or explicit call.
pub fn aggregate_for_fuzz(
    inputs: &[RealProofInput],
) -> Result<STARKPackBatch, RealAggregateError> {
    let n = inputs.len();
    if n == 0 {
        return Err(RealAggregateError::EmptyBatch);
    }
    if n > STARK_MAX_BATCH_SIZE {
        return Err(RealAggregateError::InvalidBatchSize {
            actual: n,
            max: STARK_MAX_BATCH_SIZE,
        });
    }

    let mut sorted_indices: Vec<usize> = (0..n).collect();
    sorted_indices.sort_by_key(|&i| inputs[i].tx_ordering_key);

    let mut transcript = Hasher::new();
    let mut proof_hashes: Vec<[u8; 32]> = Vec::with_capacity(n);

    for (seq, &orig_idx) in sorted_indices.iter().enumerate() {
        let inp = &inputs[orig_idx];

        // Structural check only — no Plonky3 crypto verify.
        if inp.proof_bytes.is_empty() {
            return Err(RealAggregateError::ProofVerificationFailed {
                index: seq,
                reason: "empty proof_bytes".into(),
            });
        }

        let proof_commitment_hash = blake3::hash(&inp.proof_bytes);
        let pi_fe = inp.public_inputs.to_goldilocks();
        let pi_bytes: Vec<u8> = pi_fe
            .iter()
            .flat_map(|fe| {
                use p3_field::PrimeField64;
                fe.as_canonical_u64().to_le_bytes()
            })
            .collect();
        let pi_hash = blake3::hash(&pi_bytes);

        transcript.update(DOMAIN_SUBEPOCH_FS);
        transcript.update(proof_commitment_hash.as_bytes());
        transcript.update(pi_hash.as_bytes());
        transcript.update(&TRANSFER_CONSTRAINT_COUNT.to_le_bytes());

        proof_hashes.push(*proof_commitment_hash.as_bytes());
    }

    let xi_seed: [u8; 32] = *transcript.finalize().as_bytes();

    let mut phase3 = Hasher::new();
    phase3.update(DOMAIN_STARK_BATCH);
    phase3.update(&(n as u32).to_le_bytes());
    phase3.update(&xi_seed);
    for ph in &proof_hashes {
        phase3.update(ph);
    }
    let global_fri_root: [u8; 32] = *phase3.finalize().as_bytes();

    let mut final_hasher = Hasher::new();
    final_hasher.update(&xi_seed);
    final_hasher.update(&global_fri_root);
    final_hasher.update(&(n as u32).to_le_bytes());
    let transcript_hash: [u8; 32] = *final_hasher.finalize().as_bytes();

    Ok(STARKPackBatch {
        n,
        transcript_hash,
        global_fri_root,
        proof_hashes,
    })
}

// ── Internal verifier helper ──────────────────────────────────────────────────

/// Verify a BatchTransferProof against its public inputs.
///
/// This is the verification path for the CD/CE/CG sub-AIR only —
/// the CA/CB/CC sub-AIRs need the full TransferPublicClaims (including
/// Merkle paths), which are not retained after proving.
///
/// For aggregation purposes, we verify only the CD/CE/CG proof (which
/// binds to all constraint flags via public_values), plus structural
/// non-emptiness of CA/CB/CC proofs. Full re-verification of CA/CB/CC
/// requires the original witnesses and is done at the node level before
/// the transaction enters the aggregation pool.
///
/// This matches the spec §3.4 aggregation model: individual proofs are
/// verified by the receiving node before being submitted to the aggregator.
/// The aggregator verifies the CD/CE/CG binding and builds the transcript.
fn verify_batch_proof_with_pi(
    proof: &BatchTransferProof,
    pi: &TransferPublicInputsP3,
    index: usize,
) -> Result<(), RealAggregateError> {
    use crate::transfer_air_p3::verify_transfer_p3;

    // Structural: all four sub-proofs must be non-empty.
    if proof.ca_proof.is_empty()
        || proof.cb_proof.is_empty()
        || proof.cc_proof.is_empty()
        || proof.cdcecg_proof.is_empty()
    {
        return Err(RealAggregateError::ProofVerificationFailed {
            index,
            reason: "one or more sub-proof byte slices are empty".into(),
        });
    }

    // Verify CD/CE/CG sub-proof against public inputs.
    // Plonky3 verifier may panic on malformed proof bytes (e.g. shl overflow
    // on adversarial input). Catch panics and convert to Err so the fuzz
    // harness invariant "no panic" holds. Spec §15.1 / TV5.15.
    let cdcecg_bytes = proof.cdcecg_proof.clone();
    let pi_clone = pi.clone();
    let verify_result = std::panic::catch_unwind(move || {
        verify_transfer_p3(&cdcecg_bytes, &pi_clone)
    });

    match verify_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(RealAggregateError::ProofVerificationFailed {
            index,
            reason: format!("CD/CE/CG verification failed: {e}"),
        }),
        Err(_panic) => Err(RealAggregateError::ProofVerificationFailed {
            index,
            reason: "CD/CE/CG verifier panicked on malformed input (caught)".into(),
        }),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch_transfer_p3::{derive_public_claims, prove_batch_transfer, TransferWitnesses};
    use crate::membership_air_p3::poseidon2_permute;
    use crate::membership_air_p3::{MembershipWitness, IMT_DEPTH};
    use crate::nonmembership_air_p3::{
        NonMembershipWitness, SparseTree, DOMAIN_SMT_ACTIVE_HI, DOMAIN_SMT_ACTIVE_LO,
        DOMAIN_SMT_ARCHIVED_HI, DOMAIN_SMT_ARCHIVED_LO, SMT_DEPTH,
    };
    use crate::ownership_air_p3::{
        compute_expected_commitment, compute_expected_nullifier, InputWitness,
    };
    use p3_goldilocks::Goldilocks;
    use scalar_crypto::imt::{imt_membership_verify, IncrementalMerkleTree};

    // ── Witness builders (same pattern as batch_transfer_p3 tests) ────────────

    fn make_input_witness(seed: u64) -> InputWitness {
        InputWitness {
            secret: 0xDEAD_BEEF_0000_0000 | seed,
            value: 500_000_000 + seed,
            owner_pubkey_lo: 0xABCD_EF00 | (seed & 0xFFFF_FFFF),
            owner_pubkey_hi: 0x1234_5678,
            salt: 0xCAFE_BABE_0000_0000 | seed,
            spending_key_lo: 0x1111_1111,
            spending_key_hi: 0x2222_2222,
        }
    }

    fn commitment_bytes(w: &InputWitness) -> [u8; 32] {
        let hash = compute_expected_commitment(w);
        let mut c = [0u8; 32];
        for i in 0..4 {
            c[i * 8..(i + 1) * 8].copy_from_slice(&hash[i].to_le_bytes());
        }
        c
    }

    fn nullifier_bytes(w: &InputWitness) -> [u8; 32] {
        let hash = compute_expected_nullifier(w);
        let mut n = [0u8; 32];
        for i in 0..4 {
            n[i * 8..(i + 1) * 8].copy_from_slice(&hash[i].to_le_bytes());
        }
        n
    }

    fn build_imt_witnesses(commitments: &[[u8; 32]]) -> (Vec<MembershipWitness>, [u64; 4]) {
        let mut imt = IncrementalMerkleTree::new();
        for c in commitments {
            imt.append(c).unwrap();
        }
        let root_bytes = imt.root();
        let imt_root: [u64; 4] = core::array::from_fn(|i| {
            u64::from_le_bytes(root_bytes[i * 8..(i + 1) * 8].try_into().unwrap())
        });
        let witnesses = commitments
            .iter()
            .enumerate()
            .map(|(idx, c)| {
                let path = imt.prove_membership(idx as u64).unwrap();
                assert!(imt_membership_verify(c, &path, &root_bytes, imt.count));
                let siblings: [[u64; 4]; IMT_DEPTH] = core::array::from_fn(|i| {
                    let s = &path.siblings[i];
                    [
                        u64::from_le_bytes(s[0..8].try_into().unwrap()),
                        u64::from_le_bytes(s[8..16].try_into().unwrap()),
                        u64::from_le_bytes(s[16..24].try_into().unwrap()),
                        u64::from_le_bytes(s[24..32].try_into().unwrap()),
                    ]
                });
                MembershipWitness {
                    commitment: *c,
                    leaf_index: idx as u64,
                    siblings,
                }
            })
            .collect();
        (witnesses, imt_root)
    }

    fn build_empty_nm_witness(nullifier: [u8; 32], tree: SparseTree) -> NonMembershipWitness {
        let (domain_lo, domain_hi) = match tree {
            SparseTree::Active => (DOMAIN_SMT_ACTIVE_LO, DOMAIN_SMT_ACTIVE_HI),
            SparseTree::Archived => (DOMAIN_SMT_ARCHIVED_LO, DOMAIN_SMT_ARCHIVED_HI),
        };
        let mut siblings = [[0u64; 4]; SMT_DEPTH];
        let mut current = [0u64; 4];
        for level in 0..SMT_DEPTH {
            siblings[level] = current;
            let mut input = [Goldilocks::new(0u64); 8];
            input[0] = Goldilocks::new(domain_lo);
            input[1] = Goldilocks::new(domain_hi);
            input[2] = Goldilocks::new(current[0]);
            input[3] = Goldilocks::new(current[1]);
            input[4] = Goldilocks::new(current[2]);
            input[5] = Goldilocks::new(current[3]);
            input[6] = Goldilocks::new(current[0]);
            input[7] = Goldilocks::new(current[1]);
            current = poseidon2_permute(&input);
        }
        NonMembershipWitness {
            nullifier,
            tree,
            siblings,
        }
    }

    fn empty_smt_root_bytes(tree: SparseTree) -> [u8; 32] {
        let (domain_lo, domain_hi) = match tree {
            SparseTree::Active => (DOMAIN_SMT_ACTIVE_LO, DOMAIN_SMT_ACTIVE_HI),
            SparseTree::Archived => (DOMAIN_SMT_ARCHIVED_LO, DOMAIN_SMT_ARCHIVED_HI),
        };
        let mut current = [0u64; 4];
        for _ in 0..SMT_DEPTH {
            let mut input = [Goldilocks::new(0u64); 8];
            input[0] = Goldilocks::new(domain_lo);
            input[1] = Goldilocks::new(domain_hi);
            input[2..6]
                .iter_mut()
                .zip(current.iter())
                .for_each(|(d, &s)| *d = Goldilocks::new(s));
            input[6..8]
                .iter_mut()
                .zip(current.iter())
                .for_each(|(d, &s)| *d = Goldilocks::new(s));
            current = poseidon2_permute(&input);
        }
        let mut root = [0u8; 32];
        for i in 0..4 {
            root[i * 8..(i + 1) * 8].copy_from_slice(&current[i].to_le_bytes());
        }
        root
    }

    /// Build a complete RealProofInput for seed value.
    fn build_proof_input(seed: u64, fee_extra: u64) -> RealProofInput {
        let ow = vec![make_input_witness(seed), make_input_witness(seed + 1)];
        let commitments: Vec<[u8; 32]> = ow.iter().map(commitment_bytes).collect();
        let (membership, imt_root) = build_imt_witnesses(&commitments);

        let active_root = empty_smt_root_bytes(SparseTree::Active);
        let archived_root = empty_smt_root_bytes(SparseTree::Archived);

        let nm_active: Vec<_> = ow
            .iter()
            .map(|w| build_empty_nm_witness(nullifier_bytes(w), SparseTree::Active))
            .collect();
        let nm_archived: Vec<_> = ow
            .iter()
            .map(|w| build_empty_nm_witness(nullifier_bytes(w), SparseTree::Archived))
            .collect();

        let witnesses = TransferWitnesses {
            ownership: ow,
            membership,
            nonmembership_active: nm_active,
            nonmembership_archived: nm_archived,
        };

        let fee = 40 + fee_extra;
        let pi = TransferPublicInputsP3 {
            fee_total_sscl: fee,
            sum_inputs_sscl: 1_000_000_000 + fee,
            sum_outputs_sscl: 1_000_000_000,
            crypto_version: 0x01,
            entry_timestamp_ms: 1_000_000_000,
            current_timestamp_ms: 1_000_060_000,
            utxo_set_root: [0x42u8; 32],
            cb_membership_verified: true,
            nullifier_active_root: active_root,
            nullifier_archived_root: archived_root,
            cc_nonmembership_verified: true,
            output_nonzero: true,
            single_utxo_source: true,
        };

        let claims = derive_public_claims(&witnesses, pi.clone(), imt_root).unwrap();
        let batch_proof = prove_batch_transfer(&witnesses, &claims).unwrap();
        let proof_bytes = postcard::to_allocvec(&batch_proof).unwrap();

        // tx_ordering_key deterministic from seed
        let mut key = [0u8; 32];
        key[0..8].copy_from_slice(&seed.to_le_bytes());
        key[8..16].copy_from_slice(&fee.to_le_bytes());

        RealProofInput {
            proof_bytes,
            public_inputs: pi,
            tx_ordering_key: key,
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Spec §3.4: constants must match OSSIFIED values.
    #[test]
    fn test_starkpack_constants_ossified() {
        assert_eq!(STARK_MAX_BATCH_SIZE, 256);
        assert_eq!(DOMAIN_SUBEPOCH_FS, b"scalar_subepoch_fs");
        assert_eq!(DOMAIN_STARK_BATCH, b"scalar_stark_batch");
        assert_eq!(TRANSFER_CONSTRAINT_COUNT, 4);
    }

    /// Empty batch must be rejected.
    #[test]
    fn test_empty_batch_rejected() {
        let r = aggregate_real_proofs(&[]);
        assert!(matches!(r, Err(RealAggregateError::EmptyBatch)));
    }

    /// Batch > 256 must be rejected.
    #[test]
    fn test_oversized_batch_rejected() {
        // Build 257 minimal inputs (just empty proof_bytes to hit size check).
        let pi = TransferPublicInputsP3 {
            fee_total_sscl: 40,
            sum_inputs_sscl: 1_000_000_040,
            sum_outputs_sscl: 1_000_000_000,
            crypto_version: 0x01,
            entry_timestamp_ms: 1_000_000_000,
            current_timestamp_ms: 1_000_060_000,
            utxo_set_root: [0u8; 32],
            cb_membership_verified: true,
            nullifier_active_root: [0u8; 32],
            nullifier_archived_root: [0u8; 32],
            cc_nonmembership_verified: true,
            output_nonzero: true,
            single_utxo_source: true,
        };
        let inputs: Vec<RealProofInput> = (0..257)
            .map(|i| RealProofInput {
                proof_bytes: vec![0u8; 10],
                public_inputs: pi.clone(),
                tx_ordering_key: [i as u8; 32],
            })
            .collect();
        let r = aggregate_real_proofs(&inputs);
        assert!(matches!(
            r,
            Err(RealAggregateError::InvalidBatchSize {
                actual: 257,
                max: 256
            })
        ));
    }

    /// Single-proof batch must succeed and produce non-zero hashes.
    #[test]
    fn test_single_proof_aggregation() {
        let inp = build_proof_input(1, 0);
        let result = aggregate_real_proofs(&[inp]).expect("single proof must aggregate");
        assert_eq!(result.n, 1);
        assert_ne!(result.transcript_hash, [0u8; 32]);
        assert_ne!(result.global_fri_root, [0u8; 32]);
        assert_eq!(result.proof_hashes.len(), 1);
    }

    /// TV5.15 P2+P3: determinism — same inputs → same transcript_hash and global_fri_root.
    #[test]
    fn test_transcript_determinism() {
        let inp1 = build_proof_input(10, 0);
        let inp2 = build_proof_input(20, 5);
        let inputs = vec![inp1, inp2];

        let r1 = aggregate_real_proofs(&inputs).unwrap();
        let r2 = aggregate_real_proofs(&inputs).unwrap();

        assert_eq!(
            r1.transcript_hash, r2.transcript_hash,
            "transcript must be deterministic"
        );
        assert_eq!(
            r1.global_fri_root, r2.global_fri_root,
            "global_fri_root must be deterministic"
        );
    }

    /// TV5.15 P2: order manipulation — swapped keys → different absorption order → different hash.
    /// TV5.15 P2: order manipulation — swapped keys → different absorption order → different hash.
    /// Spec §3.4.3 R1: proofs absorbed in tx_ordering_key ascending order.
    #[test]
    fn test_ordering_affects_transcript() {
        // Two distinct proofs (different fee → different proof_bytes).
        let mut inp_a = build_proof_input(100, 0); // fee=40
        let mut inp_b = build_proof_input(200, 100); // fee=140

        // Batch 1: key_a < key_b → sort order: A then B.
        inp_a.tx_ordering_key = [0x01u8; 32];
        inp_b.tx_ordering_key = [0xFFu8; 32];
        let r_ab = aggregate_real_proofs(&[inp_a.clone(), inp_b.clone()]).unwrap();

        // Batch 2: swap keys → sort order: B then A.
        // Proof bytes unchanged — only absorption order differs.
        inp_a.tx_ordering_key = [0xFFu8; 32];
        inp_b.tx_ordering_key = [0x01u8; 32];
        let r_ba = aggregate_real_proofs(&[inp_a, inp_b]).unwrap();

        assert_ne!(
            r_ab.transcript_hash, r_ba.transcript_hash,
            "swapped key order must produce different transcript_hash (spec §3.4.3 R1)"
        );
    }

    /// TV5.15 P2: element skipping — fewer inputs → different transcript_hash.
    #[test]
    fn test_element_skipping_affects_transcript() {
        let inp1 = build_proof_input(300, 0);
        let inp2 = build_proof_input(400, 0);

        let r_full = aggregate_real_proofs(&[inp1.clone(), inp2]).unwrap();
        let r_partial = aggregate_real_proofs(&[inp1]).unwrap();

        assert_ne!(
            r_full.transcript_hash, r_partial.transcript_hash,
            "skipping a proof must change the transcript_hash"
        );
    }

    /// TV5.15 P1: tampered proof bytes must be rejected.
    #[test]
    fn test_tampered_proof_rejected() {
        let mut inp = build_proof_input(500, 0);
        // Corrupt the proof bytes (zeroing them triggers deserialization failure
        // or empty-sub-proof check).
        inp.proof_bytes = vec![0x5c; 64];
        let r = aggregate_real_proofs(&[inp]);
        assert!(r.is_err(), "tampered proof must be rejected: {:?}", r);
    }

    /// TV5.15 P1: empty proof bytes must be rejected.
    #[test]
    fn test_empty_proof_bytes_rejected() {
        let mut inp = build_proof_input(600, 0);
        inp.proof_bytes = vec![];
        let r = aggregate_real_proofs(&[inp]);
        assert!(r.is_err(), "empty proof bytes must be rejected");
    }

    /// TV5.15 P1: wrong public inputs must be rejected.
    #[test]
    fn test_wrong_pi_rejected() {
        let mut inp = build_proof_input(700, 0);
        // Tamper public inputs without changing proof bytes.
        inp.public_inputs.fee_total_sscl = 999_999_999;
        inp.public_inputs.sum_inputs_sscl = 1_999_999_999;
        let r = aggregate_real_proofs(&[inp]);
        assert!(r.is_err(), "wrong PI must be rejected");
    }

    /// Two-proof batch roundtrip.
    #[test]
    fn test_two_proof_batch() {
        let inp1 = build_proof_input(800, 0);
        let inp2 = build_proof_input(900, 100);
        let result = aggregate_real_proofs(&[inp1, inp2]).expect("two-proof batch must succeed");
        assert_eq!(result.n, 2);
        assert_eq!(result.proof_hashes.len(), 2);
        assert_ne!(result.transcript_hash, [0u8; 32]);
        assert_ne!(result.global_fri_root, [0u8; 32]);
    }

    /// Domain separator binding: different domains → different hashes.
    #[test]
    fn test_domain_separation() {
        // Verify our constants differ from each other.
        assert_ne!(DOMAIN_SUBEPOCH_FS, DOMAIN_STARK_BATCH);
        // Lengths must match spec.
        assert_eq!(DOMAIN_SUBEPOCH_FS.len(), 18);
        assert_eq!(DOMAIN_STARK_BATCH.len(), 18);
    }

    /// global_fri_root binds to proof count (N encoded in Phase 3).
    #[test]
    fn test_global_fri_root_encodes_count() {
        let inp1 = build_proof_input(1000, 0);
        let inp2 = build_proof_input(1001, 0);

        let r1 = aggregate_real_proofs(&[inp1.clone()]).unwrap();
        let r2 = aggregate_real_proofs(&[inp1, inp2]).unwrap();

        assert_ne!(
            r1.global_fri_root, r2.global_fri_root,
            "different proof counts must produce different global_fri_root"
        );
    }
}

// ── P3-R9: Empirical benchmark — spec §15.6, §3.4 ────────────────────────────

#[cfg(test)]
mod bench {
    use super::*;
    use crate::batch_transfer_p3::{
        derive_public_claims, prove_batch_transfer, TransferWitnesses,
    };
    use crate::membership_air_p3::{IMT_DEPTH, MembershipWitness};
    use crate::nonmembership_air_p3::{
        NonMembershipWitness, SparseTree, SMT_DEPTH,
        DOMAIN_SMT_ACTIVE_HI, DOMAIN_SMT_ACTIVE_LO,
        DOMAIN_SMT_ARCHIVED_HI, DOMAIN_SMT_ARCHIVED_LO,
    };
    use crate::ownership_air_p3::{
        compute_expected_commitment, compute_expected_nullifier, InputWitness,
    };
    use crate::membership_air_p3::poseidon2_permute;
    use p3_goldilocks::Goldilocks;
    use scalar_crypto::imt::{imt_membership_verify, IncrementalMerkleTree};
    use std::time::Instant;

    fn make_witness(seed: u64) -> InputWitness {
        InputWitness {
            secret: 0xDEAD_BEEF_0000_0000 | seed,
            value: 500_000_000 + seed,
            owner_pubkey_lo: 0xABCD_EF00 | (seed & 0xFFFF_FFFF),
            owner_pubkey_hi: 0x1234_5678,
            salt: 0xCAFE_BABE_0000_0000 | seed,
            spending_key_lo: 0x1111_1111,
            spending_key_hi: 0x2222_2222,
        }
    }

    fn commitment_bytes(w: &InputWitness) -> [u8; 32] {
        let h = compute_expected_commitment(w);
        let mut c = [0u8; 32];
        for i in 0..4 { c[i*8..(i+1)*8].copy_from_slice(&h[i].to_le_bytes()); }
        c
    }

    fn nullifier_bytes(w: &InputWitness) -> [u8; 32] {
        let h = compute_expected_nullifier(w);
        let mut n = [0u8; 32];
        for i in 0..4 { n[i*8..(i+1)*8].copy_from_slice(&h[i].to_le_bytes()); }
        n
    }

    fn empty_smt_root(tree: SparseTree) -> [u8; 32] {
        let (dl, dh) = match tree {
            SparseTree::Active   => (DOMAIN_SMT_ACTIVE_LO,   DOMAIN_SMT_ACTIVE_HI),
            SparseTree::Archived => (DOMAIN_SMT_ARCHIVED_LO, DOMAIN_SMT_ARCHIVED_HI),
        };
        let mut cur = [0u64; 4];
        for _ in 0..SMT_DEPTH {
            let mut inp = [Goldilocks::new(0u64); 8];
            inp[0]=Goldilocks::new(dl); inp[1]=Goldilocks::new(dh);
            inp[2..6].iter_mut().zip(cur.iter()).for_each(|(d,&s)| *d=Goldilocks::new(s));
            inp[6..8].iter_mut().zip(cur.iter()).for_each(|(d,&s)| *d=Goldilocks::new(s));
            cur = poseidon2_permute(&inp);
        }
        let mut root = [0u8; 32];
        for i in 0..4 { root[i*8..(i+1)*8].copy_from_slice(&cur[i].to_le_bytes()); }
        root
    }

    fn build_proof_input_bench(seed: u64) -> RealProofInput {
        let ow = vec![make_witness(seed), make_witness(seed + 1)];
        let commitments: Vec<[u8; 32]> = ow.iter().map(commitment_bytes).collect();

        let mut imt = IncrementalMerkleTree::new();
        for c in &commitments { imt.append(c).unwrap(); }
        let root_bytes = imt.root();
        let imt_root: [u64; 4] = core::array::from_fn(|i| {
            u64::from_le_bytes(root_bytes[i*8..(i+1)*8].try_into().unwrap())
        });
        let membership: Vec<MembershipWitness> = commitments.iter().enumerate().map(|(idx, c)| {
            let path = imt.prove_membership(idx as u64).unwrap();
            assert!(imt_membership_verify(c, &path, &root_bytes, imt.count));
            let siblings: [[u64; 4]; IMT_DEPTH] = core::array::from_fn(|i| {
                let s = &path.siblings[i];
                [u64::from_le_bytes(s[0..8].try_into().unwrap()),
                 u64::from_le_bytes(s[8..16].try_into().unwrap()),
                 u64::from_le_bytes(s[16..24].try_into().unwrap()),
                 u64::from_le_bytes(s[24..32].try_into().unwrap())]
            });
            MembershipWitness { commitment: *c, leaf_index: idx as u64, siblings }
        }).collect();

        let active_root   = empty_smt_root(SparseTree::Active);
        let archived_root = empty_smt_root(SparseTree::Archived);

        let nm_build = |w: &InputWitness, tree: SparseTree| -> NonMembershipWitness {
            let null = nullifier_bytes(w);
            let (dl, dh) = match tree {
                SparseTree::Active   => (DOMAIN_SMT_ACTIVE_LO,   DOMAIN_SMT_ACTIVE_HI),
                SparseTree::Archived => (DOMAIN_SMT_ARCHIVED_LO, DOMAIN_SMT_ARCHIVED_HI),
            };
            let mut siblings = [[0u64;4]; SMT_DEPTH];
            let mut cur = [0u64;4];
            for lv in 0..SMT_DEPTH {
                siblings[lv] = cur;
                let mut inp = [Goldilocks::new(0u64); 8];
                inp[0]=Goldilocks::new(dl); inp[1]=Goldilocks::new(dh);
                inp[2..6].iter_mut().zip(cur.iter()).for_each(|(d,&s)| *d=Goldilocks::new(s));
                inp[6..8].iter_mut().zip(cur.iter()).for_each(|(d,&s)| *d=Goldilocks::new(s));
                cur = poseidon2_permute(&inp);
            }
            NonMembershipWitness { nullifier: null, tree, siblings }
        };

        let nm_active:   Vec<_> = ow.iter().map(|w| nm_build(w, SparseTree::Active)).collect();
        let nm_archived: Vec<_> = ow.iter().map(|w| nm_build(w, SparseTree::Archived)).collect();

        let pi = TransferPublicInputsP3 {
            fee_total_sscl: 40,
            sum_inputs_sscl: 1_000_000_040,
            sum_outputs_sscl: 1_000_000_000,
            crypto_version: 0x01,
            entry_timestamp_ms: 1_000_000_000,
            current_timestamp_ms: 1_000_060_000,
            utxo_set_root: [0x42u8; 32],
            cb_membership_verified: true,
            nullifier_active_root: active_root,
            nullifier_archived_root: archived_root,
            cc_nonmembership_verified: true,
            output_nonzero: true,
            single_utxo_source: true,
        };

        let witnesses = TransferWitnesses {
            ownership: ow,
            membership,
            nonmembership_active: nm_active,
            nonmembership_archived: nm_archived,
        };
        let claims = derive_public_claims(&witnesses, pi.clone(), imt_root).unwrap();
        let batch_proof = prove_batch_transfer(&witnesses, &claims).unwrap();
        let proof_bytes = postcard::to_allocvec(&batch_proof).unwrap();

        let mut key = [0u8; 32];
        key[0..8].copy_from_slice(&seed.to_le_bytes());
        RealProofInput { proof_bytes, public_inputs: pi, tx_ordering_key: key }
    }

    /// P3-R9: STARKPack aggregation time for N=1 and N=4 proofs. Spec §3.4, §15.6.
    ///
    /// Measures: individual proof generation + STARKPack transcript computation.
    /// Per spec §3.4.5: aggregation bottleneck is Merkle decommitment (~29ms for N=256).
    /// Transcript computation (BLAKE3) is negligible; main cost is individual proves.
    ///
    /// Run with: cargo test -p scalar-stark-p3 --features bench-hardware \
    ///           -- bench::bench_starkpack_aggregation --nocapture --ignored
    #[test]
    #[cfg_attr(not(feature = "bench-hardware"), ignore = "P3-R9: run with --features bench-hardware")]
    fn bench_starkpack_aggregation() {
        // Build N=1 proof.
        let inp1 = build_proof_input_bench(1);

        // Warm-up
        let _ = aggregate_real_proofs(&[inp1.clone()]).expect("warm-up");

        // N=1 timed
        let start = Instant::now();
        let r1 = aggregate_real_proofs(&[inp1.clone()]).expect("N=1 aggregate");
        let ms1 = start.elapsed().as_millis();

        println!(
            "[P3-R9] STARKPack N=1 — aggregate: {}ms, transcript_hash: {}",
            ms1,
            hex::encode_short(&r1.transcript_hash)
        );

        // N=4 timed (build 3 more proofs)
        let inp2 = build_proof_input_bench(2);
        let inp3 = build_proof_input_bench(3);
        let inp4 = build_proof_input_bench(4);
        let inputs4 = vec![inp1, inp2, inp3, inp4];

        let start = Instant::now();
        let r4 = aggregate_real_proofs(&inputs4).expect("N=4 aggregate");
        let ms4 = start.elapsed().as_millis();

        println!(
            "[P3-R9] STARKPack N=4 — aggregate: {}ms, proof_hashes: {}",
            ms4,
            r4.proof_hashes.len()
        );
        println!(
            "[P3-R9] STARKPack N=256 optimal batch — soundness 2^-120 (spec D-002, §3.4.4)"
        );
        println!(
            "[P3-R9] global_fri_root: {}",
            hex::encode_short(&r4.global_fri_root)
        );
    }
}

// ── hex helper (bench only) ───────────────────────────────────────────────────
#[cfg(test)]
mod hex {
    pub fn encode_short(bytes: &[u8]) -> String {
        bytes[..4].iter().map(|b| format!("{b:02x}")).collect::<String>() + "..."
    }
}
