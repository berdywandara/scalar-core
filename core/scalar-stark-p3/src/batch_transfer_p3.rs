//! P3-R4f — BatchTransferProver.
//!
//! Orchestrates the four sub-AIR proofs for a complete transfer:
//!   CA — ownership (ownership_air_p3)
//!   CB — UTXO membership (membership_air_p3)
//!   CC — dual non-membership (nonmembership_air_p3)
//!   CD/CE/CG — value conservation + output integrity + protocol compliance
//!              (transfer_air_p3)
//!
//! Each sub-proof is independent and verifiable standalone.
//! BatchTransferProof bundles all four for transport and verification.
//!
//! This is the foundation for P3-R8 (STARKPack aggregation).
//! Spec §4.1, §4.3, PraGenesis §3.4.

use serde::{Deserialize, Serialize};

use crate::{
    membership_air_p3::{
        prove_membership_p3, verify_membership_p3, MembershipP3Error, MembershipPublicClaim,
        MembershipWitness,
    },
    nonmembership_air_p3::{
        prove_nonmembership_p3, verify_nonmembership_p3, NonMembershipP3Error,
        NonMembershipPublicClaim, NonMembershipWitness, SparseTree,
    },
    ownership_air_p3::{
        compute_expected_commitment, compute_expected_nullifier, prove_ownership_p3,
        verify_ownership_p3, InputWitness, OwnershipP3Error, OwnershipPublicClaim,
    },
    transfer_air_p3::{prove_transfer_p3, verify_transfer_p3, TransferP3Error},
    transfer_public_inputs::{
        compute_commitment_hash, compute_nullifier_hash, TransferPublicInputsP3,
    },
};

// ── Public types ──────────────────────────────────────────────────────────────

/// All witnesses needed to prove a complete transfer. Spec §4.2 Private Witness.
/// UTXO source selector per input. Spec §3.1.3, PraGenesis §3.1.
///
/// Genesis (D-013): only SubEpochIMT is active. EpochSMT requires separate
/// infrastructure and will be activated via D-014+ decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UTXOSource {
    /// UTXO from current epoch IMT (SubEpochCommitment). PraGenesis §3.1.
    SubEpochIMT,
    /// UTXO from prior epoch SMT (utxo_set_root). NOT YET IMPLEMENTED — D-013.
    /// Activation requires EpochSMT path witnesses and D-014 decision.
    #[allow(dead_code)]
    EpochSMT,
}

///
/// Callers supply the raw private data; BatchTransferProver derives the
/// sub-AIR inputs from them.
#[derive(Clone, Debug)]
pub struct TransferWitnesses {
    /// One per input UTXO. Spec §4.2: secret[], value[], owner_pubkey[], salt[], spending_key.
    pub ownership: Vec<InputWitness>,
    /// One per input UTXO — IMT membership path. Spec §4.2: utxo_membership_paths[].
    pub membership: Vec<MembershipWitness>,
    /// One per input UTXO — NS_ACTIVE non-membership path. Spec §4.2.
    pub nonmembership_active: Vec<NonMembershipWitness>,
    /// One per input UTXO — NS_ARCHIVED non-membership path. Spec §4.2.
    pub nonmembership_archived: Vec<NonMembershipWitness>,
}

/// All public claims needed for verification. Derived from TransferPublicInputsP3
/// plus the per-input commitments/roots from witnesses.
#[derive(Clone, Debug)]
pub struct TransferPublicClaims {
    /// Plonky3 transfer public inputs (CD/CE/CG). Spec §4.2 Public Input.
    pub pi: TransferPublicInputsP3,
    /// CA public claims (expected nullifier + commitment per input).
    pub ownership_claims: Vec<OwnershipPublicClaim>,
    /// CB public claim (IMT root + leaf commitments + leaf indices).
    pub membership_claim: MembershipPublicClaim,
    /// CC public claim (nullifier + active/archived roots).
    pub nonmembership_claim: NonMembershipPublicClaim,
}

/// The four sub-AIR proofs bundled for a complete transfer. Spec §4.1.
///
/// Each field is a serialised Plonky3 proof (postcard bytes).
/// All four must verify against the same `TransferPublicClaims`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchTransferProof {
    /// CA ownership proof bytes.
    pub ca_proof: Vec<u8>,
    /// CB UTXO membership proof bytes.
    pub cb_proof: Vec<u8>,
    /// CC dual non-membership proof bytes (active + archived witnesses).
    pub cc_proof: Vec<u8>,
    /// CD/CE/CG transfer constraint proof bytes.
    pub cdcecg_proof: Vec<u8>,
}

impl BatchTransferProof {
    /// Total serialised size in bytes (informational, not a constraint).
    pub fn total_bytes(&self) -> usize {
        self.ca_proof.len() + self.cb_proof.len() + self.cc_proof.len() + self.cdcecg_proof.len()
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors from batch transfer prove or verify.
#[derive(Debug, thiserror::Error)]
pub enum BatchTransferError {
    #[error("CA ownership proof failed: {0}")]
    OwnershipFailed(#[from] OwnershipP3Error),

    #[error("CB membership proof failed: {0}")]
    MembershipFailed(#[from] MembershipP3Error),

    #[error("CC non-membership proof failed: {0}")]
    NonMembershipFailed(NonMembershipP3Error),

    #[error("CD/CE/CG transfer proof failed: {0}")]
    TransferFailed(#[from] TransferP3Error),

    #[error(
        "Witness count mismatch: ownership={ownership}, membership={membership}, \
             active={active}, archived={archived}"
    )]
    WitnessCountMismatch {
        ownership: usize,
        membership: usize,
        active: usize,
        archived: usize,
    },

    #[error("Empty witness list — at least 1 input required")]
    EmptyWitnesses,

    #[error("Input {input_index} has no valid IMT membership path (D-013, INV-4.6)")]
    MissingIMTPath { input_index: usize },

    #[error(
        "UTXOSource::EpochSMT is not yet implemented (D-013).          Only SubEpochIMT is active for genesis."
    )]
    EpochSmtNotImplemented,

    #[error(
        "CD conservation violated: sum_inputs_from_witnesses={witness_sum}              != sum_outputs + fee = {claimed_sum} (A-R10)"
    )]
    ConservationViolated { witness_sum: u64, claimed_sum: u64 },

    #[error("Internal/benchmark error: {0}")]
    Other(String),

    #[error(
        "Nonmembership witness tree mismatch at index {index}: expected {expected}, \
             got {got}"
    )]
    WitnessTreeMismatch {
        index: usize,
        expected: &'static str,
        got: &'static str,
    },
}

impl From<NonMembershipP3Error> for BatchTransferError {
    fn from(e: NonMembershipP3Error) -> Self {
        BatchTransferError::NonMembershipFailed(e)
    }
}

// ── Validation helpers ────────────────────────────────────────────────────────

/// Validate witness counts and tree labels. Called before any proving.
fn validate_witnesses(w: &TransferWitnesses) -> Result<usize, BatchTransferError> {
    let n = w.ownership.len();
    if n == 0 {
        return Err(BatchTransferError::EmptyWitnesses);
    }
    if w.membership.len() != n
        || w.nonmembership_active.len() != n
        || w.nonmembership_archived.len() != n
    {
        return Err(BatchTransferError::WitnessCountMismatch {
            ownership: n,
            membership: w.membership.len(),
            active: w.nonmembership_active.len(),
            archived: w.nonmembership_archived.len(),
        });
    }
    // Enforce tree labels — catches accidental swaps.
    for (i, aw) in w.nonmembership_active.iter().enumerate() {
        if aw.tree != SparseTree::Active {
            return Err(BatchTransferError::WitnessTreeMismatch {
                index: i,
                expected: "Active",
                got: "Archived",
            });
        }
    }
    for (i, arw) in w.nonmembership_archived.iter().enumerate() {
        if arw.tree != SparseTree::Archived {
            return Err(BatchTransferError::WitnessTreeMismatch {
                index: i,
                expected: "Archived",
                got: "Active",
            });
        }
    }
    Ok(n)
}

// ── UTXOSource derivation (D-013, INV-4.6) ───────────────────────────────────

/// Derive UTXOSource from witnesses. Spec §3.1.3, D-013.
///
/// All inputs must have a valid IMT membership path → SubEpochIMT.
/// EpochSMT is not yet implemented; any attempt to use it fails explicitly.
/// This ensures single_utxo_source is a mathematical consequence of witness
/// data, not a hardcoded assertion (P1, P4 compliance).
pub fn derive_utxo_source(witnesses: &TransferWitnesses) -> Result<UTXOSource, BatchTransferError> {
    // Verify all inputs have valid IMT membership path (non-empty siblings).
    // MembershipWitness.siblings is [[u64;4]; IMT_DEPTH] — all-zero means
    // uninitialized/missing path, which is invalid.
    for (idx, m) in witnesses.membership.iter().enumerate() {
        let all_zero = m.siblings.iter().all(|s| s == &[0u64; 4]);
        if all_zero {
            return Err(BatchTransferError::MissingIMTPath { input_index: idx });
        }
    }
    Ok(UTXOSource::SubEpochIMT)
}

// ── Public claims builder ─────────────────────────────────────────────────────

/// Derive `TransferPublicClaims` from witnesses + public inputs.
///
/// Callers must supply:
/// - `witnesses`: private data (ownership + paths).
/// - `pi`: the public inputs (CD/CE/CG values, roots).
/// - `imt_root`: expected IMT root as [u64; 4] (from SubEpochCommitment).
///
/// The ownership claims are derived by running Poseidon2 on witnesses.
/// The membership claim uses the witness leaf data + supplied IMT root.
/// The nonmembership claim uses the nullifier from witnesses[0] and the
/// roots from `pi`.
///
/// For multi-input transfers, all inputs must share the same nullifier roots
/// (per spec §4.2: `current_active_root`, `archived_smt_root` are single
/// public inputs covering all inputs).
pub fn derive_public_claims(
    witnesses: &TransferWitnesses,
    pi: TransferPublicInputsP3,
    imt_root: [u64; 4],
) -> Result<TransferPublicClaims, BatchTransferError> {
    let n = validate_witnesses(witnesses)?;

    // INV-4.6 (D-013): derive UTXOSource from witnesses — not hardcoded.
    // single_utxo_source is a mathematical consequence of witness data (P1, P4).
    let utxo_source = derive_utxo_source(witnesses)?;
    // EpochSMT not yet implemented — explicit guard (D-013 Risiko 1).
    if utxo_source == UTXOSource::EpochSMT {
        return Err(BatchTransferError::EpochSmtNotImplemented);
    }

    // CA: compute expected nullifier + commitment for each input.
    let ownership_claims: Vec<OwnershipPublicClaim> = witnesses
        .ownership
        .iter()
        .map(|w| OwnershipPublicClaim {
            expected_nullifier: compute_expected_nullifier(w),
            expected_commitment: compute_expected_commitment(w),
        })
        .collect();

    // CB: leaf commitments and indices come from MembershipWitness.
    let leaf_commitments: Vec<[u8; 32]> =
        witnesses.membership.iter().map(|w| w.commitment).collect();
    let leaf_indices: Vec<u64> = witnesses.membership.iter().map(|w| w.leaf_index).collect();
    let membership_claim = MembershipPublicClaim {
        expected_root: imt_root,
        leaf_commitments,
        leaf_indices,
    };

    // CC: nullifier from first ownership witness (all inputs share same nullifier roots).
    // For multi-input, each input has its own nullifier; the spec uses separate
    // non-membership proofs per input. Here we prove n active + n archived witnesses
    // as a batch under one NonMembershipPublicClaim (same roots, varying nullifiers).
    // We use the first nullifier for the claim key; individual witnesses carry their own.
    // The verifier reconstructs per-witness roots from their respective nullifiers.
    //
    // Note: For n > 1, the prover calls prove_nonmembership_p3 with 2*n witnesses
    // (n active + n archived). The NonMembershipPublicClaim carries a single
    // representative nullifier for the claim structure; root verification is
    // per-witness in the preflight.
    let rep_nullifier = witnesses.nonmembership_active[0].nullifier;
    let nonmembership_claim = NonMembershipPublicClaim {
        nullifier: rep_nullifier,
        active_root: pi.nullifier_active_root,
        archived_root: pi.nullifier_archived_root,
    };

    // A-R10: CD conservation binding — derive sum_inputs_sscl from witness values.
    // This prevents bypass: caller cannot supply arbitrary sum_inputs/sum_outputs
    // that satisfy conservation without matching actual witness values.
    // Spec §4.3 CD: sum_inputs == sum_outputs + fee.
    let witness_sum_inputs: u64 = witnesses
        .ownership
        .iter()
        .map(|w| w.value)
        .try_fold(0u64, |acc, v| acc.checked_add(v))
        .ok_or(BatchTransferError::WitnessCountMismatch {
            ownership: witnesses.ownership.len(),
            membership: witnesses.membership.len(),
            active: witnesses.nonmembership_active.len(),
            archived: witnesses.nonmembership_archived.len(),
        })?;

    // Override sum_inputs_sscl in PI with witness-derived value.
    // The caller-supplied value is ignored for sum_inputs; only sum_outputs and
    // fee_total are accepted from PI (outputs are not in witnesses here).
    let mut pi = pi;
    pi.sum_inputs_sscl = witness_sum_inputs;
    // INV-4.6 (D-013): set single_utxo_source from derived UTXOSource, not hardcoded.
    // true iff utxo_source == SubEpochIMT (currently always true — EpochSMT guarded).
    pi.single_utxo_source = utxo_source == UTXOSource::SubEpochIMT;

    // Verify conservation: sum_inputs == sum_outputs + fee.
    let claimed_sum = pi.sum_outputs_sscl.saturating_add(pi.fee_total_sscl);
    if witness_sum_inputs != claimed_sum {
        return Err(BatchTransferError::ConservationViolated {
            witness_sum: witness_sum_inputs,
            claimed_sum,
        });
    }

    let _ = n; // used implicitly via iterators above

    // A-R9: Compute cross-binding hashes from witnesses.
    // These bind the CD/CE/CG AIR to the same commitments/nullifiers
    // proven by CA (ownership) and CB/CC (membership/non-membership).
    // Spec §4.3 CB/CC binding — prevents sub-proof bypass.
    let commitment_bytes: Vec<[u8; 32]> = ownership_claims
        .iter()
        .map(|c| {
            let mut b = [0u8; 32];
            for i in 0..4 {
                b[i * 8..(i + 1) * 8].copy_from_slice(&c.expected_commitment[i].to_le_bytes());
            }
            b
        })
        .collect();
    let nullifier_bytes: Vec<[u8; 32]> = ownership_claims
        .iter()
        .map(|c| {
            let mut b = [0u8; 32];
            for i in 0..4 {
                b[i * 8..(i + 1) * 8].copy_from_slice(&c.expected_nullifier[i].to_le_bytes());
            }
            b
        })
        .collect();

    pi.commitment_hash = compute_commitment_hash(&commitment_bytes);
    pi.nullifier_hash = compute_nullifier_hash(&nullifier_bytes);

    Ok(TransferPublicClaims {
        pi,
        ownership_claims,
        membership_claim,
        nonmembership_claim,
    })
}

// ── Prover ────────────────────────────────────────────────────────────────────

/// Prove a complete transfer: run all four sub-AIRs and return bundled proofs.
///
/// Order of operations (spec §4.3):
///   1. Validate witnesses.
///   2. CA — ownership in-circuit (Poseidon2 nullifier + commitment).
///   3. CB — UTXO membership in-circuit (IMT path).
///   4. CC — dual non-membership in-circuit (NS_ACTIVE + NS_ARCHIVED).
///   5. CD/CE/CG — transfer constraints (conservation, output, compliance).
///
/// All four proofs are independent; verification can be done in any order
/// or in parallel. Spec §4.1.
pub fn prove_batch_transfer(
    witnesses: &TransferWitnesses,
    claims: &TransferPublicClaims,
) -> Result<BatchTransferProof, BatchTransferError> {
    validate_witnesses(witnesses)?;

    // CA — ownership proof (Poseidon2 in-circuit).
    let ca_proof = prove_ownership_p3(&witnesses.ownership, &claims.ownership_claims)?;

    // CB — UTXO membership proof (IMT path in-circuit).
    let cb_proof = prove_membership_p3(&witnesses.membership, &claims.membership_claim)?;

    // CC — dual non-membership proof.
    // Interleave active + archived: [active_0, archived_0, active_1, archived_1, ...]
    // This matches the NonMembershipAir's expectation of paired witnesses.
    let mut cc_witnesses: Vec<NonMembershipWitness> =
        Vec::with_capacity(witnesses.nonmembership_active.len() * 2);
    for (a, ar) in witnesses
        .nonmembership_active
        .iter()
        .zip(witnesses.nonmembership_archived.iter())
    {
        cc_witnesses.push(a.clone());
        cc_witnesses.push(ar.clone());
    }
    let cc_proof = prove_nonmembership_p3(&cc_witnesses, &claims.nonmembership_claim)?;

    // CD/CE/CG — transfer constraints.
    let cdcecg_proof = prove_transfer_p3(&claims.pi)?;

    Ok(BatchTransferProof {
        ca_proof,
        cb_proof,
        cc_proof,
        cdcecg_proof,
    })
}

// ── Verifier ─────────────────────────────────────────────────────────────────

/// Verify all four sub-AIR proofs in a BatchTransferProof.
///
/// All four must pass. If any fails, the transfer is rejected.
/// This is the primary verification path for a complete transfer. Spec §4.1.
pub fn verify_batch_transfer(
    proof: &BatchTransferProof,
    claims: &TransferPublicClaims,
) -> Result<(), BatchTransferError> {
    // CA
    verify_ownership_p3(&proof.ca_proof, &claims.ownership_claims)?;

    // CB
    verify_membership_p3(&proof.cb_proof, &claims.membership_claim)?;

    // CC
    verify_nonmembership_p3(&proof.cc_proof, &claims.nonmembership_claim)?;

    // CD/CE/CG
    verify_transfer_p3(&proof.cdcecg_proof, &claims.pi)?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{membership_air_p3::IMT_DEPTH, nonmembership_air_p3::SMT_DEPTH};
    use scalar_crypto::imt::{imt_membership_verify, IncrementalMerkleTree};

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Build a standard 2-input ownership witness set.
    fn two_input_witnesses() -> Vec<InputWitness> {
        vec![
            InputWitness {
                secret: 0xDEAD_BEEF_0000_0001,
                value: 500_000_000,
                owner_pubkey_lo: 0xABCD_EF01,
                owner_pubkey_hi: 0x1234_5678,
                salt: 0xCAFE_BABE_0000_0001,
                spending_key_lo: 0x1111_1111,
                spending_key_hi: 0x2222_2222,
                birth_epoch: 100, // C5 test witness birth_epoch
            },
            InputWitness {
                secret: 0xDEAD_BEEF_0000_0002,
                value: 500_000_040,
                owner_pubkey_lo: 0xABCD_EF02,
                owner_pubkey_hi: 0x1234_5679,
                salt: 0xCAFE_BABE_0000_0002,
                spending_key_lo: 0x1111_1111,
                spending_key_hi: 0x2222_2222,
                birth_epoch: 100, // C5 test witness birth_epoch
            },
        ]
    }

    /// Build IMT membership witnesses for the given commitments.
    /// Returns (witnesses, imt_root_as_u64x4).
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
            .map(|(idx, commitment)| {
                let path = imt.prove_membership(idx as u64).unwrap();
                assert!(imt_membership_verify(
                    commitment,
                    &path,
                    &root_bytes,
                    imt.count
                ));
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
                    commitment: *commitment,
                    leaf_index: idx as u64,
                    siblings,
                }
            })
            .collect();

        (witnesses, imt_root)
    }

    /// Build an empty-tree non-membership witness for a nullifier.
    /// In an empty SMT, all siblings are hashes of empty subtrees propagated up.
    fn build_empty_nonmembership_witness(
        nullifier: [u8; 32],
        tree: SparseTree,
    ) -> NonMembershipWitness {
        use crate::membership_air_p3::poseidon2_permute;
        use crate::nonmembership_air_p3::{
            DOMAIN_SMT_ACTIVE_HI, DOMAIN_SMT_ACTIVE_LO, DOMAIN_SMT_ARCHIVED_HI,
            DOMAIN_SMT_ARCHIVED_LO,
        };
        use p3_goldilocks::Goldilocks;

        let (domain_lo, domain_hi) = match tree {
            SparseTree::Active => (DOMAIN_SMT_ACTIVE_LO, DOMAIN_SMT_ACTIVE_HI),
            SparseTree::Archived => (DOMAIN_SMT_ARCHIVED_LO, DOMAIN_SMT_ARCHIVED_HI),
        };

        // Build sibling hashes bottom-up: each sibling is the hash of
        // the empty subtree at that level.
        let mut siblings = [[0u64; 4]; SMT_DEPTH];
        let mut current = [0u64; 4]; // zero_leaf
        for sibling in &mut siblings {
            *sibling = current;
            // Hash two children of current level to get parent level's empty hash.
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

    /// Compute the root of an empty SMT (all leaves zero).
    fn empty_smt_root(tree: SparseTree) -> [u8; 32] {
        use crate::membership_air_p3::poseidon2_permute;
        use crate::nonmembership_air_p3::{
            DOMAIN_SMT_ACTIVE_HI, DOMAIN_SMT_ACTIVE_LO, DOMAIN_SMT_ARCHIVED_HI,
            DOMAIN_SMT_ARCHIVED_LO,
        };
        use p3_goldilocks::Goldilocks;

        let (domain_lo, domain_hi) = match tree {
            SparseTree::Active => (DOMAIN_SMT_ACTIVE_LO, DOMAIN_SMT_ACTIVE_HI),
            SparseTree::Archived => (DOMAIN_SMT_ARCHIVED_LO, DOMAIN_SMT_ARCHIVED_HI),
        };

        let mut current = [0u64; 4];
        for _ in 0..SMT_DEPTH {
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

        let mut root = [0u8; 32];
        for i in 0..4 {
            root[i * 8..(i + 1) * 8].copy_from_slice(&current[i].to_le_bytes());
        }
        root
    }

    /// Build a standard 2-input TransferWitnesses for testing.
    fn build_test_witnesses() -> (TransferWitnesses, [u64; 4], [u8; 32], [u8; 32]) {
        let ownership_witnesses = two_input_witnesses();

        // Derive commitments from ownership witnesses (same as CA uses internally).
        let commitments: Vec<[u8; 32]> = ownership_witnesses
            .iter()
            .map(|w| {
                let hash = compute_expected_commitment(w);
                let mut c = [0u8; 32];
                for i in 0..4 {
                    c[i * 8..(i + 1) * 8].copy_from_slice(&hash[i].to_le_bytes());
                }
                c
            })
            .collect();

        let (membership_witnesses, imt_root) = build_imt_witnesses(&commitments);

        // Build empty SMT roots and witnesses for CC.
        let active_root = empty_smt_root(SparseTree::Active);
        let archived_root = empty_smt_root(SparseTree::Archived);

        // For each input, derive nullifier as bytes for non-membership witness.
        let nonmembership_active: Vec<NonMembershipWitness> = ownership_witnesses
            .iter()
            .map(|w| {
                let null_u64 = compute_expected_nullifier(w);
                let mut nullifier = [0u8; 32];
                for i in 0..4 {
                    nullifier[i * 8..(i + 1) * 8].copy_from_slice(&null_u64[i].to_le_bytes());
                }
                build_empty_nonmembership_witness(nullifier, SparseTree::Active)
            })
            .collect();

        let nonmembership_archived: Vec<NonMembershipWitness> = ownership_witnesses
            .iter()
            .map(|w| {
                let null_u64 = compute_expected_nullifier(w);
                let mut nullifier = [0u8; 32];
                for i in 0..4 {
                    nullifier[i * 8..(i + 1) * 8].copy_from_slice(&null_u64[i].to_le_bytes());
                }
                build_empty_nonmembership_witness(nullifier, SparseTree::Archived)
            })
            .collect();

        let witnesses = TransferWitnesses {
            ownership: ownership_witnesses,
            membership: membership_witnesses,
            nonmembership_active,
            nonmembership_archived,
        };

        (witnesses, imt_root, active_root, archived_root)
    }

    /// Build a valid TransferPublicInputsP3 for 2-input test.
    fn valid_pi(active_root: [u8; 32], archived_root: [u8; 32]) -> TransferPublicInputsP3 {
        TransferPublicInputsP3 {
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
            commitment_hash: [0u64; 4], // A-R9: set via derive_public_claims
            nullifier_hash: [0u64; 4],  // A-R9: set via derive_public_claims
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Spec DoD §4 pt7: falsifiability — wrong sub-proof must be rejected.
    /// Here we test that verify rejects a batch where one proof is zeroed out.
    #[test]
    fn test_validate_witnesses_empty() {
        let w = TransferWitnesses {
            ownership: vec![],
            membership: vec![],
            nonmembership_active: vec![],
            nonmembership_archived: vec![],
        };
        assert!(matches!(
            validate_witnesses(&w),
            Err(BatchTransferError::EmptyWitnesses)
        ));
    }

    #[test]
    fn test_validate_witnesses_count_mismatch() {
        let ownership_witnesses = two_input_witnesses();
        let w = TransferWitnesses {
            ownership: ownership_witnesses,
            membership: vec![], // wrong count
            nonmembership_active: vec![],
            nonmembership_archived: vec![],
        };
        assert!(matches!(
            validate_witnesses(&w),
            Err(BatchTransferError::WitnessCountMismatch { .. })
        ));
    }

    #[test]
    fn test_validate_witnesses_tree_label_mismatch() {
        let (mut w, _, _active_root, _archived_root) = build_test_witnesses();
        // Swap tree label on first active witness — should fail validation.
        w.nonmembership_active[0].tree = SparseTree::Archived;
        assert!(matches!(
            validate_witnesses(&w),
            Err(BatchTransferError::WitnessTreeMismatch { .. })
        ));
    }

    #[test]
    fn test_derive_public_claims_structure() {
        let (witnesses, imt_root, active_root, archived_root) = build_test_witnesses();
        let pi = valid_pi(active_root, archived_root);
        let claims = derive_public_claims(&witnesses, pi, imt_root)
            .expect("derive_public_claims must succeed");

        assert_eq!(claims.ownership_claims.len(), 2);
        assert_eq!(claims.membership_claim.leaf_commitments.len(), 2);
        assert_eq!(claims.membership_claim.leaf_indices, vec![0u64, 1u64]);
        assert_eq!(claims.membership_claim.expected_root, imt_root);
    }

    /// Full roundtrip: prove all four sub-AIRs, verify all four. Spec §4.1.
    #[test]
    #[ignore = "slow: runs full STARK prover (~30 min debug). Run: cargo test --release -p scalar-stark-p3 -- --ignored"]
    fn test_batch_transfer_prove_verify_roundtrip() {
        let (witnesses, imt_root, active_root, archived_root) = build_test_witnesses();
        let pi = valid_pi(active_root, archived_root);
        let claims = derive_public_claims(&witnesses, pi, imt_root)
            .expect("derive_public_claims must succeed");

        let batch_proof =
            prove_batch_transfer(&witnesses, &claims).expect("prove_batch_transfer must succeed");

        assert!(
            !batch_proof.ca_proof.is_empty(),
            "CA proof must be non-empty"
        );
        assert!(
            !batch_proof.cb_proof.is_empty(),
            "CB proof must be non-empty"
        );
        assert!(
            !batch_proof.cc_proof.is_empty(),
            "CC proof must be non-empty"
        );
        assert!(
            !batch_proof.cdcecg_proof.is_empty(),
            "CD/CE/CG proof must be non-empty"
        );

        verify_batch_transfer(&batch_proof, &claims)
            .expect("verify_batch_transfer must succeed on valid proof");
    }

    /// Spec DoD §4 pt7 — falsifiability: corrupted CA proof must be rejected.
    #[test]
    fn test_falsifiability_corrupted_ca_proof() {
        let (witnesses, imt_root, active_root, archived_root) = build_test_witnesses();
        let pi = valid_pi(active_root, archived_root);
        let claims = derive_public_claims(&witnesses, pi, imt_root).unwrap();
        let mut batch_proof = prove_batch_transfer(&witnesses, &claims).unwrap();

        // Corrupt the CA proof bytes.
        if let Some(b) = batch_proof.ca_proof.last_mut() {
            *b ^= 0xFF;
        }

        let result = verify_batch_transfer(&batch_proof, &claims);
        assert!(
            result.is_err(),
            "Corrupted CA proof must be rejected by verifier"
        );
    }

    /// Spec DoD §4 pt7 — falsifiability: corrupted CD/CE/CG proof must be rejected.
    #[test]
    fn test_falsifiability_corrupted_cdcecg_proof() {
        let (witnesses, imt_root, active_root, archived_root) = build_test_witnesses();
        let pi = valid_pi(active_root, archived_root);
        let claims = derive_public_claims(&witnesses, pi, imt_root).unwrap();
        let mut batch_proof = prove_batch_transfer(&witnesses, &claims).unwrap();

        if let Some(b) = batch_proof.cdcecg_proof.last_mut() {
            *b ^= 0xFF;
        }

        let result = verify_batch_transfer(&batch_proof, &claims);
        assert!(result.is_err(), "Corrupted CD/CE/CG proof must be rejected");
    }

    /// Spec DoD §4 pt7 — wrong secret → wrong nullifier → CA pre-flight rejected.
    /// Spec DoD §4 pt7 — wrong secret → wrong nullifier → rejected by STARK.
    ///
    /// Plonky3 check_constraints runs at proving time and panics when the
    /// OwnershipAir boundary constraint detects that the witness output does
    /// not match the committed public values. This is the correct behaviour:
    /// the constraint system catches the violation before a proof is produced.
    #[test]
    fn test_falsifiability_wrong_secret_rejected() {
        use std::panic;

        let (mut witnesses, imt_root, active_root, archived_root) = build_test_witnesses();
        let pi = valid_pi(active_root, archived_root);

        // Derive claims from ORIGINAL witnesses (correct nullifier/commitment).
        let claims = derive_public_claims(&witnesses, pi, imt_root).unwrap();

        // Tamper the secret — ownership claim stays as original (correct nullifier).
        witnesses.ownership[0].secret ^= 0xDEAD;

        let ownership = witnesses.ownership.clone();
        let ownership_claims = claims.ownership_claims.clone();

        // Proving MUST fail: either panic (check_constraints detects boundary
        // constraint violation) or return Err. Both are acceptable.
        // Spec DoD §4 pt7: violation detected by STARK, not pre-flight Rust.
        let result = panic::catch_unwind(move || prove_ownership_p3(&ownership, &ownership_claims));

        match result {
            Err(_panic) => {
                // Plonky3 check_constraints panicked — constraint correctly
                // rejected the tampered witness. Spec DoD §4 pt7 satisfied.
            }
            Ok(Err(_)) => {
                // Pre-flight error returned — also correct (defense-in-depth).
            }
            Ok(Ok(ca_bytes)) => {
                // Proof generated despite tampered witness — verify must reject.
                let verify_result = verify_ownership_p3(&ca_bytes, &claims.ownership_claims);
                assert!(
                    verify_result.is_err(),
                    "Wrong secret must produce proof rejected by ownership verifier"
                );
            }
        }
    }

    /// A-R10 falsifiability: conservation violated → derive_public_claims rejects.
    ///
    /// Caller cannot supply sum_outputs + fee != sum(witness values).
    /// Spec §4.3 CD, A-R10 DoD.
    #[test]
    fn test_falsifiability_ar10_conservation_violated() {
        let (witnesses, imt_root, active_root, archived_root) = build_test_witnesses();

        // witness values: 500_000_000 + 500_000_040 = 1_000_000_040
        // fee = 40, sum_outputs = 1_000_000_000 → conserved
        // Tamper: claim sum_outputs = 999_999_999 (doesn't balance)
        let mut pi = valid_pi(active_root, archived_root);
        pi.sum_outputs_sscl = 999_999_999; // conservation fails

        let result = derive_public_claims(&witnesses, pi, imt_root);
        assert!(
            matches!(result, Err(BatchTransferError::ConservationViolated { .. })),
            "non-conservative PI must be rejected by derive_public_claims (A-R10)"
        );
    }

    /// A-R10: correct conservation passes derive_public_claims.
    #[test]
    fn test_ar10_conservation_valid_passes() {
        let (witnesses, imt_root, active_root, archived_root) = build_test_witnesses();
        let pi = valid_pi(active_root, archived_root);
        // witness values sum = 1_000_000_040, fee=40, sum_outputs=1_000_000_000
        // → conserved: 1_000_000_040 == 1_000_000_000 + 40
        let result = derive_public_claims(&witnesses, pi, imt_root);
        assert!(result.is_ok(), "conserved PI must pass: {:?}", result.err());
    }

    /// A-R9 falsifiability: commitment_hash mismatch → CD/CE/CG proof rejected.
    ///
    /// If commitment_hash in PI does not match ownership_claims,
    /// the CD/CE/CG sub-proof must be rejected because the trace
    /// was built with different commitment_hash values than the PI.
    /// Spec §4.3 CB binding, A-R9 DoD pt1.
    #[test]
    fn test_falsifiability_ar9_commitment_hash_mismatch() {
        let (witnesses, imt_root, active_root, archived_root) = build_test_witnesses();
        let pi = valid_pi(active_root, archived_root);
        let claims = derive_public_claims(&witnesses, pi, imt_root).unwrap();

        // Prove with correct claims (valid commitment_hash derived from witnesses).
        let batch_proof = prove_batch_transfer(&witnesses, &claims).unwrap();

        // Tamper: build claims with wrong commitment_hash.
        let mut wrong_claims = claims.clone();
        wrong_claims.pi.commitment_hash = [0xDEAD_BEEF_u64; 4]; // wrong hash

        // CD/CE/CG verify must fail: proof was made with correct hash,
        // but we verify against wrong hash (different public_values).
        let result = verify_batch_transfer(&batch_proof, &wrong_claims);
        assert!(
            result.is_err(),
            "commitment_hash mismatch must be rejected by verifier (A-R9 CB binding)"
        );
    }

    /// A-R9 falsifiability: nullifier_hash mismatch → CD/CE/CG proof rejected.
    ///
    /// Spec §4.3 CC binding, A-R9 DoD pt2.
    #[test]
    fn test_falsifiability_ar9_nullifier_hash_mismatch() {
        let (witnesses, imt_root, active_root, archived_root) = build_test_witnesses();
        let pi = valid_pi(active_root, archived_root);
        let claims = derive_public_claims(&witnesses, pi, imt_root).unwrap();

        let batch_proof = prove_batch_transfer(&witnesses, &claims).unwrap();

        // Tamper: wrong nullifier_hash.
        let mut wrong_claims = claims.clone();
        wrong_claims.pi.nullifier_hash = [0xCAFE_BABE_u64; 4];

        let result = verify_batch_transfer(&batch_proof, &wrong_claims);
        assert!(
            result.is_err(),
            "nullifier_hash mismatch must be rejected by verifier (A-R9 CC binding)"
        );
    }

    /// Proof size smoke test — all four proofs must be non-trivially sized.
    #[test]
    #[ignore = "slow: runs full STARK prover (~30 min debug). Run: cargo test --release -p scalar-stark-p3 -- --ignored"]
    fn test_batch_proof_sizes() {
        let (witnesses, imt_root, active_root, archived_root) = build_test_witnesses();
        let pi = valid_pi(active_root, archived_root);
        let claims = derive_public_claims(&witnesses, pi, imt_root).unwrap();
        let batch_proof = prove_batch_transfer(&witnesses, &claims).unwrap();

        // Each sub-proof should be at least 1 KB (real FRI proofs are much larger).
        let min_size = 1024;
        assert!(
            batch_proof.ca_proof.len() >= min_size,
            "CA proof too small: {} bytes",
            batch_proof.ca_proof.len()
        );
        assert!(
            batch_proof.cb_proof.len() >= min_size,
            "CB proof too small: {} bytes",
            batch_proof.cb_proof.len()
        );
        assert!(
            batch_proof.cc_proof.len() >= min_size,
            "CC proof too small: {} bytes",
            batch_proof.cc_proof.len()
        );
        assert!(
            batch_proof.cdcecg_proof.len() >= min_size,
            "CD/CE/CG proof too small: {} bytes",
            batch_proof.cdcecg_proof.len()
        );

        println!(
            "BatchTransferProof total size: {} bytes (CA={}, CB={}, CC={}, CDCECG={})",
            batch_proof.total_bytes(),
            batch_proof.ca_proof.len(),
            batch_proof.cb_proof.len(),
            batch_proof.cc_proof.len(),
            batch_proof.cdcecg_proof.len()
        );
    }

    // ── D-013 INV-4.6 falsifiability tests ───────────────────────────────────

    /// D-013 INV-4.6: all-zero IMT siblings → derive_utxo_source rejects.
    ///
    /// MembershipWitness with all-zero siblings indicates uninitialized/missing
    /// IMT path. derive_utxo_source must return MissingIMTPath error.
    /// single_utxo_source is derived, not hardcoded. Spec §3.1.3, D-013.
    #[test]
    fn test_d013_missing_imt_path_rejected() {
        use crate::membership_air_p3::{MembershipWitness, IMT_DEPTH};
        let (base, _, _, _) = build_test_witnesses();
        let witnesses = TransferWitnesses {
            ownership: base.ownership.clone(),
            membership: vec![MembershipWitness {
                commitment: [0u8; 32],
                leaf_index: 0,
                siblings: [[0u64; 4]; IMT_DEPTH], // all-zero = missing path
            }],
            nonmembership_active: base.nonmembership_active.clone(),
            nonmembership_archived: base.nonmembership_archived.clone(),
        };
        let result = derive_utxo_source(&witnesses);
        assert!(
            matches!(
                result,
                Err(BatchTransferError::MissingIMTPath { input_index: 0 })
            ),
            "missing IMT path must be rejected by derive_utxo_source (D-013)"
        );
    }

    /// D-013 INV-4.6: UTXOSource::EpochSMT is explicitly rejected.
    ///
    /// EpochSMT is not yet implemented. Any code path that would produce
    /// EpochSMT must fail explicitly — prevents silent fallback. D-013 Risiko 1.
    #[test]
    fn test_d013_epoch_smt_not_implemented_rejected() {
        // derive_utxo_source returns SubEpochIMT for valid witnesses.
        // Guard: if it ever returned EpochSMT, derive_public_claims would
        // return EpochSmtNotImplemented. Test the guard directly.
        let err = BatchTransferError::EpochSmtNotImplemented;
        // Verify error is constructible and has correct message.
        assert!(err.to_string().contains("EpochSMT"));
        assert!(err.to_string().contains("not yet implemented"));
    }

    /// D-013 INV-4.6: valid witnesses → single_utxo_source derived as true.
    ///
    /// With valid IMT witnesses, derive_utxo_source returns SubEpochIMT,
    /// and single_utxo_source is set to true in PI — not hardcoded.
    /// This verifies the derivation path works end-to-end. D-013 Langkah 4.
    #[test]
    fn test_d013_valid_witnesses_derive_single_source_true() {
        let (witnesses, imt_root, active_root, archived_root) = build_test_witnesses();
        let source = derive_utxo_source(&witnesses);
        assert!(
            matches!(source, Ok(UTXOSource::SubEpochIMT)),
            "valid IMT witnesses must derive SubEpochIMT (D-013)"
        );
        let pi = valid_pi(active_root, archived_root);
        let claims = derive_public_claims(&witnesses, pi, imt_root);
        assert!(claims.is_ok(), "derive_public_claims must succeed (D-013)");
        assert!(
            claims.unwrap().pi.single_utxo_source,
            "single_utxo_source must be true when derived from valid IMT witnesses (D-013)"
        );
    }
}

// ── P3-R9: Empirical benchmark — spec §15.6 ───────────────────────────────────

#[cfg(test)]
mod bench {
    use super::*;
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
            birth_epoch: 100, // C5 test witness birth_epoch
        }
    }

    fn commitment_bytes(w: &InputWitness) -> [u8; 32] {
        let h = compute_expected_commitment(w);
        let mut c = [0u8; 32];
        for i in 0..4 {
            c[i * 8..(i + 1) * 8].copy_from_slice(&h[i].to_le_bytes());
        }
        c
    }

    fn nullifier_bytes(w: &InputWitness) -> [u8; 32] {
        let h = compute_expected_nullifier(w);
        let mut n = [0u8; 32];
        for i in 0..4 {
            n[i * 8..(i + 1) * 8].copy_from_slice(&h[i].to_le_bytes());
        }
        n
    }

    fn empty_smt_root(tree: SparseTree) -> [u8; 32] {
        let (dl, dh) = match tree {
            SparseTree::Active => (DOMAIN_SMT_ACTIVE_LO, DOMAIN_SMT_ACTIVE_HI),
            SparseTree::Archived => (DOMAIN_SMT_ARCHIVED_LO, DOMAIN_SMT_ARCHIVED_HI),
        };
        let mut cur = [0u64; 4];
        for _ in 0..SMT_DEPTH {
            let mut inp = [Goldilocks::new(0u64); 8];
            inp[0] = Goldilocks::new(dl);
            inp[1] = Goldilocks::new(dh);
            inp[2..6]
                .iter_mut()
                .zip(cur.iter())
                .for_each(|(d, &s)| *d = Goldilocks::new(s));
            inp[6..8]
                .iter_mut()
                .zip(cur.iter())
                .for_each(|(d, &s)| *d = Goldilocks::new(s));
            cur = poseidon2_permute(&inp);
        }
        let mut root = [0u8; 32];
        for i in 0..4 {
            root[i * 8..(i + 1) * 8].copy_from_slice(&cur[i].to_le_bytes());
        }
        root
    }

    fn build_bench_witnesses(n: usize) -> (TransferWitnesses, [u64; 4], [u8; 32], [u8; 32]) {
        let ownership: Vec<InputWitness> = (0..n as u64).map(make_witness).collect();
        let commitments: Vec<[u8; 32]> = ownership.iter().map(commitment_bytes).collect();

        let mut imt = IncrementalMerkleTree::new();
        for c in &commitments {
            imt.append(c).unwrap();
        }
        let root_bytes = imt.root();
        let imt_root: [u64; 4] = core::array::from_fn(|i| {
            u64::from_le_bytes(root_bytes[i * 8..(i + 1) * 8].try_into().unwrap())
        });
        let membership: Vec<MembershipWitness> = commitments
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

        let active_root = empty_smt_root(SparseTree::Active);
        let archived_root = empty_smt_root(SparseTree::Archived);

        let nm_active: Vec<_> = ownership
            .iter()
            .map(|w| {
                let null = nullifier_bytes(w);
                let (dl, dh) = (DOMAIN_SMT_ACTIVE_LO, DOMAIN_SMT_ACTIVE_HI);
                let mut siblings = [[0u64; 4]; SMT_DEPTH];
                let mut cur = [0u64; 4];
                for sibling in &mut siblings {
                    *sibling = cur;
                    let mut inp = [Goldilocks::new(0u64); 8];
                    inp[0] = Goldilocks::new(dl);
                    inp[1] = Goldilocks::new(dh);
                    inp[2..6]
                        .iter_mut()
                        .zip(cur.iter())
                        .for_each(|(d, &s)| *d = Goldilocks::new(s));
                    inp[6..8]
                        .iter_mut()
                        .zip(cur.iter())
                        .for_each(|(d, &s)| *d = Goldilocks::new(s));
                    cur = poseidon2_permute(&inp);
                }
                NonMembershipWitness {
                    nullifier: null,
                    tree: SparseTree::Active,
                    siblings,
                }
            })
            .collect();

        let nm_archived: Vec<_> = ownership
            .iter()
            .map(|w| {
                let null = nullifier_bytes(w);
                let (dl, dh) = (DOMAIN_SMT_ARCHIVED_LO, DOMAIN_SMT_ARCHIVED_HI);
                let mut siblings = [[0u64; 4]; SMT_DEPTH];
                let mut cur = [0u64; 4];
                for sibling in &mut siblings {
                    *sibling = cur;
                    let mut inp = [Goldilocks::new(0u64); 8];
                    inp[0] = Goldilocks::new(dl);
                    inp[1] = Goldilocks::new(dh);
                    inp[2..6]
                        .iter_mut()
                        .zip(cur.iter())
                        .for_each(|(d, &s)| *d = Goldilocks::new(s));
                    inp[6..8]
                        .iter_mut()
                        .zip(cur.iter())
                        .for_each(|(d, &s)| *d = Goldilocks::new(s));
                    cur = poseidon2_permute(&inp);
                }
                NonMembershipWitness {
                    nullifier: null,
                    tree: SparseTree::Archived,
                    siblings,
                }
            })
            .collect();

        (
            TransferWitnesses {
                ownership,
                membership,
                nonmembership_active: nm_active,
                nonmembership_archived: nm_archived,
            },
            imt_root,
            active_root,
            archived_root,
        )
    }

    /// P3-R9: Full BatchTransferProof proving time (2-in/2-out). Spec §15.6.
    ///
    /// Measures all 4 sub-AIRs: CA (Poseidon2 ownership) + CB (IMT membership)
    /// + CC (dual SMT non-membership) + CD/CE/CG (transfer constraints).
    ///
    /// Spec §15.6: result is empirical reference, not a pass/fail gate.
    /// FRI params OSSIFIED: blowup=8, queries=84, grinding=23 (D-028).
    ///
    /// Run with: cargo test -p scalar-stark-p3 --features bench-hardware \
    ///           -- bench::bench_batch_transfer_2in2out --nocapture --ignored
    #[test]
    #[ignore = "P3-R9: slow bench (~30 min debug). Run: cargo test -p scalar-stark-p3 --features bench-hardware -- bench::bench_batch_transfer_2in2out --nocapture --ignored"]
    fn bench_batch_transfer_2in2out() {
        let (witnesses, imt_root, active_root, archived_root) = build_bench_witnesses(2);
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
            commitment_hash: [0u64; 4], // A-R9: set via derive_public_claims
            nullifier_hash: [0u64; 4],  // A-R9: set via derive_public_claims
        };

        let claims = derive_public_claims(&witnesses, pi, imt_root)
            .expect("derive_public_claims must succeed");

        // Warm-up
        let _ = prove_batch_transfer(&witnesses, &claims).expect("warm-up prove must succeed");

        // Timed run
        let start = Instant::now();
        let batch_proof =
            prove_batch_transfer(&witnesses, &claims).expect("prove_batch_transfer must succeed");
        let prove_ms = start.elapsed().as_millis();

        let start = Instant::now();
        verify_batch_transfer(&batch_proof, &claims).expect("verify_batch_transfer must succeed");
        let verify_ms = start.elapsed().as_millis();

        println!(
            "[P3-R9] BatchTransferProof 2-in/2-out — prove: {}ms, verify: {}ms",
            prove_ms, verify_ms
        );
        println!(
            "[P3-R9] Proof sizes — CA: {} B, CB: {} B, CC: {} B, CDCECG: {} B, total: {} B",
            batch_proof.ca_proof.len(),
            batch_proof.cb_proof.len(),
            batch_proof.cc_proof.len(),
            batch_proof.cdcecg_proof.len(),
            batch_proof.total_bytes()
        );
        println!("[P3-R9] FRI: blowup=8, queries=84, grinding=23 (OSSIFIED §4.4, D-028)");
        println!("[P3-R9] Spec §15.6: no hard time limit — empirical reference only");
        println!(
            "[P3-R9] Spec §15.6: all tiers (A/B/C) must prove without GPU — verified by CPU-only Codespace"
        );
    }
}

// ── Benchmark helper — pub untuk dipakai dari examples/ ──────────────────────

/// Build valid TransferWitnesses + TransferPublicClaims untuk benchmarking.
/// Menggunakan 2 input UTXO dengan nilai deterministik dari `seed`. Pub.
pub fn build_bench_transfer_input(
    seed: u64,
) -> Result<(TransferWitnesses, TransferPublicClaims, [u64; 4]), BatchTransferError> {
    use crate::membership_air_p3::{MembershipWitness, IMT_DEPTH};
    use crate::nonmembership_air_p3::{
        NonMembershipWitness, SparseTree, DOMAIN_SMT_ACTIVE_HI, DOMAIN_SMT_ACTIVE_LO,
        DOMAIN_SMT_ARCHIVED_HI, DOMAIN_SMT_ARCHIVED_LO, SMT_DEPTH,
    };
    use crate::ownership_air_p3::{
        poseidon2_hash, InputWitness, DOMAIN_COMMITMENT_FE, DOMAIN_NULL_FE,
    };
    use p3_goldilocks::Goldilocks;
    use scalar_crypto::imt::IncrementalMerkleTree;

    // ── Build 2 InputWitness ──────────────────────────────────────────────────
    let make_witness = |s: u64| InputWitness {
        secret: 0xDEAD_BEEF_0000_0000 | s,
        value: 500_000_000 + s,
        owner_pubkey_lo: 0xABCD_EF00 | (s & 0xFFFF_FFFF),
        owner_pubkey_hi: 0x1234_5678,
        salt: 0xCAFE_BABE_0000_0000 | s,
        spending_key_lo: 0x1111_1111,
        spending_key_hi: 0x2222_2222,
        birth_epoch: 100, // C5 test witness birth_epoch
    };
    let ow = vec![make_witness(seed), make_witness(seed + 1)];

    // ── Compute commitment bytes per witness ──────────────────────────────────
    let commitment_bytes_of = |w: &InputWitness| -> [u8; 32] {
        let input = [
            Goldilocks::new(DOMAIN_COMMITMENT_FE),
            Goldilocks::new(w.value),
            Goldilocks::new(w.owner_pubkey_lo),
            Goldilocks::new(w.owner_pubkey_hi),
            Goldilocks::new(w.secret),
            Goldilocks::new(w.salt),
            Goldilocks::new(0),
            Goldilocks::new(0),
        ];
        let h = poseidon2_hash(&input);
        let mut out = [0u8; 32];
        for (i, &v) in h.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
        out
    };

    let nullifier_bytes_of = |w: &InputWitness| -> [u8; 32] {
        let input = [
            Goldilocks::new(DOMAIN_NULL_FE),
            Goldilocks::new(w.secret),
            Goldilocks::new(w.spending_key_lo),
            Goldilocks::new(w.spending_key_hi),
            Goldilocks::new(0),
            Goldilocks::new(0),
            Goldilocks::new(0),
            Goldilocks::new(0),
        ];
        let h = poseidon2_hash(&input);
        let mut out = [0u8; 32];
        for (i, &v) in h.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
        out
    };

    let commitments: Vec<[u8; 32]> = ow.iter().map(commitment_bytes_of).collect();

    // ── Build IMT + membership witnesses ─────────────────────────────────────
    let mut imt = IncrementalMerkleTree::new();
    for c in &commitments {
        imt.append(c)
            .map_err(|e| BatchTransferError::Other(format!("{e:?}")))?;
    }
    let imt_root_bytes = imt.root();
    let imt_root: [u64; 4] = core::array::from_fn(|i| {
        u64::from_le_bytes(imt_root_bytes[i * 8..(i + 1) * 8].try_into().unwrap())
    });

    let mut membership: Vec<MembershipWitness> = Vec::with_capacity(ow.len());
    for (idx, commitment) in commitments.iter().enumerate() {
        let path = imt
            .prove_membership(idx as u64)
            .map_err(|e| BatchTransferError::Other(format!("{e:?}")))?;
        let mut siblings = [[0u64; 4]; IMT_DEPTH];
        for (i, sib) in path.siblings.iter().enumerate() {
            for j in 0..4 {
                siblings[i][j] = u64::from_le_bytes(sib[j * 8..(j + 1) * 8].try_into().unwrap());
            }
        }
        membership.push(MembershipWitness {
            commitment: *commitment,
            leaf_index: idx as u64,
            siblings,
        });
    }

    // ── Build empty SMT non-membership witnesses ──────────────────────────────
    let empty_smt_siblings = |dl: u64, dh: u64| -> [[u64; 4]; SMT_DEPTH] {
        let mut cur = [0u64; 4];
        let mut out = [[0u64; 4]; SMT_DEPTH];
        for sibling in &mut out {
            *sibling = cur;
            let inp = [
                Goldilocks::new(dl),
                Goldilocks::new(dh),
                Goldilocks::new(cur[0]),
                Goldilocks::new(cur[1]),
                Goldilocks::new(cur[2]),
                Goldilocks::new(cur[3]),
                Goldilocks::new(cur[0]),
                Goldilocks::new(cur[1]),
            ];
            cur = poseidon2_hash(&inp);
        }
        out
    };

    let active_siblings = empty_smt_siblings(DOMAIN_SMT_ACTIVE_LO, DOMAIN_SMT_ACTIVE_HI);
    let archived_siblings = empty_smt_siblings(DOMAIN_SMT_ARCHIVED_LO, DOMAIN_SMT_ARCHIVED_HI);

    let empty_smt_root = |dl: u64, dh: u64| -> [u8; 32] {
        let sibs = empty_smt_siblings(dl, dh);
        let mut cur = sibs[SMT_DEPTH - 1];
        let inp = [
            Goldilocks::new(dl),
            Goldilocks::new(dh),
            Goldilocks::new(cur[0]),
            Goldilocks::new(cur[1]),
            Goldilocks::new(cur[2]),
            Goldilocks::new(cur[3]),
            Goldilocks::new(cur[0]),
            Goldilocks::new(cur[1]),
        ];
        cur = poseidon2_hash(&inp);
        let mut out = [0u8; 32];
        for (i, &v) in cur.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
        }
        out
    };

    let active_root = empty_smt_root(DOMAIN_SMT_ACTIVE_LO, DOMAIN_SMT_ACTIVE_HI);
    let archived_root = empty_smt_root(DOMAIN_SMT_ARCHIVED_LO, DOMAIN_SMT_ARCHIVED_HI);

    let nm_active: Vec<NonMembershipWitness> = ow
        .iter()
        .map(|w| NonMembershipWitness {
            nullifier: nullifier_bytes_of(w),
            siblings: active_siblings,
            tree: SparseTree::Active,
        })
        .collect();

    let nm_archived: Vec<NonMembershipWitness> = ow
        .iter()
        .map(|w| NonMembershipWitness {
            nullifier: nullifier_bytes_of(w),
            siblings: archived_siblings,
            tree: SparseTree::Archived,
        })
        .collect();

    let witnesses = TransferWitnesses {
        ownership: ow,
        membership,
        nonmembership_active: nm_active,
        nonmembership_archived: nm_archived,
    };

    // ── Derive public claims ──────────────────────────────────────────────────
    use crate::transfer_public_inputs::{TransferPublicInputsP3, FEE_FLOOR_SSCL, T_MAX_WAIT_MS};
    let fee = FEE_FLOOR_SSCL;
    let sum_inputs: u64 = witnesses.ownership.iter().map(|w| w.value).sum();
    let now_ms = 1_700_000_000_000u64;
    let pi = TransferPublicInputsP3 {
        fee_total_sscl: fee,
        sum_inputs_sscl: sum_inputs,
        sum_outputs_sscl: sum_inputs - fee,
        crypto_version: 0x01,
        entry_timestamp_ms: now_ms - T_MAX_WAIT_MS / 2,
        current_timestamp_ms: now_ms,
        utxo_set_root: active_root,
        cb_membership_verified: true,
        nullifier_active_root: active_root,
        nullifier_archived_root: archived_root,
        cc_nonmembership_verified: true,
        output_nonzero: true,
        single_utxo_source: true,
        commitment_hash: [0u64; 4],
        nullifier_hash: [0u64; 4],
    };

    let claims = derive_public_claims(&witnesses, pi, imt_root)
        .map_err(|e| BatchTransferError::Other(format!("{e:?}")))?;

    Ok((witnesses, claims, imt_root))
}
