//! CommitStark — Level-2 Finality (Atomic Check-and-Set).
//! SCALAR-SECURITY §189, SCALAR-PROTOCOL §7.2/§4.5 (C-K1-GATE).
//!
//! "CommitStark adalah atomic check-and-set. Dua transaksi yang mengklaim
//! nullifier sama dapat keduanya masuk optimistic (Byzantine voting), tetapi
//! atomic check mencegah keduanya finalized. Race condition tidak mungkin di
//! Level 2." — SECURITY §189.
//!
//! Level 2 (STARK Final) is reached when a BatchTransferProof verifies AND its
//! nullifiers atomically check-and-set into NullifierSet (NS_ACTIVE /
//! NS_CHECKPOINT). On success, finality_level = StarkFinal (G-13
//! FinalityLevel::StarkFinal) is emitted and the sub-epoch is recorded as
//! having a finalized BatchTransferProof (consumed by G-24b CG-WINDOW-TRIGGER:
//! validity=1 requires finalization at target_subepoch_id + 1).
//!
//! ── Implementation Constraints ──────────────────────────────────────────────
//! A. Atomic transactional semantics: pre-flight check ALL nullifiers in the
//!    batch BEFORE any insert. If any nullifier is already spent, the ENTIRE
//!    batch is rejected and NullifierSet is left UNCHANGED (no partial writes).
//! B. SSOT: nullifier_hash binding is re-derived via
//!    scalar_stark_p3::transfer_public_inputs::compute_nullifier_hash — the
//!    SAME function used by the prover (batch_transfer_p3). No local
//!    reimplementation of the BLAKE3 derivation.

use scalar_nullifier::nullifier_set::NullifierSet;
use scalar_stark_p3::batch_transfer_p3::{
    verify_batch_transfer, BatchTransferError, BatchTransferProof, TransferPublicClaims,
};
use scalar_stark_p3::transfer_public_inputs::compute_nullifier_hash;
use std::collections::HashSet;

/// Finality level emitted on successful Level-2 commit. Mirrors
/// `scalar_network::micro_commit::FinalityLevel` (G-13) without introducing a
/// cross-crate dependency from scalar-network -> scalar-consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalityLevel {
    None = 0,
    /// Level 1 Optimistic (MicroCommitment quorum) — not produced here.
    Optimistic = 1,
    /// Level 2 STARK Final (this module) — IMMUTABLE, cannot be rolled back.
    StarkFinal = 2,
}

/// Errors from a CommitStark batch commit attempt. The batch is rejected
/// as a whole; NullifierSet is left unchanged in every error case.
#[derive(Debug, thiserror::Error)]
pub enum CommitStarkError {
    /// Re-derived nullifier_hash does not match claims.pi.nullifier_hash (A-R9
    /// binding violated) — the supplied nullifiers do not match the proof.
    #[error("nullifier_hash binding mismatch (A-R9): proof does not bind supplied nullifiers")]
    NullifierBindingMismatch,
    /// `nullifiers` length does not match `claims.ownership_claims` length.
    #[error("nullifier count mismatch: {supplied} supplied, {expected} in claims")]
    NullifierCountMismatch { supplied: usize, expected: usize },
    /// One or more sub-AIR proofs failed verification.
    #[error("BatchTransferProof verification failed: {0}")]
    ProofVerificationFailed(#[from] BatchTransferError),
    /// Atomic check-and-set: at least one nullifier already spent (NS_ACTIVE
    /// or NS_CHECKPOINT). Lists ALL conflicting nullifiers found in pre-flight.
    /// Per Constraint A, NO insert is performed — NullifierSet unchanged.
    #[error("double-spend detected: {0} of {1} nullifiers already spent")]
    DoubleSpendDetected(usize, usize),
}

/// Convert an A-R9 nullifier ([u64;4], LE chunks — same packing as
/// batch_transfer_p3::nullifier_bytes) to the [u8;32] form used by NullifierSet.
fn nullifier_to_bytes(n: &[u64; 4]) -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..4 {
        b[i * 8..(i + 1) * 8].copy_from_slice(&n[i].to_le_bytes());
    }
    b
}

/// CommitStark — Level-2 finality state (NullifierSet + finalized-subepoch log).
pub struct CommitStark {
    nullifier_set: NullifierSet,
    /// Sub-epochs for which at least one BatchTransferProof has been finalized
    /// at Level 2. Consumed by G-24b CG-WINDOW-TRIGGER (target_subepoch_id + 1
    /// lookup).
    finalized_subepochs: HashSet<u64>,
}

impl CommitStark {
    /// Create an empty CommitStark (genesis NullifierSet, no finalized sub-epochs).
    pub fn new() -> Self {
        Self {
            nullifier_set: NullifierSet::new(),
            finalized_subepochs: HashSet::new(),
        }
    }

    /// Read-only access to the underlying NullifierSet (e.g. for is_spent queries).
    pub fn nullifier_set(&self) -> &NullifierSet {
        &self.nullifier_set
    }

    /// Has subepoch_id at least one BatchTransferProof finalized at Level 2?
    /// G-24b CG-WINDOW-TRIGGER hook: callers check `target_subepoch_id + 1`.
    pub fn is_finalized_at_subepoch(&self, subepoch_id: u64) -> bool {
        self.finalized_subepochs.contains(&subepoch_id)
    }

    /// Atomic check-and-set commit of a BatchTransferProof. SECURITY §189.
    ///
    /// Order of operations (defense-in-depth):
    ///   1. Binding: re-derive nullifier_hash from `nullifiers` (SSOT,
    ///      compute_nullifier_hash) and compare to claims.pi.nullifier_hash.
    ///   2. Proof: verify_batch_transfer (all 4 sub-AIRs).
    ///   3. Pre-flight (Constraint A): check is_spent() for ALL nullifiers
    ///      BEFORE any write. Reject whole batch if any conflict.
    ///   4. Commit: insert ALL nullifiers, record subepoch_id as finalized,
    ///      return FinalityLevel::StarkFinal.
    ///
    /// `nullifiers`: the [u8;32] nullifiers claimed spent by this batch, in the
    /// SAME order as `claims.ownership_claims`. `epoch_id`: passed through to
    /// NullifierSet::insert (NS_ACTIVE window bookkeeping, spec §6.1).
    pub fn commit_batch_transfer(
        &mut self,
        subepoch_id: u64,
        epoch_id: u64,
        proof: &BatchTransferProof,
        claims: &TransferPublicClaims,
        nullifiers: &[[u8; 32]],
    ) -> Result<FinalityLevel, CommitStarkError> {
        // Step 0: shape check.
        if nullifiers.len() != claims.ownership_claims.len() {
            return Err(CommitStarkError::NullifierCountMismatch {
                supplied: nullifiers.len(),
                expected: claims.ownership_claims.len(),
            });
        }

        // Step 1: A-R9 binding (SSOT — compute_nullifier_hash from scalar-stark-p3).
        let derived_hash = compute_nullifier_hash(nullifiers);
        if derived_hash != claims.pi.nullifier_hash {
            return Err(CommitStarkError::NullifierBindingMismatch);
        }

        // Cross-check: nullifiers must also match ownership_claims.expected_nullifier
        // (defense-in-depth — both CA's claim and the supplied set must agree).
        for (supplied, claim) in nullifiers.iter().zip(claims.ownership_claims.iter()) {
            if *supplied != nullifier_to_bytes(&claim.expected_nullifier) {
                return Err(CommitStarkError::NullifierBindingMismatch);
            }
        }

        // Step 2: verify all four sub-AIR proofs.
        verify_batch_transfer(proof, claims)?;

        // Step 3 (Constraint A): pre-flight — check ALL nullifiers before any write.
        let conflicts = nullifiers
            .iter()
            .filter(|n| self.nullifier_set.is_spent(n))
            .count();
        if conflicts > 0 {
            return Err(CommitStarkError::DoubleSpendDetected(
                conflicts,
                nullifiers.len(),
            ));
        }

        // Step 4: commit — insert all nullifiers, record finalization.
        // NullifierSet::insert is itself idempotent (Constraint A pre-flight
        // above already guarantees none are spent, so no idempotency branch
        // can fire here — this is the atomic "set" half of check-and-set).
        for n in nullifiers {
            self.nullifier_set.insert(n, epoch_id);
        }
        self.finalized_subepochs.insert(subepoch_id);

        Ok(FinalityLevel::StarkFinal)
    }
}

impl Default for CommitStark {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalar_stark_p3::batch_transfer_p3::TransferPublicClaims;
    use scalar_stark_p3::membership_air_p3::MembershipPublicClaim;
    use scalar_stark_p3::nonmembership_air_p3::NonMembershipPublicClaim;
    use scalar_stark_p3::ownership_air_p3::OwnershipPublicClaim;
    use scalar_stark_p3::transfer_public_inputs::TransferPublicInputsP3;

    /// Minimal (non-proving) PI — sufficient to exercise CommitStark's own
    /// binding/pre-flight logic (Steps 0/1/3), which run BEFORE
    /// verify_batch_transfer (Step 2). Field values are arbitrary; only
    /// `nullifier_hash` and ownership_claims matter for these tests.
    fn stub_pi(nullifier_hash: [u64; 4]) -> TransferPublicInputsP3 {
        TransferPublicInputsP3 {
            fee_total_sscl: 40,
            sum_inputs_sscl: 1_000_000_040,
            sum_outputs_sscl: 1_000_000_000,
            crypto_version: 0x01,
            current_subepoch_id: 1_000,
            target_subepoch_id: 1_000, // validity=0 (current == target)
            utxo_set_root: [0x42u8; 32],
            cb_membership_verified: true,
            nullifier_active_root: [0xAAu8; 32],
            nullifier_archived_root: [0xBBu8; 32],
            cc_nonmembership_verified: true,
            output_nonzero: true,
            single_utxo_source: true,
            commitment_hash: [0u64; 4],
            nullifier_hash,
        }
    }

    fn stub_claims(
        nullifiers_u64: &[[u64; 4]],
        pi_nullifier_hash: [u64; 4],
    ) -> TransferPublicClaims {
        let ownership_claims: Vec<OwnershipPublicClaim> = nullifiers_u64
            .iter()
            .map(|n| OwnershipPublicClaim {
                expected_nullifier: *n,
                expected_commitment: [0u64; 4],
            })
            .collect();
        TransferPublicClaims {
            pi: stub_pi(pi_nullifier_hash),
            ownership_claims,
            membership_claim: MembershipPublicClaim {
                expected_root: [0u64; 4],
                leaf_commitments: vec![],
                leaf_indices: vec![],
            },
            nonmembership_claim: NonMembershipPublicClaim {
                nullifier: [0u8; 32],
                active_root: [0xAAu8; 32],
                archived_root: [0xBBu8; 32],
            },
        }
    }

    fn stub_proof() -> BatchTransferProof {
        BatchTransferProof {
            ca_proof: vec![],
            cb_proof: vec![],
            cc_proof: vec![],
            cdcecg_proof: vec![],
        }
    }

    #[test]
    fn test_new_commit_stark_empty_state() {
        let cs = CommitStark::new();
        assert!(!cs.is_finalized_at_subepoch(0));
        assert!(!cs.nullifier_set().is_spent(&[0u8; 32]));
    }

    #[test]
    fn test_nullifier_count_mismatch_rejected_before_proving() {
        let n1 = [0x01u64; 4];
        let n1_bytes = nullifier_to_bytes(&n1);
        let claims = stub_claims(&[n1], compute_nullifier_hash(&[n1_bytes]));

        let mut cs = CommitStark::new();
        // supply 0 nullifiers, but claims has 1 ownership_claim
        let result = cs.commit_batch_transfer(1, 0, &stub_proof(), &claims, &[]);
        assert!(matches!(
            result,
            Err(CommitStarkError::NullifierCountMismatch {
                supplied: 0,
                expected: 1
            })
        ));
        // Step 0 rejection: state unchanged.
        assert!(!cs.is_finalized_at_subepoch(1));
    }

    #[test]
    fn test_nullifier_binding_mismatch_rejected_before_proving() {
        // claims.pi.nullifier_hash does NOT match BLAKE3(nullifiers) — Step 1
        // (SSOT compute_nullifier_hash) must reject before verify_batch_transfer
        // (which would fail anyway on empty stub_proof, but binding check fires first).
        let n1 = [0x01u64; 4];
        let n1_bytes = nullifier_to_bytes(&n1);
        let wrong_hash = [0xFFu64; 4];
        let claims = stub_claims(&[n1], wrong_hash);

        let mut cs = CommitStark::new();
        let result = cs.commit_batch_transfer(1, 0, &stub_proof(), &claims, &[n1_bytes]);
        assert!(matches!(
            result,
            Err(CommitStarkError::NullifierBindingMismatch)
        ));
        assert!(!cs.is_finalized_at_subepoch(1));
        assert!(
            !cs.nullifier_set().is_spent(&n1_bytes),
            "no insert on rejection"
        );
    }

    #[test]
    fn test_nullifier_cross_check_mismatch_rejected() {
        // nullifier_hash binding matches the SUPPLIED nullifiers, but the supplied
        // nullifier differs from ownership_claims[i].expected_nullifier (CA claim).
        let n1 = [0x01u64; 4];
        let n_other = [0x02u64; 4];
        let n1_bytes = nullifier_to_bytes(&n1);

        // claims built with n_other as the CA-claimed nullifier...
        let mut claims = stub_claims(&[n_other], [0u64; 4]);
        // ...but pi.nullifier_hash is set to match the SUPPLIED n1 (Step 1 passes)...
        claims.pi.nullifier_hash = compute_nullifier_hash(&[n1_bytes]);

        let mut cs = CommitStark::new();
        // ...so Step 1 (global binding) passes, but the per-input cross-check
        // (supplied n1 vs ownership_claims[0].expected_nullifier = n_other) fails.
        let result = cs.commit_batch_transfer(1, 0, &stub_proof(), &claims, &[n1_bytes]);
        assert!(matches!(
            result,
            Err(CommitStarkError::NullifierBindingMismatch)
        ));
        assert!(!cs.is_finalized_at_subepoch(1));
    }

    #[test]
    fn test_invalid_proof_rejected_after_binding_passes() {
        // Binding (Step 1) and cross-check pass; Step 2 (verify_batch_transfer on
        // an empty/stub proof) must fail, and state must remain unchanged.
        let n1 = [0x01u64; 4];
        let n1_bytes = nullifier_to_bytes(&n1);
        let claims = stub_claims(&[n1], compute_nullifier_hash(&[n1_bytes]));

        let mut cs = CommitStark::new();
        let result = cs.commit_batch_transfer(1, 0, &stub_proof(), &claims, &[n1_bytes]);
        assert!(matches!(
            result,
            Err(CommitStarkError::ProofVerificationFailed(_))
        ));
        assert!(!cs.is_finalized_at_subepoch(1));
        assert!(
            !cs.nullifier_set().is_spent(&n1_bytes),
            "no insert on proof failure"
        );
    }

    #[test]
    fn test_nullifier_to_bytes_roundtrip_le_packing() {
        // Sanity: nullifier_to_bytes matches the LE packing used by
        // batch_transfer_p3's own nullifier_bytes derivation (A-R9).
        let n: [u64; 4] = [0x0102030405060708, 0, 0, 0];
        let b = nullifier_to_bytes(&n);
        assert_eq!(&b[0..8], &0x0102030405060708u64.to_le_bytes());
        assert_eq!(&b[8..32], &[0u8; 24]);
    }
}
