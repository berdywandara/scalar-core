//! Parallel Validation + Fallback Protocol — Spec §8.1, §8.3
//!
//! Flow v9.0:
//!   Step 1: Aggregator compute manifest + manifest_hash
//!   Step 2: Broadcast ke 10 validator paralel (rank_2..rank_11)
//!   Step 3: Quorum check — 7/10 validator harus setuju pada manifest_hash
//!   Step 4: Jika quorum gagal → fallback ke rank berikutnya (max 3x)
//!   Step 5: Jika fallback_count > AGGREGATOR_FALLBACK_MAX → epoch DEFERRED
//!
//! OSSIFIED constants (dari manifest.rs):
//!   AGGREGATOR_VALIDATOR_COUNT = 10  — validator paralel
//!   AGGREGATOR_VALIDATOR_QUORUM = 7  — quorum minimum
//!   AGGREGATOR_FALLBACK_MAX = 3      — max fallback sebelum deferred
//!
//! Epoch boundary: seq_num based — Rule T-1 §7.2c. BUKAN wall-clock.

use crate::dmm::{
    verify_manifest_hash, AggregatorSelection, EpochRewardManifest, EpochStatus,
    AGGREGATOR_FALLBACK_MAX, AGGREGATOR_VALIDATOR_QUORUM,
};

// ── ValidationVote — spec §8.1 ────────────────────────────────────────────────

/// Vote dari satu validator. Spec §8.1 Step 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationVote {
    /// Validator node_id yang memberikan vote.
    pub validator_id: [u8; 4],
    /// manifest_hash yang di-vote validator. Spec §8.1.
    pub manifest_hash: [u8; 32],
    /// true = setuju dengan manifest_hash aggregator.
    pub agrees: bool,
}

// ── QuorumResult — spec §8.1 ──────────────────────────────────────────────────

/// Hasil quorum check. Spec §8.1 Step 3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumResult {
    /// Quorum tercapai — manifest_hash disetujui ≥7/10 validator.
    Achieved { agree_count: u32 },
    /// Quorum gagal — kurang dari 7 validator setuju.
    Failed { agree_count: u32 },
}

/// Jalankan quorum check: hitung berapa validator setuju pada manifest_hash. Spec §8.1.
///
/// Quorum = 7/10 validator harus memiliki manifest_hash yang identik.
/// AGGREGATOR_VALIDATOR_QUORUM = 7. OSSIFIED — spec §8.1.
pub fn check_quorum(votes: &[ValidationVote], expected_manifest_hash: &[u8; 32]) -> QuorumResult {
    let agree_count = votes
        .iter()
        .filter(|v| v.agrees && &v.manifest_hash == expected_manifest_hash)
        .count() as u32;

    if agree_count >= AGGREGATOR_VALIDATOR_QUORUM {
        QuorumResult::Achieved { agree_count }
    } else {
        QuorumResult::Failed { agree_count }
    }
}

// ── FallbackState — spec §8.3 ────────────────────────────────────────────────

/// State fallback aggregator. Spec §8.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackState {
    /// Masih dalam fallback — coba aggregator berikutnya.
    Retry {
        fallback_count: u32,
        next_aggregator: [u8; 4],
    },
    /// Fallback_count > AGGREGATOR_FALLBACK_MAX → epoch DEFERRED. Spec §8.3.
    EpochDeferred,
}

/// Jalankan fallback protocol. Spec §8.3.
///
/// Jika quorum gagal, coba rank berikutnya dari validator set.
/// fallback_max = AGGREGATOR_FALLBACK_MAX = 3. OSSIFIED — spec §8.3.
/// Jika sudah 3x fallback → epoch DEFERRED.
pub fn try_fallback(
    fallback_count: u32,
    selection: &AggregatorSelection,
    current_fallback_index: usize,
) -> FallbackState {
    // Spec §8.3: fallback_count > AGGREGATOR_FALLBACK_MAX → deferred
    if fallback_count >= AGGREGATOR_FALLBACK_MAX {
        return FallbackState::EpochDeferred;
    }

    // Ambil aggregator berikutnya dari validator set (rank_2..rank_11)
    if let Some(&next_aggregator) = selection.validators.get(current_fallback_index) {
        FallbackState::Retry {
            fallback_count: fallback_count + 1,
            next_aggregator,
        }
    } else {
        // Tidak ada validator tersisa → deferred
        FallbackState::EpochDeferred
    }
}

// ── ConsensusState — spec §8.1 ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusState {
    Open { manifest: Box<EpochRewardManifest> },
    Finalized,
}

// ── ConsensusEngine — spec §8.1 ───────────────────────────────────────────────

/// ConsensusEngine v9.0 — parallel validation + fallback. Spec §8.1, §8.3.
pub struct ConsensusEngine {
    pub state: ConsensusState,
    /// Jumlah fallback yang sudah dilakukan dalam epoch ini. Spec §8.3.
    pub fallback_count: u32,
}

impl ConsensusEngine {
    pub fn new(initial_epoch: u64) -> Self {
        let initial_manifest = EpochRewardManifest::deferred(initial_epoch, 0);
        Self {
            state: ConsensusState::Open {
                manifest: Box::new(initial_manifest),
            },
            fallback_count: 0,
        }
    }

    /// Finalize manifest setelah quorum tercapai. Spec §8.1 Step 3.
    ///
    /// Verifikasi:
    ///   1. manifest.status == Finalized
    ///   2. manifest.verify_arithmetic_invariants()
    ///   3. verify_manifest_hash(manifest) — canonical hash valid
    pub fn transition_to_finalized(
        &mut self,
        final_manifest: EpochRewardManifest,
    ) -> Result<(), &'static str> {
        if final_manifest.status != EpochStatus::Finalized {
            return Err("Manifest must be Finalized status");
        }
        if !final_manifest.verify_arithmetic_invariants() {
            return Err("Manifest arithmetic invariants failed");
        }
        if !verify_manifest_hash(&final_manifest) {
            return Err("Manifest hash mismatch — canonical verification failed");
        }
        self.state = ConsensusState::Finalized;
        self.fallback_count = 0;
        Ok(())
    }

    /// Proses votes dari validator set. Spec §8.1 Step 3.
    ///
    /// Returns QuorumResult — caller bertanggung jawab untuk fallback jika gagal.
    pub fn process_votes(
        &self,
        votes: &[ValidationVote],
        manifest_hash: &[u8; 32],
    ) -> QuorumResult {
        check_quorum(votes, manifest_hash)
    }

    /// Increment fallback counter dan cek apakah epoch harus deferred. Spec §8.3.
    pub fn increment_fallback(&mut self) -> FallbackState {
        self.fallback_count += 1;
        if self.fallback_count > AGGREGATOR_FALLBACK_MAX {
            FallbackState::EpochDeferred
        } else {
            // Placeholder — caller harus provide next aggregator dari selection
            FallbackState::Retry {
                fallback_count: self.fallback_count,
                next_aggregator: [0u8; 4],
            }
        }
    }

    /// Defer epoch — reset state. Spec §8.3.
    pub fn defer_epoch(&mut self, epoch_id: u64) {
        let deferred = EpochRewardManifest::deferred(epoch_id, 0);
        self.state = ConsensusState::Open {
            manifest: Box::new(deferred),
        };
        self.fallback_count = 0;
    }
}

impl Default for ConsensusEngine {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dmm::{compute_manifest_hash, SPEC_VERSION_MANIFEST};

    fn make_finalized_manifest(epoch_id: u64) -> EpochRewardManifest {
        let mut m = EpochRewardManifest {
            epoch_id,
            node_list: vec![],
            spec_version: SPEC_VERSION_MANIFEST,
            total_emission_sscl: 12_600_000_000_000,
            deferred: false,
            seed_k: [0xCCu8; 32],
            manifest_hash: [0u8; 32],
            reward_root: [0xDDu8; 32],
            network_health_digest: [0xBBu8; 32],
            tx_set_root: [0u8; 32],
            status: EpochStatus::Finalized,
        };
        // Compute dan set manifest_hash yang benar
        m.manifest_hash = compute_manifest_hash(&m);
        m
    }

    fn make_vote(validator_id: u8, manifest_hash: [u8; 32], agrees: bool) -> ValidationVote {
        ValidationVote {
            validator_id: [validator_id, 0, 0, 0],
            manifest_hash,
            agrees,
        }
    }

    // ── check_quorum ──────────────────────────────────────────────────────────

    #[test]
    fn test_quorum_achieved_7_of_10() {
        // 7/10 setuju → quorum achieved. Spec §8.1.
        let hash = [0x42u8; 32];
        let votes: Vec<ValidationVote> = (0..10).map(|i| make_vote(i, hash, i < 7)).collect();
        assert_eq!(
            check_quorum(&votes, &hash),
            QuorumResult::Achieved { agree_count: 7 }
        );
    }

    #[test]
    fn test_quorum_achieved_10_of_10() {
        // 10/10 setuju → quorum achieved. Spec §8.1.
        let hash = [0x42u8; 32];
        let votes: Vec<ValidationVote> = (0..10).map(|i| make_vote(i, hash, true)).collect();
        assert_eq!(
            check_quorum(&votes, &hash),
            QuorumResult::Achieved { agree_count: 10 }
        );
    }

    #[test]
    fn test_quorum_failed_6_of_10() {
        // 6/10 setuju → quorum GAGAL. Spec §8.1.
        let hash = [0x42u8; 32];
        let votes: Vec<ValidationVote> = (0..10).map(|i| make_vote(i, hash, i < 6)).collect();
        assert_eq!(
            check_quorum(&votes, &hash),
            QuorumResult::Failed { agree_count: 6 }
        );
    }

    #[test]
    fn test_quorum_failed_wrong_hash() {
        // Hash berbeda → tidak dihitung agree walaupun agrees=true. Spec §8.1.
        let expected = [0x42u8; 32];
        let wrong = [0xFFu8; 32];
        let votes: Vec<ValidationVote> = (0..10)
            .map(|i| make_vote(i, wrong, true)) // semua agree tapi hash salah
            .collect();
        assert_eq!(
            check_quorum(&votes, &expected),
            QuorumResult::Failed { agree_count: 0 }
        );
    }

    #[test]
    fn test_quorum_empty_votes_fails() {
        // Tidak ada votes → quorum gagal. Spec §8.1.
        assert_eq!(
            check_quorum(&[], &[0x42u8; 32]),
            QuorumResult::Failed { agree_count: 0 }
        );
    }

    #[test]
    fn test_quorum_threshold_is_7() {
        // Threshold tepat 7 — bukan 6, bukan 8. Spec §8.1 OSSIFIED.
        let hash = [0x42u8; 32];
        // 6 → fail
        let votes6: Vec<ValidationVote> = (0..6).map(|i| make_vote(i, hash, true)).collect();
        assert!(matches!(
            check_quorum(&votes6, &hash),
            QuorumResult::Failed { .. }
        ));
        // 7 → achieved
        let votes7: Vec<ValidationVote> = (0..7).map(|i| make_vote(i, hash, true)).collect();
        assert!(matches!(
            check_quorum(&votes7, &hash),
            QuorumResult::Achieved { .. }
        ));
    }

    // ── try_fallback — spec §8.3 ──────────────────────────────────────────────

    #[test]
    fn test_fallback_first_attempt_retry() {
        // Fallback pertama (count=0) → Retry. Spec §8.3.
        let selection = AggregatorSelection {
            aggregator: [0x01u8; 4],
            validators: vec![[0x02u8; 4], [0x03u8; 4]],
            seed_k: [0u8; 32],
        };
        let result = try_fallback(0, &selection, 0);
        assert!(matches!(
            result,
            FallbackState::Retry {
                fallback_count: 1,
                ..
            }
        ));
    }

    #[test]
    fn test_fallback_at_max_defers_epoch() {
        // fallback_count >= AGGREGATOR_FALLBACK_MAX (3) → EpochDeferred. Spec §8.3.
        let selection = AggregatorSelection {
            aggregator: [0x01u8; 4],
            validators: vec![[0x02u8; 4], [0x03u8; 4], [0x04u8; 4]],
            seed_k: [0u8; 32],
        };
        let result = try_fallback(AGGREGATOR_FALLBACK_MAX, &selection, 0);
        assert_eq!(result, FallbackState::EpochDeferred);
    }

    #[test]
    fn test_fallback_no_validators_left_defers() {
        // Tidak ada validator tersisa → EpochDeferred. Spec §8.3.
        let selection = AggregatorSelection {
            aggregator: [0x01u8; 4],
            validators: vec![],
            seed_k: [0u8; 32],
        };
        let result = try_fallback(0, &selection, 0);
        assert_eq!(result, FallbackState::EpochDeferred);
    }

    #[test]
    fn test_fallback_max_is_3() {
        // AGGREGATOR_FALLBACK_MAX = 3. OSSIFIED — spec §8.3.
        assert_eq!(AGGREGATOR_FALLBACK_MAX, 3u32);
    }

    #[test]
    fn test_fallback_next_aggregator_from_validators() {
        // Fallback mengambil aggregator dari validator set. Spec §8.3.
        let next = [0x05u8, 0x00, 0x00, 0x00];
        let selection = AggregatorSelection {
            aggregator: [0x01u8; 4],
            validators: vec![next, [0x06u8; 4]],
            seed_k: [0u8; 32],
        };
        let result = try_fallback(0, &selection, 0);
        if let FallbackState::Retry {
            next_aggregator, ..
        } = result
        {
            assert_eq!(next_aggregator, next);
        } else {
            panic!("Expected Retry");
        }
    }

    // ── ConsensusEngine ───────────────────────────────────────────────────────

    #[test]
    fn test_transition_to_finalized_valid() {
        // Manifest valid → transition ok. Spec §8.1.
        let mut engine = ConsensusEngine::new(1);
        let manifest = make_finalized_manifest(1);
        assert!(engine.transition_to_finalized(manifest).is_ok());
        assert_eq!(engine.state, ConsensusState::Finalized);
    }

    #[test]
    fn test_transition_rejects_non_finalized_status() {
        // Manifest status bukan Finalized → error. Spec §8.1.
        let mut engine = ConsensusEngine::new(1);
        let mut manifest = make_finalized_manifest(1);
        manifest.status = EpochStatus::Open;
        assert!(engine.transition_to_finalized(manifest).is_err());
    }

    #[test]
    fn test_transition_rejects_wrong_manifest_hash() {
        // manifest_hash salah → error. Spec §8.2.
        let mut engine = ConsensusEngine::new(1);
        let mut manifest = make_finalized_manifest(1);
        manifest.manifest_hash = [0xFFu8; 32]; // tamper
        assert!(engine.transition_to_finalized(manifest).is_err());
    }

    #[test]
    fn test_process_votes_quorum_achieved() {
        // ConsensusEngine::process_votes — quorum achieved. Spec §8.1.
        let engine = ConsensusEngine::new(1);
        let hash = [0x42u8; 32];
        let votes: Vec<ValidationVote> = (0..7).map(|i| make_vote(i, hash, true)).collect();
        assert!(matches!(
            engine.process_votes(&votes, &hash),
            QuorumResult::Achieved { .. }
        ));
    }

    #[test]
    fn test_increment_fallback_defers_after_max() {
        // Setelah AGGREGATOR_FALLBACK_MAX+1 increment → EpochDeferred. Spec §8.3.
        let mut engine = ConsensusEngine::new(1);
        for _ in 0..=AGGREGATOR_FALLBACK_MAX {
            engine.increment_fallback();
        }
        assert!(engine.fallback_count > AGGREGATOR_FALLBACK_MAX);
    }

    #[test]
    fn test_defer_epoch_resets_fallback_count() {
        // defer_epoch reset fallback_count ke 0. Spec §8.3.
        let mut engine = ConsensusEngine::new(1);
        engine.fallback_count = 3;
        engine.defer_epoch(2);
        assert_eq!(engine.fallback_count, 0);
    }

    #[test]
    fn test_defer_epoch_sets_deferred_manifest() {
        // defer_epoch set manifest ke Deferred status. Spec §8.3.
        let mut engine = ConsensusEngine::new(1);
        engine.defer_epoch(5);
        if let ConsensusState::Open { manifest } = &engine.state {
            assert_eq!(manifest.status, EpochStatus::Deferred);
            assert_eq!(manifest.epoch_id, 5);
        } else {
            panic!("Expected Open state after defer");
        }
    }

    #[test]
    fn test_fallback_count_zero_on_new() {
        // ConsensusEngine baru → fallback_count = 0. Spec §8.3.
        let engine = ConsensusEngine::new(0);
        assert_eq!(engine.fallback_count, 0);
    }

    #[test]
    fn test_transition_resets_fallback_count() {
        // Setelah finalize berhasil → fallback_count direset ke 0. Spec §8.3.
        let mut engine = ConsensusEngine::new(1);
        engine.fallback_count = 2;
        let manifest = make_finalized_manifest(1);
        engine.transition_to_finalized(manifest).unwrap();
        assert_eq!(engine.fallback_count, 0);
    }
}
