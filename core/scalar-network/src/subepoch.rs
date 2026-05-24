//! Sub-Epoch Finality — Research Package §3.2, Decision D-003
//!
//! Separates epoch as measurement unit (PoU, governance, maturity — 30 days)
//! from epoch as finality unit (transactions — ~1 hour).
//!
//! Each epoch consists of 720 sub-epochs (1 hour each).
//! SubEpochCommitment requires quorum 5/7 from Manifest-tier validators.
//!
//! Safety (Pigeonhole): Two valid commitments impossible if honest ≥ 5/7.
//! Proof: 5+5-7=3 must sign both → contradiction (honest sign only 1).
//!
//! Domain separators (OSSIFIED — Research Package Bagian 8):
//!   DOMAIN_SUBEPOCH       = b"scalar_subepoch"       (15 byte)
//!   DOMAIN_SUBEPOCH_SEED  = b"scalar_subepoch_seed"  (20 byte)
//!   DOMAIN_SUBEPOCH_SCORE = b"scalar_subepoch_score" (21 byte)
//!   DOMAIN_SUBEPOCH_FS    = b"scalar_subepoch_fs"    (18 byte)
//!
//! Decision D-003: imt_frontier_root MUST come from quorum SubEpochCommitment.
//! Decision D-008: Poseidon2 t=8 (future; current uses BLAKE3 out-circuit).

use blake3::Hasher;
use scalar_crypto::domain::{
    DOMAIN_IMT_FRONTIER, DOMAIN_SMT_ACTIVE, DOMAIN_SUBEPOCH, DOMAIN_SUBEPOCH_SCORE,
    DOMAIN_SUBEPOCH_SEED,
};
use std::collections::HashMap;

// ── Constants — OSSIFIED ──────────────────────────────────────────────────────

/// Sub-epochs per epoch (720 × 1 hour = 30 days). Research Package §3.2.1.
pub const SUBEPOCHS_PER_EPOCH: u32 = 720;

/// Sub-epoch duration in seconds (~1 hour). Research Package §3.2.1.
pub const SUBEPOCH_DURATION_S: u64 = 3600;

/// Collection phase duration (0-45 min). Research Package §3.2.3.
pub const SUBEPOCH_COLLECT_S: u64 = 2700;

/// Quorum phase duration (45-60 min). Research Package §3.2.3.
pub const SUBEPOCH_QUORUM_S: u64 = 3600;

/// Quorum threshold: 5 out of 7 validators. Research Package §3.2.3.
pub const SUBEPOCH_QUORUM_THRESHOLD: usize = 5;

/// Total validators per sub-epoch. Research Package §3.2.3.
pub const SUBEPOCH_VALIDATOR_COUNT: usize = 7;

// ── SubEpochCommitment — Research Package §3.2.2 ─────────────────────────────

/// SubEpochCommitment — finality commitment for one sub-epoch.
/// Research Package §3.2.2.
///
/// Valid when at least SUBEPOCH_QUORUM_THRESHOLD (5) validator signatures present.
/// Safety: Two valid commitments impossible if honest validators ≥ 5 of 7.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubEpochCommitment {
    pub epoch_id: u64,
    pub subepoch_id: u32, // 0..719
    pub tx_set_root: [u8; 32],
    pub cumulative_utxo_root: [u8; 32],
    /// Explicit field — D-003: imt_frontier_root from this commitment.
    pub imt_frontier_root: [u8; 32],
    pub nullifier_batch_root: [u8; 32],
    pub prev_subepoch_hash: [u8; 32],
    /// Computed via compute_subepoch_hash(). Research Package §3.2.2.
    pub subepoch_hash: [u8; 32],
    pub imt_count: u64,
    pub tx_count: u32,
    pub timestamp: u64,
    /// Aggregator SLH-DSA signature. Research Package §3.2.3.
    pub aggregator_sig: Vec<u8>,
    /// Validator signatures: (node_id_full, slh_dsa_sig). Quorum 5/7.
    pub validator_sigs: Vec<([u8; 32], Vec<u8>)>,
}

impl SubEpochCommitment {
    /// Create a new SubEpochCommitment with computed hash.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch_id: u64,
        subepoch_id: u32,
        tx_set_root: [u8; 32],
        cumulative_utxo_root: [u8; 32],
        imt_frontier_root: [u8; 32],
        nullifier_batch_root: [u8; 32],
        prev_subepoch_hash: [u8; 32],
        imt_count: u64,
        tx_count: u32,
        timestamp: u64,
    ) -> Self {
        let mut c = Self {
            epoch_id,
            subepoch_id,
            tx_set_root,
            cumulative_utxo_root,
            imt_frontier_root,
            nullifier_batch_root,
            prev_subepoch_hash,
            subepoch_hash: [0u8; 32],
            imt_count,
            tx_count,
            timestamp,
            aggregator_sig: Vec::new(),
            validator_sigs: Vec::new(),
        };
        c.subepoch_hash = compute_subepoch_hash(&c);
        c
    }

    /// Check if this commitment has achieved quorum (5/7). Research Package §3.2.3.
    pub fn has_quorum(&self) -> bool {
        self.validator_sigs.len() >= SUBEPOCH_QUORUM_THRESHOLD
    }

    /// Add a validator signature. Returns true if quorum is now achieved.
    pub fn add_validator_sig(&mut self, node_id: [u8; 32], sig: Vec<u8>) -> bool {
        // Don't add duplicate signatures
        if !self.validator_sigs.iter().any(|(id, _)| id == &node_id) {
            self.validator_sigs.push((node_id, sig));
        }
        self.has_quorum()
    }

    /// Check if this is a DMM-lite commitment (no full quorum). Research Package §3.2.6.
    pub fn is_dmm_lite(&self) -> bool {
        !self.has_quorum()
    }
}

/// Compute subepoch_hash with domain separation. Research Package §3.2.2. OSSIFIED.
///
/// subepoch_hash = BLAKE3(
///     b"scalar_subepoch"                                   ||
///     epoch_id (LE)                                        ||
///     subepoch_id (LE)                                     ||
///     tx_set_root                                          ||
///     BLAKE3(b"scalar_smt_active"   || cumulative_utxo_root) ||
///     BLAKE3(b"scalar_imt_frontier" || imt_frontier_root)    ||
///     nullifier_batch_root                                 ||
///     prev_subepoch_hash                                   ||
///     imt_count (LE)                                       ||
///     tx_count (LE)                                        ||
///     timestamp (LE)
/// )
///
/// Domain separation between cumulative_utxo_root and imt_frontier_root is
/// mandatory — prevents value swap attack. Research Package §3.2.2.
pub fn compute_subepoch_hash(c: &SubEpochCommitment) -> [u8; 32] {
    // Inner hashes for domain separation
    let utxo_wrapped = {
        let mut h = Hasher::new();
        h.update(DOMAIN_SMT_ACTIVE);
        h.update(&c.cumulative_utxo_root);
        *h.finalize().as_bytes()
    };
    let imt_wrapped = {
        let mut h = Hasher::new();
        h.update(DOMAIN_IMT_FRONTIER);
        h.update(&c.imt_frontier_root);
        *h.finalize().as_bytes()
    };

    let mut h = Hasher::new();
    h.update(DOMAIN_SUBEPOCH);
    h.update(&c.epoch_id.to_le_bytes());
    h.update(&c.subepoch_id.to_le_bytes());
    h.update(&c.tx_set_root);
    h.update(&utxo_wrapped);
    h.update(&imt_wrapped);
    h.update(&c.nullifier_batch_root);
    h.update(&c.prev_subepoch_hash);
    h.update(&c.imt_count.to_le_bytes());
    h.update(&c.tx_count.to_le_bytes());
    h.update(&c.timestamp.to_le_bytes());
    *h.finalize().as_bytes()
}

// ── Aggregator selection — Research Package §3.2.3 ───────────────────────────

/// Deterministic aggregator selection for a sub-epoch. Research Package §3.2.3.
///
/// subepoch_seed = BLAKE3(DOMAIN_SUBEPOCH_SEED || committed_manifest_hash || subepoch_id)
/// score_i = BLAKE3(DOMAIN_SUBEPOCH_SCORE || node_id_full || subepoch_seed)
/// aggregator = argmin(score_i) from EligibleSet
pub fn compute_subepoch_seed(committed_manifest_hash: &[u8; 32], subepoch_id: u32) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_SUBEPOCH_SEED);
    h.update(committed_manifest_hash);
    h.update(&subepoch_id.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Compute score for a node in sub-epoch aggregator selection. Research Package §3.2.3.
pub fn compute_subepoch_score(node_id_full: &[u8; 32], subepoch_seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_SUBEPOCH_SCORE);
    h.update(node_id_full);
    h.update(subepoch_seed);
    *h.finalize().as_bytes()
}

/// Select aggregator: node with minimum score from eligible set.
/// Research Package §3.2.3.
pub fn select_subepoch_aggregator(
    eligible_nodes: &[[u8; 32]],
    subepoch_seed: &[u8; 32],
) -> Option<[u8; 32]> {
    eligible_nodes
        .iter()
        .min_by_key(|id| compute_subepoch_score(id, subepoch_seed))
        .copied()
}

// ── SubEpochChain — chain of commitments ─────────────────────────────────────

/// Chain of SubEpochCommitments for one epoch. Research Package §3.2.
///
/// Maintains prev_subepoch_hash chain for integrity.
/// Only commitments with quorum (or DMM-lite fallback) are stored.
#[derive(Default)]
pub struct SubEpochChain {
    /// Commitments indexed by subepoch_id.
    commitments: HashMap<u32, SubEpochCommitment>,
    /// Latest committed subepoch_id.
    pub latest_subepoch_id: Option<u32>,
    pub epoch_id: u64,
}

impl SubEpochChain {
    pub fn new(epoch_id: u64) -> Self {
        Self {
            commitments: HashMap::new(),
            latest_subepoch_id: None,
            epoch_id,
        }
    }

    /// Add a commitment to the chain. Research Package §3.2.
    ///
    /// Validates:
    /// 1. epoch_id matches
    /// 2. prev_subepoch_hash is correct
    /// 3. subepoch_hash is correct
    pub fn add_commitment(&mut self, c: SubEpochCommitment) -> Result<(), SubEpochError> {
        if c.epoch_id != self.epoch_id {
            return Err(SubEpochError::EpochMismatch {
                expected: self.epoch_id,
                got: c.epoch_id,
            });
        }

        // Verify subepoch_hash
        let expected_hash = compute_subepoch_hash(&c);
        if c.subepoch_hash != expected_hash {
            return Err(SubEpochError::InvalidHash);
        }

        // Verify prev_subepoch_hash chain — F-002, F-005 fixes.
        // F-005: subepoch_id=0 must have prev_subepoch_hash = [0u8;32]. Research Package §3.2.2.
        // F-002: missing predecessor is a hard rejection, not a default to zero.
        if c.subepoch_id == 0 {
            if c.prev_subepoch_hash != [0u8; 32] {
                return Err(SubEpochError::ChainBroken { subepoch_id: 0 });
            }
        } else {
            let expected_prev = match self.commitments.get(&(c.subepoch_id - 1)) {
                Some(prev) => prev.subepoch_hash,
                None => {
                    // F-002: predecessor missing — reject, do not default to zero.
                    // Prevents out-of-order insertion with arbitrary prev_hash.
                    return Err(SubEpochError::ChainBroken {
                        subepoch_id: c.subepoch_id,
                    });
                }
            };
            if c.prev_subepoch_hash != expected_prev {
                return Err(SubEpochError::ChainBroken {
                    subepoch_id: c.subepoch_id,
                });
            }
        }

        let id = c.subepoch_id;
        self.commitments.insert(id, c);
        self.latest_subepoch_id = Some(self.latest_subepoch_id.map_or(id, |latest| latest.max(id)));
        Ok(())
    }

    /// Get a commitment by subepoch_id.
    pub fn get(&self, subepoch_id: u32) -> Option<&SubEpochCommitment> {
        self.commitments.get(&subepoch_id)
    }

    /// Check if a sub-epoch has quorum. Decision D-003.
    pub fn has_quorum(&self, subepoch_id: u32) -> bool {
        self.commitments
            .get(&subepoch_id)
            .map(|c| c.has_quorum())
            .unwrap_or(false)
    }

    /// Get imt_frontier_root for a sub-epoch with quorum. Decision D-003.
    ///
    /// Returns None if sub-epoch not found or no quorum.
    /// imt_frontier_root MUST come from a commitment with quorum 5/7.
    pub fn get_imt_frontier_root(&self, subepoch_id: u32) -> Option<[u8; 32]> {
        self.commitments
            .get(&subepoch_id)
            .filter(|c| c.has_quorum())
            .map(|c| c.imt_frontier_root)
    }

    /// Verify imt_frontier_root source per Decision D-003.
    ///
    /// Used by verify_imt_source() in network layer.
    /// Verify imt_frontier_root source per Decision D-003. 5-step (§3.1.5).
    ///
    /// Steps: 1 NotFound → 2 QuorumFailed → 3 Hash/FrontierMismatch
    ///        → 4 IMTCountMismatch → 5 EpochMismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_imt_source(
        &self,
        subepoch_id: u32,
        claimed_imt_frontier_root: &[u8; 32],
        claimed_subepoch_hash: &[u8; 32],
        claimed_imt_commitment_count: u64,
        ref_epoch_id: u64,
        current_epoch_id: u64,
    ) -> scalar_crypto::imt::VerificationResult {
        use scalar_crypto::imt::VerificationResult;

        // Step 1.
        let Some(commitment) = self.commitments.get(&subepoch_id) else {
            return VerificationResult::SubEpochNotFound;
        };

        // Step 2.
        if !commitment.has_quorum() {
            return VerificationResult::SubEpochQuorumFailed { subepoch_id };
        }

        // Step 3 (hash then frontier).
        if &commitment.subepoch_hash != claimed_subepoch_hash {
            return VerificationResult::SubEpochHashMismatch;
        }
        if &commitment.imt_frontier_root != claimed_imt_frontier_root {
            return VerificationResult::IMTFrontierMismatch;
        }

        // Step 4 (§3.1.5): imt_count pairing with imt_frontier_root (INV-4.2).
        if commitment.imt_count != claimed_imt_commitment_count {
            return VerificationResult::IMTCountMismatch;
        }

        // Step 5 (§3.1.5): SubEpochIMT valid only for the current epoch (INV-4.9, Rule A/C).
        if ref_epoch_id != current_epoch_id {
            return VerificationResult::EpochMismatch {
                tx_epoch_id: ref_epoch_id,
                current_epoch_id,
            };
        }

        VerificationResult::Valid
    }

    pub fn commitment_count(&self) -> usize {
        self.commitments.len()
    }
}

// ── DMM-lite — fallback protocol ─────────────────────────────────────────────

/// DMM-lite fallback when quorum 5/7 not achieved. Research Package §3.2.6.
///
/// Safety weaker than full quorum — aggregator could propose incorrect commitment.
/// Temporary fallback only; system prioritizes returning to full quorum.
///
/// Double-spend prevention still guaranteed by NullifierSet (independent of sub-epoch).
pub struct DmmLite {
    pub epoch_id: u64,
}

impl DmmLite {
    pub fn new(epoch_id: u64) -> Self {
        Self { epoch_id }
    }

    /// Build a DMM-lite commitment from aggregator's local state.
    /// Research Package §3.2.6.
    #[allow(clippy::too_many_arguments)]
    pub fn build_commitment(
        &self,
        subepoch_id: u32,
        tx_set_root: [u8; 32],
        cumulative_utxo_root: [u8; 32],
        imt_frontier_root: [u8; 32],
        nullifier_batch_root: [u8; 32],
        prev_subepoch_hash: [u8; 32],
        imt_count: u64,
        tx_count: u32,
        timestamp: u64,
    ) -> SubEpochCommitment {
        // DMM-lite: no validator signatures, only aggregator
        SubEpochCommitment::new(
            self.epoch_id,
            subepoch_id,
            tx_set_root,
            cumulative_utxo_root,
            imt_frontier_root,
            nullifier_batch_root,
            prev_subepoch_hash,
            imt_count,
            tx_count,
            timestamp,
        )
        // aggregator_sig and validator_sigs remain empty — DMM-lite marker
    }
}

// ── SubEpochError ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubEpochError {
    EpochMismatch { expected: u64, got: u64 },
    InvalidHash,
    ChainBroken { subepoch_id: u32 },
    QuorumNotAchieved { subepoch_id: u32 },
}

impl core::fmt::Display for SubEpochError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EpochMismatch { expected, got } => {
                write!(f, "epoch mismatch: expected {expected}, got {got}")
            }
            Self::InvalidHash => write!(f, "subepoch_hash invalid"),
            Self::ChainBroken { subepoch_id } => {
                write!(f, "chain broken at subepoch {subepoch_id}")
            }
            Self::QuorumNotAchieved { subepoch_id } => {
                write!(f, "quorum not achieved for subepoch {subepoch_id}")
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_commitment(epoch_id: u64, subepoch_id: u32, prev: [u8; 32]) -> SubEpochCommitment {
        SubEpochCommitment::new(
            epoch_id,
            subepoch_id,
            [0x01u8; 32],
            [0x02u8; 32],
            [0x03u8; 32],
            [0x04u8; 32],
            prev,
            100,
            10,
            1_700_000_000,
        )
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn test_subepochs_per_epoch() {
        // 720 sub-epochs per 30-day epoch. Research Package §3.2.1.
        assert_eq!(SUBEPOCHS_PER_EPOCH, 720);
    }

    #[test]
    fn test_subepoch_duration_1_hour() {
        // 1 sub-epoch = 3600 seconds = 1 hour. Research Package §3.2.1.
        assert_eq!(SUBEPOCH_DURATION_S, 3600);
    }

    #[test]
    fn test_quorum_threshold_5_of_7() {
        // Quorum = 5/7. Research Package §3.2.3.
        assert_eq!(SUBEPOCH_QUORUM_THRESHOLD, 5);
        assert_eq!(SUBEPOCH_VALIDATOR_COUNT, 7);
    }

    // ── SubEpochCommitment ────────────────────────────────────────────────────

    #[test]
    fn test_commitment_hash_computed_on_new() {
        let c = make_commitment(1, 0, [0u8; 32]);
        assert_ne!(c.subepoch_hash, [0u8; 32]);
    }

    #[test]
    fn test_commitment_hash_deterministic() {
        let c1 = make_commitment(1, 0, [0u8; 32]);
        let c2 = make_commitment(1, 0, [0u8; 32]);
        assert_eq!(c1.subepoch_hash, c2.subepoch_hash);
    }

    #[test]
    fn test_commitment_hash_differs_per_subepoch() {
        let c0 = make_commitment(1, 0, [0u8; 32]);
        let c1 = make_commitment(1, 1, c0.subepoch_hash);
        assert_ne!(c0.subepoch_hash, c1.subepoch_hash);
    }

    #[test]
    fn test_commitment_no_quorum_initially() {
        let c = make_commitment(1, 0, [0u8; 32]);
        assert!(!c.has_quorum());
        assert!(c.is_dmm_lite());
    }

    #[test]
    fn test_commitment_quorum_after_5_sigs() {
        let mut c = make_commitment(1, 0, [0u8; 32]);
        for i in 0..5u8 {
            let node_id = [i; 32];
            let achieved = c.add_validator_sig(node_id, vec![i; 10]);
            if i < 4 {
                assert!(!achieved);
            } else {
                assert!(achieved); // 5th sig achieves quorum
            }
        }
        assert!(c.has_quorum());
        assert!(!c.is_dmm_lite());
    }

    #[test]
    fn test_commitment_no_duplicate_sigs() {
        let mut c = make_commitment(1, 0, [0u8; 32]);
        let node_id = [0x01u8; 32];
        c.add_validator_sig(node_id, vec![1u8; 10]);
        c.add_validator_sig(node_id, vec![2u8; 10]); // duplicate
        assert_eq!(c.validator_sigs.len(), 1);
    }

    // ── Domain separation in hash ─────────────────────────────────────────────

    #[test]
    fn test_subepoch_hash_domain_separation() {
        // Swapping cumulative_utxo_root and imt_frontier_root must change hash.
        // Research Package §3.2.2: domain separation prevents swap attack.
        let mut c1 = make_commitment(1, 0, [0u8; 32]);
        let mut c2 = make_commitment(1, 0, [0u8; 32]);

        c1.cumulative_utxo_root = [0xAAu8; 32];
        c1.imt_frontier_root = [0xBBu8; 32];
        c1.subepoch_hash = compute_subepoch_hash(&c1);

        // Swap the two values
        c2.cumulative_utxo_root = [0xBBu8; 32];
        c2.imt_frontier_root = [0xAAu8; 32];
        c2.subepoch_hash = compute_subepoch_hash(&c2);

        assert_ne!(
            c1.subepoch_hash, c2.subepoch_hash,
            "Domain separation must prevent hash collision on value swap"
        );
    }

    // ── Aggregator selection ──────────────────────────────────────────────────

    #[test]
    fn test_subepoch_seed_deterministic() {
        let manifest_hash = [0x42u8; 32];
        let s1 = compute_subepoch_seed(&manifest_hash, 0);
        let s2 = compute_subepoch_seed(&manifest_hash, 0);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_subepoch_seed_differs_per_subepoch() {
        let manifest_hash = [0x42u8; 32];
        let s0 = compute_subepoch_seed(&manifest_hash, 0);
        let s1 = compute_subepoch_seed(&manifest_hash, 1);
        assert_ne!(s0, s1);
    }

    #[test]
    fn test_aggregator_selection_deterministic() {
        let seed = [0x42u8; 32];
        let nodes: Vec<[u8; 32]> = (0..5u8).map(|i| [i; 32]).collect();
        let a1 = select_subepoch_aggregator(&nodes, &seed);
        let a2 = select_subepoch_aggregator(&nodes, &seed);
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_aggregator_selection_empty_returns_none() {
        let seed = [0x42u8; 32];
        assert!(select_subepoch_aggregator(&[], &seed).is_none());
    }

    #[test]
    fn test_aggregator_selection_different_seed_may_differ() {
        let nodes: Vec<[u8; 32]> = (0..10u8).map(|i| [i; 32]).collect();
        let a1 = select_subepoch_aggregator(&nodes, &[0x01u8; 32]);
        let a2 = select_subepoch_aggregator(&nodes, &[0x02u8; 32]);
        // Different seeds likely select different aggregators
        // (not guaranteed but extremely likely with 10 nodes)
        // We just verify both return Some
        assert!(a1.is_some());
        assert!(a2.is_some());
    }

    // ── SubEpochChain ─────────────────────────────────────────────────────────

    #[test]
    fn test_chain_add_genesis_commitment() {
        let mut chain = SubEpochChain::new(1);
        let c = make_commitment(1, 0, [0u8; 32]);
        assert!(chain.add_commitment(c).is_ok());
        assert_eq!(chain.commitment_count(), 1);
    }

    #[test]
    fn test_chain_epoch_mismatch_rejected() {
        let mut chain = SubEpochChain::new(1);
        let c = make_commitment(2, 0, [0u8; 32]); // wrong epoch
        assert_eq!(
            chain.add_commitment(c),
            Err(SubEpochError::EpochMismatch {
                expected: 1,
                got: 2
            })
        );
    }

    #[test]
    fn test_chain_invalid_hash_rejected() {
        let mut chain = SubEpochChain::new(1);
        let mut c = make_commitment(1, 0, [0u8; 32]);
        c.subepoch_hash = [0xFFu8; 32]; // tamper hash
        assert_eq!(chain.add_commitment(c), Err(SubEpochError::InvalidHash));
    }

    #[test]
    fn test_chain_sequential_commitments() {
        let mut chain = SubEpochChain::new(1);
        let c0 = make_commitment(1, 0, [0u8; 32]);
        let prev = c0.subepoch_hash;
        chain.add_commitment(c0).unwrap();

        let c1 = make_commitment(1, 1, prev);
        chain.add_commitment(c1).unwrap();

        assert_eq!(chain.commitment_count(), 2);
        assert_eq!(chain.latest_subepoch_id, Some(1));
    }

    #[test]
    fn test_chain_has_quorum_requires_5_sigs() {
        let mut chain = SubEpochChain::new(1);
        let mut c = make_commitment(1, 0, [0u8; 32]);

        // Add only 4 sigs — no quorum
        for i in 0..4u8 {
            c.add_validator_sig([i; 32], vec![i]);
        }
        chain.add_commitment(c).unwrap();
        assert!(!chain.has_quorum(0));

        // Add 5th sig — quorum achieved
        let c2 = chain.commitments.get_mut(&0).unwrap();
        c2.add_validator_sig([4u8; 32], vec![4]);
        assert!(chain.has_quorum(0));
    }

    // ── Decision D-003: imt_frontier_root from quorum ────────────────────────

    #[test]
    fn test_get_imt_frontier_root_requires_quorum() {
        // D-003: imt_frontier_root only available with quorum.
        let mut chain = SubEpochChain::new(1);
        let c = make_commitment(1, 0, [0u8; 32]);
        chain.add_commitment(c).unwrap();

        // No quorum → None
        assert!(chain.get_imt_frontier_root(0).is_none());
    }

    #[test]
    fn test_get_imt_frontier_root_with_quorum() {
        let mut chain = SubEpochChain::new(1);
        let mut c = make_commitment(1, 0, [0u8; 32]);
        let expected_frontier = c.imt_frontier_root;

        for i in 0..5u8 {
            c.add_validator_sig([i; 32], vec![i]);
        }
        chain.add_commitment(c).unwrap();

        assert_eq!(chain.get_imt_frontier_root(0), Some(expected_frontier));
    }

    // ── verify_imt_source ─────────────────────────────────────────────────────

    #[test]
    fn test_verify_imt_source_valid() {
        use scalar_crypto::imt::VerificationResult;
        let mut chain = SubEpochChain::new(1);
        let mut c = make_commitment(1, 0, [0u8; 32]);
        let frontier = c.imt_frontier_root;
        let hash = c.subepoch_hash;
        for i in 0..5u8 {
            c.add_validator_sig([i; 32], vec![i]);
        }
        chain.add_commitment(c).unwrap();

        // count=100 (make_commitment), epoch ref=current=1.
        let result = chain.verify_imt_source(0, &frontier, &hash, 100, 1, 1);
        assert_eq!(result, VerificationResult::Valid);
    }

    #[test]
    fn test_verify_imt_source_not_found() {
        use scalar_crypto::imt::VerificationResult;
        let chain = SubEpochChain::new(1);
        let result = chain.verify_imt_source(99, &[0u8; 32], &[0u8; 32], 0, 0, 0);
        assert_eq!(result, VerificationResult::SubEpochNotFound);
    }

    #[test]
    fn test_verify_imt_source_quorum_failed() {
        use scalar_crypto::imt::VerificationResult;
        let mut chain = SubEpochChain::new(1);
        let c = make_commitment(1, 0, [0u8; 32]);
        let hash = c.subepoch_hash;
        let frontier = c.imt_frontier_root;
        chain.add_commitment(c).unwrap();

        let result = chain.verify_imt_source(0, &frontier, &hash, 0, 0, 0);
        assert_eq!(
            result,
            VerificationResult::SubEpochQuorumFailed { subepoch_id: 0 }
        );
    }

    #[test]
    fn test_verify_imt_source_frontier_mismatch() {
        use scalar_crypto::imt::VerificationResult;
        let mut chain = SubEpochChain::new(1);
        let mut c = make_commitment(1, 0, [0u8; 32]);
        let hash = c.subepoch_hash;
        for i in 0..5u8 {
            c.add_validator_sig([i; 32], vec![i]);
        }
        chain.add_commitment(c).unwrap();

        let wrong_frontier = [0xFFu8; 32];
        let result = chain.verify_imt_source(0, &wrong_frontier, &hash, 100, 1, 1);
        assert_eq!(result, VerificationResult::IMTFrontierMismatch);
    }

    #[test]
    fn test_verify_imt_source_hash_mismatch() {
        // Step 3 (hash branch, §3.1.5): correct frontier but wrong subepoch_hash.
        use scalar_crypto::imt::VerificationResult;
        let mut chain = SubEpochChain::new(1);
        let mut c = make_commitment(1, 0, [0u8; 32]);
        let frontier = c.imt_frontier_root;
        for i in 0..5u8 {
            c.add_validator_sig([i; 32], vec![i]);
        }
        chain.add_commitment(c).unwrap();

        // Quorum OK, but claimed hash is wrong → SubEpochHashMismatch (before frontier check).
        let wrong_hash = [0xFFu8; 32];
        let result = chain.verify_imt_source(0, &frontier, &wrong_hash, 100, 1, 1);
        assert_eq!(result, VerificationResult::SubEpochHashMismatch);
    }

    // ── DMM-lite ──────────────────────────────────────────────────────────────

    #[test]
    fn test_dmm_lite_commitment_no_quorum() {
        let dmm = DmmLite::new(1);
        let c = dmm.build_commitment(
            0,
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            0,
            0,
            1_700_000_000,
        );
        assert!(c.is_dmm_lite());
        assert!(!c.has_quorum());
    }

    #[test]
    fn test_dmm_lite_has_valid_hash() {
        let dmm = DmmLite::new(1);
        let c = dmm.build_commitment(
            5,
            [0x01u8; 32],
            [0x02u8; 32],
            [0x03u8; 32],
            [0x04u8; 32],
            [0u8; 32],
            100,
            10,
            1_700_000_000,
        );
        let expected = compute_subepoch_hash(&c);
        assert_eq!(c.subepoch_hash, expected);
    }

    // ── Safety proof (Pigeonhole) ─────────────────────────────────────────────

    #[test]
    fn test_safety_pigeonhole_two_commitments_impossible() {
        // Research Package §3.2.4: Safety proof via Pigeonhole Principle.
        // If 7 validators exist and quorum=5, then 5+5-7=3 must sign both.
        // Honest validators sign only ONE commitment → contradiction.
        // This test verifies the mathematical invariant:
        // Two commitments C1 and C2 both with 5 sigs from {V1..V7}
        // must share at least 3 validators.
        let all_validators: Vec<[u8; 32]> = (0..7u8).map(|i| [i; 32]).collect();

        let sigs_c1: std::collections::HashSet<u8> = [0, 1, 2, 3, 4].iter().copied().collect();
        let sigs_c2: std::collections::HashSet<u8> = [2, 3, 4, 5, 6].iter().copied().collect();

        let intersection: std::collections::HashSet<u8> =
            sigs_c1.intersection(&sigs_c2).copied().collect();

        // Must have at least SUBEPOCH_QUORUM_THRESHOLD*2 - SUBEPOCH_VALIDATOR_COUNT = 3
        let min_overlap = SUBEPOCH_QUORUM_THRESHOLD * 2 - SUBEPOCH_VALIDATOR_COUNT;
        assert!(
            intersection.len() >= min_overlap,
            "Pigeonhole: at least {min_overlap} validators must overlap"
        );
        assert_eq!(min_overlap, 3);
        // Honest validators can't sign two conflicting commitments → safety guaranteed
        let _ = all_validators;
    }
    // ── F-002: Out-of-order insertion rejected ────────────────────────────────

    #[test]
    fn f002_out_of_order_insertion_rejected() {
        // F-002 fix: missing predecessor must be rejected, not defaulted to zero.
        // Research Package §3.2.2, INV-4.3.
        let mut chain = SubEpochChain::new(1);
        // Insert subepoch 2 without subepoch 1 — must be rejected
        let c2 = make_commitment(1, 2, [0u8; 32]); // wrong prev (should be subepoch1.hash)
        let err = chain.add_commitment(c2);
        assert_eq!(
            err,
            Err(SubEpochError::ChainBroken { subepoch_id: 2 }),
            "F-002: out-of-order insertion must be rejected"
        );
    }

    #[test]
    fn f002_zero_prev_hash_rejected_for_non_genesis() {
        // F-002: subepoch N with prev_hash=[0;32] rejected when predecessor exists.
        let mut chain = SubEpochChain::new(1);
        let c0 = make_commitment(1, 0, [0u8; 32]);
        chain.add_commitment(c0).unwrap();

        // subepoch 1 with wrong prev_hash (zero instead of c0.subepoch_hash)
        let c1_wrong = make_commitment(1, 1, [0u8; 32]); // wrong prev
        let err = chain.add_commitment(c1_wrong);
        assert_eq!(
            err,
            Err(SubEpochError::ChainBroken { subepoch_id: 1 }),
            "F-002: wrong prev_hash must be rejected"
        );
    }

    // ── F-005: subepoch_id=0 must have prev_subepoch_hash=[0;32] ─────────────

    #[test]
    fn f005_genesis_subepoch_wrong_prev_rejected() {
        // F-005 fix: subepoch_id=0 with non-zero prev_subepoch_hash must be rejected.
        // Research Package §3.2.2.
        let mut chain = SubEpochChain::new(1);
        let mut c = make_commitment(1, 0, [0xFFu8; 32]); // wrong prev for genesis
                                                         // Recompute hash with the wrong prev to make subepoch_hash valid
        c.subepoch_hash = compute_subepoch_hash(&c);
        let err = chain.add_commitment(c);
        assert_eq!(
            err,
            Err(SubEpochError::ChainBroken { subepoch_id: 0 }),
            "F-005: genesis subepoch with non-zero prev must be rejected"
        );
    }

    #[test]
    fn f005_genesis_subepoch_zero_prev_accepted() {
        // F-005: subepoch_id=0 with prev=[0;32] must be accepted (genesis).
        let mut chain = SubEpochChain::new(1);
        let c = make_commitment(1, 0, [0u8; 32]); // correct genesis prev
        assert!(
            chain.add_commitment(c).is_ok(),
            "F-005: genesis subepoch must be accepted"
        );
    }

    // ── TV 5.6 — IMTCountMismatch (step 4, §3.1.5) ────────────────────────────
    #[test]
    fn tv_5_6_imt_count_mismatch() {
        use scalar_crypto::imt::VerificationResult;
        let mut chain = SubEpochChain::new(1);
        let mut c = make_commitment(1, 0, [0u8; 32]); // imt_count = 100
        let frontier = c.imt_frontier_root;
        let hash = c.subepoch_hash;
        for i in 0..5u8 {
            c.add_validator_sig([i; 32], vec![i]);
        }
        chain.add_commitment(c).unwrap();

        // Claim wrong count (50 != 100) — frontier/hash/epoch all correct.
        let result = chain.verify_imt_source(0, &frontier, &hash, 50, 1, 1);
        assert_eq!(result, VerificationResult::IMTCountMismatch);
    }

    // ── TV 5.12 — EpochMismatch (step 5, §3.1.5 / INV-4.9) ────────────────────
    #[test]
    fn tv_5_12_epoch_mismatch() {
        use scalar_crypto::imt::VerificationResult;
        let mut chain = SubEpochChain::new(1);
        let mut c = make_commitment(1, 0, [0u8; 32]); // imt_count = 100, epoch_id=1
        let frontier = c.imt_frontier_root;
        let hash = c.subepoch_hash;
        for i in 0..5u8 {
            c.add_validator_sig([i; 32], vec![i]);
        }
        chain.add_commitment(c).unwrap();

        // All correct through step 4, but ref_epoch (0) != current_epoch (1).
        let result = chain.verify_imt_source(0, &frontier, &hash, 100, 0, 1);
        assert_eq!(
            result,
            VerificationResult::EpochMismatch {
                tx_epoch_id: 0,
                current_epoch_id: 1,
            }
        );
    }
}
