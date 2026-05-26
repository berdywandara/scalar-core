//! UTXO Set EpochSMT — IMT-based Snapshot & Node Sync Protocol
//!
//! D3 decision (FASE D3): Replaced sequential-hash UtxoSetAccumulator with
//! IncrementalMerkleTree (IMT) from scalar_crypto::imt.
//!
//! The root is now a true Poseidon2 IMT root (depth-32), enabling:
//!   - O(log n) membership proof per UTXO (CB constraint in Transfer Circuit)
//!   - Deterministic root identical across all honest nodes
//!   - imt_membership_verify() can verify UTXO inclusion in-circuit
//!
//! Root value change: IMT empty root != [0u8;32]. Genesis UtxoSetState
//! uses imt_empty_root() as the canonical empty root.
//!
//! Hash discipline: Poseidon2 in-circuit (IMT nodes/leaves), BLAKE3 out-circuit.
//! Spec §8.5, §16.1, §3.1 Scalar_Optimalisasi_PraGenesis, INV-4.1, INV-4.2.

use crate::ordering::{sort_transactions_canonical, TxEntry};
use scalar_crypto::imt::{imt_empty_root, IMTPath, IncrementalMerkleTree};

// Re-export DOMAIN_UTXO_SMT for backward compatibility (D.1 OSSIFIED).
pub use scalar_crypto::domain::DOMAIN_UTXO_SMT;

/// Genesis epoch ID. Spec §8.5.
pub const GENESIS_EPOCH_ID: u64 = 0;

// ── UtxoSetState — committed state per epoch ──────────────────────────────────

/// UTXO set state committed at end of each epoch. Spec §16.1.
///
/// utxo_set_root is now a true IMT root (Poseidon2 depth-32).
/// Used as public input utxo_set_root for Transfer Circuit in epoch k+1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoSetState {
    /// IMT root of all UTXOs created up to end of this epoch.
    /// Empty tree root = imt_empty_root() (NOT [0u8;32]).
    pub utxo_set_root: [u8; 32],
    /// Epoch ID when snapshot was taken. Spec §8.5.
    pub snapshot_epoch: u64,
    /// Total UTXO count in set. Spec §16.1.
    pub utxo_count: u64,
}

impl UtxoSetState {
    /// Genesis state — empty IMT root, epoch 0. Spec §8.5.
    ///
    /// NOTE: utxo_set_root = imt_empty_root() (Poseidon2 hash of empty depth-32 tree),
    /// NOT [0u8;32]. This is the correct canonical empty root per INV-4.1.
    pub fn genesis() -> Self {
        Self {
            utxo_set_root: imt_empty_root(),
            snapshot_epoch: GENESIS_EPOCH_ID,
            utxo_count: 0,
        }
    }

    /// Verify this root is from the correct epoch for use in epoch k.
    pub fn is_valid_for_epoch(&self, epoch_k: u64) -> bool {
        self.snapshot_epoch == epoch_k.saturating_sub(1)
            || (epoch_k == 0 && self.snapshot_epoch == 0)
    }
}

// ── UtxoSetEpochSMT — IMT-based EpochSMT ─────────────────────────────────────

/// UTXO Set EpochSMT — true IMT-based implementation. Spec §16.1, §8.5.
///
/// D3: Replaces UtxoSetAccumulator (sequential BLAKE3 hash) with
/// IncrementalMerkleTree (Poseidon2 depth-32). Root is now provable
/// via imt_membership_verify() for CB constraint in Transfer Circuit.
///
/// Backward-compat alias: UtxoSetAccumulator = UtxoSetEpochSMT (in lib.rs).
pub struct UtxoSetEpochSMT {
    /// IMT holding all UTXO commitments in canonical insertion order.
    imt: IncrementalMerkleTree,
    /// Current epoch.
    current_epoch: u64,
}

impl UtxoSetEpochSMT {
    /// Create new EpochSMT from genesis. Spec §8.5.
    pub fn new() -> Self {
        Self {
            imt: IncrementalMerkleTree::new(),
            current_epoch: GENESIS_EPOCH_ID,
        }
    }

    /// Insert a UTXO commitment. Spec §8.5.
    ///
    /// Commitments must be inserted in canonical ordering to guarantee
    /// root determinism across all honest nodes (INV-4.2).
    pub fn insert_utxo(&mut self, commitment: [u8; 32], epoch: u64) {
        self.imt
            .append(&commitment)
            .expect("IMT full — depth-32 supports 2^32 UTXOs");
        self.current_epoch = epoch;
    }

    /// Process a batch of transactions with canonical ordering. Spec §8.5.
    pub fn process_epoch_transactions(&mut self, txs: &[TxEntry], epoch_id: u64) {
        let ordered_txs = sort_transactions_canonical(txs, epoch_id);
        for tx in &ordered_txs {
            self.insert_utxo(tx.tx_hash, epoch_id);
        }
        self.current_epoch = epoch_id;
    }

    /// Take snapshot at end of epoch. Returns UtxoSetState for epoch k.
    /// Root used as utxo_set_root public input for epoch k+1. Spec §8.5.
    pub fn take_snapshot(&self, epoch_id: u64) -> UtxoSetState {
        UtxoSetState {
            utxo_set_root: self.imt.root(),
            snapshot_epoch: epoch_id,
            utxo_count: self.imt.count,
        }
    }

    /// Current IMT root. Spec §8.5.
    pub fn root(&self) -> [u8; 32] {
        self.imt.root()
    }

    /// UTXO count in IMT.
    pub fn utxo_count(&self) -> usize {
        self.imt.count as usize
    }

    /// Generate membership proof for UTXO at leaf_index. Spec §3.1.3, CB constraint.
    ///
    /// Proof can be verified with imt_membership_verify() in Transfer Circuit.
    pub fn prove_membership(
        &self,
        leaf_index: u64,
    ) -> Result<IMTPath, scalar_crypto::imt::IMTError> {
        self.imt.prove_membership(leaf_index)
    }

    /// Reset IMT to genesis state. Called by EpochTransitionOrchestrator. INV-4.10.
    pub fn reset(&mut self) {
        self.imt.reset();
        // Post-reset: root must equal imt_empty_root()
        debug_assert_eq!(
            self.imt.root(),
            imt_empty_root(),
            "INV-4.10: root must equal imt_empty_root() after reset"
        );
    }
}

impl Default for UtxoSetEpochSMT {
    fn default() -> Self {
        Self::new()
    }
}

// Backward-compat alias — callers using UtxoSetAccumulator still compile.
pub type UtxoSetAccumulator = UtxoSetEpochSMT;

// ── SyncVerificationResult ────────────────────────────────────────────────────

/// Result of verifying utxo_set_root against manifest. Spec §8.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncVerificationResult {
    Valid,
    RootMismatch {
        local_root: [u8; 32],
        expected_root: [u8; 32],
    },
    NoManifestAvailable,
}

/// Verify peer utxo_set_root against network_health_digest. Spec §8.5.
pub fn verify_utxo_root_against_manifest(
    peer_root: &[u8; 32],
    expected_root: &[u8; 32],
) -> SyncVerificationResult {
    if peer_root == expected_root {
        SyncVerificationResult::Valid
    } else {
        SyncVerificationResult::RootMismatch {
            local_root: *peer_root,
            expected_root: *expected_root,
        }
    }
}

/// Extract expected utxo_set_root from network_health_digest. Spec §8.5.
pub fn extract_expected_root_from_manifest(
    network_health_digest: &[u8; 32],
    epoch_id: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(network_health_digest);
    hasher.update(&epoch_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ordering::TxEntry;
    use scalar_crypto::imt::{imt_empty_root, imt_membership_verify};

    fn make_commitment(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn make_tx(seed: u8) -> TxEntry {
        TxEntry {
            tx_hash: [seed; 32],
            tx_data: vec![seed],
        }
    }

    // ── D3: Genesis root is imt_empty_root(), NOT [0u8;32] ───────────────────

    #[test]
    fn test_d3_genesis_root_is_imt_empty_root() {
        // D3: empty IMT root = Poseidon2 hash of empty depth-32 tree, NOT zero.
        let smt = UtxoSetEpochSMT::new();
        assert_eq!(smt.root(), imt_empty_root());
        assert_ne!(smt.root(), [0u8; 32], "D3: empty root must not be zero");
    }

    #[test]
    fn test_d3_genesis_state_uses_imt_empty_root() {
        let state = UtxoSetState::genesis();
        assert_eq!(state.utxo_set_root, imt_empty_root());
        assert_ne!(state.utxo_set_root, [0u8; 32]);
        assert_eq!(state.snapshot_epoch, 0);
        assert_eq!(state.utxo_count, 0);
    }

    // ── D3: Membership proof roundtrip ────────────────────────────────────────

    #[test]
    fn test_d3_membership_proof_roundtrip() {
        // D3: prove_membership + imt_membership_verify must work. CB constraint.
        let mut smt = UtxoSetEpochSMT::new();
        let c0 = make_commitment(0xAA);
        let c1 = make_commitment(0xBB);
        let c2 = make_commitment(0xCC);

        smt.insert_utxo(c0, 1);
        smt.insert_utxo(c1, 1);
        smt.insert_utxo(c2, 1);

        let root = smt.root();
        let count = smt.utxo_count() as u64;

        // Prove and verify each leaf
        for (i, commitment) in [c0, c1, c2].iter().enumerate() {
            let path = smt.prove_membership(i as u64).unwrap();
            assert!(
                imt_membership_verify(commitment, &path, &root, count),
                "D3: membership verify must pass for leaf {i}"
            );
        }

        // Wrong commitment must fail
        let path0 = smt.prove_membership(0).unwrap();
        assert!(
            !imt_membership_verify(&make_commitment(0xFF), &path0, &root, count),
            "D3: wrong commitment must fail"
        );
    }

    // ── D3: Determinism — same insertions same root ───────────────────────────

    #[test]
    fn test_d3_root_determinism() {
        // INV-4.2: same commitments in same order -> identical root.
        let mut smt1 = UtxoSetEpochSMT::new();
        let mut smt2 = UtxoSetEpochSMT::new();

        for seed in [0x01u8, 0x02, 0x03] {
            smt1.insert_utxo(make_commitment(seed), 1);
            smt2.insert_utxo(make_commitment(seed), 1);
        }

        assert_eq!(smt1.root(), smt2.root(), "INV-4.2: roots must be identical");
    }

    // ── D3: Canonical ordering ensures deterministic root across nodes ─────────

    #[test]
    fn test_d3_canonical_ordering_determinism() {
        let txs = vec![make_tx(0xAA), make_tx(0xBB), make_tx(0xCC)];
        let txs_reordered = vec![make_tx(0xCC), make_tx(0xAA), make_tx(0xBB)];

        let mut smt1 = UtxoSetEpochSMT::new();
        smt1.process_epoch_transactions(&txs, 5);

        let mut smt2 = UtxoSetEpochSMT::new();
        smt2.process_epoch_transactions(&txs_reordered, 5);

        assert_eq!(
            smt1.root(),
            smt2.root(),
            "D3: canonical ordering must produce identical root regardless of receive order"
        );
    }

    // ── D3: Snapshot timing ───────────────────────────────────────────────────

    #[test]
    fn test_d3_snapshot_timing() {
        let mut smt = UtxoSetEpochSMT::new();
        let empty_root = smt.root();
        assert_eq!(empty_root, imt_empty_root());

        let txs = vec![make_tx(0x01), make_tx(0x02), make_tx(0x03)];
        smt.process_epoch_transactions(&txs, 1);

        let root_after = smt.root();
        assert_ne!(root_after, empty_root, "Root must change after insertions");

        let snapshot = smt.take_snapshot(1);
        assert_eq!(snapshot.utxo_set_root, root_after);
        assert_eq!(snapshot.snapshot_epoch, 1);
        assert_eq!(snapshot.utxo_count, 3);
    }

    // ── D3: Reset returns to imt_empty_root() ────────────────────────────────

    #[test]
    fn test_d3_reset_returns_to_empty_root() {
        let mut smt = UtxoSetEpochSMT::new();
        smt.insert_utxo(make_commitment(0x42), 1);
        smt.insert_utxo(make_commitment(0x43), 1);
        assert_ne!(smt.root(), imt_empty_root());

        smt.reset();
        assert_eq!(
            smt.root(),
            imt_empty_root(),
            "D3: reset must restore empty root"
        );
        assert_eq!(smt.utxo_count(), 0);
    }

    // ── D3: Snapshot multiple epochs ─────────────────────────────────────────

    #[test]
    fn test_d3_snapshot_multiple_epochs() {
        let mut smt = UtxoSetEpochSMT::new();

        smt.process_epoch_transactions(&[make_tx(0x01), make_tx(0x02)], 1);
        let snap1 = smt.take_snapshot(1);

        smt.process_epoch_transactions(&[make_tx(0x03), make_tx(0x04)], 2);
        let snap2 = smt.take_snapshot(2);

        assert_ne!(snap1.utxo_set_root, snap2.utxo_set_root);
        assert!(snap2.utxo_count > snap1.utxo_count);
        assert!(snap2.is_valid_for_epoch(3));
        assert!(snap1.is_valid_for_epoch(2));
    }

    // ── D3: Verify root against manifest ─────────────────────────────────────

    #[test]
    fn test_d3_verify_root_against_manifest() {
        let mut smt = UtxoSetEpochSMT::new();
        smt.insert_utxo(make_commitment(0x01), 1);
        let root = smt.root();

        assert_eq!(
            verify_utxo_root_against_manifest(&root, &root),
            SyncVerificationResult::Valid
        );
        assert!(matches!(
            verify_utxo_root_against_manifest(&root, &[0xFFu8; 32]),
            SyncVerificationResult::RootMismatch { .. }
        ));
    }

    // ── D3: Node sync — new node rebuilds identical root ─────────────────────

    #[test]
    fn test_d3_new_node_sync() {
        let epoch_id = 3u64;
        let txs = vec![
            make_tx(0x01),
            make_tx(0x02),
            make_tx(0x03),
            make_tx(0x04),
            make_tx(0x05),
        ];
        let txs_gossip = vec![
            make_tx(0x05),
            make_tx(0x01),
            make_tx(0x04),
            make_tx(0x02),
            make_tx(0x03),
        ];

        let mut old_node = UtxoSetEpochSMT::new();
        old_node.process_epoch_transactions(&txs, epoch_id);

        let mut new_node = UtxoSetEpochSMT::new();
        new_node.process_epoch_transactions(&txs_gossip, epoch_id);

        assert_eq!(
            old_node.root(),
            new_node.root(),
            "D3: new node sync must produce identical root"
        );
    }

    // ── D3: DOMAIN_UTXO_SMT still OSSIFIED ───────────────────────────────────

    #[test]
    fn test_domain_separator_utxo_ossified() {
        assert_eq!(DOMAIN_UTXO_SMT, b"scalar_utxo_set");
    }

    // ── D3: is_valid_for_epoch ────────────────────────────────────────────────

    #[test]
    fn test_is_valid_for_epoch() {
        let state = UtxoSetState {
            utxo_set_root: imt_empty_root(),
            snapshot_epoch: 4,
            utxo_count: 10,
        };
        assert!(state.is_valid_for_epoch(5));
        assert!(!state.is_valid_for_epoch(4));
    }
}
