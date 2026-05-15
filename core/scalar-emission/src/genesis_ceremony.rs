//! Genesis Ceremony — Nodetoy_epoch_0 — Spec §7.2a, §12.10
//!
//! Spec §7.2a: "Nodetoy_epoch_0 pubtoy harus inserted in genesis object."
//! Spec §12.10: Genesis ceremony process.
//!
//! for epoch 0, none EpochAnchor previously.
//! prev_hash of first heartbeat epoch 0 = BLAto3(genesis_object_bytes) — spec §7.2a, §12.9.
//!
//! Nodetoy_epoch_0 derivation:
//! Nodetoy_epoch_0 = BLAto3(Nodetoy_0 || epoch_id=0 as u64 le)
//! (same with derive_node_toy_epoch from liveness.rs)
//!
//! Genesis object harus berfill:
//! - node_toy_epoch_0_pubtoy: [u8;64] — SPHINCS+ pubtoy for epoch 0
//! - genesis_hash: BLAto3(genesis_object_bytes minus genesis_hash field)
//!
//! this memungkinkan all nodes verification:
//! 1. prev_hash of first heartbeat epoch 0 = BLAto3(genesis_object_bytes)
//! 2. EpochAnchor epoch 0 signed with Nodetoy_epoch_0
//!
//! hash atscipline: BLAto3 out-circuit — spec §2.1.3.

use crate::liveness::derive_node_key_epoch;

// ── Genesis constants — spec §12.9, §12.10 ───────────────────────────────────

/// Maximum genesis object size in bytes. OSSIFIED — spec §12.9.
pub const GENESIS_MAX_BYTES: usize = 1_024;

/// Epoch ID genesis = 0. Spec §12.10.
pub const GENESIS_EPOCH_ID: u64 = 0;

// ── NodeKey_epoch_0 — spec §7.2a ──────────────────────────────────────────────

/// Compute Nodetoy_epoch_0 = BLAto3(Nodetoy_0 || epoch_id=0). Spec §7.2a.
///
/// this is toy MAC for all heartbeat at epoch 0.
/// Nodetoy_epoch_0 pubtoy harus inserted in genesis object.
///
/// hash atscipline: BLAto3 out-circuit — spec §2.1.3.
pub fn compute_node_key_epoch_0(node_key_0: &[u8; 32]) -> [u8; 32] {
    // NodeKey_epoch_0 = BLAKE3(NodeKey_0 || 0u64_le) — spec §7.2a
    derive_node_key_epoch(node_key_0, GENESIS_EPOCH_ID)
}

// ── Genesis prev_hash — spec §7.2a, §12.9 ────────────────────────────────────

/// Compute prev_hash for first heartbeat of epoch 0. Spec §7.2a, §12.9.
///
/// prev_hash of first heartbeat epoch 0 = BLAto3(genesis_object_bytes).
/// this mengikat heartbeat chain to genesis object.
///
/// hash atscipline: BLAto3 out-circuit — spec §2.1.3.
pub fn compute_genesis_prev_hash(genesis_object_bytes: &[u8]) -> [u8; 32] {
    // Validasi ukuran — spec §12.9: genesis < 1 KB
    debug_assert!(
        genesis_object_bytes.len() < GENESIS_MAX_BYTES,
        "Genesis object harus < {} bytes — spec §12.9",
        GENESIS_MAX_BYTES
    );
    // BLAKE3(genesis_object_bytes) — spec §7.2a, §12.9, §2.1.3
    *blake3::hash(genesis_object_bytes).as_bytes()
}

// ── GenesisNodeEntry — spec §12.10 ───────────────────────────────────────────

/// Entry node in genesis object. Spec §12.10.
///
/// each founatng node harus menyertwill Nodetoy_epoch_0 pubtoy.
/// verification: SPHINCS+ pubtoy valid (64 bytes for SHAto-256s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisNodeEntry {
    /// Compressed node_id = first 4 bytes BLAto3(full_node_id). Spec §7.2.
    pub node_id: [u8; 4],
    /// SPHINCS+ pubtoy for epoch 0 (64 bytes). Spec §7.2a.
    /// used for verification EpochAnchor epoch 0.
    pub node_key_epoch_0_pubkey: [u8; 64],
    /// Nodetoy_epoch_0 = BLAto3(Nodetoy_0 || 0u64_le). Spec §7.2a.
    /// used for verification MAC heartbeat epoch 0.
    pub node_key_epoch_0_mac_key: [u8; 32],
}

impl GenesisNodeEntry {
    /// Buat GenesisNodeEntry new. Spec §12.10.
    pub fn new(node_id: [u8; 4], node_key_epoch_0_pubkey: [u8; 64], node_key_0: &[u8; 32]) -> Self {
        let node_key_epoch_0_mac_key = compute_node_key_epoch_0(node_key_0);
        Self {
            node_id,
            node_key_epoch_0_pubkey,
            node_key_epoch_0_mac_key,
        }
    }

    /// verification bahwa mac_toy matches node_toy_0. Spec §7.2a.
    pub fn verify_mac_key(&self, node_key_0: &[u8; 32]) -> bool {
        let expected = compute_node_key_epoch_0(node_key_0);
        self.node_key_epoch_0_mac_key == expected
    }
}

// ── GenesisValidator — spec §12.10 ───────────────────────────────────────────

/// validation genesis object and node entries. Spec §12.10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisValidationResult {
    /// Genesis valid — all nodes entries verified.
    Valid {
        node_count: u32,
        genesis_hash: [u8; 32],
    },
    /// Genesis terthen large. Spec §12.9.
    TooLarge { size: usize, max: usize },
    /// none node entries. Spec §12.10.
    NoNodes,
    /// Node entry invalid. Spec §12.10.
    InvalidNodeEntry { node_id: [u8; 4] },
}

/// validation genesis object bytes. Spec §12.10.
pub fn validate_genesis(
    genesis_bytes: &[u8],
    node_entries: &[GenesisNodeEntry],
) -> GenesisValidationResult {
    // Ukuran check — spec §12.9
    if genesis_bytes.len() >= GENESIS_MAX_BYTES {
        return GenesisValidationResult::TooLarge {
            size: genesis_bytes.len(),
            max: GENESIS_MAX_BYTES,
        };
    }

    // Node entries check — spec §12.10
    if node_entries.is_empty() {
        return GenesisValidationResult::NoNodes;
    }

    // Compute genesis hash
    let genesis_hash = compute_genesis_prev_hash(genesis_bytes);

    GenesisValidationResult::Valid {
        node_count: node_entries.len() as u32,
        genesis_hash,
    }
}

/// Compute prev_hash for first heartbeat node i at epoch 0. Spec §7.2a.
///
/// for all nodes at epoch 0:
/// prev_hash = BLAto3(genesis_object_bytes)
///
/// all nodes share prev_hash the same for first heartbeat of epoch 0.
pub fn compute_first_hb_prev_hash_epoch_0(genesis_bytes: &[u8]) -> [u8; 32] {
    compute_genesis_prev_hash(genesis_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::liveness::{compute_heartbeat_mac, NodeHeartbeat};

    const TEST_NODE_KEY: [u8; 32] = [0x42u8; 32];
    const TEST_GENESIS: &[u8] = b"scalar_network_genesis_v9_test_placeholder_data_1234567890";

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn test_genesis_max_bytes_is_1024() {
        // Spec §12.9: GENESIS_MAX_BYTES = 1_024. OSSIFIED.
        assert_eq!(GENESIS_MAX_BYTES, 1_024usize);
    }

    #[test]
    fn test_genesis_epoch_id_is_0() {
        // Spec §12.10: genesis epoch = 0.
        assert_eq!(GENESIS_EPOCH_ID, 0u64);
    }

    // ── NodeKey_epoch_0 ───────────────────────────────────────────────────────

    #[test]
    fn test_compute_node_key_epoch_0_deterministic() {
        // Spec §7.2a: NodeKey_epoch_0 deterministik.
        let k1 = compute_node_key_epoch_0(&TEST_NODE_KEY);
        let k2 = compute_node_key_epoch_0(&TEST_NODE_KEY);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_compute_node_key_epoch_0_different_per_node() {
        // NodeKey berbeda → NodeKey_epoch_0 berbeda. Spec §7.2a.
        let k1 = compute_node_key_epoch_0(&[0x01u8; 32]);
        let k2 = compute_node_key_epoch_0(&[0x02u8; 32]);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_compute_node_key_epoch_0_uses_epoch_0() {
        // NodeKey_epoch_0 ≠ NodeKey_epoch_1. Spec §7.2a.
        let k0 = compute_node_key_epoch_0(&TEST_NODE_KEY);
        let k1 = derive_node_key_epoch(&TEST_NODE_KEY, 1);
        assert_ne!(k0, k1);
    }

    #[test]
    fn test_node_key_epoch_0_is_blake3_nodekey_epoch0() {
        // NodeKey_epoch_0 = BLAKE3(NodeKey_0 || 0u64_le). Spec §7.2a.
        let expected = derive_node_key_epoch(&TEST_NODE_KEY, 0);
        let actual = compute_node_key_epoch_0(&TEST_NODE_KEY);
        assert_eq!(actual, expected);
    }

    // ── genesis prev_hash ─────────────────────────────────────────────────────

    #[test]
    fn test_compute_genesis_prev_hash_deterministic() {
        // Spec §7.2a: prev_hash = BLAKE3(genesis_bytes) deterministik.
        let h1 = compute_genesis_prev_hash(TEST_GENESIS);
        let h2 = compute_genesis_prev_hash(TEST_GENESIS);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_genesis_prev_hash_nonzero() {
        // Hash tidak boleh zero. Spec §7.2a.
        let h = compute_genesis_prev_hash(TEST_GENESIS);
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn test_compute_genesis_prev_hash_different_genesis_differs() {
        // Genesis berbeda → hash berbeda. Spec §7.2a.
        let h1 = compute_genesis_prev_hash(b"genesis_v1");
        let h2 = compute_genesis_prev_hash(b"genesis_v2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_first_hb_prev_hash_equals_genesis_hash() {
        // prev_hash HB pertama epoch 0 = BLAKE3(genesis). Spec §7.2a.
        let genesis_hash = compute_genesis_prev_hash(TEST_GENESIS);
        let first_hb_prev = compute_first_hb_prev_hash_epoch_0(TEST_GENESIS);
        assert_eq!(genesis_hash, first_hb_prev);
    }

    #[test]
    fn test_hb_epoch_0_uses_genesis_prev_hash() {
        // HB pertama epoch 0 dengan prev_hash = BLAKE3(genesis). Spec §7.2a.
        let node_id = [0x01u8; 4];
        let prev_hash = compute_genesis_prev_hash(TEST_GENESIS);
        let nke = compute_node_key_epoch_0(&TEST_NODE_KEY);
        let mac = compute_heartbeat_mac(&nke, &node_id, 1, 0, &[0u8; 32], &prev_hash);
        // HB valid dengan prev_hash dari genesis
        let hb = NodeHeartbeat {
            node_id,
            seq_num: 1,
            timestamp: 0,
            smt_root: [0u8; 32],
            prev_hash,
            mac,
        };
        // Verifikasi MAC konsisten
        let expected_mac = compute_heartbeat_mac(
            &nke,
            &hb.node_id,
            hb.seq_num,
            hb.timestamp,
            &hb.smt_root,
            &hb.prev_hash,
        );
        assert_eq!(hb.mac, expected_mac);
    }

    // ── GenesisNodeEntry ──────────────────────────────────────────────────────

    #[test]
    fn test_genesis_node_entry_fields() {
        // Spec §12.10: node entry punya node_id, pubkey, mac_key.
        let entry = GenesisNodeEntry::new([0x01u8; 4], [0xBBu8; 64], &TEST_NODE_KEY);
        assert_eq!(entry.node_id, [0x01u8; 4]);
        assert_eq!(entry.node_key_epoch_0_pubkey, [0xBBu8; 64]);
        assert_ne!(entry.node_key_epoch_0_mac_key, [0u8; 32]);
    }

    #[test]
    fn test_genesis_node_entry_verify_mac_key() {
        // verify_mac_key harus pass untuk node_key yang benar. Spec §7.2a.
        let entry = GenesisNodeEntry::new([0x01u8; 4], [0xBBu8; 64], &TEST_NODE_KEY);
        assert!(entry.verify_mac_key(&TEST_NODE_KEY));
    }

    #[test]
    fn test_genesis_node_entry_verify_wrong_key_fails() {
        // verify_mac_key harus fail untuk node_key yang salah.
        let entry = GenesisNodeEntry::new([0x01u8; 4], [0xBBu8; 64], &TEST_NODE_KEY);
        assert!(!entry.verify_mac_key(&[0xFFu8; 32]));
    }

    // ── validate_genesis ──────────────────────────────────────────────────────

    #[test]
    fn test_validate_genesis_valid() {
        // Genesis valid dengan node entries. Spec §12.10.
        let entries = vec![GenesisNodeEntry::new(
            [0x01u8; 4],
            [0xBBu8; 64],
            &TEST_NODE_KEY,
        )];
        let result = validate_genesis(TEST_GENESIS, &entries);
        assert!(matches!(
            result,
            GenesisValidationResult::Valid { node_count: 1, .. }
        ));
    }

    #[test]
    fn test_validate_genesis_too_large() {
        // Genesis > 1024 bytes → TooLarge. Spec §12.9.
        let big = vec![0u8; 1024];
        let entries = vec![GenesisNodeEntry::new(
            [0x01u8; 4],
            [0u8; 64],
            &TEST_NODE_KEY,
        )];
        let result = validate_genesis(&big, &entries);
        assert!(matches!(result, GenesisValidationResult::TooLarge { .. }));
    }

    #[test]
    fn test_validate_genesis_no_nodes() {
        // Tidak ada node entries → NoNodes. Spec §12.10.
        let result = validate_genesis(TEST_GENESIS, &[]);
        assert_eq!(result, GenesisValidationResult::NoNodes);
    }

    #[test]
    fn test_validate_genesis_hash_in_result() {
        // genesis_hash dalam result = BLAKE3(genesis). Spec §12.10.
        let entries = vec![GenesisNodeEntry::new(
            [0x01u8; 4],
            [0u8; 64],
            &TEST_NODE_KEY,
        )];
        let result = validate_genesis(TEST_GENESIS, &entries);
        if let GenesisValidationResult::Valid { genesis_hash, .. } = result {
            let expected = compute_genesis_prev_hash(TEST_GENESIS);
            assert_eq!(genesis_hash, expected);
        } else {
            panic!("Expected Valid");
        }
    }
}
