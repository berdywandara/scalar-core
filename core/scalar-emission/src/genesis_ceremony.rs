//! Genesis Ceremony — NodeKey_epoch_0 — Spec §7.2a, §12.10
//!
//! Spec §7.2a: "NodeKey_epoch_0 pubkey harus dimasukkan dalam genesis object."
//! Spec §12.10: Genesis ceremony process.
//!
//! Untuk epoch 0, tidak ada EpochAnchor sebelumnya.
//! prev_hash HB pertama epoch 0 = BLAKE3(genesis_object_bytes) — spec §7.2a, §12.9.
//!
//! NodeKey_epoch_0 derivation:
//!   NodeKey_epoch_0 = BLAKE3(NodeKey_0 || epoch_id=0 as u64 le)
//!   (sama dengan derive_node_key_epoch dari liveness.rs)
//!
//! Genesis object harus berisi:
//!   - node_key_epoch_0_pubkey: [u8;64] — SPHINCS+ pubkey untuk epoch 0
//!   - genesis_hash: BLAKE3(genesis_object_bytes minus genesis_hash field)
//!
//! Ini memungkinkan semua node verifikasi:
//!   1. prev_hash HB pertama epoch 0 = BLAKE3(genesis_object_bytes)
//!   2. EpochAnchor epoch 0 signed dengan NodeKey_epoch_0
//!
//! Hash discipline: BLAKE3 out-circuit — spec §2.1.3.

use crate::liveness::derive_node_key_epoch;

// ── Genesis constants — spec §12.9, §12.10 ───────────────────────────────────

/// Maximum genesis object size dalam bytes. OSSIFIED — spec §12.9.
pub const GENESIS_MAX_BYTES: usize = 1_024;

/// Epoch ID genesis = 0. Spec §12.10.
pub const GENESIS_EPOCH_ID: u64 = 0;

// ── NodeKey_epoch_0 — spec §7.2a ──────────────────────────────────────────────

/// Compute NodeKey_epoch_0 = BLAKE3(NodeKey_0 || epoch_id=0). Spec §7.2a.
///
/// Ini adalah kunci MAC untuk semua heartbeat di epoch 0.
/// NodeKey_epoch_0 pubkey harus dimasukkan dalam genesis object.
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compute_node_key_epoch_0(node_key_0: &[u8; 32]) -> [u8; 32] {
    // NodeKey_epoch_0 = BLAKE3(NodeKey_0 || 0u64_le) — spec §7.2a
    derive_node_key_epoch(node_key_0, GENESIS_EPOCH_ID)
}

// ── Genesis prev_hash — spec §7.2a, §12.9 ────────────────────────────────────

/// Compute prev_hash untuk HB pertama epoch 0. Spec §7.2a, §12.9.
///
/// prev_hash HB pertama epoch 0 = BLAKE3(genesis_object_bytes).
/// Ini mengikat heartbeat chain ke genesis object.
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
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

/// Entry node dalam genesis object. Spec §12.10.
///
/// Setiap founding node harus menyertakan NodeKey_epoch_0 pubkey.
/// Verifikasi: SPHINCS+ pubkey valid (64 bytes untuk SHAKE-256s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisNodeEntry {
    /// Compressed node_id = first 4 bytes BLAKE3(full_node_id). Spec §7.2.
    pub node_id: [u8; 4],
    /// SPHINCS+ pubkey untuk epoch 0 (64 bytes). Spec §7.2a.
    /// Digunakan untuk verifikasi EpochAnchor epoch 0.
    pub node_key_epoch_0_pubkey: [u8; 64],
    /// NodeKey_epoch_0 = BLAKE3(NodeKey_0 || 0u64_le). Spec §7.2a.
    /// Digunakan untuk verifikasi MAC heartbeat epoch 0.
    pub node_key_epoch_0_mac_key: [u8; 32],
}

impl GenesisNodeEntry {
    /// Buat GenesisNodeEntry baru. Spec §12.10.
    pub fn new(node_id: [u8; 4], node_key_epoch_0_pubkey: [u8; 64], node_key_0: &[u8; 32]) -> Self {
        let node_key_epoch_0_mac_key = compute_node_key_epoch_0(node_key_0);
        Self {
            node_id,
            node_key_epoch_0_pubkey,
            node_key_epoch_0_mac_key,
        }
    }

    /// Verifikasi bahwa mac_key cocok dengan node_key_0. Spec §7.2a.
    pub fn verify_mac_key(&self, node_key_0: &[u8; 32]) -> bool {
        let expected = compute_node_key_epoch_0(node_key_0);
        self.node_key_epoch_0_mac_key == expected
    }
}

// ── GenesisValidator — spec §12.10 ───────────────────────────────────────────

/// Validasi genesis object dan node entries. Spec §12.10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisValidationResult {
    /// Genesis valid — semua node entries verified.
    Valid {
        node_count: u32,
        genesis_hash: [u8; 32],
    },
    /// Genesis terlalu besar. Spec §12.9.
    TooLarge { size: usize, max: usize },
    /// Tidak ada node entries. Spec §12.10.
    NoNodes,
    /// Node entry tidak valid. Spec §12.10.
    InvalidNodeEntry { node_id: [u8; 4] },
}

/// Validasi genesis object bytes. Spec §12.10.
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

/// Compute prev_hash untuk HB pertama node i di epoch 0. Spec §7.2a.
///
/// Untuk semua node di epoch 0:
///   prev_hash = BLAKE3(genesis_object_bytes)
///
/// Semua node share prev_hash yang sama untuk HB pertama epoch 0.
pub fn compute_first_hb_prev_hash_epoch_0(genesis_bytes: &[u8]) -> [u8; 32] {
    compute_genesis_prev_hash(genesis_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::liveness::{compute_heartbeat_mac, HeartbeatUnit};

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
        let mac = compute_heartbeat_mac(
            &nke, &node_id, 1, 0, &[0u8; 32], &[0u8; 32], 0u64, &prev_hash,
        );
        // HB valid dengan prev_hash dari genesis
        let hb = HeartbeatUnit {
            node_id,
            seq_num: 1,
            timestamp: 0,
            smt_root: [0u8; 32],
            imt_frontier: [0u8; 32],
            imt_count: 0u64,
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
            &hb.imt_frontier,
            hb.imt_count,
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

// ═══════════════════════════════════════════════════════════════════════════════
// GENESIS TWO-PHASE PROTOCOL — MAD §3.1 (ADR-SEC-009)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Phase 0 — PARAMETER COMMITMENT (public, no participants required):
//   genesis_params_hash = BLAKE3(DOMAIN_GENESIS_BOOTSTRAP || serialize(params))
//   Hash PUBLISHED before any participant registration.
//
// Phase 1 — PARTICIPANT REGISTRATION:
//   per-participant: registration_commitment = BLAKE3(pubkey || genesis_params_hash || nonce)
//   aggregate:       genesis_commitment_root = BLAKE3(DOMAIN_GENESIS_BOOTSTRAP
//                      || genesis_params_hash || concat(sorted_commitments))
//
// Phase 2 — GENESIS OBJECT FINALIZATION:
//   genesis_object  = { genesis_params_hash, genesis_commitment_root,
//                       participant_pubkeys, initial_utxo_set_root, timestamp }
//   genesis_hash    = BLAKE3(DOMAIN_GENESIS_BOOTSTRAP || serialize(genesis_object))
//   genesis_hash    hardcoded in binary.

use scalar_crypto::domain::DOMAIN_GENESIS_BOOTSTRAP;

// ── Phase 0 — Genesis Params ──────────────────────────────────────────────────

/// OSSIFIED genesis parameters. MAD §3.1 Phase 0.
/// Serialized deterministically for genesis_params_hash computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisParams {
    /// S_MAX in sSCL. OSSIFIED — spec §3.2.
    pub s_max_sscl:         u64,
    /// S_E (emission pool) in sSCL. OSSIFIED.
    pub s_e_sscl:           u64,
    /// S_R (reserve) in sSCL. OSSIFIED.
    pub s_r_sscl:           u64,
    /// FRI blowup. OSSIFIED.
    pub fri_blowup:         u8,
    /// FRI queries. OSSIFIED.
    pub fri_queries:        u8,
    /// FRI grinding bits. OSSIFIED.
    pub fri_grinding:       u8,
    /// Crypto suite version. OSSIFIED.
    pub crypto_version:     u8,
    /// Genesis timestamp (Unix seconds).
    pub genesis_timestamp:  u64,
    /// Genesis version string (UTF-8, max 32 bytes).
    pub genesis_version:    [u8; 32],
}

impl GenesisParams {
    /// Canonical genesis params with OSSIFIED values. MAD §3.1.
    pub fn canonical(genesis_timestamp: u64) -> Self {
        let mut genesis_version = [0u8; 32];
        let ver = b"scalar-genesis-1.0";
        genesis_version[..ver.len()].copy_from_slice(ver);
        Self {
            s_max_sscl:        2_100_000_000_000_000,
            s_e_sscl:          1_890_000_000_000_000,
            s_r_sscl:            210_000_000_000_000,
            fri_blowup:        8,
            fri_queries:       84,
            fri_grinding:      20,
            crypto_version:    0x01,
            genesis_timestamp,
            genesis_version,
        }
    }

    /// Deterministic serialization for hashing. Field order is OSSIFIED.
    /// Format: fixed-size little-endian fields, no length prefixes.
    pub fn serialize(&self) -> [u8; 72] {
        let mut out = [0u8; 72];
        out[0..8].copy_from_slice(&self.s_max_sscl.to_le_bytes());
        out[8..16].copy_from_slice(&self.s_e_sscl.to_le_bytes());
        out[16..24].copy_from_slice(&self.s_r_sscl.to_le_bytes());
        out[24] = self.fri_blowup;
        out[25] = self.fri_queries;
        out[26] = self.fri_grinding;
        out[27] = self.crypto_version;
        out[28..36].copy_from_slice(&self.genesis_timestamp.to_le_bytes());
        out[36..68].copy_from_slice(&self.genesis_version);
        // bytes 68-71: reserved, zero
        out
    }
}

/// Phase 0: compute genesis_params_hash. MAD §3.1.
///
/// genesis_params_hash = BLAKE3(DOMAIN_GENESIS_BOOTSTRAP || serialize(params))
/// MUST be published before Phase 1 participant registration begins.
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compute_genesis_params_hash(params: &GenesisParams) -> [u8; 32] {
    let serialized = params.serialize();
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_GENESIS_BOOTSTRAP);
    hasher.update(&serialized);
    *hasher.finalize().as_bytes()
}

// ── Phase 1 — Participant Registration ───────────────────────────────────────

/// Registration commitment from one participant. MAD §3.1 Phase 1.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegistrationCommitment {
    /// Participant's SLH-DSA public key (64 bytes for SHAKE-256s).
    pub pubkey: [u8; 64],
    /// BLAKE3(pubkey || genesis_params_hash || nonce). Commitment to nonce.
    pub commitment: [u8; 32],
}

/// Phase 1 per-participant: compute registration_commitment. MAD §3.1.
///
/// registration_commitment = BLAKE3(pubkey || genesis_params_hash || nonce)
/// nonce: 128-bit random, kept secret by participant.
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn register_participant(
    pubkey: &[u8; 64],
    genesis_params_hash: &[u8; 32],
    nonce: &[u8; 16],
) -> RegistrationCommitment {
    let mut hasher = blake3::Hasher::new();
    hasher.update(pubkey.as_ref());
    hasher.update(genesis_params_hash);
    hasher.update(nonce);
    let commitment = *hasher.finalize().as_bytes();
    RegistrationCommitment {
        pubkey: *pubkey,
        commitment,
    }
}

/// Phase 1 aggregation: compute genesis_commitment_root. MAD §3.1.
///
/// Participants sorted by pubkey ascending before hashing.
/// genesis_commitment_root = BLAKE3(
///   DOMAIN_GENESIS_BOOTSTRAP || genesis_params_hash
///   || concat(sorted_registration_commitments)
/// )
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compute_genesis_commitment_root(
    genesis_params_hash: &[u8; 32],
    mut registrations: Vec<RegistrationCommitment>,
) -> [u8; 32] {
    // Sort by pubkey ascending — deterministic ordering. MAD §3.1.
    registrations.sort_by_key(|r| r.pubkey);

    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_GENESIS_BOOTSTRAP);
    hasher.update(genesis_params_hash);
    for reg in &registrations {
        hasher.update(reg.pubkey.as_ref());
        hasher.update(&reg.commitment);
    }
    *hasher.finalize().as_bytes()
}

// ── Phase 2 — Genesis Object ──────────────────────────────────────────────────

/// Genesis object. MAD §3.1 Phase 2.
/// genesis_hash is computed from this and hardcoded in binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisObject {
    /// From Phase 0. MAD §3.1.
    pub genesis_params_hash:     [u8; 32],
    /// From Phase 1. MAD §3.1.
    pub genesis_commitment_root: [u8; 32],
    /// Participant pubkeys (sorted ascending). MAD §3.1.
    pub participant_pubkeys:     Vec<[u8; 64]>,
    /// Initial UTXO set root (typically IMT empty root). MAD §3.1.
    pub initial_utxo_set_root:   [u8; 32],
    /// Genesis timestamp (Unix seconds).
    pub timestamp:               u64,
}

impl GenesisObject {
    /// Deterministic serialization for genesis_hash. Field order OSSIFIED.
    pub fn serialize(&self) -> Vec<u8> {
        let pubkey_count = self.participant_pubkeys.len() as u64;
        let mut out = Vec::with_capacity(32 + 32 + 8 + pubkey_count as usize * 64 + 32 + 8);
        out.extend_from_slice(&self.genesis_params_hash);
        out.extend_from_slice(&self.genesis_commitment_root);
        out.extend_from_slice(&pubkey_count.to_le_bytes());
        for pk in &self.participant_pubkeys {
            out.extend_from_slice(pk.as_ref());
        }
        out.extend_from_slice(&self.initial_utxo_set_root);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out
    }
}

/// Phase 2: finalize genesis — compute genesis_hash. MAD §3.1.
///
/// genesis_hash = BLAKE3(DOMAIN_GENESIS_BOOTSTRAP || serialize(genesis_object))
/// This hash is hardcoded in the binary.
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn finalize_genesis(object: &GenesisObject) -> [u8; 32] {
    let serialized = object.serialize();
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_GENESIS_BOOTSTRAP);
    hasher.update(&serialized);
    *hasher.finalize().as_bytes()
}

// ── GVP — Genesis Verification Points (GVP-1..4) ─────────────────────────────

/// Genesis Verification Point result. MAD §3.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GvpResult {
    Pass,
    Fail(String),
}

/// GVP-1: genesis_params_hash matches params. MAD §3.1.
pub fn gvp1_params_hash(
    genesis_params_hash: &[u8; 32],
    params: &GenesisParams,
) -> GvpResult {
    let computed = compute_genesis_params_hash(params);
    if &computed == genesis_params_hash {
        GvpResult::Pass
    } else {
        GvpResult::Fail(format!(
            "GVP-1: params_hash mismatch: expected {:?} got {:?}",
            genesis_params_hash, computed
        ))
    }
}

/// GVP-2: genesis_commitment_root correctly aggregates registrations. MAD §3.1.
pub fn gvp2_commitment_root(
    genesis_commitment_root: &[u8; 32],
    genesis_params_hash: &[u8; 32],
    registrations: Vec<RegistrationCommitment>,
) -> GvpResult {
    let computed = compute_genesis_commitment_root(genesis_params_hash, registrations);
    if &computed == genesis_commitment_root {
        GvpResult::Pass
    } else {
        GvpResult::Fail(format!(
            "GVP-2: commitment_root mismatch: expected {:?} got {:?}",
            genesis_commitment_root, computed
        ))
    }
}

/// GVP-3: genesis_object fields are internally consistent. MAD §3.1.
pub fn gvp3_object_consistency(object: &GenesisObject) -> GvpResult {
    if object.participant_pubkeys.is_empty() {
        return GvpResult::Fail("GVP-3: no participant pubkeys in genesis object".into());
    }
    if object.timestamp == 0 {
        return GvpResult::Fail("GVP-3: genesis timestamp is zero".into());
    }
    // Pubkeys must be sorted ascending (deterministic ordering).
    let mut sorted = object.participant_pubkeys.clone();
    sorted.sort();
    if sorted != object.participant_pubkeys {
        return GvpResult::Fail("GVP-3: participant_pubkeys not sorted ascending".into());
    }
    GvpResult::Pass
}

/// GVP-4: genesis_hash matches genesis_object. MAD §3.1.
pub fn gvp4_genesis_hash(
    expected_genesis_hash: &[u8; 32],
    object: &GenesisObject,
) -> GvpResult {
    let computed = finalize_genesis(object);
    if &computed == expected_genesis_hash {
        GvpResult::Pass
    } else {
        GvpResult::Fail(format!(
            "GVP-4: genesis_hash mismatch: expected {:?} got {:?}",
            expected_genesis_hash, computed
        ))
    }
}

/// Run all GVP-1..4 in sequence. Returns first failure, or Pass. MAD §3.1.
pub fn run_all_gvp(
    genesis_params_hash: &[u8; 32],
    params: &GenesisParams,
    genesis_commitment_root: &[u8; 32],
    registrations: Vec<RegistrationCommitment>,
    expected_genesis_hash: &[u8; 32],
    object: &GenesisObject,
) -> GvpResult {
    let checks = [
        gvp1_params_hash(genesis_params_hash, params),
        gvp2_commitment_root(genesis_commitment_root, genesis_params_hash, registrations),
        gvp3_object_consistency(object),
        gvp4_genesis_hash(expected_genesis_hash, object),
    ];
    for check in checks {
        if check != GvpResult::Pass {
            return check;
        }
    }
    GvpResult::Pass
}

// ── Tests — Two-Phase Protocol ───────────────────────────────────────────────

#[cfg(test)]
mod two_phase_tests {
    use super::*;

    fn make_params() -> GenesisParams {
        GenesisParams::canonical(1_700_000_000)
    }

    fn make_pubkey(seed: u8) -> [u8; 64] {
        [seed; 64]
    }

    fn make_nonce(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    // ── Phase 0 ───────────────────────────────────────────────────────────────

    #[test]
    fn test_phase0_params_hash_deterministic() {
        let params = make_params();
        let h1 = compute_genesis_params_hash(&params);
        let h2 = compute_genesis_params_hash(&params);
        assert_eq!(h1, h2, "Phase 0: params_hash must be deterministic");
    }

    #[test]
    fn test_phase0_params_hash_nonzero() {
        let params = make_params();
        let h = compute_genesis_params_hash(&params);
        assert_ne!(h, [0u8; 32], "Phase 0: params_hash must not be zero");
    }

    #[test]
    fn test_phase0_params_hash_changes_with_timestamp() {
        let p1 = GenesisParams::canonical(1_000);
        let p2 = GenesisParams::canonical(2_000);
        let h1 = compute_genesis_params_hash(&p1);
        let h2 = compute_genesis_params_hash(&p2);
        assert_ne!(h1, h2, "Phase 0: different timestamps → different hashes");
    }

    #[test]
    fn test_phase0_canonical_params_ossified_values() {
        let p = make_params();
        assert_eq!(p.s_max_sscl, 2_100_000_000_000_000);
        assert_eq!(p.s_e_sscl,   1_890_000_000_000_000);
        assert_eq!(p.s_r_sscl,     210_000_000_000_000);
        assert_eq!(p.fri_blowup, 8);
        assert_eq!(p.fri_queries, 84);
        assert_eq!(p.fri_grinding, 20);
        assert_eq!(p.crypto_version, 0x01);
        let ver = b"scalar-genesis-1.0";
        assert_eq!(&p.genesis_version[..ver.len()], ver);
    }

    // ── Phase 1 ───────────────────────────────────────────────────────────────

    #[test]
    fn test_phase1_registration_deterministic() {
        let pk = make_pubkey(0xAA);
        let hash = [0x11u8; 32];
        let nonce = make_nonce(0x55);
        let r1 = register_participant(&pk, &hash, &nonce);
        let r2 = register_participant(&pk, &hash, &nonce);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_phase1_different_nonces_differ() {
        let pk = make_pubkey(0xAA);
        let hash = [0x11u8; 32];
        let r1 = register_participant(&pk, &hash, &make_nonce(0x01));
        let r2 = register_participant(&pk, &hash, &make_nonce(0x02));
        assert_ne!(r1.commitment, r2.commitment, "Different nonces → different commitments");
    }

    #[test]
    fn test_phase1_commitment_root_deterministic() {
        let params_hash = [0xAAu8; 32];
        let regs = vec![
            register_participant(&make_pubkey(0x01), &params_hash, &make_nonce(0x01)),
            register_participant(&make_pubkey(0x02), &params_hash, &make_nonce(0x02)),
        ];
        let r1 = compute_genesis_commitment_root(&params_hash, regs.clone());
        let r2 = compute_genesis_commitment_root(&params_hash, regs);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_phase1_commitment_root_order_independent() {
        // MAD §3.1: sorted by pubkey → order-independent.
        let params_hash = [0xAAu8; 32];
        let regs_ab = vec![
            register_participant(&make_pubkey(0x01), &params_hash, &make_nonce(0x01)),
            register_participant(&make_pubkey(0x02), &params_hash, &make_nonce(0x02)),
        ];
        let regs_ba = vec![regs_ab[1].clone(), regs_ab[0].clone()];
        let root_ab = compute_genesis_commitment_root(&params_hash, regs_ab);
        let root_ba = compute_genesis_commitment_root(&params_hash, regs_ba);
        assert_eq!(root_ab, root_ba, "Commitment root must be order-independent (sorted)");
    }

    // ── Phase 2 ───────────────────────────────────────────────────────────────

    #[test]
    fn test_phase2_genesis_hash_deterministic() {
        let obj = GenesisObject {
            genesis_params_hash:     [0x11u8; 32],
            genesis_commitment_root: [0x22u8; 32],
            participant_pubkeys:     vec![make_pubkey(0x01)],
            initial_utxo_set_root:   [0x33u8; 32],
            timestamp:               1_700_000_000,
        };
        let h1 = finalize_genesis(&obj);
        let h2 = finalize_genesis(&obj);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_phase2_genesis_hash_nonzero() {
        let obj = GenesisObject {
            genesis_params_hash:     [0x11u8; 32],
            genesis_commitment_root: [0x22u8; 32],
            participant_pubkeys:     vec![make_pubkey(0x01)],
            initial_utxo_set_root:   [0x33u8; 32],
            timestamp:               1_700_000_000,
        };
        let h = finalize_genesis(&obj);
        assert_ne!(h, [0u8; 32]);
    }

    // ── GVP-1..4 ─────────────────────────────────────────────────────────────

    #[test]
    fn test_gvp1_pass() {
        let params = make_params();
        let hash = compute_genesis_params_hash(&params);
        assert_eq!(gvp1_params_hash(&hash, &params), GvpResult::Pass);
    }

    #[test]
    fn test_gvp1_fail_wrong_hash() {
        let params = make_params();
        let wrong = [0xFFu8; 32];
        assert!(matches!(gvp1_params_hash(&wrong, &params), GvpResult::Fail(_)));
    }

    #[test]
    fn test_gvp2_pass() {
        let params_hash = [0xAAu8; 32];
        let regs = vec![
            register_participant(&make_pubkey(0x01), &params_hash, &make_nonce(0x01)),
        ];
        let root = compute_genesis_commitment_root(&params_hash, regs.clone());
        assert_eq!(gvp2_commitment_root(&root, &params_hash, regs), GvpResult::Pass);
    }

    #[test]
    fn test_gvp3_pass() {
        let mut pubkeys = vec![make_pubkey(0x01), make_pubkey(0x02)];
        pubkeys.sort();
        let obj = GenesisObject {
            genesis_params_hash:     [0x11u8; 32],
            genesis_commitment_root: [0x22u8; 32],
            participant_pubkeys:     pubkeys,
            initial_utxo_set_root:   [0x33u8; 32],
            timestamp:               1_700_000_000,
        };
        assert_eq!(gvp3_object_consistency(&obj), GvpResult::Pass);
    }

    #[test]
    fn test_gvp3_fail_unsorted_pubkeys() {
        let obj = GenesisObject {
            genesis_params_hash:     [0x11u8; 32],
            genesis_commitment_root: [0x22u8; 32],
            // Intentionally unsorted
            participant_pubkeys:     vec![make_pubkey(0x02), make_pubkey(0x01)],
            initial_utxo_set_root:   [0x33u8; 32],
            timestamp:               1_700_000_000,
        };
        assert!(matches!(gvp3_object_consistency(&obj), GvpResult::Fail(_)));
    }

    #[test]
    fn test_gvp4_pass() {
        let obj = GenesisObject {
            genesis_params_hash:     [0x11u8; 32],
            genesis_commitment_root: [0x22u8; 32],
            participant_pubkeys:     vec![make_pubkey(0x01)],
            initial_utxo_set_root:   [0x33u8; 32],
            timestamp:               1_700_000_000,
        };
        let hash = finalize_genesis(&obj);
        assert_eq!(gvp4_genesis_hash(&hash, &obj), GvpResult::Pass);
    }

    #[test]
    fn test_run_all_gvp_full_flow() {
        // MAD §3.1: full two-phase ceremony flow.
        let params = make_params();
        let params_hash = compute_genesis_params_hash(&params);

        // Phase 1
        let regs = vec![
            register_participant(&make_pubkey(0x01), &params_hash, &make_nonce(0x01)),
            register_participant(&make_pubkey(0x02), &params_hash, &make_nonce(0x02)),
        ];
        let commitment_root = compute_genesis_commitment_root(&params_hash, regs.clone());

        // Phase 2
        let mut pubkeys = vec![make_pubkey(0x01), make_pubkey(0x02)];
        pubkeys.sort();
        let obj = GenesisObject {
            genesis_params_hash:     params_hash,
            genesis_commitment_root: commitment_root,
            participant_pubkeys:     pubkeys,
            initial_utxo_set_root:   [0xFFu8; 32],
            timestamp:               1_700_000_000,
        };
        let genesis_hash = finalize_genesis(&obj);

        let result = run_all_gvp(
            &params_hash, &params,
            &commitment_root, regs,
            &genesis_hash, &obj,
        );
        assert_eq!(result, GvpResult::Pass, "Full GVP-1..4 must pass");
    }
}
