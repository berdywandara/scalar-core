//! StateBeacon + MAC Authentication — Spec §12.2
//!
//! StateBeacon: struct 44 bytes yang muat dalam satu LoRa packet.
//! Spec §12.2:
//!   epoch_id:  u64  — 8 bytes
//!   smt_root:  [u8;32] — 32 bytes
//!   mac:       [u8;4]  — 4 bytes
//!   Total: 44 bytes
//!
//! MAC construction — spec §12.2, §7.4:
//!   NodeKey_epoch = BLAKE3(NodeKey || epoch_id_le64)
//!   mac = BLAKE3(NodeKey_epoch || epoch_id_le64 || smt_root)[0..4]
//!
//! NodeKey_epoch wajib disertakan — tanpanya beacon MAC hanya checksum
//! deterministik yang bisa dipalsukan siapapun yang tahu epoch_id dan smt_root
//! (keduanya data publik). Spec §12.2.
//!
//! STATE_BEACON_MAX_BYTES = 64. Fits one LoRa packet. OSSIFIED — spec §12.2.
//!
//! Hash discipline: BLAKE3 out-circuit — spec §2.1.

use blake3::Hasher;
use scalar_crypto::domain::DOMAIN_BEACON;

// ── Constants — spec §12.2 ───────────────────────────────────────────────────

/// Maximum bytes StateBeacon. OSSIFIED — spec §12.2.
pub const STATE_BEACON_MAX_BYTES: usize = 64;

/// StateBeacon wire size dalam bytes. Spec §12.2.
/// epoch_id(8) + smt_root(32) + mac(4) = 44 bytes.
pub const STATE_BEACON_WIRE_SIZE: usize = 44;

// ── MAC computation — spec §12.2, §7.4 ──────────────────────────────────────

/// Derive NodeKey_epoch dari NodeKey dan epoch_id. Spec §7.4.
///
/// NodeKey_epoch = BLAKE3(NodeKey || epoch_id_le64)
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.
pub fn derive_node_key_epoch(node_key: &[u8; 32], epoch_id: u64) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(node_key);
    hasher.update(&epoch_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Compute beacon MAC. Spec §12.2.
///
/// mac = BLAKE3(NodeKey_epoch || epoch_id_le64 || smt_root)[0..4]
///
/// `node_key_epoch`: hasil derive_node_key_epoch(NodeKey, epoch_id).
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.
pub fn compute_beacon_mac(
    node_key_epoch: &[u8; 32],
    epoch_id: u64,
    smt_root: &[u8; 32],
) -> [u8; 4] {
    let mut hasher = Hasher::new();
    hasher.update(DOMAIN_BEACON); // spec §2.3
    hasher.update(node_key_epoch);
    hasher.update(&epoch_id.to_le_bytes());
    hasher.update(smt_root);
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

// ── StateBeacon — spec §12.2 ─────────────────────────────────────────────────

/// StateBeacon 44 bytes — authenticated beacon. Spec §12.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateBeacon {
    pub epoch_id: u64,
    pub smt_root: [u8; 32],
    /// mac = BLAKE3(NodeKey_epoch || epoch_id_le64 || smt_root)[0..4]. Spec §12.2.
    pub mac: [u8; 4],
}

impl StateBeacon {
    /// Buat StateBeacon baru dengan MAC yang benar. Spec §12.2.
    ///
    /// `node_key`: NodeKey node yang menerbitkan beacon.
    pub fn new(epoch_id: u64, smt_root: [u8; 32], node_key: &[u8; 32]) -> Self {
        let node_key_epoch = derive_node_key_epoch(node_key, epoch_id);
        let mac = compute_beacon_mac(&node_key_epoch, epoch_id, &smt_root);
        Self {
            epoch_id,
            smt_root,
            mac,
        }
    }

    /// Verifikasi MAC beacon. Spec §12.2.
    ///
    /// Returns true jika MAC valid untuk node_key yang diberikan.
    pub fn verify(&self, node_key: &[u8; 32]) -> bool {
        let node_key_epoch = derive_node_key_epoch(node_key, self.epoch_id);
        let expected_mac = compute_beacon_mac(&node_key_epoch, self.epoch_id, &self.smt_root);
        self.mac == expected_mac
    }

    /// Serialize ke wire format 44 bytes. Spec §12.2.
    pub fn to_bytes(&self) -> [u8; STATE_BEACON_WIRE_SIZE] {
        let mut out = [0u8; STATE_BEACON_WIRE_SIZE];
        out[0..8].copy_from_slice(&self.epoch_id.to_le_bytes());
        out[8..40].copy_from_slice(&self.smt_root);
        out[40..44].copy_from_slice(&self.mac);
        out
    }

    /// Deserialize dari wire format 44 bytes. Spec §12.2.
    pub fn from_bytes(b: &[u8; STATE_BEACON_WIRE_SIZE]) -> Self {
        let mut epoch_id_bytes = [0u8; 8];
        epoch_id_bytes.copy_from_slice(&b[0..8]);
        let epoch_id = u64::from_le_bytes(epoch_id_bytes);
        let mut smt_root = [0u8; 32];
        smt_root.copy_from_slice(&b[8..40]);
        let mut mac = [0u8; 4];
        mac.copy_from_slice(&b[40..44]);
        Self {
            epoch_id,
            smt_root,
            mac,
        }
    }
}

// ── Transport classification — spec §12.1 ────────────────────────────────────

/// Transport classification v9.0. Spec §12.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportClass {
    /// Tier 1-2: Full consensus participation. Uptime counted. Spec §12.1.
    ConsensusTransport,
    /// Tier 3-5: State Beacon ONLY. Zero uptime contribution. Spec §12.1.
    StateBeaconTransport,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_NODE_KEY: [u8; 32] = [0xABu8; 32];
    const TEST_EPOCH: u64 = 42;
    const TEST_SMT_ROOT: [u8; 32] = [0xCDu8; 32];

    // ── derive_node_key_epoch ─────────────────────────────────────────────────

    #[test]
    fn test_node_key_epoch_deterministic() {
        // NodeKey_epoch deterministik untuk input yang sama. Spec §7.4.
        let k1 = derive_node_key_epoch(&TEST_NODE_KEY, TEST_EPOCH);
        let k2 = derive_node_key_epoch(&TEST_NODE_KEY, TEST_EPOCH);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_node_key_epoch_differs_per_epoch() {
        // Epoch berbeda → NodeKey_epoch berbeda. Spec §7.4.
        let k1 = derive_node_key_epoch(&TEST_NODE_KEY, 1);
        let k2 = derive_node_key_epoch(&TEST_NODE_KEY, 2);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_node_key_epoch_differs_per_key() {
        // NodeKey berbeda → NodeKey_epoch berbeda. Spec §7.4.
        let k1 = derive_node_key_epoch(&[0xAAu8; 32], TEST_EPOCH);
        let k2 = derive_node_key_epoch(&[0xBBu8; 32], TEST_EPOCH);
        assert_ne!(k1, k2);
    }

    // ── compute_beacon_mac ────────────────────────────────────────────────────

    #[test]
    fn test_mac_is_4_bytes() {
        // MAC harus 4 bytes. Spec §12.2.
        let nke = derive_node_key_epoch(&TEST_NODE_KEY, TEST_EPOCH);
        let mac = compute_beacon_mac(&nke, TEST_EPOCH, &TEST_SMT_ROOT);
        assert_eq!(mac.len(), 4);
    }

    #[test]
    fn test_mac_deterministic() {
        // MAC deterministik. Spec §12.2.
        let nke = derive_node_key_epoch(&TEST_NODE_KEY, TEST_EPOCH);
        let m1 = compute_beacon_mac(&nke, TEST_EPOCH, &TEST_SMT_ROOT);
        let m2 = compute_beacon_mac(&nke, TEST_EPOCH, &TEST_SMT_ROOT);
        assert_eq!(m1, m2);
    }

    #[test]
    fn test_mac_differs_without_node_key_epoch() {
        // MAC dengan NodeKey_epoch berbeda → MAC berbeda.
        // Membuktikan NodeKey_epoch mempengaruhi MAC. Spec §12.2.
        let nke1 = derive_node_key_epoch(&[0xAAu8; 32], TEST_EPOCH);
        let nke2 = derive_node_key_epoch(&[0xBBu8; 32], TEST_EPOCH);
        let m1 = compute_beacon_mac(&nke1, TEST_EPOCH, &TEST_SMT_ROOT);
        let m2 = compute_beacon_mac(&nke2, TEST_EPOCH, &TEST_SMT_ROOT);
        assert_ne!(m1, m2, "MAC harus berbeda untuk NodeKey yang berbeda");
    }

    #[test]
    fn test_mac_differs_for_different_epoch() {
        // Epoch berbeda → MAC berbeda. Spec §12.2.
        let nke1 = derive_node_key_epoch(&TEST_NODE_KEY, 1);
        let nke2 = derive_node_key_epoch(&TEST_NODE_KEY, 2);
        let m1 = compute_beacon_mac(&nke1, 1, &TEST_SMT_ROOT);
        let m2 = compute_beacon_mac(&nke2, 2, &TEST_SMT_ROOT);
        assert_ne!(m1, m2);
    }

    #[test]
    fn test_mac_differs_for_different_smt_root() {
        // SMT root berbeda → MAC berbeda. Spec §12.2.
        let nke = derive_node_key_epoch(&TEST_NODE_KEY, TEST_EPOCH);
        let m1 = compute_beacon_mac(&nke, TEST_EPOCH, &[0xAAu8; 32]);
        let m2 = compute_beacon_mac(&nke, TEST_EPOCH, &[0xBBu8; 32]);
        assert_ne!(m1, m2);
    }

    // ── StateBeacon ───────────────────────────────────────────────────────────

    #[test]
    fn test_beacon_new_verify_roundtrip() {
        // Beacon yang dibuat dengan node_key harus verify dengan node_key yang sama.
        let beacon = StateBeacon::new(TEST_EPOCH, TEST_SMT_ROOT, &TEST_NODE_KEY);
        assert!(beacon.verify(&TEST_NODE_KEY));
    }

    #[test]
    fn test_beacon_verify_fails_wrong_key() {
        // Beacon verify gagal dengan NodeKey yang salah. Spec §12.2.
        let beacon = StateBeacon::new(TEST_EPOCH, TEST_SMT_ROOT, &TEST_NODE_KEY);
        assert!(!beacon.verify(&[0x00u8; 32]));
    }

    #[test]
    fn test_beacon_wire_size_44_bytes() {
        // Wire size harus 44 bytes. Spec §12.2.
        let beacon = StateBeacon::new(TEST_EPOCH, TEST_SMT_ROOT, &TEST_NODE_KEY);
        assert_eq!(beacon.to_bytes().len(), STATE_BEACON_WIRE_SIZE);
        assert_eq!(STATE_BEACON_WIRE_SIZE, 44);
    }

    #[test]
    fn test_beacon_serialization_roundtrip() {
        // Serialize → deserialize menghasilkan beacon identik. Spec §12.2.
        let beacon = StateBeacon::new(TEST_EPOCH, TEST_SMT_ROOT, &TEST_NODE_KEY);
        let bytes = beacon.to_bytes();
        let restored = StateBeacon::from_bytes(&bytes);
        assert_eq!(beacon, restored);
    }

    #[test]
    fn test_beacon_max_bytes_constant() {
        // STATE_BEACON_MAX_BYTES = 64. OSSIFIED — spec §12.2.
        assert_eq!(STATE_BEACON_MAX_BYTES, 64);
    }

    #[test]
    fn test_beacon_wire_size_fits_in_max() {
        // Wire size (44) harus muat dalam MAX_BYTES (64). Spec §12.2.
        const { assert!(STATE_BEACON_WIRE_SIZE <= STATE_BEACON_MAX_BYTES) };
    }

    #[test]
    fn test_beacon_mac_field_name() {
        // Field bernama mac, bukan checksum. Spec §12.2.
        let beacon = StateBeacon::new(TEST_EPOCH, TEST_SMT_ROOT, &TEST_NODE_KEY);
        let _ = beacon.mac; // compile error jika field tidak ada
        assert_eq!(beacon.mac.len(), 4);
    }
}
