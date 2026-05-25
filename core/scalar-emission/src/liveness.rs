//! Liveness — NodeHeartbeat v9.0, Uptime Weight, Maturity, Gov Weight
//!
//! Spec §7.2 v9.0: NodeHeartbeat = 108 bytes, BLAKE3-MAC, NO SPHINCS+ per-HB.
//! Spec §7.4: maturity(j,k) = Σ w_j(epoch) untuk W_MATURE_EPOCHS epoch terakhir.
//! Spec §7.4: gov_weight(j,k) = min(maturity(j,k) / W_MATURE, 1_000_000).

use std::collections::HashMap;

// ── Ossified Constants ────────────────────────────────────────────────────────

/// Heartbeat yang diharapkan per epoch. OSSIFIED — spec §7.2.
pub const EXPECTED_HEARTBEATS_PER_EPOCH: u32 = 4_320;

/// Epoch heartbeat count — alias untuk EXPECTED_HEARTBEATS_PER_EPOCH. OSSIFIED — spec §7.2c T-1.
pub const EPOCH_HB_COUNT: u32 = 4_320;

/// Fixed-point basis global. OSSIFIED — spec §18.1.
pub const FIXED_POINT_BASIS: u64 = 1_000_000;

/// Jumlah epoch yang diakumulasi untuk maturity. OSSIFIED — spec §7.4.
pub const W_MATURE_EPOCHS: u64 = 6;

/// Nilai maturity penuh (denominator gov_weight). OSSIFIED — spec §7.4.
/// = W_MATURE_EPOCHS × EXPECTED_HEARTBEATS_PER_EPOCH × FIXED_POINT_BASIS
/// = 6 × 4_320 × 1_000_000 = 25_920_000_000
pub const W_MATURE: u64 =
    W_MATURE_EPOCHS * (EXPECTED_HEARTBEATS_PER_EPOCH as u64) * FIXED_POINT_BASIS;

// ── NodeHeartbeat v9.0 — spec §7.2 ───────────────────────────────────────────

/// NodeHeartbeat v9.1 — 148 bytes wire size. Spec §7.2, Research Package §3.1.4.
///
/// v9.1 additions (Research Package §3.1.4):
///   - TAMBAH: imt_frontier [u8;32] — IMT frontier root saat heartbeat dikirim
///   - TAMBAH: imt_count u64 — jumlah daun dalam IMT saat heartbeat dikirim
///
/// Wire layout: node_id(4) + seq_num(4) + timestamp(4) + smt_root(32) +
///              imt_frontier(32) + imt_count(8) + prev_hash(32) + mac(32) = 148 bytes
///
/// MAC construction updated (Research Package §3.1.4):
///   mac = BLAKE3(b"scalar_beacon" || NodeKey_epoch || node_id || seq_num_le32 ||
///               timestamp_le32 || smt_root || imt_frontier || imt_count_le64 || prev_hash)
///
/// INV-4.4: prev_hash includes mac of previous heartbeat (chain integrity).
#[derive(Clone, Debug, PartialEq)]
// K2-04 NOTE: struct is named NodeHeartbeat in code; spec §7.3 names it HeartbeatUnit.
// Pending team decision — see docs/decisions/DESIGN_DECISIONS_PENDING.md D.2
pub struct NodeHeartbeat {
    /// Compressed node ID — 4 bytes pertama dari BLAKE3(full_node_id). Spec §7.2.
    pub node_id: [u8; 4],
    /// Monotonic global sequence number, dimulai dari 1 setiap epoch. Spec §7.2.
    pub seq_num: u32,
    /// Delta seconds dari epoch_start_wall_clock. Spec §7.2.
    pub timestamp: u32,
    /// Root SMT saat heartbeat dikirim. Spec §7.2.
    pub smt_root: [u8; 32],
    /// IMT frontier root saat heartbeat dikirim. Research Package §3.1.4.
    /// Genesis state: [0u8;32]. Updated per append().
    pub imt_frontier: [u8; 32],
    /// Jumlah daun dalam IMT saat heartbeat dikirim. Research Package §3.1.4.
    /// Genesis state: 0.
    pub imt_count: u64,
    /// BLAKE3(heartbeat sebelumnya). Spec §7.2, Research Package §3.1.4.
    /// prev_hash menyertakan mac dari HB sebelumnya — INV-4.4 chain integrity.
    pub prev_hash: [u8; 32],
    /// BLAKE3-MAC. Research Package §3.1.4.
    /// = BLAKE3(b"scalar_beacon" || NodeKey_epoch || node_id || seq_num_le32 ||
    ///          timestamp_le32 || smt_root || imt_frontier || imt_count_le64 || prev_hash)
    pub mac: [u8; 32],
}

impl NodeHeartbeat {
    /// Serialisasi ke wire format — 148 bytes. Research Package §3.1.4.
    pub fn to_bytes(&self) -> [u8; 148] {
        let mut out = [0u8; 148];
        out[0..4].copy_from_slice(&self.node_id);
        out[4..8].copy_from_slice(&self.seq_num.to_le_bytes());
        out[8..12].copy_from_slice(&self.timestamp.to_le_bytes());
        out[12..44].copy_from_slice(&self.smt_root);
        out[44..76].copy_from_slice(&self.imt_frontier);
        out[76..84].copy_from_slice(&self.imt_count.to_le_bytes());
        out[84..116].copy_from_slice(&self.prev_hash);
        out[116..148].copy_from_slice(&self.mac);
        out
    }

    /// Deserialise dari wire format — 148 bytes. Research Package §3.1.4.
    pub fn from_bytes(b: &[u8; 148]) -> Self {
        let mut node_id = [0u8; 4];
        node_id.copy_from_slice(&b[0..4]);
        let seq_num = u32::from_le_bytes(b[4..8].try_into().unwrap());
        let timestamp = u32::from_le_bytes(b[8..12].try_into().unwrap());
        let mut smt_root = [0u8; 32];
        smt_root.copy_from_slice(&b[12..44]);
        let mut imt_frontier = [0u8; 32];
        imt_frontier.copy_from_slice(&b[44..76]);
        let imt_count = u64::from_le_bytes(b[76..84].try_into().unwrap());
        let mut prev_hash = [0u8; 32];
        prev_hash.copy_from_slice(&b[84..116]);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&b[116..148]);
        Self {
            node_id,
            seq_num,
            timestamp,
            smt_root,
            imt_frontier,
            imt_count,
            prev_hash,
            mac,
        }
    }
}

// ── NodeKey derivation — spec §7.2 ───────────────────────────────────────────

/// Derive NodeKey_epoch_i = BLAKE3(NodeKey_i || epoch_id_le64). Spec §7.2.
///
/// Compromise satu epoch tidak mempengaruhi epoch lain karena epoch_id berbeda.
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn derive_node_key_epoch(node_key: &[u8; 32], epoch_id: u64) -> [u8; 32] {
    // BLAKE3 out-circuit — spec §7.2, hash discipline §2.1.3
    let mut hasher = blake3::Hasher::new();
    hasher.update(node_key);
    hasher.update(&epoch_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

// ── MAC construction — spec §7.2 ─────────────────────────────────────────────

/// Compute MAC untuk NodeHeartbeat. Research Package §3.1.4.
///
/// mac = BLAKE3(b"scalar_beacon" || NodeKey_epoch || node_id_4 || seq_num_le32 ||
///              timestamp_le32 || smt_root || imt_frontier || imt_count_le64 || prev_hash)
///
/// Field order OSSIFIED — Research Package §3.1.4.
/// imt_frontier after smt_root, imt_count after imt_frontier, prev_hash last.
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
#[allow(clippy::too_many_arguments)]
pub fn compute_heartbeat_mac(
    node_key_epoch: &[u8; 32],
    node_id: &[u8; 4],
    seq_num: u32,
    timestamp: u32,
    smt_root: &[u8; 32],
    imt_frontier: &[u8; 32],
    imt_count: u64,
    prev_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"scalar_beacon"); // DOMAIN_BEACON — spec §2.3
    hasher.update(node_key_epoch);
    hasher.update(node_id);
    hasher.update(&seq_num.to_le_bytes());
    hasher.update(&timestamp.to_le_bytes());
    hasher.update(smt_root);
    hasher.update(imt_frontier); // BARU — Research Package §3.1.4
    hasher.update(&imt_count.to_le_bytes()); // BARU — Research Package §3.1.4
    hasher.update(prev_hash);
    *hasher.finalize().as_bytes()
}

/// Compute prev_hash untuk HeartbeatUnit berikutnya. Research Package §3.1.4. OSSIFIED.
///
/// prev_hash(n) = BLAKE3(
///     b"scalar_beacon"  ||  // DOMAIN_BEACON — spec §2.3
///     node_id_short       ||
///     seq_num(n-1) LE     ||
///     timestamp(n-1) LE   ||
///     smt_root(n-1)       ||
///     imt_frontier(n-1)   ||  // BARU v9.1
///     imt_count(n-1) LE   ||  // BARU v9.1
///     mac(n-1)               // MAC disertakan — INV-4.4 chain integrity
/// )
///
/// NOTE: prev_hash field dari HB sebelumnya TIDAK disertakan —
/// hanya mac(n-1) yang menjadi chain anchor.
///
/// Genesis: prev_hash(0) = [0u8;32] for the very first heartbeat (no prior HB).
/// (Implementation: heartbeat_service sets [0u8;32] when last_hb_bytes is None.)
/// On epoch rollover, the first HB of epoch k+1 chains from EpochAnchor.chain_head
/// of epoch k (see EpochAnchor below), NOT from a genesis_object hash.
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compute_prev_hash(hb: &NodeHeartbeat) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"scalar_beacon"); // DOMAIN_BEACON — spec §2.3
    hasher.update(&hb.node_id);
    hasher.update(&hb.seq_num.to_le_bytes());
    hasher.update(&hb.timestamp.to_le_bytes());
    hasher.update(&hb.smt_root);
    hasher.update(&hb.imt_frontier); // BARU v9.1 — Research Package §3.1.4
    hasher.update(&hb.imt_count.to_le_bytes()); // BARU v9.1
    hasher.update(&hb.mac); // mac(n-1) — chain integrity INV-4.4
    *hasher.finalize().as_bytes()
}

/// Compress full node_id ke 4 bytes — 4 bytes pertama BLAKE3(full_node_id). Spec §7.2.
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compress_node_id(full_node_id: &[u8; 32]) -> [u8; 4] {
    // BLAKE3 out-circuit — spec §7.2
    let hash = blake3::hash(full_node_id);
    let bytes = hash.as_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

// ── Uptime Weight §7.3 ────────────────────────────────────────────────────────

/// Hitung uptime weight dari 2 komponen. Spec §7.3 v6.0.
/// Semua input dan output dalam fixed-point basis 1_000_000.
/// 0.70×uptime_ratio + 0.30×root_alignment_score — phase coherence dihapus v7.0.
pub fn compute_uptime_weight(uptime_ratio: u64, root_alignment_score: u64) -> u64 {
    let component_uptime = (uptime_ratio * 700_000) / FIXED_POINT_BASIS;
    let component_align = (root_alignment_score * 300_000) / FIXED_POINT_BASIS;
    component_uptime + component_align
}

// ── EpochWeightSummary ────────────────────────────────────────────────────────

/// Summary uptime weight per node per epoch. Spec §7.4.
#[derive(Clone, Debug, PartialEq)]
pub struct EpochWeightSummary {
    pub node_id: [u8; 32],
    pub epoch_id: u64,
    /// w_j(epoch) dalam fixed-point basis 1_000_000 — spec §7.3.
    pub uptime_weight: u64,
}

// ── MaturityStore §7.4 ────────────────────────────────────────────────────────

/// Menyimpan EpochWeightSummary dan menghitung maturity + gov_weight. Spec §7.4.
#[derive(Default)]
pub struct MaturityStore {
    /// Key: (node_id, epoch_id) → uptime_weight
    summaries: HashMap<([u8; 32], u64), u64>,
}

impl MaturityStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Simpan summary uptime weight untuk satu node satu epoch.
    pub fn record(&mut self, summary: EpochWeightSummary) {
        self.summaries
            .insert((summary.node_id, summary.epoch_id), summary.uptime_weight);
    }

    /// Hitung maturity(j, current_epoch) = Σ w_j(epoch) untuk
    /// epoch ∈ [current_epoch - W_MATURE_EPOCHS, current_epoch]. Spec §7.4.
    pub fn maturity(&self, node_id: [u8; 32], current_epoch: u64) -> u64 {
        let start = current_epoch.saturating_sub(W_MATURE_EPOCHS);
        (start..=current_epoch)
            .map(|epoch| self.summaries.get(&(node_id, epoch)).copied().unwrap_or(0))
            .fold(0u64, |acc, w| acc.saturating_add(w))
    }

    /// Hitung gov_weight(j, k) = min(maturity / W_MATURE, 1_000_000). Spec §7.4.
    pub fn gov_weight(&self, node_id: [u8; 32], current_epoch: u64) -> u64 {
        let m = self.maturity(node_id, current_epoch);
        let scaled = (m as u128).saturating_mul(FIXED_POINT_BASIS as u128) / (W_MATURE as u128);
        (scaled as u64).min(FIXED_POINT_BASIS)
    }

    /// Hapus summary yang sudah lebih tua dari W_MATURE_EPOCHS + 2 epoch. Spec §7.4.
    pub fn prune(&mut self, current_epoch: u64) {
        let cutoff = current_epoch.saturating_sub(W_MATURE_EPOCHS + 2);
        self.summaries
            .retain(|&(_, epoch_id), _| epoch_id >= cutoff);
    }
}

// ── LivenessSMT ───────────────────────────────────────────────────────────────

/// LivenessSMT — tracking heartbeat chain. Spec §7.2.
pub struct LivenessSMT {
    root: [u8; 32],
}

impl LivenessSMT {
    pub fn new() -> Self {
        Self { root: [0u8; 32] }
    }

    /// Insert heartbeat — update SMT root. Spec §7.2.
    pub fn insert_heartbeat(&mut self, _hb: &NodeHeartbeat) {}

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Delegasi ke MaturityStore::gov_weight. Spec §7.4.
    pub fn compute_uptime_weight_fp(
        &self,
        node_id: [u8; 32],
        current_epoch: u64,
        store: &MaturityStore,
    ) -> u64 {
        store.gov_weight(node_id, current_epoch)
    }
}

impl Default for LivenessSMT {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn node(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    #[allow(dead_code)]
    fn node4(b: u8) -> [u8; 4] {
        [b, 0, 0, 0]
    }

    // ── NodeHeartbeat v9.0 struct ─────────────────────────────────────────────

    #[test]
    fn test_node_heartbeat_v9_fields() {
        // Spec §7.2: 6 fields, tipe yang benar.
        let hb = NodeHeartbeat {
            node_id: [0x01, 0x02, 0x03, 0x04],
            seq_num: 1u32,
            timestamp: 600u32,
            smt_root: [0xAAu8; 32],
            imt_frontier: [0u8; 32],
            imt_count: 0u64,
            prev_hash: [0xBBu8; 32],
            mac: [0xCCu8; 32],
        };
        assert_eq!(hb.node_id, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(hb.seq_num, 1u32);
        assert_eq!(hb.timestamp, 600u32);
    }

    #[test]
    fn test_node_heartbeat_wire_size_148() {
        // Research Package §3.1.4: wire size = 148 bytes.
        // 4 + 4 + 4 + 32 + 32 + 8 + 32 + 32 = 148
        let hb = NodeHeartbeat {
            node_id: [0x01, 0x00, 0x00, 0x00],
            seq_num: 1u32,
            timestamp: 0u32,
            smt_root: [0u8; 32],
            imt_frontier: [0u8; 32],
            imt_count: 0u64,
            prev_hash: [0u8; 32],
            mac: [0u8; 32],
        };
        assert_eq!(hb.to_bytes().len(), 148);
    }

    #[test]
    fn test_node_heartbeat_roundtrip() {
        // Serialisasi dan deserialisasi harus menghasilkan struct yang sama.
        let hb = NodeHeartbeat {
            node_id: [0xDE, 0xAD, 0xBE, 0xEF],
            seq_num: 42u32,
            timestamp: 1234u32,
            smt_root: [0x11u8; 32],
            imt_frontier: [0u8; 32],
            imt_count: 0u64,
            prev_hash: [0x22u8; 32],
            mac: [0x33u8; 32],
        };
        let bytes = hb.to_bytes();
        let hb2 = NodeHeartbeat::from_bytes(&bytes);
        assert_eq!(hb, hb2);
    }

    #[test]
    fn test_node_heartbeat_no_signature_field() {
        // Spec §7.2: TIDAK ada signature field di NodeHeartbeat v9.0.
        // Test ini memverifikasi bahwa struct hanya punya 6 fields yang benar.
        // Jika ada field signature, kode tidak akan compile dengan struct literal ini.
        let _ = NodeHeartbeat {
            node_id: [0u8; 4],
            seq_num: 0u32,
            timestamp: 0u32,
            smt_root: [0u8; 32],
            imt_frontier: [0u8; 32],
            imt_count: 0u64,
            prev_hash: [0u8; 32],
            mac: [0u8; 32],
        };
    }

    // ── EPOCH_HB_COUNT ────────────────────────────────────────────────────────

    #[test]
    fn test_epoch_hb_count_ossified() {
        // Spec §7.2c T-1. OSSIFIED.
        assert_eq!(EPOCH_HB_COUNT, 4_320u32);
    }

    #[test]
    fn test_epoch_hb_count_equals_expected_heartbeats() {
        // Keduanya harus identik — spec §7.2c.
        assert_eq!(EPOCH_HB_COUNT, EXPECTED_HEARTBEATS_PER_EPOCH);
    }

    // ── NodeKey_epoch derivation ──────────────────────────────────────────────

    #[test]
    fn test_derive_node_key_epoch_deterministic() {
        // Spec §7.2: BLAKE3(NodeKey_i || epoch_id_le64). Deterministik.
        let node_key = [0x42u8; 32];
        let k1 = derive_node_key_epoch(&node_key, 5);
        let k2 = derive_node_key_epoch(&node_key, 5);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_node_key_epoch_different_per_epoch() {
        // Epoch berbeda → NodeKey_epoch berbeda. Spec §7.2.
        let node_key = [0x42u8; 32];
        let k0 = derive_node_key_epoch(&node_key, 0);
        let k1 = derive_node_key_epoch(&node_key, 1);
        assert_ne!(k0, k1);
    }

    #[test]
    fn test_derive_node_key_epoch_different_keys() {
        // NodeKey berbeda → NodeKey_epoch berbeda untuk epoch sama.
        let k1 = derive_node_key_epoch(&[0x01u8; 32], 0);
        let k2 = derive_node_key_epoch(&[0x02u8; 32], 0);
        assert_ne!(k1, k2);
    }

    // ── MAC computation ───────────────────────────────────────────────────────

    #[test]
    fn test_compute_heartbeat_mac_deterministic() {
        // Spec §7.2: MAC deterministik untuk input yang sama.
        let nke = [0x01u8; 32];
        let nid = [0x02u8; 4];
        let mac1 = compute_heartbeat_mac(
            &nke,
            &nid,
            1,
            600,
            &[0xAAu8; 32],
            &[0u8; 32],
            0u64,
            &[0xBBu8; 32],
        );
        let mac2 = compute_heartbeat_mac(
            &nke,
            &nid,
            1,
            600,
            &[0xAAu8; 32],
            &[0u8; 32],
            0u64,
            &[0xBBu8; 32],
        );
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_compute_heartbeat_mac_different_seq_differs() {
        // seq_num berbeda → MAC berbeda. Spec §7.2.
        let nke = [0x01u8; 32];
        let nid = [0x02u8; 4];
        let mac1 =
            compute_heartbeat_mac(&nke, &nid, 1, 600, &[0u8; 32], &[0u8; 32], 0u64, &[0u8; 32]);
        let mac2 =
            compute_heartbeat_mac(&nke, &nid, 2, 600, &[0u8; 32], &[0u8; 32], 0u64, &[0u8; 32]);
        assert_ne!(mac1, mac2);
    }

    #[test]
    fn test_compute_heartbeat_mac_different_key_differs() {
        // NodeKey_epoch berbeda → MAC berbeda. Spec §7.2.
        let nid = [0x02u8; 4];
        let mac1 = compute_heartbeat_mac(
            &[0x01u8; 32],
            &nid,
            1,
            0,
            &[0u8; 32],
            &[0u8; 32],
            0u64,
            &[0u8; 32],
        );
        let mac2 = compute_heartbeat_mac(
            &[0xFFu8; 32],
            &nid,
            1,
            0,
            &[0u8; 32],
            &[0u8; 32],
            0u64,
            &[0u8; 32],
        );
        assert_ne!(mac1, mac2);
    }

    // ── compress_node_id ──────────────────────────────────────────────────────

    #[test]
    fn test_compress_node_id_deterministic() {
        // Spec §7.2: 4 bytes pertama BLAKE3(full_node_id). Deterministik.
        let full = [0xABu8; 32];
        let c1 = compress_node_id(&full);
        let c2 = compress_node_id(&full);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_compress_node_id_different_inputs_differ() {
        let c1 = compress_node_id(&[0x01u8; 32]);
        let c2 = compress_node_id(&[0x02u8; 32]);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_compress_node_id_len_4() {
        let c = compress_node_id(&[0xFFu8; 32]);
        assert_eq!(c.len(), 4);
    }

    // ── Constant correctness ──────────────────────────────────────────────────

    #[test]
    fn test_w_mature_value() {
        // Spec §7.4: W_MATURE = 6 × 4_320 × 1_000_000 = 25_920_000_000
        assert_eq!(W_MATURE, 25_920_000_000u64);
    }

    #[test]
    fn test_w_mature_epochs_is_six() {
        assert_eq!(W_MATURE_EPOCHS, 6);
    }

    #[test]
    fn test_expected_heartbeats_per_epoch() {
        assert_eq!(EXPECTED_HEARTBEATS_PER_EPOCH, 4_320u32);
    }

    // ── Uptime weight §7.3 ────────────────────────────────────────────────────

    #[test]
    fn test_uptime_weight_full() {
        let w = compute_uptime_weight(1_000_000, 1_000_000);
        assert_eq!(w, 1_000_000);
    }

    #[test]
    fn test_uptime_weight_only_uptime() {
        let w = compute_uptime_weight(1_000_000, 0);
        assert_eq!(w, 700_000);
    }

    #[test]
    fn test_uptime_weight_zero() {
        assert_eq!(compute_uptime_weight(0, 0), 0);
    }

    #[test]
    fn test_no_floating_point() {
        let w = compute_uptime_weight(750_000, 600_000);
        // 0.70×750k + 0.30×600k = 525k + 180k = 705k
        assert_eq!(w, 705_000u64);
    }

    // ── Maturity §7.4 ─────────────────────────────────────────────────────────

    #[test]
    fn test_maturity_zero_epochs_recorded() {
        let store = MaturityStore::new();
        assert_eq!(store.maturity(node(1), 10), 0);
    }

    #[test]
    fn test_maturity_single_epoch() {
        let mut store = MaturityStore::new();
        store.record(EpochWeightSummary {
            node_id: node(1),
            epoch_id: 10,
            uptime_weight: 800_000,
        });
        assert_eq!(store.maturity(node(1), 10), 800_000);
    }

    #[test]
    fn test_maturity_full_window_accumulates() {
        let mut store = MaturityStore::new();
        for epoch in 4u64..=10 {
            store.record(EpochWeightSummary {
                node_id: node(2),
                epoch_id: epoch,
                uptime_weight: 1_000_000,
            });
        }
        assert_eq!(store.maturity(node(2), 10), 7_000_000);
    }

    #[test]
    fn test_maturity_missing_epoch_counts_zero() {
        let mut store = MaturityStore::new();
        for epoch in 8u64..=10 {
            store.record(EpochWeightSummary {
                node_id: node(3),
                epoch_id: epoch,
                uptime_weight: 1_000_000,
            });
        }
        assert_eq!(store.maturity(node(3), 10), 3_000_000);
    }

    // ── gov_weight §7.4 ───────────────────────────────────────────────────────

    #[test]
    fn test_gov_weight_zero_maturity() {
        let store = MaturityStore::new();
        assert_eq!(store.gov_weight(node(1), 10), 0);
    }

    #[test]
    fn test_gov_weight_full_mature() {
        let mut store = MaturityStore::new();
        let per_epoch = W_MATURE;
        for epoch in 4u64..=10 {
            store.record(EpochWeightSummary {
                node_id: node(4),
                epoch_id: epoch,
                uptime_weight: per_epoch,
            });
        }
        assert_eq!(store.gov_weight(node(4), 10), 1_000_000);
    }

    #[test]
    fn test_gov_weight_half_mature() {
        let mut store = MaturityStore::new();
        store.record(EpochWeightSummary {
            node_id: node(5),
            epoch_id: 10,
            uptime_weight: W_MATURE / 2,
        });
        assert_eq!(store.gov_weight(node(5), 10), 500_000);
    }

    #[test]
    fn test_gov_weight_capped_at_basis() {
        let mut store = MaturityStore::new();
        store.record(EpochWeightSummary {
            node_id: node(6),
            epoch_id: 10,
            uptime_weight: u64::MAX / 2,
        });
        assert_eq!(store.gov_weight(node(6), 10), 1_000_000);
    }

    // ── Pruning §7.4 ──────────────────────────────────────────────────────────

    #[test]
    fn test_prune_removes_old_epochs() {
        let mut store = MaturityStore::new();
        for epoch in 1u64..=20 {
            store.record(EpochWeightSummary {
                node_id: node(7),
                epoch_id: epoch,
                uptime_weight: 500_000,
            });
        }
        store.prune(20);
        assert_eq!(store.summaries.get(&(node(7), 11)), None);
        assert!(store.summaries.contains_key(&(node(7), 12)));
    }

    // ── LivenessSMT delegation ────────────────────────────────────────────────

    #[test]
    fn test_liveness_smt_delegates_to_store() {
        let smt = LivenessSMT::new();
        let mut store = MaturityStore::new();
        store.record(EpochWeightSummary {
            node_id: node(8),
            epoch_id: 5,
            uptime_weight: W_MATURE,
        });
        let gw = smt.compute_uptime_weight_fp(node(8), 5, &store);
        assert_eq!(gw, 1_000_000);
    }
}

// ── EpochAnchor §7.2a ────────────────────────────────────────────────────────

/// EpochAnchor — SPHINCS+ commitment sekali per epoch per node. Spec §7.2a.
///
/// Dikirim di END_EPOCH (seq_num-triggered, BUKAN wall-clock — Rule T-1 §7.2c).
/// chain_head = BLAKE3(last NodeHeartbeat bytes of the epoch).
/// sig = SPHINCS+(NodeKey_epoch_i, canonical_bytes(EpochAnchor minus sig field)).
///
/// Canonical bytes untuk signing:
///   node_id(4) || epoch_id_le64(8) || hb_count_le32(4) || chain_head(32) || pubkey(64)
///   = 112 bytes total (NO sig field).
///
/// Bootstrap edge case:
///   - Epoch 0: tidak ada EpochAnchor sebelumnya.
///     prev_hash HB pertama epoch 0 = BLAKE3(genesis_object_bytes) — spec §7.2a, §12.9.
///   - Epoch k+1: prev_hash HB pertama = EpochAnchor.chain_head dari epoch k.
///
/// NodeKey_epoch_0 pubkey harus dimasukkan dalam genesis object — spec §12.10.
pub struct EpochAnchor {
    /// Compressed node ID — 4 bytes pertama BLAKE3(full_node_id). Spec §7.2.
    pub node_id: [u8; 4],
    /// Epoch ID yang di-anchor. Spec §7.2a.
    pub epoch_id: u64,
    /// Jumlah heartbeat yang dikirim dalam epoch ini. Spec §7.2a.
    pub hb_count: u32,
    /// BLAKE3(last NodeHeartbeat bytes of epoch). Spec §7.2a.
    /// Digunakan sebagai prev_hash untuk HB pertama epoch berikutnya.
    pub chain_head: [u8; 32],
    /// SPHINCS+ public key node (64 bytes). Spec §7.2a.
    pub pubkey: [u8; 64],
    /// SPHINCS+-SHAKE256s signature atas canonical_bytes(EpochAnchor minus sig).
    /// Vec<u8> karena panjang signature variable. Spec §7.2a.
    pub sig: Vec<u8>,
}

impl EpochAnchor {
    /// Canonical bytes untuk SPHINCS+ signing — NO sig field. Spec §7.2a.
    ///
    /// Layout: node_id(4) || epoch_id_le64(8) || hb_count_le32(4) ||
    ///         chain_head(32) || pubkey(64) = 112 bytes.
    pub fn canonical_bytes_to_sign(&self) -> [u8; 112] {
        let mut out = [0u8; 112];
        out[0..4].copy_from_slice(&self.node_id);
        out[4..12].copy_from_slice(&self.epoch_id.to_le_bytes());
        out[12..16].copy_from_slice(&self.hb_count.to_le_bytes());
        out[16..48].copy_from_slice(&self.chain_head);
        out[48..112].copy_from_slice(&self.pubkey);
        out
    }

    /// Compute chain_head = BLAKE3(last_heartbeat_bytes). Spec §7.2a.
    ///
    /// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
    pub fn compute_chain_head(last_heartbeat: &NodeHeartbeat) -> [u8; 32] {
        // BLAKE3 out-circuit — spec §7.2a, §2.1.3
        let bytes = last_heartbeat.to_bytes();
        *blake3::hash(&bytes).as_bytes()
    }
}

/// EpochAnchorTiming — behavioral constant. Spec §7.2a.
///
/// EpochAnchor dikirim di END_EPOCH — saat node telah mengirim
/// heartbeat ke-EPOCH_HB_COUNT dalam epoch. Bukan wall-clock.
pub const EPOCH_ANCHOR_TIMING: &str = "END_EPOCH";

/// EpochTracker — tracking heartbeat count per node per epoch. Spec §7.2a.
///
/// Digunakan untuk mendeteksi END_EPOCH via seq_num (Rule T-1).
/// Saat hb_count mencapai EPOCH_HB_COUNT, node harus produce EpochAnchor.
#[derive(Default)]
pub struct EpochTracker {
    /// Key: (node_id_4, epoch_id) → heartbeat count dalam epoch ini
    counts: std::collections::HashMap<([u8; 4], u64), u32>,
    /// Key: (node_id_4, epoch_id) → last heartbeat bytes
    last_hb: std::collections::HashMap<([u8; 4], u64), NodeHeartbeat>,
}

impl EpochTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record heartbeat — update count dan last_hb. Spec §7.2a.
    pub fn record_heartbeat(&mut self, hb: &NodeHeartbeat, epoch_id: u64) {
        let key = (hb.node_id, epoch_id);
        *self.counts.entry(key).or_insert(0) += 1;
        self.last_hb.insert(key, hb.clone());
    }

    /// Cek apakah node sudah mencapai END_EPOCH (seq_num-based). Spec §7.2c T-1.
    ///
    /// Returns true jika hb_count == EPOCH_HB_COUNT.
    /// Wall-clock TIDAK digunakan — Rule T-1.
    pub fn is_end_epoch(&self, node_id: [u8; 4], epoch_id: u64) -> bool {
        let count = self.counts.get(&(node_id, epoch_id)).copied().unwrap_or(0);
        count >= EPOCH_HB_COUNT
    }

    /// Ambil heartbeat count untuk node dalam epoch. Spec §7.2a.
    pub fn hb_count(&self, node_id: [u8; 4], epoch_id: u64) -> u32 {
        self.counts.get(&(node_id, epoch_id)).copied().unwrap_or(0)
    }

    /// Ambil last heartbeat untuk node dalam epoch. Spec §7.2a.
    pub fn last_heartbeat(&self, node_id: [u8; 4], epoch_id: u64) -> Option<&NodeHeartbeat> {
        self.last_hb.get(&(node_id, epoch_id))
    }
}

#[cfg(test)]
mod epoch_anchor_tests {
    use super::*;

    fn make_hb(seq: u32) -> NodeHeartbeat {
        NodeHeartbeat {
            node_id: [0x01, 0x02, 0x03, 0x04],
            seq_num: seq,
            timestamp: seq * 600,
            smt_root: [seq as u8; 32],
            imt_frontier: [0u8; 32],
            imt_count: 0u64,
            prev_hash: [0u8; 32],
            mac: [0u8; 32],
        }
    }

    // ── EpochAnchor struct ────────────────────────────────────────────────────

    #[test]
    fn test_epoch_anchor_has_six_fields() {
        // Spec §7.2a: 6 fields — node_id, epoch_id, hb_count, chain_head, pubkey, sig.
        let anchor = EpochAnchor {
            node_id: [0x01, 0x02, 0x03, 0x04],
            epoch_id: 1u64,
            hb_count: 4_320u32,
            chain_head: [0xAAu8; 32],
            pubkey: [0xBBu8; 64],
            sig: vec![0xCCu8; 16],
        };
        assert_eq!(anchor.node_id, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(anchor.epoch_id, 1u64);
        assert_eq!(anchor.hb_count, 4_320u32);
    }

    #[test]
    fn test_epoch_anchor_sig_is_vec() {
        // Spec §7.2a: sig = Vec<u8> (variable length). BUKAN [u8; N] fixed.
        let anchor = EpochAnchor {
            node_id: [0u8; 4],
            epoch_id: 0u64,
            hb_count: 0u32,
            chain_head: [0u8; 32],
            pubkey: [0u8; 64],
            sig: Vec::new(),
        };
        // Vec<u8> bisa push — fixed array tidak bisa
        let mut s = anchor.sig;
        s.push(0xFF);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn test_canonical_bytes_to_sign_length_112() {
        // Spec §7.2a: canonical bytes = 112 bytes (NO sig field).
        let anchor = EpochAnchor {
            node_id: [0x01, 0x02, 0x03, 0x04],
            epoch_id: 5u64,
            hb_count: 4_320u32,
            chain_head: [0xAAu8; 32],
            pubkey: [0xBBu8; 64],
            sig: vec![],
        };
        let bytes = anchor.canonical_bytes_to_sign();
        assert_eq!(bytes.len(), 112);
    }

    #[test]
    fn test_canonical_bytes_layout() {
        // Layout: node_id(4) || epoch_id_le64(8) || hb_count_le32(4) ||
        //         chain_head(32) || pubkey(64). Spec §7.2a.
        let anchor = EpochAnchor {
            node_id: [0x01, 0x02, 0x03, 0x04],
            epoch_id: 0x0102030405060708u64,
            hb_count: 0x0A0B0C0Du32,
            chain_head: [0xAAu8; 32],
            pubkey: [0xBBu8; 64],
            sig: vec![],
        };
        let bytes = anchor.canonical_bytes_to_sign();
        // node_id di bytes[0..4]
        assert_eq!(&bytes[0..4], &[0x01, 0x02, 0x03, 0x04]);
        // epoch_id little-endian di bytes[4..12]
        assert_eq!(&bytes[4..12], &0x0102030405060708u64.to_le_bytes());
        // hb_count little-endian di bytes[12..16]
        assert_eq!(&bytes[12..16], &0x0A0B0C0Du32.to_le_bytes());
        // chain_head di bytes[16..48]
        assert_eq!(&bytes[16..48], &[0xAAu8; 32]);
        // pubkey di bytes[48..112]
        assert_eq!(&bytes[48..112], &[0xBBu8; 64]);
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        // Canonical bytes harus deterministik untuk input yang sama.
        let anchor = EpochAnchor {
            node_id: [0x01, 0x00, 0x00, 0x00],
            epoch_id: 3u64,
            hb_count: 100u32,
            chain_head: [0x55u8; 32],
            pubkey: [0x66u8; 64],
            sig: vec![0xFF],
        };
        let b1 = anchor.canonical_bytes_to_sign();
        let b2 = EpochAnchor {
            node_id: [0x01, 0x00, 0x00, 0x00],
            epoch_id: 3u64,
            hb_count: 100u32,
            chain_head: [0x55u8; 32],
            pubkey: [0x66u8; 64],
            sig: vec![0xAA], // sig berbeda — tidak masuk canonical
        }
        .canonical_bytes_to_sign();
        assert_eq!(b1, b2);
    }

    // ── compute_chain_head ────────────────────────────────────────────────────

    #[test]
    fn test_compute_chain_head_deterministic() {
        // BLAKE3(last_hb_bytes) harus deterministik. Spec §7.2a.
        let hb = make_hb(4320);
        let h1 = EpochAnchor::compute_chain_head(&hb);
        let h2 = EpochAnchor::compute_chain_head(&hb);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_chain_head_different_hb_differs() {
        // HB berbeda → chain_head berbeda. Spec §7.2a.
        let h1 = EpochAnchor::compute_chain_head(&make_hb(4319));
        let h2 = EpochAnchor::compute_chain_head(&make_hb(4320));
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_chain_head_nonzero() {
        let hb = make_hb(1);
        let ch = EpochAnchor::compute_chain_head(&hb);
        assert_ne!(ch, [0u8; 32]);
    }

    // ── EpochTracker ──────────────────────────────────────────────────────────

    #[test]
    fn test_epoch_tracker_count_zero_initially() {
        let tracker = EpochTracker::new();
        assert_eq!(tracker.hb_count([0x01, 0x00, 0x00, 0x00], 0), 0);
    }

    #[test]
    fn test_epoch_tracker_records_heartbeats() {
        let mut tracker = EpochTracker::new();
        let hb = make_hb(1);
        tracker.record_heartbeat(&hb, 0);
        tracker.record_heartbeat(&hb, 0);
        assert_eq!(tracker.hb_count([0x01, 0x02, 0x03, 0x04], 0), 2);
    }

    #[test]
    fn test_epoch_tracker_is_end_epoch_false_below_count() {
        // Belum END_EPOCH jika count < EPOCH_HB_COUNT. Rule T-1. Spec §7.2c.
        let mut tracker = EpochTracker::new();
        let node = [0x01, 0x00, 0x00, 0x00];
        for i in 1..EPOCH_HB_COUNT {
            tracker.record_heartbeat(
                &NodeHeartbeat {
                    node_id: node,
                    seq_num: i,
                    timestamp: 0,
                    smt_root: [0u8; 32],
                    imt_frontier: [0u8; 32],
                    imt_count: 0u64,
                    prev_hash: [0u8; 32],
                    mac: [0u8; 32],
                },
                0,
            );
        }
        assert!(!tracker.is_end_epoch(node, 0));
    }

    #[test]
    fn test_epoch_tracker_is_end_epoch_true_at_count() {
        // END_EPOCH saat count == EPOCH_HB_COUNT. Rule T-1. Spec §7.2c.
        let mut tracker = EpochTracker::new();
        let node = [0x01, 0x00, 0x00, 0x00];
        for i in 1..=EPOCH_HB_COUNT {
            tracker.record_heartbeat(
                &NodeHeartbeat {
                    node_id: node,
                    seq_num: i,
                    timestamp: 0,
                    smt_root: [0u8; 32],
                    imt_frontier: [0u8; 32],
                    imt_count: 0u64,
                    prev_hash: [0u8; 32],
                    mac: [0u8; 32],
                },
                0,
            );
        }
        assert!(tracker.is_end_epoch(node, 0));
    }

    #[test]
    fn test_epoch_tracker_last_heartbeat() {
        // last_heartbeat harus return HB terakhir yang di-record.
        let mut tracker = EpochTracker::new();
        let hb1 = make_hb(1);
        let hb2 = make_hb(2);
        tracker.record_heartbeat(&hb1, 0);
        tracker.record_heartbeat(&hb2, 0);
        let last = tracker.last_heartbeat([0x01, 0x02, 0x03, 0x04], 0).unwrap();
        assert_eq!(last.seq_num, 2);
    }

    #[test]
    fn test_epoch_tracker_separate_epochs() {
        // Count terpisah per epoch — spec §7.2a.
        let mut tracker = EpochTracker::new();
        let node = [0x01, 0x00, 0x00, 0x00];
        tracker.record_heartbeat(
            &NodeHeartbeat {
                node_id: node,
                seq_num: 1,
                timestamp: 0,
                smt_root: [0u8; 32],
                imt_frontier: [0u8; 32],
                imt_count: 0u64,
                prev_hash: [0u8; 32],
                mac: [0u8; 32],
            },
            0,
        );
        tracker.record_heartbeat(
            &NodeHeartbeat {
                node_id: node,
                seq_num: 1,
                timestamp: 0,
                smt_root: [0u8; 32],
                imt_frontier: [0u8; 32],
                imt_count: 0u64,
                prev_hash: [0u8; 32],
                mac: [0u8; 32],
            },
            1,
        );
        assert_eq!(tracker.hb_count(node, 0), 1);
        assert_eq!(tracker.hb_count(node, 1), 1);
    }

    #[test]
    fn test_epoch_anchor_timing_constant() {
        // Spec §7.2a: EpochAnchor dikirim di END_EPOCH.
        assert_eq!(EPOCH_ANCHOR_TIMING, "END_EPOCH");
    }

    // ── TV 5.4 — MAC sensitivity to imt_frontier & imt_count (§3.1.4, INV-4.4) ─
    #[test]
    fn tv_5_4_mac_sensitive_to_imt_frontier() {
        let nke = [0x01u8; 32];
        let nid = [0x02u8; 4];
        // Identical except imt_frontier.
        let mac_a = compute_heartbeat_mac(
            &nke,
            &nid,
            1,
            600,
            &[0xAAu8; 32],
            &[0x00u8; 32],
            42u64,
            &[0xBBu8; 32],
        );
        let mac_b = compute_heartbeat_mac(
            &nke,
            &nid,
            1,
            600,
            &[0xAAu8; 32],
            &[0xCDu8; 32],
            42u64,
            &[0xBBu8; 32],
        );
        assert_ne!(
            mac_a, mac_b,
            "TV5.4: MAC must change when imt_frontier changes"
        );
    }

    #[test]
    fn tv_5_4_mac_sensitive_to_imt_count() {
        let nke = [0x01u8; 32];
        let nid = [0x02u8; 4];
        // Identical except imt_count.
        let mac_a = compute_heartbeat_mac(
            &nke,
            &nid,
            1,
            600,
            &[0xAAu8; 32],
            &[0xCDu8; 32],
            42u64,
            &[0xBBu8; 32],
        );
        let mac_b = compute_heartbeat_mac(
            &nke,
            &nid,
            1,
            600,
            &[0xAAu8; 32],
            &[0xCDu8; 32],
            43u64,
            &[0xBBu8; 32],
        );
        assert_ne!(
            mac_a, mac_b,
            "TV5.4: MAC must change when imt_count changes"
        );
    }

    // ── TV 5.4 — prev_hash chain integrity includes imt fields + mac(n-1) ─────
    #[test]
    fn tv_5_4_prev_hash_sensitive_to_imt_and_mac() {
        let base = NodeHeartbeat {
            node_id: [0x02u8; 4],
            seq_num: 1,
            timestamp: 600,
            smt_root: [0xAAu8; 32],
            imt_frontier: [0xCDu8; 32],
            imt_count: 42,
            prev_hash: [0xBBu8; 32],
            mac: [0x11u8; 32],
        };
        let h_base = compute_prev_hash(&base);

        // Changing imt_frontier(n-1) must change prev_hash(n).
        let mut a = base.clone();
        a.imt_frontier = [0xEEu8; 32];
        assert_ne!(
            h_base,
            compute_prev_hash(&a),
            "prev_hash must depend on imt_frontier(n-1)"
        );

        // Changing imt_count(n-1) must change prev_hash(n).
        let mut b = base.clone();
        b.imt_count = 99;
        assert_ne!(
            h_base,
            compute_prev_hash(&b),
            "prev_hash must depend on imt_count(n-1)"
        );

        // Changing mac(n-1) must change prev_hash(n) — INV-4.4 chain anchor.
        let mut c = base.clone();
        c.mac = [0x22u8; 32];
        assert_ne!(
            h_base,
            compute_prev_hash(&c),
            "prev_hash must depend on mac(n-1)"
        );
    }
}
