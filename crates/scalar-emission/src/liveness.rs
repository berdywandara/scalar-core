//! LivenessSMT — State object untuk heartbeat node per epoch
//!
//! Spesifikasi: Scalar_Master_Technical_Spec.docx §B.3
//!
//! Key dalam SMT  : Poseidon2(node_id_lo ∥ epoch_id) XOR heartbeat_index
//! Value dalam SMT: BLAKE3(serialized_heartbeat)[0..8] as u64
//!
//! Konstanta ossified (§B.6 Layer 1):
//! - EXPECTED_HEARTBEATS_PER_EPOCH = 4_320  (30d × 24h × 6/h)
//! - MIN_UPTIME_RATIO_FP           = 300_000 (30% dalam basis 1_000_000)

use scalar_crypto::poseidon2::hash_2_to_1;
use std::collections::HashMap;

/// Jumlah heartbeat yang diharapkan per epoch. OSSIFIED.
pub const EXPECTED_HEARTBEATS_PER_EPOCH: u64 = 4_320;

/// Threshold uptime minimum (30%) dalam fixed-point basis 1_000_000. OSSIFIED.
pub const MIN_UPTIME_RATIO_FP: u64 = 300_000;

/// Heartbeat yang dikirim node setiap 10 menit.
/// Signature SPHINCS+ diverifikasi di luar struct ini (publik, seperti C8).
pub struct NodeHeartbeat {
    pub node_id: [u8; 32],
    pub timestamp: u64,
    pub smt_root: [u8; 32],
    pub epoch_id: u64,
    /// SPHINCS+ signature — 29.8 KB, disimpan sebagai Vec<u8>
    pub signature: Vec<u8>,
}

impl NodeHeartbeat {
    /// Kunci SMT untuk heartbeat ini pada index tertentu.
    pub fn smt_key(&self, heartbeat_index: u64) -> u64 {
        let node_id_lo = u64::from_le_bytes(self.node_id[0..8].try_into().unwrap());
        let base = hash_2_to_1(node_id_lo, self.epoch_id);
        base ^ heartbeat_index
    }

    /// Value SMT: BLAKE3(node_id ∥ timestamp ∥ smt_root ∥ epoch_id)[0..8] as u64
    pub fn smt_value(&self) -> u64 {
        let mut data = Vec::new();
        data.extend_from_slice(&self.node_id);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.smt_root);
        data.extend_from_slice(&self.epoch_id.to_le_bytes());
        let hash = blake3::hash(&data);
        u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap())
    }
}

/// LivenessSMT — menyimpan heartbeat node yang valid per epoch.
/// Identik dengan NullifierSet — gossip + root reconciliation (§B.3).
pub struct LivenessSMT {
    entries: HashMap<u64, u64>,
    heartbeat_counts: HashMap<(u64, u64), u64>, // (node_id_lo, epoch_id) → count
}

impl LivenessSMT {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            heartbeat_counts: HashMap::new(),
        }
    }

    /// Tambahkan heartbeat yang sudah terverifikasi SPHINCS+ ke SMT.
    pub fn insert_heartbeat(&mut self, hb: &NodeHeartbeat) {
        let node_id_lo = u64::from_le_bytes(hb.node_id[0..8].try_into().unwrap());
        let count_key = (node_id_lo, hb.epoch_id);
        let index = *self.heartbeat_counts.get(&count_key).unwrap_or(&0);
        self.entries.insert(hb.smt_key(index), hb.smt_value());
        self.heartbeat_counts.insert(count_key, index + 1);
    }

    /// Jumlah heartbeat valid milik node pada epoch tertentu.
    pub fn count_heartbeats(&self, node_id: &[u8; 32], epoch_id: u64) -> u64 {
        let node_id_lo = u64::from_le_bytes(node_id[0..8].try_into().unwrap());
        *self
            .heartbeat_counts
            .get(&(node_id_lo, epoch_id))
            .unwrap_or(&0)
    }

    /// Uptime weight w_i(k) dalam fixed-point basis 1_000_000.
    /// Return 0 jika di bawah threshold 30% (§B.1.4).
    pub fn compute_uptime_weight_fp(&self, node_id: &[u8; 32], epoch_id: u64) -> u64 {
        let actual = self.count_heartbeats(node_id, epoch_id);
        let ratio_fp = (actual as u128)
            .saturating_mul(1_000_000)
            .checked_div(EXPECTED_HEARTBEATS_PER_EPOCH as u128)
            .unwrap_or(0) as u64;
        if ratio_fp < MIN_UPTIME_RATIO_FP {
            0
        } else {
            ratio_fp
        }
    }

    /// Root deterministik dari seluruh isi SMT.
    /// Produksi: integrasikan dengan ScalarSMT depth-32 (Fase 3).
    pub fn root(&self) -> [u8; 32] {
        let mut pairs: Vec<(u64, u64)> = self.entries.iter().map(|(&k, &v)| (k, v)).collect();
        pairs.sort_unstable_by_key(|&(k, _)| k);
        let mut acc: u64 = 0;
        for (k, v) in pairs {
            acc = hash_2_to_1(hash_2_to_1(acc, k), v);
        }
        let hash = blake3::hash(&acc.to_le_bytes());
        *hash.as_bytes()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for LivenessSMT {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_hb(node_byte: u8, epoch_id: u64, timestamp: u64) -> NodeHeartbeat {
        let mut node_id = [0u8; 32];
        node_id[0] = node_byte;
        NodeHeartbeat {
            node_id,
            timestamp,
            smt_root: [0u8; 32],
            epoch_id,
            signature: vec![],
        }
    }

    #[test]
    fn test_insert_and_count() {
        let mut smt = LivenessSMT::new();
        let hb = dummy_hb(1, 0, 1000);
        smt.insert_heartbeat(&hb);
        assert_eq!(smt.count_heartbeats(&hb.node_id, 0), 1);
    }

    #[test]
    fn test_uptime_below_threshold_returns_zero() {
        let mut smt = LivenessSMT::new();
        let hb = dummy_hb(2, 0, 1000);
        smt.insert_heartbeat(&hb); // 1 dari 4320 — jauh di bawah 30%
        assert_eq!(smt.compute_uptime_weight_fp(&hb.node_id, 0), 0);
    }

    #[test]
    fn test_uptime_full() {
        let mut smt = LivenessSMT::new();
        let mut node_id = [0u8; 32];
        node_id[0] = 3;
        for i in 0..EXPECTED_HEARTBEATS_PER_EPOCH {
            smt.insert_heartbeat(&NodeHeartbeat {
                node_id,
                timestamp: i * 600,
                smt_root: [0u8; 32],
                epoch_id: 0,
                signature: vec![],
            });
        }
        assert_eq!(smt.compute_uptime_weight_fp(&node_id, 0), 1_000_000);
    }

    #[test]
    fn test_root_deterministic() {
        let mut s1 = LivenessSMT::new();
        let mut s2 = LivenessSMT::new();
        let hb = dummy_hb(4, 1, 500);
        s1.insert_heartbeat(&hb);
        s2.insert_heartbeat(&hb);
        assert_eq!(s1.root(), s2.root());
    }

    #[test]
    fn test_root_changes_on_insert() {
        let mut smt = LivenessSMT::new();
        let r0 = smt.root();
        smt.insert_heartbeat(&dummy_hb(5, 0, 100));
        assert_ne!(r0, smt.root());
    }

    #[test]
    fn test_separate_epochs_independent() {
        let mut smt = LivenessSMT::new();
        let hb0 = dummy_hb(10, 0, 1000);
        let hb1 = dummy_hb(10, 1, 2000);
        smt.insert_heartbeat(&hb0);
        smt.insert_heartbeat(&hb1);
        assert_eq!(smt.count_heartbeats(&hb0.node_id, 0), 1);
        assert_eq!(smt.count_heartbeats(&hb0.node_id, 1), 1);
    }
}
