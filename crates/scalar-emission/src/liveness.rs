//! Liveness — Uptime Weight, Maturity, Gov Weight
//!
//! Spec §7.3: w_i(k) = 0.60×uptime_ratio + 0.30×root_alignment + 0.10×phase_coherence
//! Spec §7.4: maturity(j,k) = Σ_{epoch=k-W_MATURE_EPOCHS}^{k} w_j(epoch)
//!            gov_weight(j,k) = min(maturity(j,k) / W_MATURE, 1_000_000)
//!
//! W_MATURE = W_MATURE_EPOCHS × EXPECTED_HEARTBEATS_PER_EPOCH × FIXED_POINT_BASIS
//!          = 6 × 4_320 × 1_000_000 = 25_920_000_000

use std::collections::HashMap;

// ── Ossified Constants ────────────────────────────────────────────────────────

/// Heartbeat yang diharapkan per epoch. OSSIFIED — spec §7.7.
pub const EXPECTED_HEARTBEATS_PER_EPOCH: u32 = 4_320;

/// Fixed-point basis. OSSIFIED — spec §7.3.
pub const FIXED_POINT_BASIS: u64 = 1_000_000;

/// Jumlah epoch yang diakumulasi untuk maturity. OSSIFIED — spec §7.4.
pub const W_MATURE_EPOCHS: u64 = 6;

/// Nilai maturity penuh (denominator gov_weight). OSSIFIED — spec §7.4.
/// = W_MATURE_EPOCHS × EXPECTED_HEARTBEATS_PER_EPOCH × FIXED_POINT_BASIS
/// = 6 × 4_320 × 1_000_000 = 25_920_000_000
pub const W_MATURE: u64 =
    W_MATURE_EPOCHS * (EXPECTED_HEARTBEATS_PER_EPOCH as u64) * FIXED_POINT_BASIS;

// ── Uptime Weight §7.3 ────────────────────────────────────────────────────────

/// Hitung uptime weight dari 3 komponen. Spec §7.3.
/// Semua input dan output dalam fixed-point basis 1_000_000.
pub fn compute_uptime_weight(
    uptime_ratio: u64,
    root_alignment_score: u64,
    phase_coherence_score: u64,
) -> u64 {
    let component_uptime = (uptime_ratio * 600_000) / FIXED_POINT_BASIS;
    let component_align = (root_alignment_score * 300_000) / FIXED_POINT_BASIS;
    let component_phase = (phase_coherence_score * 100_000) / FIXED_POINT_BASIS;
    component_uptime + component_align + component_phase
}

// ── NodeHeartbeat §7.7 ────────────────────────────────────────────────────────

/// Heartbeat dari satu node dalam satu epoch. Spec §7.7.
#[derive(Clone, Debug, PartialEq)]
pub struct NodeHeartbeat {
    pub node_id: [u8; 32],
    pub timestamp: u64,
    /// V5.0 requirement — spec §7.7.
    pub seq_num: u64,
    pub smt_root: [u8; 32],
    pub epoch_id: u64,
    /// BLAKE3 out-circuit hash dari recent nullifiers — spec §7.7.
    pub connectivity_proof: [u8; 32],
    pub signature: Vec<u8>,
}

/// Hitung connectivity_proof = BLAKE3(nullifiers). Out-circuit — spec §7.7.
pub fn compute_connectivity_proof(recent_nullifiers: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for nullifier in recent_nullifiers {
        hasher.update(nullifier);
    }
    *hasher.finalize().as_bytes()
}

// ── EpochWeightSummary ────────────────────────────────────────────────────────

/// Summary uptime weight per node per epoch.
/// Disimpan selama W_MATURE_EPOCHS + 2 epoch — spec §7.4 storage impl.
#[derive(Clone, Debug, PartialEq)]
pub struct EpochWeightSummary {
    pub node_id: [u8; 32],
    pub epoch_id: u64,
    /// w_j(epoch) dalam fixed-point basis 1_000_000 — spec §7.3.
    pub uptime_weight: u64,
}

// ── MaturityStore §7.4 ────────────────────────────────────────────────────────

/// Menyimpan EpochWeightSummary dan menghitung maturity + gov_weight.
/// Spec §7.4.
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
    ///
    /// Epoch yang tidak ada datanya dianggap w=0 (node offline).
    pub fn maturity(&self, node_id: [u8; 32], current_epoch: u64) -> u64 {
        let start = current_epoch.saturating_sub(W_MATURE_EPOCHS);
        (start..=current_epoch)
            .map(|epoch| self.summaries.get(&(node_id, epoch)).copied().unwrap_or(0))
            .fold(0u64, |acc, w| acc.saturating_add(w))
    }

    /// Hitung gov_weight(j, k) = min(maturity / W_MATURE, 1_000_000). Spec §7.4.
    pub fn gov_weight(&self, node_id: [u8; 32], current_epoch: u64) -> u64 {
        let m = self.maturity(node_id, current_epoch);
        // Skala ke [0, FIXED_POINT_BASIS] dengan menghindari overflow u64
        // m / W_MATURE × FIXED_POINT_BASIS, dikap di FIXED_POINT_BASIS
        let scaled = (m as u128).saturating_mul(FIXED_POINT_BASIS as u128) / (W_MATURE as u128);
        (scaled as u64).min(FIXED_POINT_BASIS)
    }

    /// Hapus summary yang sudah lebih tua dari W_MATURE_EPOCHS + 2 epoch.
    /// Spec §7.4 storage impl.
    pub fn prune(&mut self, current_epoch: u64) {
        let cutoff = current_epoch.saturating_sub(W_MATURE_EPOCHS + 2);
        self.summaries
            .retain(|&(_, epoch_id), _| epoch_id >= cutoff);
    }
}

// ── LivenessSMT (stub — interface dipertahankan) ──────────────────────────────

/// LivenessSMT stub. compute_uptime_weight_fp kini delegasi ke MaturityStore.
pub struct LivenessSMT {
    root: [u8; 32],
}

impl LivenessSMT {
    pub fn new() -> Self {
        Self { root: [0u8; 32] }
    }

    pub fn insert_heartbeat(&mut self, _hb: &NodeHeartbeat) {}

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Delegasi ke MaturityStore::gov_weight. Spec §7.4.
    /// Caller harus menyediakan MaturityStore yang sudah diisi.
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

    // ── Constant correctness ──────────────────────────────────────────────────

    #[test]
    fn test_w_mature_value() {
        // Spec §7.4: W_MATURE = 6 × 4_320 × 1_000_000 = 25_920_000_000
        assert_eq!(W_MATURE, 25_920_000_000u64);
    }

    #[test]
    fn test_w_mature_epochs_is_six() {
        // Spec §7.4: W_MATURE_EPOCHS = 6. OSSIFIED.
        assert_eq!(W_MATURE_EPOCHS, 6);
    }

    #[test]
    fn test_expected_heartbeats_per_epoch() {
        // Spec §7.7: 4_320 heartbeat/epoch. OSSIFIED.
        assert_eq!(EXPECTED_HEARTBEATS_PER_EPOCH, 4_320u32);
    }

    // ── Uptime weight §7.3 ────────────────────────────────────────────────────

    #[test]
    fn test_uptime_weight_full() {
        let w = compute_uptime_weight(1_000_000, 1_000_000, 1_000_000);
        assert_eq!(w, 1_000_000);
    }

    #[test]
    fn test_uptime_weight_only_uptime() {
        let w = compute_uptime_weight(1_000_000, 0, 0);
        assert_eq!(w, 600_000); // 60% dari basis
    }

    #[test]
    fn test_uptime_weight_zero() {
        assert_eq!(compute_uptime_weight(0, 0, 0), 0);
    }

    // ── Maturity accumulation §7.4 ────────────────────────────────────────────

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
        // maturity pada epoch 10 = w(10) saja (window [4..=10])
        assert_eq!(store.maturity(node(1), 10), 800_000);
    }

    #[test]
    fn test_maturity_full_window_accumulates() {
        let mut store = MaturityStore::new();
        // 7 epoch berturut — window [4..=10] mencakup epoch 4–10 = 7 epoch
        // W_MATURE_EPOCHS=6 → window [10-6..=10] = [4..=10] = 7 entries
        for epoch in 4u64..=10 {
            store.record(EpochWeightSummary {
                node_id: node(2),
                epoch_id: epoch,
                uptime_weight: 1_000_000,
            });
        }
        // 7 epoch × 1_000_000 = 7_000_000
        assert_eq!(store.maturity(node(2), 10), 7_000_000);
    }

    #[test]
    fn test_maturity_missing_epoch_counts_zero() {
        let mut store = MaturityStore::new();
        // Hanya epoch 8, 9, 10 yang diisi — 7, 6, 5, 4 dianggap 0
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
        // Isi setiap epoch dengan nilai maksimum agar maturity = W_MATURE
        // W_MATURE = 6 × 4320 × 1_000_000 = 25_920_000_000
        // Kita perlu total Σ = 25_920_000_000
        // Gunakan window 7 epoch × (25_920_000_000 / 7) ≈ tidak bulat.
        // Cara mudah: isi 7 epoch masing-masing dengan per_epoch_target
        // agar total ≥ W_MATURE → gov_weight dikap di 1_000_000
        let per_epoch = W_MATURE; // jauh lebih dari cukup
        for epoch in 4u64..=10 {
            store.record(EpochWeightSummary {
                node_id: node(4),
                epoch_id: epoch,
                uptime_weight: per_epoch,
            });
        }
        assert_eq!(store.gov_weight(node(4), 10), 1_000_000); // dikap
    }

    #[test]
    fn test_gov_weight_half_mature() {
        let mut store = MaturityStore::new();
        // Isi window penuh dengan setengah W_MATURE dibagi 7 epoch
        // Target maturity = W_MATURE / 2 = 12_960_000_000
        // Per epoch = 12_960_000_000 / 7 — tidak bulat, gunakan pendekatan
        // Lebih mudah: isi 1 epoch dengan tepat W_MATURE/2
        store.record(EpochWeightSummary {
            node_id: node(5),
            epoch_id: 10,
            uptime_weight: W_MATURE / 2,
        });
        let gw = store.gov_weight(node(5), 10);
        // gov_weight = (W_MATURE/2) / W_MATURE × 1_000_000 = 500_000
        assert_eq!(gw, 500_000);
    }

    #[test]
    fn test_gov_weight_capped_at_basis() {
        let mut store = MaturityStore::new();
        // maturity jauh melebihi W_MATURE → dikap di 1_000_000
        store.record(EpochWeightSummary {
            node_id: node(6),
            epoch_id: 10,
            uptime_weight: u64::MAX / 2,
        });
        assert_eq!(store.gov_weight(node(6), 10), 1_000_000);
    }

    // ── Pruning §7.4 storage ──────────────────────────────────────────────────

    #[test]
    fn test_prune_removes_old_epochs() {
        let mut store = MaturityStore::new();
        // Rekam epoch 1–20
        for epoch in 1u64..=20 {
            store.record(EpochWeightSummary {
                node_id: node(7),
                epoch_id: epoch,
                uptime_weight: 500_000,
            });
        }
        // Prune pada current_epoch=20 → cutoff = 20 - (6+2) = 12
        // epoch < 12 dihapus
        store.prune(20);
        // Epoch 11 harus sudah hilang
        assert_eq!(
            store.summaries.get(&(node(7), 11)),
            None,
            "epoch 11 harus dipruned"
        );
        // Epoch 12 harus masih ada
        assert!(
            store.summaries.get(&(node(7), 12)).is_some(),
            "epoch 12 harus masih ada"
        );
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
        // gov_weight harus 1_000_000 (dikap)
        let gw = smt.compute_uptime_weight_fp(node(8), 5, &store);
        assert_eq!(gw, 1_000_000);
    }

    // ── No float ─────────────────────────────────────────────────────────────

    #[test]
    fn test_no_floating_point() {
        // Semua kalkulasi harus pure integer — jika ada f32/f64 kode tidak kompil
        let w = compute_uptime_weight(750_000, 600_000, 400_000);
        // 0.60×750k + 0.30×600k + 0.10×400k = 450k + 180k + 40k = 670k
        assert_eq!(w, 670_000u64);
    }
}
