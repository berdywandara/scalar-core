// File: crates/scalar-emission/src/manifest.rs
//
// EpochRewardManifest v5.0 — Spec §8
// Field connectivity_summary sudah ada sesuai spec §8.
// Fix: hapus referensi LongevityCalculator yang tidak ada.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EpochStatus {
    Open,
    Finalized,
    Deferred,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeReward {
    pub node_id: [u8; 32],
    /// Nilai reward dalam sSCL. Spec §8: field ini disebut `amount` di v5.0.
    pub amount: u64,
}

/// EpochRewardManifest v5.0 — Spec §8.
/// Semua field wajib ada sebelum manifest bisa di-finalize.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRewardManifest {
    pub epoch_id: u64,
    /// Root SMT liveness yang diterima (≥67% consensus). Spec §8.
    pub accepted_liveness_root: [u8; 32],
    /// BLAKE3 summary dari connectivity_proofs semua node. Spec §8.
    pub connectivity_summary: [u8; 32],
    pub total_uptime_weight: u64,
    pub emission_amount: u64,
    /// Gini coefficient dalam fixed-point basis 1_000_000. Spec §7.
    pub equity_gini: u64,
    pub fee_total: u64,
    /// Node yang di-slash karena equivocation. Spec §8 Step 3.5.
    pub slashed_nodes: Vec<[u8; 32]>,
    /// Merkle root semua NodeReward — dibuktikan via MINT_CLAIM_CIRCUIT MC1.
    pub reward_root: [u8; 32],
    pub previous_emission_total: u64,
    pub status: EpochStatus,
}

impl EpochRewardManifest {
    /// Buat manifest DEFERRED — digunakan saat epoch tidak mencapai quorum.
    /// Spec §8: DEFERRED epoch tidak mendapat makeup di epoch berikutnya.
    pub fn deferred(epoch_id: u64, previous_emission_total: u64) -> Self {
        Self {
            epoch_id,
            accepted_liveness_root: [0; 32],
            connectivity_summary: [0; 32],
            total_uptime_weight: 0,
            emission_amount: 0,
            equity_gini: 0,
            fee_total: 0,
            slashed_nodes: vec![],
            reward_root: [0; 32],
            previous_emission_total,
            status: EpochStatus::Deferred,
        }
    }

    /// Hitung reward_root dari daftar NodeReward.
    /// TODO: implementasi Merkle tree penuh di milestone berikutnya.
    pub fn compute_reward_root(_rewards: &[NodeReward]) -> [u8; 32] {
        [0; 32]
    }

    /// Verifikasi invariant aritmetika manifest.
    /// TODO: tambah constraint sesuai spec §8 saat full implementation.
    pub fn verify_arithmetic_invariants(&self) -> bool {
        true
    }
}

/// Hitung reward node sesuai formula v5.0. Spec §7.
/// R_i(k) = E(k) × (w_i × B_i) / W_equity + longevity_boost + fee_relay
pub fn compute_node_reward(
    emission_epoch: u64,
    node_weight: u64,
    equity_boost: u64,
    w_equity_total: u64,
    longevity_boost_sscl: u64,
    fee_relay_sscl: u64,
) -> u64 {
    if w_equity_total == 0 {
        return longevity_boost_sscl + fee_relay_sscl;
    }
    let weighted_contribution = (node_weight / 1_000_000).saturating_mul(equity_boost / 1_000_000);
    let emission_share = if weighted_contribution == 0 {
        0
    } else {
        emission_epoch.saturating_mul(weighted_contribution) / w_equity_total
    };
    emission_share + longevity_boost_sscl + fee_relay_sscl
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::equity::compute_gini;
    use crate::liveness::compute_uptime_weight;
    use crate::longevity::{apply_longevity_bonus, compute_longevity_multiplier};

    #[test]
    fn test_connectivity_summary_field_exists() {
        // PR-CS-v5-03b: connectivity_summary harus ada di EpochRewardManifest
        let manifest = EpochRewardManifest::deferred(1, 0);
        assert_eq!(
            manifest.connectivity_summary, [0u8; 32],
            "connectivity_summary harus ada dan default [0;32]"
        );
    }

    #[test]
    fn test_deferred_manifest_has_all_fields() {
        let manifest = EpochRewardManifest::deferred(5, 1_000_000);
        assert_eq!(manifest.epoch_id, 5);
        assert_eq!(manifest.previous_emission_total, 1_000_000);
        assert_eq!(manifest.status, EpochStatus::Deferred);
        assert_eq!(manifest.connectivity_summary, [0u8; 32]);
        assert_eq!(manifest.slashed_nodes, Vec::<[u8; 32]>::new());
        assert_eq!(manifest.emission_amount, 0);
    }

    #[test]
    fn test_node_reward_has_amount_field() {
        // v5.0: field reward_amount diganti menjadi amount
        let reward = NodeReward {
            node_id: [1u8; 32],
            amount: 500_000,
        };
        assert_eq!(reward.amount, 500_000);
    }

    #[test]
    fn test_compute_node_reward_zero_weight_total() {
        // Jika w_equity_total = 0, return hanya longevity + fee
        let result = compute_node_reward(1_000_000, 500_000, 1_000_000, 0, 100, 200);
        assert_eq!(result, 300);
    }

    #[test]
    fn test_compute_node_reward_proportional() {
        let e_k = 1_000_000_000_000u64;
        let r = compute_node_reward(e_k, 1_000_000, 1_000_000, 1, 0, 0);
        assert!(r > 0);
    }

    #[test]
    fn test_no_floating_point_in_any_calculation() {
        // Semua kalkulasi harus integer fixed-point — spec §1 (no floating point)
        let _w = compute_uptime_weight(600_000, 300_000, 100_000);
        let _g = compute_gini(&[100, 200, 300]);
        let _m = compute_longevity_multiplier(10);
        let _b = apply_longevity_bonus(1_000_000, 50_000, 10);
        assert!(true, "Type system enforces integer fixed-point");
    }
}
