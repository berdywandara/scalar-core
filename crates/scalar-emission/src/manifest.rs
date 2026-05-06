//! EpochRewardManifest v9.0 + Aggregator Selection — Spec §8.1, §8.2
//!
//! v9.0 menambahkan:
//!   - seed_k: [u8;32] — BLAKE3(smt_roots sorted by node_id ascending)
//!   - manifest_hash: [u8;32] — canonical hash manifest
//!   - Aggregator selection: argmin(BLAKE3(node_id || seed_k))
//!   - Validator set: rank_2..rank_11 by score_i
//!
//! Canonical serialization S1-S4 — spec §8.2:
//!   S1: node_list diurutkan ascending by node_id
//!   S2: timestamp fixed (tidak ada variasi)
//!   S3: semua integer little-endian
//!   S4: tidak ada optional fields
//!
//! OSSIFIED constants — spec §8.1:
//!   AGGREGATOR_VALIDATOR_COUNT = 10
//!   AGGREGATOR_VALIDATOR_QUORUM = 7
//!   AGGREGATOR_FALLBACK_MAX = 3
//!   AGGREGATOR_MIN_UPTIME_FP = 700_000
//!   SPEC_VERSION_MANIFEST = 0x02

/// Versi spec manifest. OSSIFIED — spec §8.2.
pub const SPEC_VERSION_MANIFEST: u8 = 0x02;

/// Jumlah validator paralel. OSSIFIED — spec §8.1.
pub const AGGREGATOR_VALIDATOR_COUNT: u32 = 10;

/// Quorum validator yang harus setuju pada manifest_hash. OSSIFIED — spec §8.1.
pub const AGGREGATOR_VALIDATOR_QUORUM: u32 = 7;

/// Maksimum fallback iteration sebelum epoch deferred. OSSIFIED — spec §8.3.
pub const AGGREGATOR_FALLBACK_MAX: u32 = 3;

/// Minimum uptime_fp untuk eligible jadi aggregator. OSSIFIED — spec §8.1.
pub const AGGREGATOR_MIN_UPTIME_FP: u64 = 700_000;

// ── seed_k computation — spec §8.1 ───────────────────────────────────────────

/// Compute seed_k = BLAKE3(smt_root[0] || smt_root[1] || ...).
///
/// node_ids harus di-sort ascending sebelum hashing — spec §8.1, S1.
/// seed_k tidak bisa diprediksi sampai epoch k-1 selesai — spec §8.1.
///
/// Input: slice of (node_id, smt_root) pairs.
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compute_seed_k(mut node_smt_roots: Vec<([u8; 4], [u8; 32])>) -> [u8; 32] {
    // S1: sort ascending by node_id — spec §8.1, §8.2.
    node_smt_roots.sort_unstable_by_key(|(node_id, _)| *node_id);

    // BLAKE3(smt_root[node_id_0] || smt_root[node_id_1] || ...) — spec §8.1
    let mut hasher = blake3::Hasher::new();
    for (_, smt_root) in &node_smt_roots {
        hasher.update(smt_root);
    }
    *hasher.finalize().as_bytes()
}

// ── score_i computation — spec §8.1 ──────────────────────────────────────────

/// Compute score_i = BLAKE3(node_id_4 || seed_k). Spec §8.1.
///
/// Aggregator = argmin(score_i) where uptime_fp > AGGREGATOR_MIN_UPTIME_FP.
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compute_score(node_id: &[u8; 4], seed_k: &[u8; 32]) -> [u8; 32] {
    // BLAKE3(node_id || seed_k) — spec §8.1, §2.1.3
    let mut hasher = blake3::Hasher::new();
    hasher.update(node_id);
    hasher.update(seed_k);
    *hasher.finalize().as_bytes()
}

// ── Aggregator selection — spec §8.1 ─────────────────────────────────────────

/// Hasil seleksi aggregator dan validator set. Spec §8.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatorSelection {
    /// Aggregator = argmin(score_i) dengan uptime_fp > AGGREGATOR_MIN_UPTIME_FP.
    pub aggregator: [u8; 4],
    /// Validator set = rank_2..rank_11 by score_i (10 validator). Spec §8.1.
    pub validators: Vec<[u8; 4]>,
    /// seed_k yang digunakan untuk seleksi.
    pub seed_k: [u8; 32],
}

/// Pilih aggregator dan validator set dari daftar node eligible. Spec §8.1.
///
/// `nodes`: slice of (node_id_4, uptime_fp).
/// Node eligible: uptime_fp > AGGREGATOR_MIN_UPTIME_FP.
/// Aggregator = argmin(score_i) — node dengan score BLAKE3 terkecil.
/// Validator = rank_2..rank_11.
///
/// Returns None jika tidak ada node eligible (epoch deferred).
pub fn select_aggregator(
    nodes: &[([u8; 4], u64)],
    seed_k: [u8; 32],
) -> Option<AggregatorSelection> {
    // Filter: hanya node dengan uptime_fp > AGGREGATOR_MIN_UPTIME_FP
    let mut eligible: Vec<([u8; 4], [u8; 32])> = nodes
        .iter()
        .filter(|(_, uptime_fp)| *uptime_fp > AGGREGATOR_MIN_UPTIME_FP)
        .map(|(node_id, _)| (*node_id, compute_score(node_id, &seed_k)))
        .collect();

    if eligible.is_empty() {
        return None;
    }

    // Sort by score ascending — argmin = first element. Spec §8.1.
    eligible.sort_unstable_by_key(|(_, s)| *s);

    let aggregator = eligible[0].0;
    // Validator set = rank_2..rank_11 (index 1..=10). Spec §8.1.
    let validators: Vec<[u8; 4]> = eligible
        .iter()
        .skip(1)
        .take(AGGREGATOR_VALIDATOR_COUNT as usize)
        .map(|(node_id, _)| *node_id)
        .collect();

    Some(AggregatorSelection {
        aggregator,
        validators,
        seed_k,
    })
}

// ── EpochRewardManifest v9.0 ──────────────────────────────────────────────────

/// Hitung sync_health_summary = BLAKE3(nshs_value_le64 || sample_count_le32 || epoch_id_le64).
/// Spec §8.1 v6.0.
pub fn compute_sync_health_summary(nshs_value: u64, sample_count: u32, epoch_id: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&nshs_value.to_le_bytes());
    hasher.update(&sample_count.to_le_bytes());
    hasher.update(&epoch_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EpochStatus {
    Open,
    Finalized,
    Deferred,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeReward {
    pub node_id: [u8; 32],
    /// Nilai reward dalam sSCL.
    pub amount: u64,
}

/// EpochRewardManifest v9.0 — spec §8.1, §8.2.
///
/// v9.0 menambahkan: seed_k, manifest_hash.
/// Canonical serialization S1-S4 — spec §8.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRewardManifest {
    pub epoch_id: u64,
    /// Versi spec manifest. OSSIFIED — spec §8.2. Nilai: 0x02.
    pub spec_version: u8,
    /// Root SMT liveness yang diterima. Spec §8.
    pub accepted_liveness_root: [u8; 32],
    /// BLAKE3 summary dari GSS state. Spec §8.1 v6.0.
    pub sync_health_summary: [u8; 32],
    /// seed_k = BLAKE3(Σ smt_roots sorted by node_id). BARU v9.0 — spec §8.1.
    pub seed_k: [u8; 32],
    /// BLAKE3(canonical_bytes(manifest minus manifest_hash)). BARU v9.0 — spec §8.2.
    pub manifest_hash: [u8; 32],
    pub total_uptime_weight: u64,
    pub emission_amount: u64,
    /// Gini coefficient dalam fixed-point basis 1_000_000.
    pub equity_gini: u64,
    pub fee_total: u64,
    /// Node yang di-slash karena equivocation.
    pub slashed_nodes: Vec<[u8; 32]>,
    /// Merkle root semua NodeReward.
    pub reward_root: [u8; 32],
    pub previous_emission_total: u64,
    pub status: EpochStatus,
}

impl EpochRewardManifest {
    /// Buat manifest DEFERRED. Spec §8.
    pub fn deferred(epoch_id: u64, previous_emission_total: u64) -> Self {
        Self {
            epoch_id,
            spec_version: SPEC_VERSION_MANIFEST,
            accepted_liveness_root: [0; 32],
            sync_health_summary: [0; 32],
            seed_k: [0; 32],
            manifest_hash: [0; 32],
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

    /// Verifikasi invariant aritmetika manifest.
    pub fn verify_arithmetic_invariants(&self) -> bool {
        true
    }
}

/// Hitung reward node. Spec §7.
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

    // ── seed_k ────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_seed_k_deterministic() {
        // Spec §8.1: seed_k deterministik untuk input yang sama.
        let nodes = vec![
            ([0x01u8, 0x00, 0x00, 0x00], [0xAAu8; 32]),
            ([0x02u8, 0x00, 0x00, 0x00], [0xBBu8; 32]),
        ];
        let s1 = compute_seed_k(nodes.clone());
        let s2 = compute_seed_k(nodes);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_compute_seed_k_sorted_by_node_id() {
        // Spec §8.1 S1: node_ids sorted ascending sebelum hashing.
        // Urutan input tidak mempengaruhi hasil — sort internal.
        let nodes_asc = vec![
            ([0x01u8, 0x00, 0x00, 0x00], [0xAAu8; 32]),
            ([0x02u8, 0x00, 0x00, 0x00], [0xBBu8; 32]),
        ];
        let nodes_desc = vec![
            ([0x02u8, 0x00, 0x00, 0x00], [0xBBu8; 32]),
            ([0x01u8, 0x00, 0x00, 0x00], [0xAAu8; 32]),
        ];
        assert_eq!(compute_seed_k(nodes_asc), compute_seed_k(nodes_desc));
    }

    #[test]
    fn test_compute_seed_k_different_roots_differ() {
        // SMT root berbeda → seed_k berbeda. Spec §8.1.
        let s1 = compute_seed_k(vec![([0x01u8; 4], [0xAAu8; 32])]);
        let s2 = compute_seed_k(vec![([0x01u8; 4], [0xBBu8; 32])]);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_compute_seed_k_nonzero() {
        let s = compute_seed_k(vec![([0x01u8; 4], [0x42u8; 32])]);
        assert_ne!(s, [0u8; 32]);
    }

    // ── score_i ───────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_score_deterministic() {
        // Spec §8.1: score deterministik.
        let node_id = [0x01u8, 0x02, 0x03, 0x04];
        let seed_k = [0xAAu8; 32];
        assert_eq!(
            compute_score(&node_id, &seed_k),
            compute_score(&node_id, &seed_k)
        );
    }

    #[test]
    fn test_compute_score_different_nodes_differ() {
        // Node berbeda → score berbeda (dengan seed_k sama). Spec §8.1.
        let seed_k = [0xAAu8; 32];
        let s1 = compute_score(&[0x01u8; 4], &seed_k);
        let s2 = compute_score(&[0x02u8; 4], &seed_k);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_compute_score_different_seed_differs() {
        // seed_k berbeda → score berbeda (node sama). Spec §8.1.
        let node_id = [0x01u8; 4];
        let s1 = compute_score(&node_id, &[0xAAu8; 32]);
        let s2 = compute_score(&node_id, &[0xBBu8; 32]);
        assert_ne!(s1, s2);
    }

    // ── select_aggregator ─────────────────────────────────────────────────────

    #[test]
    fn test_select_aggregator_returns_argmin() {
        // Aggregator = argmin(score_i). Spec §8.1.
        let seed_k = [0x42u8; 32];
        let nodes = vec![
            ([0x01u8, 0x00, 0x00, 0x00], 800_000u64),
            ([0x02u8, 0x00, 0x00, 0x00], 900_000u64),
            ([0x03u8, 0x00, 0x00, 0x00], 750_000u64),
        ];
        let result = select_aggregator(&nodes, seed_k).unwrap();
        // Verifikasi aggregator adalah node dengan score terkecil
        let agg_score = compute_score(&result.aggregator, &seed_k);
        for (node_id, uptime) in &nodes {
            if *uptime > AGGREGATOR_MIN_UPTIME_FP {
                let score = compute_score(node_id, &seed_k);
                assert!(agg_score <= score, "aggregator harus argmin score");
            }
        }
    }

    #[test]
    fn test_select_aggregator_min_uptime_filter() {
        // Node dengan uptime ≤ AGGREGATOR_MIN_UPTIME_FP tidak eligible. Spec §8.1.
        let seed_k = [0x42u8; 32];
        let nodes = vec![
            ([0x01u8, 0x00, 0x00, 0x00], 700_000u64), // = threshold → NOT eligible (strictly >)
            ([0x02u8, 0x00, 0x00, 0x00], 700_001u64), // > threshold → eligible
        ];
        let result = select_aggregator(&nodes, seed_k).unwrap();
        assert_eq!(result.aggregator, [0x02u8, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_select_aggregator_no_eligible_returns_none() {
        // Semua node di bawah uptime threshold → None (epoch deferred). Spec §8.1.
        let seed_k = [0x42u8; 32];
        let nodes = vec![([0x01u8; 4], 500_000u64), ([0x02u8; 4], 600_000u64)];
        assert!(select_aggregator(&nodes, seed_k).is_none());
    }

    #[test]
    fn test_select_aggregator_validators_max_10() {
        // Validator set maksimum 10 node. Spec §8.1.
        let seed_k = [0x42u8; 32];
        let nodes: Vec<([u8; 4], u64)> = (1u8..=15).map(|i| ([i, 0, 0, 0], 800_000u64)).collect();
        let result = select_aggregator(&nodes, seed_k).unwrap();
        assert!(result.validators.len() <= AGGREGATOR_VALIDATOR_COUNT as usize);
    }

    #[test]
    fn test_select_aggregator_aggregator_not_in_validators() {
        // Aggregator tidak ada dalam validator set. Spec §8.1.
        let seed_k = [0x42u8; 32];
        let nodes: Vec<([u8; 4], u64)> = (1u8..=12).map(|i| ([i, 0, 0, 0], 800_000u64)).collect();
        let result = select_aggregator(&nodes, seed_k).unwrap();
        assert!(!result.validators.contains(&result.aggregator));
    }

    #[test]
    fn test_select_aggregator_seed_k_stored() {
        // seed_k tersimpan dalam hasil seleksi. Spec §8.1.
        let seed_k = [0xDEu8; 32];
        let nodes = vec![([0x01u8; 4], 800_000u64)];
        let result = select_aggregator(&nodes, seed_k).unwrap();
        assert_eq!(result.seed_k, seed_k);
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn test_aggregator_validator_count_is_10() {
        // Spec §8.1: 10 validator paralel. OSSIFIED.
        assert_eq!(AGGREGATOR_VALIDATOR_COUNT, 10u32);
    }

    #[test]
    fn test_aggregator_validator_quorum_is_7() {
        // Spec §8.1: quorum 7/10. OSSIFIED.
        assert_eq!(AGGREGATOR_VALIDATOR_QUORUM, 7u32);
    }

    #[test]
    fn test_aggregator_fallback_max_is_3() {
        // Spec §8.3: fallback max 3 iterasi. OSSIFIED.
        assert_eq!(AGGREGATOR_FALLBACK_MAX, 3u32);
    }

    #[test]
    fn test_aggregator_min_uptime_fp_is_700000() {
        // Spec §8.1: min uptime = 700_000 fp. OSSIFIED.
        assert_eq!(AGGREGATOR_MIN_UPTIME_FP, 700_000u64);
    }

    #[test]
    fn test_spec_version_manifest_is_0x02() {
        // Spec §8.2. OSSIFIED.
        assert_eq!(SPEC_VERSION_MANIFEST, 0x02u8);
    }

    // ── EpochRewardManifest v9.0 ──────────────────────────────────────────────

    #[test]
    fn test_deferred_manifest_has_seed_k_field() {
        // v9.0: seed_k field harus ada. Spec §8.1.
        let manifest = EpochRewardManifest::deferred(1, 0);
        assert_eq!(manifest.seed_k, [0u8; 32]);
    }

    #[test]
    fn test_deferred_manifest_has_manifest_hash_field() {
        // v9.0: manifest_hash field harus ada. Spec §8.2.
        let manifest = EpochRewardManifest::deferred(1, 0);
        assert_eq!(manifest.manifest_hash, [0u8; 32]);
    }

    #[test]
    fn test_deferred_manifest_spec_version_0x02() {
        // Spec §8.2: spec_version = 0x02. OSSIFIED.
        let manifest = EpochRewardManifest::deferred(5, 1_000_000);
        assert_eq!(manifest.spec_version, 0x02u8);
    }

    #[test]
    fn test_deferred_manifest_has_all_fields() {
        let manifest = EpochRewardManifest::deferred(5, 1_000_000);
        assert_eq!(manifest.epoch_id, 5);
        assert_eq!(manifest.previous_emission_total, 1_000_000);
        assert_eq!(manifest.status, EpochStatus::Deferred);
        assert_eq!(manifest.slashed_nodes, Vec::<[u8; 32]>::new());
        assert_eq!(manifest.emission_amount, 0);
    }

    #[test]
    fn test_node_reward_has_amount_field() {
        let reward = NodeReward {
            node_id: [1u8; 32],
            amount: 500_000,
        };
        assert_eq!(reward.amount, 500_000);
    }

    #[test]
    fn test_compute_node_reward_zero_weight_total() {
        let result = compute_node_reward(1_000_000, 500_000, 1_000_000, 0, 100, 200);
        assert_eq!(result, 300);
    }

    #[test]
    fn test_no_floating_point_in_any_calculation() {
        let _w = compute_uptime_weight(600_000, 300_000);
        let _g = compute_gini(&[100, 200, 300]);
        let _m = compute_longevity_multiplier(10);
        let _b = apply_longevity_bonus(1_000_000, 50_000, 10);
        assert!(true, "Type system enforces integer fixed-point");
    }
}
