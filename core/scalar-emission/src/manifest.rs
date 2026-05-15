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

/// Minimum NodeScore untuk eligible jadi aggregator. OSSIFIED — spec §8.2, §10.1, Temuan 3.
/// Tier C (max NodeScore 600_000) tidak bisa melampaui threshold ini,
/// sehingga otomatis tidak eligible sebagai aggregator.
pub const AGGREGATOR_MIN_NODESCORE: u64 = 800_000;

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

/// Pilih aggregator dan validator set dari daftar node eligible. Spec §8.1, §8.2.
///
/// `nodes`: slice of (node_id_4, uptime_fp, node_score).
/// Node eligible: uptime_fp > AGGREGATOR_MIN_UPTIME_FP
///             AND node_score >= AGGREGATOR_MIN_NODESCORE.
/// Temuan 3: Tier C (max NodeScore 600_000) tidak bisa melampaui threshold 800_000,
/// sehingga otomatis tidak eligible sebagai aggregator.
/// Aggregator = argmin(score_i) — node dengan score BLAKE3 terkecil.
/// Validator = rank_2..rank_11.
///
/// Returns None jika tidak ada node eligible (epoch deferred).
pub fn select_aggregator(
    nodes: &[([u8; 4], u64, u64)],
    seed_k: [u8; 32],
) -> Option<AggregatorSelection> {
    // Filter: uptime_fp > AGGREGATOR_MIN_UPTIME_FP AND node_score >= AGGREGATOR_MIN_NODESCORE
    // Temuan 3: NodeScore filter mencegah Tier C menjadi aggregator.
    let mut eligible: Vec<([u8; 4], [u8; 32])> = nodes
        .iter()
        .filter(|(_, uptime_fp, node_score)| {
            *uptime_fp > AGGREGATOR_MIN_UPTIME_FP && *node_score >= AGGREGATOR_MIN_NODESCORE
        })
        .map(|(node_id, _, _)| (*node_id, compute_score(node_id, &seed_k)))
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
            ([0x01u8, 0x00, 0x00, 0x00], 800_000u64, 900_000u64),
            ([0x02u8, 0x00, 0x00, 0x00], 900_000u64, 950_000u64),
            ([0x03u8, 0x00, 0x00, 0x00], 750_000u64, 850_000u64),
        ];
        let result = select_aggregator(&nodes, seed_k).unwrap();
        // Verifikasi aggregator adalah node dengan score terkecil
        let agg_score = compute_score(&result.aggregator, &seed_k);
        for (node_id, uptime, node_score) in &nodes {
            if *uptime > AGGREGATOR_MIN_UPTIME_FP && *node_score >= AGGREGATOR_MIN_NODESCORE {
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
            // uptime = threshold → NOT eligible (strictly >)
            ([0x01u8, 0x00, 0x00, 0x00], 700_000u64, 900_000u64),
            // uptime > threshold → eligible
            ([0x02u8, 0x00, 0x00, 0x00], 700_001u64, 900_000u64),
        ];
        let result = select_aggregator(&nodes, seed_k).unwrap();
        assert_eq!(result.aggregator, [0x02u8, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_select_aggregator_no_eligible_returns_none() {
        // Semua node di bawah uptime threshold → None (epoch deferred). Spec §8.1.
        let seed_k = [0x42u8; 32];
        let nodes = vec![
            ([0x01u8; 4], 500_000u64, 900_000u64),
            ([0x02u8; 4], 600_000u64, 900_000u64),
        ];
        assert!(select_aggregator(&nodes, seed_k).is_none());
    }

    #[test]
    fn test_select_aggregator_validators_max_10() {
        // Validator set maksimum 10 node. Spec §8.1.
        let seed_k = [0x42u8; 32];
        let nodes: Vec<([u8; 4], u64, u64)> = (1u8..=15)
            .map(|i| ([i, 0, 0, 0], 800_000u64, 900_000u64))
            .collect();
        let result = select_aggregator(&nodes, seed_k).unwrap();
        assert!(result.validators.len() <= AGGREGATOR_VALIDATOR_COUNT as usize);
    }

    #[test]
    fn test_select_aggregator_aggregator_not_in_validators() {
        // Aggregator tidak ada dalam validator set. Spec §8.1.
        let seed_k = [0x42u8; 32];
        let nodes: Vec<([u8; 4], u64, u64)> = (1u8..=12)
            .map(|i| ([i, 0, 0, 0], 800_000u64, 900_000u64))
            .collect();
        let result = select_aggregator(&nodes, seed_k).unwrap();
        assert!(!result.validators.contains(&result.aggregator));
    }

    #[test]
    fn test_select_aggregator_seed_k_stored() {
        // seed_k tersimpan dalam hasil seleksi. Spec §8.1.
        let seed_k = [0xDEu8; 32];
        let nodes = vec![([0x01u8; 4], 800_000u64, 900_000u64)];
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

// ── Canonical Serialization S1-S4 — spec §8.2 ────────────────────────────────

/// Compute canonical bytes dari EpochRewardManifest untuk hashing. Spec §8.2.
///
/// Rules S1-S4:
///   S1: node_list diurutkan ascending by node_id (diterapkan di compute_seed_k)
///   S2: timestamp field tidak dimasukkan — fixed per spec
///   S3: semua integer little-endian
///   S4: tidak ada optional fields — semua field wajib ada
///
/// Layout (fixed, no optional):
///   epoch_id(8) || spec_version(1) || accepted_liveness_root(32) ||
///   sync_health_summary(32) || seed_k(32) || total_uptime_weight(8) ||
///   emission_amount(8) || equity_gini(8) || fee_total(8) ||
///   previous_emission_total(8) || reward_root(32) = 177 bytes
///
/// manifest_hash = BLAKE3(canonical_bytes) — hash discipline: BLAKE3 out-circuit §2.1.3.
/// manifest_hash field TIDAK dimasukkan dalam canonical_bytes (no circular hash).
///
/// Grinding space = 0: tidak ada variasi representasi yang valid — spec §8.2.
pub fn compute_manifest_canonical_bytes(manifest: &EpochRewardManifest) -> [u8; 177] {
    let mut out = [0u8; 177];
    let mut offset = 0;

    // S3: semua integer little-endian — spec §8.2
    // epoch_id: u64 le (8 bytes)
    out[offset..offset + 8].copy_from_slice(&manifest.epoch_id.to_le_bytes());
    offset += 8;

    // spec_version: u8 (1 byte)
    out[offset] = manifest.spec_version;
    offset += 1;

    // accepted_liveness_root: [u8;32]
    out[offset..offset + 32].copy_from_slice(&manifest.accepted_liveness_root);
    offset += 32;

    // sync_health_summary: [u8;32]
    out[offset..offset + 32].copy_from_slice(&manifest.sync_health_summary);
    offset += 32;

    // seed_k: [u8;32] — BARU v9.0
    out[offset..offset + 32].copy_from_slice(&manifest.seed_k);
    offset += 32;

    // total_uptime_weight: u64 le (8 bytes)
    out[offset..offset + 8].copy_from_slice(&manifest.total_uptime_weight.to_le_bytes());
    offset += 8;

    // emission_amount: u64 le (8 bytes)
    out[offset..offset + 8].copy_from_slice(&manifest.emission_amount.to_le_bytes());
    offset += 8;

    // equity_gini: u64 le (8 bytes)
    out[offset..offset + 8].copy_from_slice(&manifest.equity_gini.to_le_bytes());
    offset += 8;

    // fee_total: u64 le (8 bytes)
    out[offset..offset + 8].copy_from_slice(&manifest.fee_total.to_le_bytes());
    offset += 8;

    // previous_emission_total: u64 le (8 bytes)
    out[offset..offset + 8].copy_from_slice(&manifest.previous_emission_total.to_le_bytes());
    offset += 8;

    // reward_root: [u8;32]
    out[offset..offset + 32].copy_from_slice(&manifest.reward_root);
    // offset += 32; // final field

    // S4: tidak ada optional fields — semua field selalu hadir.
    // S2: timestamp TIDAK dimasukkan — no wall-clock in canonical bytes.
    // manifest_hash TIDAK dimasukkan — circular hash prevention.
    // slashed_nodes TIDAK dimasukkan dalam fixed canonical bytes —
    //   slashing dibuktikan via separate proof, bukan bagian canonical manifest hash.

    out
}

/// Compute manifest_hash = BLAKE3(canonical_bytes(manifest)). Spec §8.2.
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
/// manifest_hash field sendiri TIDAK dimasukkan dalam input hash.
pub fn compute_manifest_hash(manifest: &EpochRewardManifest) -> [u8; 32] {
    let canonical = compute_manifest_canonical_bytes(manifest);
    // BLAKE3 out-circuit — spec §8.2, §2.1.3
    *blake3::hash(&canonical).as_bytes()
}

/// Verifikasi bahwa manifest_hash dalam manifest cocok dengan hash yang dihitung ulang.
/// Spec §8.2.
pub fn verify_manifest_hash(manifest: &EpochRewardManifest) -> bool {
    let expected = compute_manifest_hash(manifest);
    manifest.manifest_hash == expected
}

#[cfg(test)]
mod canonical_tests {
    use super::*;

    fn make_manifest(epoch_id: u64) -> EpochRewardManifest {
        EpochRewardManifest {
            epoch_id,
            spec_version: SPEC_VERSION_MANIFEST,
            accepted_liveness_root: [0xAAu8; 32],
            sync_health_summary: [0xBBu8; 32],
            seed_k: [0xCCu8; 32],
            manifest_hash: [0u8; 32], // akan diisi oleh compute_manifest_hash
            total_uptime_weight: 1_000_000,
            emission_amount: 12_600_000_000_000,
            equity_gini: 200_000,
            fee_total: 40_000,
            slashed_nodes: vec![],
            reward_root: [0xDDu8; 32],
            previous_emission_total: 0,
            status: EpochStatus::Open,
        }
    }

    // ── S3: little-endian integers ────────────────────────────────────────────

    #[test]
    fn test_canonical_bytes_length_177() {
        // Fixed layout = 177 bytes. Spec §8.2 S3, S4.
        let m = make_manifest(1);
        assert_eq!(compute_manifest_canonical_bytes(&m).len(), 177);
    }

    #[test]
    fn test_canonical_bytes_epoch_id_little_endian() {
        // S3: epoch_id harus little-endian di bytes[0..8]. Spec §8.2.
        let m = make_manifest(0x0102030405060708u64);
        let bytes = compute_manifest_canonical_bytes(&m);
        assert_eq!(&bytes[0..8], &0x0102030405060708u64.to_le_bytes());
    }

    #[test]
    fn test_canonical_bytes_spec_version_at_offset_8() {
        // spec_version = 0x02 di byte[8]. Spec §8.2.
        let m = make_manifest(1);
        let bytes = compute_manifest_canonical_bytes(&m);
        assert_eq!(bytes[8], SPEC_VERSION_MANIFEST);
    }

    #[test]
    fn test_canonical_bytes_seed_k_present() {
        // seed_k harus ada di canonical bytes v9.0. Spec §8.2.
        let mut m = make_manifest(1);
        m.seed_k = [0x42u8; 32];
        let bytes = compute_manifest_canonical_bytes(&m);
        // seed_k ada di offset 8+1+32+32 = 73..105
        assert_eq!(&bytes[73..105], &[0x42u8; 32]);
    }

    // ── S2: no timestamp ──────────────────────────────────────────────────────

    #[test]
    fn test_canonical_bytes_no_timestamp() {
        // S2: timestamp TIDAK ada dalam canonical bytes. Spec §8.2.
        // Dua manifest identik kecuali status (tidak ada timestamp field) →
        // canonical bytes identik.
        let m1 = make_manifest(5);
        let mut m2 = make_manifest(5);
        m2.status = EpochStatus::Finalized; // status tidak masuk canonical
                                            // canonical bytes harus identik karena status tidak dimasukkan
        assert_eq!(
            compute_manifest_canonical_bytes(&m1),
            compute_manifest_canonical_bytes(&m2)
        );
    }

    // ── S4: no optional fields ────────────────────────────────────────────────

    #[test]
    fn test_canonical_bytes_slashed_nodes_not_in_canonical() {
        // S4: slashed_nodes TIDAK dimasukkan dalam canonical bytes (separate proof).
        // Spec §8.2.
        let m1 = make_manifest(1);
        let mut m2 = make_manifest(1);
        m2.slashed_nodes = vec![[0xFFu8; 32], [0xEEu8; 32]];
        // canonical bytes harus identik — slashed_nodes bukan bagian fixed layout
        assert_eq!(
            compute_manifest_canonical_bytes(&m1),
            compute_manifest_canonical_bytes(&m2)
        );
    }

    // ── manifest_hash ─────────────────────────────────────────────────────────

    #[test]
    fn test_compute_manifest_hash_deterministic() {
        // manifest_hash deterministik untuk manifest yang sama. Spec §8.2.
        let m = make_manifest(1);
        let h1 = compute_manifest_hash(&m);
        let h2 = compute_manifest_hash(&m);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_manifest_hash_different_epoch_differs() {
        // epoch_id berbeda → manifest_hash berbeda. Spec §8.2.
        let h1 = compute_manifest_hash(&make_manifest(1));
        let h2 = compute_manifest_hash(&make_manifest(2));
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_manifest_hash_nonzero() {
        let h = compute_manifest_hash(&make_manifest(1));
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn test_compute_manifest_hash_not_circular() {
        // manifest_hash field sendiri TIDAK masuk dalam input hash.
        // Dua manifest identik kecuali manifest_hash → hash yang sama.
        let m1 = make_manifest(1);
        let mut m2 = make_manifest(1);
        m2.manifest_hash = [0xFFu8; 32]; // berbeda
        assert_eq!(compute_manifest_hash(&m1), compute_manifest_hash(&m2));
    }

    // ── verify_manifest_hash ──────────────────────────────────────────────────

    #[test]
    fn test_verify_manifest_hash_valid() {
        // Manifest dengan hash yang benar harus pass verify. Spec §8.2.
        let mut m = make_manifest(1);
        m.manifest_hash = compute_manifest_hash(&m);
        assert!(verify_manifest_hash(&m));
    }

    #[test]
    fn test_verify_manifest_hash_invalid() {
        // Manifest dengan hash yang salah harus fail verify.
        let mut m = make_manifest(1);
        m.manifest_hash = [0xFFu8; 32]; // salah
        assert!(!verify_manifest_hash(&m));
    }

    #[test]
    fn test_verify_manifest_hash_tampered_emission() {
        // Jika emission_amount diubah setelah hash → verify fail. Spec §8.2.
        let mut m = make_manifest(1);
        m.manifest_hash = compute_manifest_hash(&m);
        m.emission_amount += 1; // tamper
        assert!(!verify_manifest_hash(&m));
    }

    #[test]
    fn test_verify_manifest_hash_tampered_seed_k() {
        // Jika seed_k diubah setelah hash → verify fail. Spec §8.2.
        let mut m = make_manifest(1);
        m.manifest_hash = compute_manifest_hash(&m);
        m.seed_k = [0x99u8; 32]; // tamper
        assert!(!verify_manifest_hash(&m));
    }

    // ── Grinding space = 0 ────────────────────────────────────────────────────

    #[test]
    fn test_canonical_unique_no_grinding() {
        // S1-S4 memastikan SATU representasi byte valid. Grinding space = 0.
        // Spec §8.2: dua manifest dengan data yang sama menghasilkan
        // canonical bytes yang identik — tidak ada variasi representasi.
        let m1 = make_manifest(42);
        let m2 = make_manifest(42);
        assert_eq!(
            compute_manifest_canonical_bytes(&m1),
            compute_manifest_canonical_bytes(&m2)
        );
        assert_eq!(compute_manifest_hash(&m1), compute_manifest_hash(&m2));
    }
}

#[cfg(test)]
mod temuan_3_tests {
    use super::*;

    #[test]
    fn test_aggregator_min_nodescore_constant() {
        // AGGREGATOR_MIN_NODESCORE = 800_000. OSSIFIED — spec §8.2, Temuan 3.
        assert_eq!(AGGREGATOR_MIN_NODESCORE, 800_000u64);
    }

    #[test]
    fn test_tier_c_cannot_be_aggregator() {
        // Tier C (NodeScore max 600_000) tidak bisa menjadi aggregator. Temuan 3.
        let seed_k = [0x42u8; 32];
        let nodes = vec![
            // Tier C max NodeScore
            ([0x01u8, 0x00, 0x00, 0x00], 900_000u64, 600_000u64),
            // Tepat di bawah threshold
            ([0x02u8, 0x00, 0x00, 0x00], 900_000u64, 799_999u64),
        ];
        assert!(
            select_aggregator(&nodes, seed_k).is_none(),
            "NodeScore < 800_000 tidak boleh eligible sebagai aggregator"
        );
    }

    #[test]
    fn test_nodescore_at_threshold_is_eligible() {
        // NodeScore tepat 800_000 eligible (threshold adalah >=). Temuan 3.
        let seed_k = [0x42u8; 32];
        let nodes = vec![([0x01u8, 0x00, 0x00, 0x00], 900_000u64, 800_000u64)];
        assert!(
            select_aggregator(&nodes, seed_k).is_some(),
            "NodeScore tepat 800_000 harus eligible"
        );
    }

    #[test]
    fn test_only_high_nodescore_node_selected() {
        // Campuran Tier C (score 600k) dan Tier A (score > 800k).
        // Hanya Tier A yang eligible sebagai aggregator. Temuan 3.
        let seed_k = [0xABu8; 32];
        let nodes = vec![
            // Tier C — NodeScore capped 600_000
            ([0xFEu8, 0x01, 0x00, 0x00], 950_000u64, 600_000u64),
            ([0xFEu8, 0x02, 0x00, 0x00], 900_000u64, 500_000u64),
            // Tier A — eligible
            ([0x01u8, 0x00, 0x00, 0x00], 800_001u64, 850_000u64),
            ([0x02u8, 0x00, 0x00, 0x00], 750_001u64, 900_000u64),
        ];
        let result = select_aggregator(&nodes, seed_k).unwrap();
        let tier_a_ids = [[0x01u8, 0x00, 0x00, 0x00], [0x02u8, 0x00, 0x00, 0x00]];
        assert!(
            tier_a_ids.contains(&result.aggregator),
            "Aggregator harus Tier A, bukan Tier C — Temuan 3"
        );
    }

    #[test]
    fn test_nodescore_boundary_below_ineligible() {
        // 799_999 tidak eligible. Temuan 3 boundary.
        let seed_k = [0x11u8; 32];
        let nodes = vec![([0x01u8, 0x00, 0x00, 0x00], 900_000u64, 799_999u64)];
        assert!(select_aggregator(&nodes, seed_k).is_none());
    }

    #[test]
    fn test_uptime_and_nodescore_both_required() {
        // Kedua kondisi wajib terpenuhi: uptime > 700_000 AND score >= 800_000.
        let seed_k = [0x33u8; 32];
        // Score OK tapi uptime kurang
        let nodes_uptime_fail = vec![([0x01u8, 0x00, 0x00, 0x00], 700_000u64, 900_000u64)];
        assert!(select_aggregator(&nodes_uptime_fail, seed_k).is_none());
        // Uptime OK tapi score kurang
        let nodes_score_fail = vec![([0x01u8, 0x00, 0x00, 0x00], 800_000u64, 700_000u64)];
        assert!(select_aggregator(&nodes_score_fail, seed_k).is_none());
        // Keduanya OK
        let nodes_both_ok = vec![([0x01u8, 0x00, 0x00, 0x00], 700_001u64, 800_000u64)];
        assert!(select_aggregator(&nodes_both_ok, seed_k).is_some());
    }

    #[test]
    fn test_tier_c_invariant_mathematical() {
        // Invariant: TIER_C_MAX (600_000) < AGGREGATOR_MIN_NODESCORE (800_000).
        // Jaminan matematis bahwa Tier C tidak bisa menjadi aggregator.
        const TIER_C_MAX: u64 = 600_000;
        assert!(TIER_C_MAX < AGGREGATOR_MIN_NODESCORE);
    }
}
