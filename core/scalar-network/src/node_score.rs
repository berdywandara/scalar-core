//! NodeScore + Tier C Sybil Control — Spec §10.1, §12.4 v11.1
//!
//! NodeScore: metrik kesehatan node (0–1_000_000).
//! Tidak mempengaruhi reward secara langsung, tapi menentukan eligibilitas:
//!   - NMT peer: NodeScore > NMT_SCORE_THRESHOLD (800_000)
//!   - Aggregator: NodeScore > AGGREGATOR_MIN_UPTIME_FP (700_000)
//!
//! Tier C (prefix 0xFE):
//!   - NodeScore dibatasi maksimum TIER_C_MAX_NODESCORE = 600_000
//!   - Secara otomatis tidak eligible NMT (threshold 800_000 tidak bisa dicapai)
//!   - Ini menutup celah Sybil tanpa perlu fraksi eksplisit
//!
//! Spec §10.1: "Tier C — Mobile / Low-resource"
//! Spec §12.4: "Batas atas Tier C: max_score = 600_000"

// ── Ossified constants — spec §10.1, §12.4, §17 ──────────────────────────────

/// Maksimum NodeScore untuk node Tier C (prefix 0xFE). OSSIFIED — spec §10.1, §12.4.
/// Tier C tidak bisa melebihi nilai ini, sehingga otomatis tidak eligible NMT.
pub const TIER_C_MAX_NODESCORE: u64 = 600_000;

/// Threshold NodeScore untuk eligible NMT peer. OSSIFIED — spec §12.4, T-3.
/// Node dengan NodeScore ≤ NMT_SCORE_THRESHOLD tidak eligible sebagai NMT peer.
pub const NMT_SCORE_THRESHOLD: u64 = 800_000;

/// NodeScore maksimum (Tier A/B). OSSIFIED — spec §10.1.
pub const MAX_NODESCORE: u64 = 1_000_000;

/// Prefix byte node Tier C. OSSIFIED — spec §10.1.
pub const TIER_C_PREFIX: u8 = 0xFE;

/// Fixed-point basis. Spec §18.1.
pub const FIXED_POINT_BASIS: u64 = 1_000_000;

// ── Tier detection — spec §10.1 ───────────────────────────────────────────────

/// Deteksi apakah node adalah Tier C berdasarkan prefix node_id_full. Spec §10.1.
///
/// Node Tier C memiliki node_id_full[0] == 0xFE.
/// Ini berasal dari Argon2id parameter yang berbeda (16MB/100iter vs 4GB/3600iter).
///
/// Hash discipline: tidak ada hashing di fungsi ini — pure prefix check.
pub fn is_tier_c(node_id_full: &[u8; 32]) -> bool {
    node_id_full[0] == TIER_C_PREFIX
}

/// Deteksi tier berdasarkan node_id_full. Spec §10.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeTier {
    /// Tier A: Dedicated hardware. NodeScore maks 1_000_000. Spec §10.1.
    TierA,
    /// Tier B: Virtualized cloud dengan TEE. NodeScore maks 1_000_000. Spec §10.1.
    TierB,
    /// Tier C: Mobile/low-resource. NodeScore maks 600_000. Spec §10.1.
    TierC,
}

/// Ambil tier node dari node_id_full. Spec §10.1.
///
/// Tier C: node_id_full[0] == 0xFE.
/// Tier A/B: semua yang lain (dibedakan oleh TEE di runtime, bukan node_id).
pub fn get_node_tier(node_id_full: &[u8; 32]) -> NodeTier {
    if is_tier_c(node_id_full) {
        NodeTier::TierC
    } else {
        // Tier A dan B tidak bisa dibedakan dari node_id saja
        // Default ke TierA untuk keperluan scoring
        NodeTier::TierA
    }
}

// ── NodeScore computation — spec §12.4 ───────────────────────────────────────

/// NodeScore — metrik kesehatan node (0–1_000_000). Spec §12.4.
///
/// Tidak mempengaruhi reward secara langsung.
/// Digunakan untuk NMT eligibility dan adaptive fanout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeScore {
    /// node_id_full (32 bytes). Spec §10.2.
    pub node_id_full: [u8; 32],
    /// NodeScore raw (sebelum cap). Internal use.
    raw_score: u64,
    /// Tier node. Spec §10.1.
    pub tier: NodeTier,
}

impl NodeScore {
    /// Buat NodeScore baru. Score otomatis di-cap sesuai tier. Spec §12.4.
    pub fn new(node_id_full: [u8; 32], raw_score: u64) -> Self {
        let tier = get_node_tier(&node_id_full);
        Self {
            node_id_full,
            raw_score,
            tier,
        }
    }

    /// Ambil NodeScore yang sudah di-cap sesuai tier. Spec §12.4.
    ///
    /// Tier C: score dibatasi TIER_C_MAX_NODESCORE = 600_000.
    /// Tier A/B: score dibatasi MAX_NODESCORE = 1_000_000.
    pub fn score(&self) -> u64 {
        let cap = match self.tier {
            NodeTier::TierC => TIER_C_MAX_NODESCORE,
            NodeTier::TierA | NodeTier::TierB => MAX_NODESCORE,
        };
        self.raw_score.min(cap)
    }

    /// Cek apakah node eligible sebagai NMT peer. Spec §12.4, T-3.
    ///
    /// NMT mensyaratkan NodeScore > NMT_SCORE_THRESHOLD (800_000).
    /// Tier C dibatasi 600_000 → otomatis tidak eligible.
    /// Ini menutup celah Sybil tanpa perlu fraksi eksplisit.
    pub fn is_nmt_eligible(&self) -> bool {
        self.score() > NMT_SCORE_THRESHOLD
    }

    /// Cek apakah node adalah Tier C. Spec §10.1.
    pub fn is_tier_c(&self) -> bool {
        matches!(self.tier, NodeTier::TierC)
    }
}

// ── enforce_nodescore_cap — spec §12.4 ───────────────────────────────────────

/// Enforce NodeScore cap berdasarkan tier. Spec §12.4.
///
/// node dengan prefix 0xFE tidak bisa > 600_000.
/// Dipanggil setiap kali score diperbarui.
pub fn enforce_nodescore_cap(node_id_full: &[u8; 32], score: u64) -> u64 {
    if is_tier_c(node_id_full) {
        score.min(TIER_C_MAX_NODESCORE)
    } else {
        score.min(MAX_NODESCORE)
    }
}

// ── NMT peer selection filter — spec §12.4 ───────────────────────────────────

/// Filter node yang eligible sebagai NMT peer. Spec §12.4, T-3.
///
/// Mengembalikan slice dari `nodes` yang memenuhi NMT_SCORE_THRESHOLD.
/// Tier C secara otomatis terfilter karena score maks 600_000 < 800_000.
pub fn filter_nmt_eligible(nodes: &[NodeScore]) -> Vec<&NodeScore> {
    nodes.iter().filter(|n| n.is_nmt_eligible()).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tier_c_node(seed: u8) -> [u8; 32] {
        let mut id = [seed; 32];
        id[0] = TIER_C_PREFIX; // 0xFE
        id
    }

    fn tier_a_node(seed: u8) -> [u8; 32] {
        let mut id = [seed; 32];
        id[0] = 0x01; // bukan 0xFE
        id
    }

    // ── test_tier_c_nodescore_cap ─────────────────────────────────────────────

    #[test]
    fn test_tier_c_nodescore_cap() {
        // Tier C tidak bisa > 600_000. Spec §10.1, §12.4.
        let node = NodeScore::new(tier_c_node(0x42), 1_000_000);
        assert_eq!(
            node.score(),
            TIER_C_MAX_NODESCORE,
            "Tier C harus dibatasi TIER_C_MAX_NODESCORE = 600_000"
        );
        assert!(node.score() <= TIER_C_MAX_NODESCORE);
    }

    #[test]
    fn test_tier_c_nodescore_cap_at_exact_value() {
        // Score tepat 600_000 → tidak di-cap. Spec §12.4.
        let node = NodeScore::new(tier_c_node(0x01), TIER_C_MAX_NODESCORE);
        assert_eq!(node.score(), TIER_C_MAX_NODESCORE);
    }

    #[test]
    fn test_tier_c_nodescore_below_cap_unchanged() {
        // Score < 600_000 → tidak berubah. Spec §12.4.
        let node = NodeScore::new(tier_c_node(0x01), 400_000);
        assert_eq!(node.score(), 400_000);
    }

    // ── test_tier_c_nmt_ineligible ────────────────────────────────────────────

    #[test]
    fn test_tier_c_nmt_ineligible() {
        // Tier C tidak eligible NMT. Spec §12.4, T-3.
        let node = NodeScore::new(tier_c_node(0x42), 1_000_000); // raw=1M, capped=600k
        assert!(
            !node.is_nmt_eligible(),
            "Tier C tidak boleh eligible NMT — score maks 600k < threshold 800k"
        );
    }

    #[test]
    fn test_tier_c_nmt_ineligible_even_max_score() {
        // Bahkan dengan raw_score maksimum, Tier C tetap tidak eligible NMT.
        let node = NodeScore::new(tier_c_node(0x01), u64::MAX);
        assert!(
            !node.is_nmt_eligible(),
            "Tier C dengan raw_score MAX tetap tidak eligible NMT"
        );
        assert_eq!(
            node.score(),
            TIER_C_MAX_NODESCORE,
            "Score tetap dibatasi 600_000"
        );
    }

    // ── test_tier_a_b_full_score ──────────────────────────────────────────────

    #[test]
    fn test_tier_a_full_score() {
        // Tier A bisa mencapai 1_000_000. Spec §10.1.
        let node = NodeScore::new(tier_a_node(0x01), 1_000_000);
        assert_eq!(
            node.score(),
            1_000_000,
            "Tier A/B harus bisa mencapai score 1_000_000"
        );
    }

    #[test]
    fn test_tier_a_nmt_eligible() {
        // Tier A dengan score > 800_000 eligible NMT. Spec §12.4.
        let node = NodeScore::new(tier_a_node(0x01), 900_000);
        assert!(node.is_nmt_eligible());
    }

    #[test]
    fn test_tier_a_nmt_ineligible_low_score() {
        // Tier A dengan score ≤ 800_000 tidak eligible NMT. Spec §12.4.
        let node = NodeScore::new(tier_a_node(0x01), 800_000);
        assert!(
            !node.is_nmt_eligible(),
            "Score tepat 800_000 tidak eligible (butuh strictly >)"
        );
    }

    // ── test_is_tier_c_prefix_detection ──────────────────────────────────────

    #[test]
    fn test_is_tier_c_prefix_detection() {
        // Deteksi prefix 0xFE akurat. Spec §10.1.
        let tier_c = tier_c_node(0x42);
        let tier_a = tier_a_node(0x42);
        assert!(
            is_tier_c(&tier_c),
            "0xFE prefix harus terdeteksi sebagai Tier C"
        );
        assert!(!is_tier_c(&tier_a), "Non-0xFE prefix bukan Tier C");
    }

    #[test]
    fn test_is_tier_c_prefix_0xfe_exact() {
        // Hanya 0xFE yang Tier C — 0xFD dan 0xFF bukan Tier C.
        let mut id_fd = [0u8; 32];
        id_fd[0] = 0xFD;
        let mut id_ff = [0u8; 32];
        id_ff[0] = 0xFF;
        let mut id_fe = [0u8; 32];
        id_fe[0] = 0xFE;
        assert!(!is_tier_c(&id_fd));
        assert!(!is_tier_c(&id_ff));
        assert!(is_tier_c(&id_fe));
    }

    // ── test_enforce_nodescore_cap ────────────────────────────────────────────

    #[test]
    fn test_enforce_nodescore_cap_tier_c() {
        // enforce_nodescore_cap untuk Tier C. Spec §12.4.
        let id = tier_c_node(0x01);
        assert_eq!(enforce_nodescore_cap(&id, 999_999), TIER_C_MAX_NODESCORE);
        assert_eq!(enforce_nodescore_cap(&id, 600_000), 600_000);
        assert_eq!(enforce_nodescore_cap(&id, 100_000), 100_000);
    }

    #[test]
    fn test_enforce_nodescore_cap_tier_a() {
        // enforce_nodescore_cap untuk Tier A. Spec §12.4.
        let id = tier_a_node(0x01);
        assert_eq!(enforce_nodescore_cap(&id, 1_000_000), 1_000_000);
        assert_eq!(enforce_nodescore_cap(&id, 1_000_001), 1_000_000); // capped at MAX
    }

    // ── test_filter_nmt_eligible ──────────────────────────────────────────────

    #[test]
    fn test_filter_nmt_eligible_excludes_tier_c() {
        // Tier C tidak muncul di NMT peer list. Spec §12.4.
        let nodes = vec![
            NodeScore::new(tier_a_node(0x01), 900_000),   // eligible
            NodeScore::new(tier_c_node(0x02), 1_000_000), // Tier C → capped 600k → not eligible
            NodeScore::new(tier_a_node(0x03), 850_000),   // eligible
            NodeScore::new(tier_a_node(0x04), 700_000),   // below threshold → not eligible
        ];
        let eligible = filter_nmt_eligible(&nodes);
        assert_eq!(
            eligible.len(),
            2,
            "Hanya 2 node yang eligible (Tier A score > 800k)"
        );
        for n in &eligible {
            assert!(
                !n.is_tier_c(),
                "Tier C tidak boleh ada di NMT eligible list"
            );
            assert!(n.score() > NMT_SCORE_THRESHOLD);
        }
    }

    // ── test_constants ────────────────────────────────────────────────────────

    #[test]
    fn test_tier_c_max_nodescore_constant() {
        // TIER_C_MAX_NODESCORE = 600_000. OSSIFIED — spec §12.4, §17.
        assert_eq!(TIER_C_MAX_NODESCORE, 600_000u64);
    }

    #[test]
    fn test_nmt_score_threshold_constant() {
        // NMT_SCORE_THRESHOLD = 800_000. OSSIFIED — spec §12.4.
        assert_eq!(NMT_SCORE_THRESHOLD, 800_000u64);
    }

    #[test]
    fn test_tier_c_always_below_nmt_threshold() {
        // TIER_C_MAX_NODESCORE < NMT_SCORE_THRESHOLD — invariant kritis. Spec §10.1.
        const { assert!(TIER_C_MAX_NODESCORE < NMT_SCORE_THRESHOLD) };
    }

    #[test]
    fn test_tier_c_prefix_is_0xfe() {
        // TIER_C_PREFIX = 0xFE. Spec §10.1.
        assert_eq!(TIER_C_PREFIX, 0xFEu8);
    }
}
