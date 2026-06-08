//! NodeScore — Node health metric — SCALAR-PROTOCOL §12.4, MAD §21.1
//!
//! NodeScore: metrik kesehatan node (0–1_000_000).
//! Menentukan eligibilitas:
//!   - NMT peer     : NodeScore > NMT_SCORE_THRESHOLD (800_000) — spec §12.4, T-3
//!   - GP cap       : gov_max_fp(node_score_prev_epoch) — governance_power_v12.rs
//!   - Aggregator   : NodeScore >= 800_000 — tidak berubah
//!
//! NodeScore formula: UPTIME×500K + PROOF×300K + AGE×200K — OSSIFIED, MAD §21.1.
//! Semua node menggunakan cap yang sama: MAX_NODESCORE = 1_000_000.

// ── Ossified constants — SCALAR-PROTOCOL §12.4, MAD §21.1 ────────────────────

/// Threshold NodeScore untuk eligible NMT peer. OSSIFIED — SCALAR-PROTOCOL §12.4, T-3.
/// NodeScore harus strictly > 800_000 untuk eligible NMT.
pub const NMT_SCORE_THRESHOLD: u64 = 800_000;

/// NodeScore maksimum. OSSIFIED — SCALAR-PROTOCOL §12.4.
pub const MAX_NODESCORE: u64 = 1_000_000;

/// Fixed-point basis. Spec §18.1.
pub const FIXED_POINT_BASIS: u64 = 1_000_000;

/// NodeScore uptime component weight. OSSIFIED — MAD §21.1.
/// uptime_component = (uptime_fp / 1_000_000) × NODESCORE_UPTIME_W
pub const NODESCORE_UPTIME_W: u64 = 500_000;

/// NodeScore proof component weight. OSSIFIED — MAD §21.1.
/// proof_component = (proof_rate_fp / 1_000_000) × NODESCORE_PROOF_W
pub const NODESCORE_PROOF_W: u64 = 300_000;

/// NodeScore age component weight. OSSIFIED — MAD §21.1.
/// age_component = (age_fp / 1_000_000) × NODESCORE_AGE_W
/// Invariant: NODESCORE_UPTIME_W + NODESCORE_PROOF_W + NODESCORE_AGE_W == 1_000_000
pub const NODESCORE_AGE_W: u64 = 200_000;

/// Compile-time check: weights sum to 1_000_000. OSSIFIED — MAD §21.1.
const _: () = assert!(
    NODESCORE_UPTIME_W + NODESCORE_PROOF_W + NODESCORE_AGE_W == 1_000_000,
    "NodeScore weights must sum to 1_000_000 (MAD §21.1)"
);

// ── NodeScore struct — SCALAR-PROTOCOL §12.4 ──────────────────────────────────

/// NodeScore — metrik kesehatan node (0–1_000_000). SCALAR-PROTOCOL §12.4.
///
/// Digunakan untuk NMT eligibility dan Governance Power cap.
/// Tidak mempengaruhi reward secara langsung.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeScore {
    /// node_id_full (32 bytes). SCALAR-PROTOCOL §3.1.
    pub node_id_full: [u8; 32],
    /// Raw score sebelum cap MAX_NODESCORE. Internal use.
    raw_score: u64,
}

impl NodeScore {
    /// Buat NodeScore baru. SCALAR-PROTOCOL §12.4.
    pub fn new(node_id_full: [u8; 32], raw_score: u64) -> Self {
        Self {
            node_id_full,
            raw_score,
        }
    }

    /// NodeScore yang sudah di-cap di MAX_NODESCORE. SCALAR-PROTOCOL §12.4.
    pub fn score(&self) -> u64 {
        self.raw_score.min(MAX_NODESCORE)
    }

    /// Cek eligibilitas NMT: NodeScore > NMT_SCORE_THRESHOLD. SCALAR-PROTOCOL §12.4, T-3.
    pub fn is_nmt_eligible(&self) -> bool {
        self.score() > NMT_SCORE_THRESHOLD
    }
}

// ── enforce_nodescore_cap — SCALAR-PROTOCOL §12.4 ────────────────────────────

/// Enforce NodeScore cap di MAX_NODESCORE. SCALAR-PROTOCOL §12.4.
///
/// node_id_full dipertahankan untuk kompatibilitas API — tidak digunakan untuk cap.
pub fn enforce_nodescore_cap(_node_id_full: &[u8; 32], score: u64) -> u64 {
    score.min(MAX_NODESCORE)
}

// ── NMT peer selection filter — SCALAR-PROTOCOL §12.4 ────────────────────────

/// Filter node yang eligible sebagai NMT peer. SCALAR-PROTOCOL §12.4, T-3.
///
/// Node eligible jika NodeScore > NMT_SCORE_THRESHOLD (800_000).
pub fn filter_nmt_eligible(nodes: &[NodeScore]) -> Vec<&NodeScore> {
    nodes.iter().filter(|n| n.is_nmt_eligible()).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(seed: u8, score: u64) -> NodeScore {
        NodeScore::new([seed; 32], score)
    }

    // ── test_nodescore_cap_at_max ─────────────────────────────────────────────

    #[test]
    fn test_nodescore_cap_at_max() {
        // Score caps at MAX_NODESCORE = 1_000_000. SCALAR-PROTOCOL §12.4.
        let node = make_node(0x01, 1_500_000);
        assert_eq!(node.score(), MAX_NODESCORE);
    }

    #[test]
    fn test_nodescore_below_max_unchanged() {
        // Score < MAX_NODESCORE → tidak berubah.
        let node = make_node(0x01, 750_000);
        assert_eq!(node.score(), 750_000);
    }

    // ── test_nmt_eligibility ──────────────────────────────────────────────────

    #[test]
    fn test_tier_a_full_score() {
        // Any node dapat mencapai 1_000_000. SCALAR-PROTOCOL §12.4.
        let node = make_node(0x01, 1_000_000);
        assert_eq!(node.score(), 1_000_000);
    }

    #[test]
    fn test_tier_a_nmt_eligible() {
        // NodeScore > 800_000 → eligible NMT. SCALAR-PROTOCOL §12.4.
        let node = make_node(0x01, 900_000);
        assert!(node.is_nmt_eligible());
    }

    #[test]
    fn test_tier_a_nmt_ineligible_low_score() {
        // NodeScore tepat 800_000 → NOT eligible (strictly >). SCALAR-PROTOCOL §12.4.
        let node = make_node(0x01, 800_000);
        assert!(
            !node.is_nmt_eligible(),
            "Score tepat 800_000 tidak eligible (butuh strictly >)"
        );
    }

    // ── test_nmt_score_threshold_constant ────────────────────────────────────

    #[test]
    fn test_nmt_score_threshold_constant() {
        // NMT_SCORE_THRESHOLD = 800_000. OSSIFIED — SCALAR-PROTOCOL §12.4.
        assert_eq!(NMT_SCORE_THRESHOLD, 800_000u64);
    }

    // ── test_enforce_nodescore_cap ────────────────────────────────────────────

    #[test]
    fn test_enforce_nodescore_cap_tier_a() {
        // enforce_nodescore_cap capped at MAX_NODESCORE. SCALAR-PROTOCOL §12.4.
        let id = [0x01u8; 32];
        assert_eq!(enforce_nodescore_cap(&id, 1_000_000), 1_000_000);
        assert_eq!(enforce_nodescore_cap(&id, 1_000_001), 1_000_000); // capped at MAX
        assert_eq!(enforce_nodescore_cap(&id, 500_000), 500_000);
    }

    #[test]
    fn test_enforce_nodescore_cap_tier_c() {
        // Node dengan prefix apapun di-cap sama di MAX_NODESCORE. SCALAR-PROTOCOL §12.4.
        let id = [0xFEu8; 32]; // old Tier C prefix — no longer special
        assert_eq!(enforce_nodescore_cap(&id, 999_999), 999_999); // capped at MAX, not 600k
        assert_eq!(enforce_nodescore_cap(&id, 1_500_000), MAX_NODESCORE);
    }

    // ── test_filter_nmt_eligible ──────────────────────────────────────────────

    #[test]
    fn test_filter_nmt_eligible_excludes_tier_c() {
        // Hanya node dengan NodeScore > 800_000 yang eligible NMT.
        // Prefix 0xFE tidak lagi otomatis eksklusif — NodeScore yang menentukan.
        let nodes = vec![
            make_node(0x01, 900_000), // eligible
            make_node(0x02, 850_000), // eligible
            make_node(0x03, 800_000), // NOT eligible (exactly threshold)
            make_node(0x04, 700_000), // NOT eligible
        ];
        let eligible = filter_nmt_eligible(&nodes);
        assert_eq!(
            eligible.len(),
            2,
            "Hanya 2 node yang eligible (score > 800k)"
        );
        for n in &eligible {
            assert!(n.score() > NMT_SCORE_THRESHOLD);
        }
    }

    // ── test_is_tier_c_prefix_detection (removed) ────────────────────────────
    // Tier C prefix 0xFE tidak lagi special. Tidak ada is_tier_c() function.
    // NMT eligibility ditentukan oleh NodeScore saja.
}

// ── NodeScore formula — MAD §21.1 ─────────────────────────────────────────────

/// Compute raw NodeScore dari fixed-point component inputs. MAD §21.1.
///
/// Formula:
///   raw = (uptime_fp × NODESCORE_UPTIME_W
///        + proof_rate_fp × NODESCORE_PROOF_W
///        + age_fp × NODESCORE_AGE_W) / 1_000_000
///
/// All inputs: fixed-point in [0, 1_000_000].
/// Output:     fixed-point in [0, 1_000_000] (before MAX_NODESCORE cap).
/// Overflow:   impossible — max numerator = 3 × 1_000_000² < u128::MAX.
pub fn compute_node_score(uptime_fp: u64, proof_rate_fp: u64, age_fp: u64) -> u64 {
    let numer = (uptime_fp as u128) * (NODESCORE_UPTIME_W as u128)
        + (proof_rate_fp as u128) * (NODESCORE_PROOF_W as u128)
        + (age_fp as u128) * (NODESCORE_AGE_W as u128);
    (numer / FIXED_POINT_BASIS as u128) as u64
}

// ── OSSIFIED test vectors — MAD §21.1, §22 ────────────────────────────────────
//
// These vectors are OSSIFIED: any change to compute_node_score that produces
// a different output for these inputs is a protocol-breaking change requiring
// governance + hard fork.

/// OSSIFIED test vector: (uptime_fp, proof_rate_fp, age_fp) → expected_score.
/// MAD §21.1, §22.
pub const NODESCORE_TEST_VECTORS: &[(u64, u64, u64, u64)] = &[
    // Vector 1: all perfect → max score
    (1_000_000, 1_000_000, 1_000_000, 1_000_000),
    // Vector 2: all zero → zero score
    (0, 0, 0, 0),
    // Vector 3: uptime only → 500_000
    (1_000_000, 0, 0, 500_000),
    // Vector 4: proof only → 300_000
    (0, 1_000_000, 0, 300_000),
    // Vector 5: age only → 200_000
    (0, 0, 1_000_000, 200_000),
    // Vector 6: typical good node → 710_000
    (700_000, 800_000, 600_000, 710_000),
    // Vector 7: marginal node → 821_000
    (850_000, 820_000, 750_000, 821_000),
    // Vector 8: half performance → half score
    (500_000, 500_000, 500_000, 500_000),
];

#[cfg(test)]
mod nodescore_formula_tests {
    use super::*;

    #[test]
    fn test_nodescore_ossified_vectors() {
        // MAD §22: OSSIFIED test vectors must pass before genesis.
        for &(uptime, proof, age, expected) in NODESCORE_TEST_VECTORS {
            let actual = compute_node_score(uptime, proof, age);
            assert_eq!(
                actual, expected,
                "OSSIFIED vector failed: compute_node_score({uptime}, {proof}, {age}) \
                 = {actual}, expected {expected}. Formula change requires hard fork."
            );
        }
    }

    #[test]
    fn test_nodescore_weights_sum_to_basis() {
        // Invariant: weights sum == FIXED_POINT_BASIS. MAD §21.1.
        assert_eq!(
            NODESCORE_UPTIME_W + NODESCORE_PROOF_W + NODESCORE_AGE_W,
            FIXED_POINT_BASIS
        );
    }

    #[test]
    fn test_nodescore_output_bounded() {
        // compute_node_score harus tidak pernah melebihi 1_000_000 untuk valid inputs.
        assert!(compute_node_score(1_000_000, 1_000_000, 1_000_000) <= MAX_NODESCORE);
        assert!(compute_node_score(0, 0, 0) <= MAX_NODESCORE);
    }

    #[test]
    fn test_nodescore_no_overflow_u128() {
        // Max numerator: 3 × 1_000_000 × 1_000_000 = 3 × 10^12 << u128::MAX. Safe.
        let max = compute_node_score(1_000_000, 1_000_000, 1_000_000);
        assert_eq!(max, 1_000_000);
    }

    #[test]
    fn test_nodescore_tier_c_cap_applied() {
        // Semua node sekarang di-cap di MAX_NODESCORE = 1_000_000.
        // Node dengan prefix 0xFE tidak lagi special.
        let raw = compute_node_score(1_000_000, 1_000_000, 1_000_000);
        let node = NodeScore::new([0xFEu8; 32], raw); // old Tier C prefix
        assert_eq!(
            node.score(),
            MAX_NODESCORE,
            "All nodes capped at MAX_NODESCORE"
        );
    }
}
