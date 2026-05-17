// File: core/scalar-emission/src/pou.rs

pub const FIXED_POINT_BASIS: u64 = 1_000_000;

/// Menghitung bobot uptime berdasarkan 2 komponen sesuai spec §7.7.
///
/// w_i_fp(k) = (700_000 x uptime_ratio_fp + 300_000 x root_alignment_fp) / 1_000_000
///
/// Pembagian bobot: Uptime 70%, Root Alignment 30%. Spec §7.7. OSSIFIED.
///
/// Input dalam fixed-point basis 1_000_000:
///   uptime_ratio_fp    : 0..1_000_000
///   root_alignment_fp  : 0..1_000_000
///
/// Output: 0..1_000_000
pub fn compute_uptime_weight(uptime_ratio_fp: u64, root_alignment_fp: u64) -> u64 {
    let component_uptime = (uptime_ratio_fp * 700_000) / FIXED_POINT_BASIS;
    let component_align = (root_alignment_fp * 300_000) / FIXED_POINT_BASIS;
    component_uptime + component_align
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uptime_weight_full() {
        // 100% uptime + 100% alignment = 1_000_000. Spec §7.7.
        let w = compute_uptime_weight(1_000_000, 1_000_000);
        assert_eq!(w, FIXED_POINT_BASIS);
    }

    #[test]
    fn test_uptime_weight_uptime_only() {
        // 100% uptime, 0% alignment = 700_000. Spec §7.7.
        let w = compute_uptime_weight(1_000_000, 0);
        assert_eq!(w, 700_000);
    }

    #[test]
    fn test_uptime_weight_alignment_only() {
        // 0% uptime, 100% alignment = 300_000. Spec §7.7.
        let w = compute_uptime_weight(0, 1_000_000);
        assert_eq!(w, 300_000);
    }

    #[test]
    fn test_uptime_weight_zero() {
        // 0% uptime + 0% alignment = 0. Spec §7.7.
        let w = compute_uptime_weight(0, 0);
        assert_eq!(w, 0);
    }

    #[test]
    fn test_uptime_weight_half() {
        // 50% uptime + 50% alignment = 500_000. Spec §7.7.
        let w = compute_uptime_weight(500_000, 500_000);
        assert_eq!(w, 500_000);
    }

    #[test]
    fn test_uptime_weight_never_exceeds_basis() {
        // Weight tidak boleh melebihi 1_000_000. Spec §7.7.
        let w = compute_uptime_weight(1_000_000, 1_000_000);
        assert!(w <= FIXED_POINT_BASIS);
    }

    #[test]
    fn test_no_floating_point() {
        // Semua kalkulasi integer fixed-point. Spec §7.7.
        let w = compute_uptime_weight(500_000, 500_000);
        assert_eq!(w, 500_000);
    }

    #[test]
    fn test_uptime_weighted_70_percent() {
        // Uptime dikali 700_000 / 1_000_000 = 70%. Spec §7.7.
        let w = compute_uptime_weight(1_000_000, 0);
        assert_eq!(w, 700_000, "uptime component harus 70% dari basis");
    }

    #[test]
    fn test_alignment_weighted_30_percent() {
        // Alignment dikali 300_000 / 1_000_000 = 30%. Spec §7.7.
        let w = compute_uptime_weight(0, 1_000_000);
        assert_eq!(w, 300_000, "alignment component harus 30% dari basis");
    }
}
