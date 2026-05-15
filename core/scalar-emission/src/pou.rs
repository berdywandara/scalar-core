// File: crates/scalar-emission/src/pou.rs

pub const FIXED_POINT_BASIS: u64 = 1_000_000;

/// compute bobot uptime based on 3 komponen per specification v5.0.
/// Pembagian bobot: Uptime 60%, root Alignment 30%, Phase Coherence 10%.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uptime_weight_components() {
        let w = compute_uptime_weight(1_000_000, 1_000_000, 1_000_000);
        assert_eq!(w, FIXED_POINT_BASIS); // 100% total
    }

    #[test]
    fn test_uptime_weight_floor_invariant() {
        let w = compute_uptime_weight(1_000_000, 1_000_000, 1_000_000);
        assert!(
            w <= FIXED_POINT_BASIS,
            "Weight tidak boleh melebihi basis 1.000.000"
        );
    }

    #[test]
    fn test_no_floating_point_in_any_calculation() {
        // Assert bahwa kalkulasi bisa dilakukan murni dengan integer fixed-point
        let res = compute_uptime_weight(500_000, 500_000, 500_000);
        assert_eq!(res, 500_000);
    }
}
