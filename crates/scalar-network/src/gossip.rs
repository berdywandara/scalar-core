// File: crates/scalar-network/src/gossip.rs

use std::collections::HashMap;

pub const MAX_FANOUT: usize = 15; // OSSIFIED — tidak bisa lebih dari ini

/// Hitung fanout yang tepat berdasarkan order parameter Kuramoto
/// r → 1: sinkronisasi baik, fanout rendah (hemat bandwidth)
/// r → 0: sinkronisasi buruk, fanout tinggi (aggressive sync)
pub fn compute_adaptive_fanout(order_parameter_r: u64) -> usize {
    // r dalam fixed-point basis 1,000,000
    // r > 950,000 (0.95): fanout = 3  (maintenance mode)
    // r > 800,000 (0.80): fanout = 5  (normal)
    // r > 670,000 (0.67): fanout = 7  (mulai diverge)
    // r > 500,000 (0.50): fanout = 10 (crisis)
    // r ≤ 500,000:        fanout = 15 (emergency — MAX)

    match order_parameter_r {
        r if r > 950_000 => 3,
        r if r > 800_000 => 5,
        r if r > 670_000 => 7,
        r if r > 500_000 => 10,
        _ => MAX_FANOUT, // 15
    }
}

/// Helper: Mencari nilai fase mayoritas (mode)
fn compute_mode_phase(phases: &[u64]) -> u64 {
    let mut counts = HashMap::new();
    let mut max_count = 0;
    let mut mode = 0;

    for &p in phases {
        let count = counts.entry(p).or_insert(0);
        *count += 1;
        if *count > max_count {
            max_count = *count;
            mode = p;
        }
    }
    mode
}

/// Hitung Kuramoto order parameter dari fase peer
/// r = |(1/N) × Σ e^(iθⱼ)| (simplified integer approximation)
pub fn compute_order_parameter(phases: &[u64], // fase setiap peer dalam basis 1,000,000
) -> u64 {
    if phases.is_empty() {
        return 0;
    }
    // Simplified: r ≈ agreement_fraction
    // Node yang "setuju" = yang punya smt_root mayoritas
    // Untuk sekarang: hitung fraksi yang aligned
    let n = phases.len() as u64;
    let mode = compute_mode_phase(phases);
    let aligned = phases.iter().filter(|&&p| p == mode).count() as u64;

    (aligned * 1_000_000) / n
}

#[cfg(test)]
mod tests_adaptive_fanout {
    use super::*;

    #[test]
    fn test_fanout_in_sync_network() {
        // r = 0.97 → fanout = 3 (maintenance mode)
        assert_eq!(compute_adaptive_fanout(970_000), 3);
    }

    #[test]
    fn test_fanout_in_normal_network() {
        // r = 0.85 → fanout = 5
        assert_eq!(compute_adaptive_fanout(850_000), 5);
    }

    #[test]
    fn test_fanout_in_crisis_network() {
        // r = 0.55 → fanout = 10
        assert_eq!(compute_adaptive_fanout(550_000), 10);
    }

    #[test]
    fn test_fanout_in_emergency_never_exceeds_max() {
        // r = 0.10 → fanout = MAX_FANOUT = 15
        assert_eq!(compute_adaptive_fanout(100_000), MAX_FANOUT);
        assert_eq!(MAX_FANOUT, 15, "MAX_FANOUT harus 15 — OSSIFIED");
    }

    #[test]
    fn test_max_fanout_is_ossified_at_15() {
        // Verifikasi konstanta sesuai spec
        assert_eq!(MAX_FANOUT, 15);
        // Fanout tidak boleh melebihi 15 dalam kondisi apapun
        for r in 0..=1_000_000u64 {
            let fanout = compute_adaptive_fanout(r);
            assert!(
                fanout <= MAX_FANOUT,
                "Fanout {} melebihi MAX {} pada r={}",
                fanout,
                MAX_FANOUT,
                r
            );
        }
    }
}
