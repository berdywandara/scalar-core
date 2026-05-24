// File: crates/scalar-compliance/src/v6_parameters.rs
//
// Parameter OSSIFIED v6.0 berdasarkan Scalar_Master_Technical_Spec v6.0.
// Perubahan dari v5.0: Kuramoto dihapus, GSS diimplementasikan.
// Sumber kebenaran: §7.4 v6.0, §8.1 v6.0, §12.3 v6.0, §12.8 v6.0

// ── §7.4 v6.0 Uptime Weight ───────────────────────────────────────────────────

/// Bobot uptime dalam formula w_i(k). OSSIFIED — spec §7.4 v6.0.
/// Naik dari 600_000 (v5.0) ke 700_000 (v6.0) karena phase_coherence dihapus.
pub const V6_UPTIME_WEIGHT_FACTOR: u64 = 700_000;

/// Bobot root alignment dalam formula w_i(k). OSSIFIED — spec §7.4 v6.0.
pub const V6_ALIGNMENT_WEIGHT_FACTOR: u64 = 300_000;

/// Phase coherence factor DIHAPUS di v6.0. Nilai 0 untuk dokumentasi.
pub const V6_PHASE_COHERENCE_FACTOR: u64 = 0;

/// uptime_weight_floor: komponen uptime selalu >= 70% dari total weight.
/// OSSIFIED — spec §7.4 v6.0 Invariant W-1.
pub const V6_UPTIME_WEIGHT_FLOOR: u64 = 700_000;

// ── §8.1 v6.0 Manifest ───────────────────────────────────────────────────────

/// Versi spec manifest v6.0. OSSIFIED — spec §8.1 v6.0.
/// Node v5.0 akan REJECT manifest dengan spec_version = 0x02.
// K12-02 NOTE: 0x02 is a stale pre-genesis value. The OSSIFIED genesis value is
// 0x01 (scalar_emission::dmm::SPEC_VERSION_MANIFEST). This constant is retained
// only as a historical compliance marker and is NOT used in production.
pub const V6_SPEC_VERSION_MANIFEST: u8 = 0x02;

// ── §12.3 v6.0 GSS ───────────────────────────────────────────────────────────

/// Latency maksimum untuk GSS score. OSSIFIED — spec §12.3 v6.0.
pub const V6_GSS_MAX_LATENCY_MS: u64 = 300_000;

/// Threshold staleness heartbeat untuk GSS. OSSIFIED — spec §12.3 v6.0.
pub const V6_GSS_HEARTBEAT_STALENESS_S: u64 = 900;

/// Threshold GSS untuk eclipse detection Layer 1. OSSIFIED — spec §12.8 v6.0.
pub const V6_GSS_ECLIPSE_THRESHOLD: u64 = 400_000;

// ── §12.5 v6.0 Fanout Thresholds ─────────────────────────────────────────────

/// GSS threshold fanout excellent (→ fanout 3). OSSIFIED — spec §12.5 v6.0.
pub const V6_GSS_FANOUT_EXCELLENT: u64 = 900_000;

/// GSS threshold fanout good (→ fanout 5). OSSIFIED — spec §12.5 v6.0.
pub const V6_GSS_FANOUT_GOOD: u64 = 750_000;

/// GSS threshold fanout degraded (→ fanout 7). OSSIFIED — spec §12.5 v6.0.
pub const V6_GSS_FANOUT_DEGRADED: u64 = 600_000;

/// GSS threshold fanout poor (→ fanout 10). OSSIFIED — spec §12.5 v6.0.
pub const V6_GSS_FANOUT_POOR: u64 = 400_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v6_uptime_weight_factor_ossified() {
        // Spec §7.4 v6.0: uptime factor = 700_000 (naik dari 600_000 v5.0)
        assert_eq!(V6_UPTIME_WEIGHT_FACTOR, 700_000);
    }

    #[test]
    fn test_v6_alignment_weight_factor_ossified() {
        assert_eq!(V6_ALIGNMENT_WEIGHT_FACTOR, 300_000);
    }

    #[test]
    fn test_v6_weight_factors_sum_to_basis() {
        // Spec §7.4 v6.0: 700_000 + 300_000 = 1_000_000
        assert_eq!(
            V6_UPTIME_WEIGHT_FACTOR + V6_ALIGNMENT_WEIGHT_FACTOR,
            1_000_000
        );
    }

    #[test]
    fn test_v6_phase_coherence_factor_is_zero() {
        // Spec §7.4 v6.0: phase_coherence DIHAPUS — nilai 0
        assert_eq!(V6_PHASE_COHERENCE_FACTOR, 0);
    }

    #[test]
    fn test_v6_uptime_weight_floor_ossified() {
        // Spec §7.4 v6.0 Invariant W-1: uptime >= 70% dari total weight
        assert_eq!(V6_UPTIME_WEIGHT_FLOOR, 700_000);
    }

    #[test]
    fn test_v6_spec_version_manifest_ossified() {
        // Spec §8.1 v6.0: spec_version = 0x02
        assert_eq!(V6_SPEC_VERSION_MANIFEST, 0x02);
    }

    #[test]
    fn test_v6_spec_version_differs_from_v5() {
        // v6.0 breaking change: spec_version berbeda dari v5.0 (implisit 0x01)
        assert_ne!(V6_SPEC_VERSION_MANIFEST, 0x01);
    }

    #[test]
    fn test_v6_gss_max_latency_ms_ossified() {
        assert_eq!(V6_GSS_MAX_LATENCY_MS, 300_000);
    }

    #[test]
    fn test_v6_gss_heartbeat_staleness_ossified() {
        assert_eq!(V6_GSS_HEARTBEAT_STALENESS_S, 900);
    }

    #[test]
    fn test_v6_gss_eclipse_threshold_ossified() {
        assert_eq!(V6_GSS_ECLIPSE_THRESHOLD, 400_000);
    }

    #[test]
    fn test_v6_gss_fanout_thresholds_descending() {
        // Threshold harus descending untuk tabel fanout yang benar
        const { assert!(V6_GSS_FANOUT_EXCELLENT > V6_GSS_FANOUT_GOOD) };
        const { assert!(V6_GSS_FANOUT_GOOD > V6_GSS_FANOUT_DEGRADED) };
        const { assert!(V6_GSS_FANOUT_DEGRADED > V6_GSS_FANOUT_POOR) };
    }

    #[test]
    fn test_v6_gss_fanout_excellent_ossified() {
        assert_eq!(V6_GSS_FANOUT_EXCELLENT, 900_000);
    }

    #[test]
    fn test_v6_gss_fanout_poor_matches_eclipse_threshold() {
        // GSS_FANOUT_POOR = GSS_ECLIPSE_THRESHOLD = 400_000
        assert_eq!(V6_GSS_FANOUT_POOR, V6_GSS_ECLIPSE_THRESHOLD);
    }
}
