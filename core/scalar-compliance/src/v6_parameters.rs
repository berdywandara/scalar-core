// File: crates/scalar-compliance/src/v6_parameters.rs
//
// Parameter OSSIFIED v6.0 berdasarkan Scalar_Master_Technical_Spec v6.0.
// Perubahan dari v5.0: Kuramoto dihapus, GSS diimplementasikan.
// Sumber kebenaran: §7.4 v6.0, §8.1 v6.0, §12.3 v6.0, §12.8 v6.0

// ── §7.4 v6.0 Uptime Weight ───────────────────────────────────────────────────

/// Bobot uptime in formula w_i(k). OSSIFIED — spec §7.4 v6.0.
/// Naik from 600_000 (v5.0) to 700_000 (v6.0) karena phase_coherence deleted.
pub const V6_UPTIME_WEIGHT_FACTOR: u64 = 700_000;

/// Bobot root alignment in formula w_i(k). OSSIFIED — spec §7.4 v6.0.
pub const V6_ALIGNMENT_WEIGHT_FACTOR: u64 = 300_000;

/// Phase coherence factor deleted at v6.0. value 0 for dokumentasi.
pub const V6_PHASE_COHERENCE_FACTOR: u64 = 0;

/// uptime_weight_floor: komponen uptime always >= 70% from total weight.
/// OSSIFIED — spec §7.4 v6.0 Invariant W-1.
pub const V6_UPTIME_WEIGHT_FLOOR: u64 = 700_000;

// ── §8.1 v6.0 Manifest ───────────────────────────────────────────────────────

/// version spec manifest v6.0. OSSIFIED — spec §8.1 v6.0.
/// Node v5.0 will REJECT manifest with spec_versionon = 0x02.
pub const V6_SPEC_VERSION_MANIFEST: u8 = 0x02;

// ── §12.3 v6.0 GSS ───────────────────────────────────────────────────────────

/// Latency maksimum for GSS score. OSSIFIED — spec §12.3 v6.0.
pub const V6_GSS_MAX_LATENCY_MS: u64 = 300_000;

/// Threshold staleness heartbeat for GSS. OSSIFIED — spec §12.3 v6.0.
pub const V6_GSS_HEARTBEAT_STALENESS_S: u64 = 900;

/// Threshold GSS for eclipse detection Layer 1. OSSIFIED — spec §12.8 v6.0.
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
        assert!(V6_GSS_FANOUT_EXCELLENT > V6_GSS_FANOUT_GOOD);
        assert!(V6_GSS_FANOUT_GOOD > V6_GSS_FANOUT_DEGRADED);
        assert!(V6_GSS_FANOUT_DEGRADED > V6_GSS_FANOUT_POOR);
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
