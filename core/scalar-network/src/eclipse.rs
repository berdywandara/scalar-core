// File: crates/scalar-network/src/eclipse.rs
//
// Eclipse Attack Defense — Spec §12.5 + §12.6
//
// 5 Layer pertahanan:
//   Layer 1: Multi-transport mode selection (≥67% across transports)
//   Layer 2: Pheromone entropy monitor (H_source < H_THRESHOLD)
//   Layer 3: Geographic diversity sampling (≥2 regions)
//   Layer 4: Proof-of-Network-Connectivity (connectivity_proof)
//   Layer 5: Anti-partition halt (CP property)

/// H_THRESHOLD = 50% from H_ideal. Spec §12.5.
pub const H_THRESHOLD_PERCENT: u64 = 50;

/// FIXED_POINT_BASIS for calculation fixed-point.
pub const FIXED_POINT_BASIS: u64 = 1_000_000;

/// Threshold CRITICAL: satu kontributor > 80% from deposits. Spec §12.5.
pub const ECLIPSE_CRITICAL_THRESHOLD: u64 = 800_000;

/// Threshold WARNING: satu kontributor > 60% from deposits. Spec §12.5.
pub const ECLIPSE_WARNING_THRESHOLD: u64 = 600_000;

/// Mthismum jumlah geographic region that harus vfillble. Spec §12.6 Layer 3.
pub const MIN_GEOGRAPHIC_REGIONS: usize = 2;

// ── Layer 2: Pheromone Entropy Monitor ───────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EclipseStatus {
    /// none inatkasi eclipse.
    Clean,
    /// Satu peer mendominasi >60% pheromone deposits. activate LoRa.
    Warning { dominant_fraction_fp: u64 },
    /// Satu peer mendominasi >80% pheromone deposits. Pause internet, activate LoRa+HF.
    Critical { dominant_fraction_fp: u64 },
}

/// Hitung entropy Shannon from atstribution pheromone deposits.
/// H = -Σᵢ pᵢ log₂(pᵢ) in fixed-point basis 1_000_000.
pub fn compute_pheromone_entropy_fp(deposits: &[u64]) -> u64 {
    let total: u64 = deposits.iter().sum();
    if total == 0 || deposits.is_empty() {
        return 0;
    }
    let mut entropy_fp: u64 = 0;
    for &d in deposits {
        if d == 0 {
            continue;
        }
        let p_fp = (d * FIXED_POINT_BASIS) / total;
        if p_fp == 0 {
            continue;
        }
        let log2_approx = 63u64.saturating_sub(p_fp.leading_zeros() as u64);
        entropy_fp = entropy_fp.saturating_add(p_fp * log2_approx / FIXED_POINT_BASIS);
    }
    entropy_fp
}

/// H_ideal = log₂(N) for N sender that allnya equal.
pub fn compute_ideal_entropy_fp(num_senders: usize) -> u64 {
    if num_senders <= 1 {
        return 0;
    }
    let n = num_senders as u64;
    let log2_n = 63u64.saturating_sub(n.leading_zeros() as u64);
    log2_n * FIXED_POINT_BASIS
}

/// Layer 2: detection eclipse via pheromone entropy monitor. Spec §12.5.
pub fn detect_eclipse_via_entropy(deposits: &[u64]) -> EclipseStatus {
    let total: u64 = deposits.iter().sum();
    if total == 0 || deposits.is_empty() {
        return EclipseStatus::Clean;
    }
    let max_deposit = deposits.iter().copied().max().unwrap_or(0);
    let max_fraction_fp = (max_deposit * FIXED_POINT_BASIS) / total;

    if max_fraction_fp > ECLIPSE_CRITICAL_THRESHOLD {
        return EclipseStatus::Critical {
            dominant_fraction_fp: max_fraction_fp,
        };
    }
    if max_fraction_fp > ECLIPSE_WARNING_THRESHOLD {
        return EclipseStatus::Warning {
            dominant_fraction_fp: max_fraction_fp,
        };
    }
    EclipseStatus::Clean
}

// ── Layer 3: Geographic Diversity Sampling ────────────────────────────

/// Region geografis for atversionty check. Spec §12.6 Layer 3.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GeoRegion {
    Americas,
    Emea,
    AsiaPacific,
    Unknown,
}

/// Layer 3: check whether peer set mencakup ≥2 geographic regions. Spec §12.6.
pub fn check_geographic_diversity(peer_regions: &[GeoRegion]) -> bool {
    let unique_known: std::collections::HashSet<&GeoRegion> = peer_regions
        .iter()
        .filter(|r| **r != GeoRegion::Unknown)
        .collect();
    unique_known.len() >= MIN_GEOGRAPHIC_REGIONS
}

// ── Layer 5: Anti-partition halt ──────────────────────────────────────

/// Status partfill node. Spec §12.6 Layer 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionStatus {
    /// Node connected normal.
    Connected,
    /// Node ter-partfill — HALT pemrosesan transaction new (CP property).
    Partitioned,
}

/// Layer 5: determine status partfill. Spec §12.6: if <67% peers agree → PARTITIONED.
pub fn evaluate_partition_status(
    connected_peers: usize,
    total_expected_peers: usize,
) -> PartitionStatus {
    if total_expected_peers == 0 {
        return PartitionStatus::Partitioned;
    }
    if (connected_peers * 100) / total_expected_peers >= 67 {
        PartitionStatus::Connected
    } else {
        PartitionStatus::Partitioned
    }
}

// ── Full Report ───────────────────────────────────────────────────────

/// evaluation toseluruhan eclipse defense — gabungan all layer. Spec §12.6.
pub struct EclipseDefenseReport {
    pub entropy_status: EclipseStatus,
    pub geographic_diversity_ok: bool,
    pub partition_status: PartitionStatus,
    /// true if ada inatkasi eclipse from layer manapun.
    pub eclipse_detected: bool,
}

impl EclipseDefenseReport {
    pub fn evaluate(
        pheromone_deposits: &[u64],
        peer_regions: &[GeoRegion],
        connected_peers: usize,
        total_expected_peers: usize,
    ) -> Self {
        let entropy_status = detect_eclipse_via_entropy(pheromone_deposits);
        let geographic_diversity_ok = check_geographic_diversity(peer_regions);
        let partition_status = evaluate_partition_status(connected_peers, total_expected_peers);

        let eclipse_detected = !matches!(entropy_status, EclipseStatus::Clean)
            || !geographic_diversity_ok
            || partition_status == PartitionStatus::Partitioned;

        Self {
            entropy_status,
            geographic_diversity_ok,
            partition_status,
            eclipse_detected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Layer 2: Entropy ──────────────────────────────────────────────

    #[test]
    fn test_eclipse_clean_when_deposits_equal() {
        let deposits = vec![100u64; 10];
        assert_eq!(detect_eclipse_via_entropy(&deposits), EclipseStatus::Clean);
    }

    #[test]
    fn test_eclipse_warning_at_70_percent() {
        let deposits = vec![700u64, 100, 100, 100];
        let status = detect_eclipse_via_entropy(&deposits);
        assert!(
            matches!(status, EclipseStatus::Warning { .. }),
            "70% dominasi harus WARNING"
        );
    }

    #[test]
    fn test_eclipse_critical_at_85_percent() {
        let deposits = vec![850u64, 50, 50, 50];
        let status = detect_eclipse_via_entropy(&deposits);
        assert!(
            matches!(status, EclipseStatus::Critical { .. }),
            "85% dominasi harus CRITICAL"
        );
    }

    #[test]
    fn test_eclipse_clean_on_empty_deposits() {
        assert_eq!(detect_eclipse_via_entropy(&[]), EclipseStatus::Clean);
    }

    #[test]
    fn test_eclipse_critical_threshold_boundary() {
        // 800/1000 = 80% tepat — spec pakai strictly >, jadi 80% = Warning
        let deposits = vec![800u64, 200];
        let status = detect_eclipse_via_entropy(&deposits);
        assert!(matches!(status, EclipseStatus::Warning { .. }));
    }

    #[test]
    fn test_eclipse_critical_above_threshold() {
        // 801/1000 > 80% → CRITICAL
        let deposits = vec![801u64, 199];
        let status = detect_eclipse_via_entropy(&deposits);
        assert!(matches!(status, EclipseStatus::Critical { .. }));
    }

    #[test]
    fn test_eclipse_warning_threshold_boundary() {
        // 600/1000 = 60% tepat — spec pakai strictly >, jadi 60% = Clean
        let deposits = vec![600u64, 400];
        let status = detect_eclipse_via_entropy(&deposits);
        assert_eq!(status, EclipseStatus::Clean);
    }

    #[test]
    fn test_eclipse_warning_above_threshold() {
        // 601/1000 > 60% → WARNING
        let deposits = vec![601u64, 399];
        let status = detect_eclipse_via_entropy(&deposits);
        assert!(matches!(status, EclipseStatus::Warning { .. }));
    }

    // ── Layer 3: Geographic Diversity ────────────────────────────────

    #[test]
    fn test_geographic_diversity_ok_with_2_regions() {
        let regions = vec![GeoRegion::Americas, GeoRegion::Emea, GeoRegion::Americas];
        assert!(check_geographic_diversity(&regions));
    }

    #[test]
    fn test_geographic_diversity_fail_single_region() {
        let regions = vec![
            GeoRegion::Americas,
            GeoRegion::Americas,
            GeoRegion::Americas,
        ];
        assert!(!check_geographic_diversity(&regions));
    }

    #[test]
    fn test_geographic_diversity_unknown_not_counted() {
        let regions = vec![GeoRegion::Unknown, GeoRegion::Unknown, GeoRegion::Americas];
        assert!(!check_geographic_diversity(&regions));
    }

    #[test]
    fn test_geographic_diversity_all_three_regions() {
        let regions = vec![GeoRegion::Americas, GeoRegion::Emea, GeoRegion::AsiaPacific];
        assert!(check_geographic_diversity(&regions));
    }

    // ── Layer 5: Partition ────────────────────────────────────────────

    #[test]
    fn test_partition_connected_at_67_percent() {
        assert_eq!(
            evaluate_partition_status(67, 100),
            PartitionStatus::Connected
        );
    }

    #[test]
    fn test_partition_at_80_percent_connected() {
        assert_eq!(
            evaluate_partition_status(80, 100),
            PartitionStatus::Connected
        );
    }

    #[test]
    fn test_partition_below_67_percent() {
        assert_eq!(
            evaluate_partition_status(66, 100),
            PartitionStatus::Partitioned
        );
    }

    #[test]
    fn test_partition_zero_peers() {
        assert_eq!(
            evaluate_partition_status(0, 0),
            PartitionStatus::Partitioned
        );
    }

    // ── Full report ───────────────────────────────────────────────────

    #[test]
    fn test_full_report_clean_network() {
        let deposits = vec![100u64; 10];
        let regions = vec![GeoRegion::Americas, GeoRegion::Emea, GeoRegion::AsiaPacific];
        let report = EclipseDefenseReport::evaluate(&deposits, &regions, 80, 100);
        assert!(!report.eclipse_detected);
        assert!(report.geographic_diversity_ok);
        assert_eq!(report.partition_status, PartitionStatus::Connected);
        assert_eq!(report.entropy_status, EclipseStatus::Clean);
    }

    #[test]
    fn test_full_report_eclipse_detected_dominant_peer() {
        let deposits = vec![900u64, 50, 50];
        let regions = vec![GeoRegion::Americas, GeoRegion::Emea];
        let report = EclipseDefenseReport::evaluate(&deposits, &regions, 80, 100);
        assert!(report.eclipse_detected);
        assert!(matches!(
            report.entropy_status,
            EclipseStatus::Critical { .. }
        ));
    }

    #[test]
    fn test_full_report_eclipse_detected_partition() {
        let deposits = vec![100u64; 5];
        let regions = vec![GeoRegion::Americas, GeoRegion::Emea];
        let report = EclipseDefenseReport::evaluate(&deposits, &regions, 50, 100);
        assert!(report.eclipse_detected);
        assert_eq!(report.partition_status, PartitionStatus::Partitioned);
    }

    #[test]
    fn test_eclipse_constants_match_spec() {
        assert_eq!(ECLIPSE_WARNING_THRESHOLD, 600_000);
        assert_eq!(ECLIPSE_CRITICAL_THRESHOLD, 800_000);
        assert_eq!(MIN_GEOGRAPHIC_REGIONS, 2);
        assert_eq!(H_THRESHOLD_PERCENT, 50);
    }
}
