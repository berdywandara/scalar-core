// File: crates/scalar-network/src/gss.rs
//
// Gossip Synchronization Score (GSS) — Spec §12.3 v6.0
// Menggantikan Kuramoto Phase Synchronization.
//
// GSS adalah metrik sinkronisasi jaringan yang:
//   - Integer fixed-point (basis 1_000_000) — tidak ada floating point
//   - Lokal — hanya butuh data dari k=7 peers terdekat
//   - Verifiable — semua input ada dalam signed NodeHeartbeat
//   - Tidak mempengaruhi E(k) atau R_i(k) — hanya menentukan fanout

/// Fixed-point basis. OSSIFIED — spec §12.3 v6.0.
pub const FIXED_POINT_BASIS: u64 = 1_000_000;

/// Latency maksimum yang dipertimbangkan. OSSIFIED — spec §12.3 v6.0.
pub const MAX_LATENCY_MS: u64 = 300_000;

/// Threshold staleness heartbeat. OSSIFIED — spec §12.3 v6.0.
pub const HEARTBEAT_STALENESS_S: u64 = 900;

/// Threshold GSS untuk eclipse detection Layer 1. OSSIFIED — spec §12.8 v6.0.
pub const GSS_ECLIPSE_THRESHOLD: u64 = 400_000;

/// Data sinkronisasi satu peer untuk kalkulasi GSS.
#[derive(Debug, Clone)]
pub struct PeerSyncData {
    pub smt_root: [u8; 32],
    pub latency_ms: u64,
    pub age_seconds: u64,
}

/// Hitung GSS_fp untuk satu node berdasarkan data peers.
/// Spec §12.3 v6.0: GSS_fp = Σ(root_match x latency_score x recency_score) / N
pub fn compute_gss_fp(my_root: &[u8; 32], peers: &[PeerSyncData]) -> u64 {
    if peers.is_empty() {
        return 0;
    }
    let n = peers.len() as u64;
    let sum: u64 = peers
        .iter()
        .map(|peer| {
            let root_match: u64 = if peer.smt_root == *my_root {
                FIXED_POINT_BASIS
            } else {
                0
            };
            let latency_score: u64 = FIXED_POINT_BASIS
                .saturating_sub(peer.latency_ms.saturating_mul(FIXED_POINT_BASIS) / MAX_LATENCY_MS);
            let recency_score: u64 = FIXED_POINT_BASIS.saturating_sub(
                peer.age_seconds.saturating_mul(FIXED_POINT_BASIS) / HEARTBEAT_STALENESS_S,
            );
            // Kombinasi 3 komponen, hasil dalam basis 1_000_000
            // Gunakan u128 untuk cegah overflow, lalu skala ke basis
            let score = (root_match as u128)
                .saturating_mul(latency_score as u128)
                .saturating_mul(recency_score as u128);
            // score sekarang dalam basis 1_000_000^3, bagi kembali ke 1_000_000
            (score / (FIXED_POINT_BASIS as u128 * FIXED_POINT_BASIS as u128)) as u64
        })
        .fold(0u64, |acc, v| acc.saturating_add(v));
    sum / n
}

/// Hitung peer_sync_summary untuk NodeHeartbeat.
/// Spec §12.3 v6.0: BLAKE3(node_id || epoch_id || seq_num || gss_fp_le64)
pub fn compute_peer_sync_summary(
    node_id: &[u8; 32],
    epoch_id: u64,
    seq_num: u64,
    gss_fp: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(node_id);
    hasher.update(&epoch_id.to_le_bytes());
    hasher.update(&seq_num.to_le_bytes());
    hasher.update(&gss_fp.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Deteksi eclipse proxy via GSS — Layer 1. Spec §12.8 v6.0.
/// Returns true jika GSS_fp konsisten di bawah threshold selama >3 heartbeat.
pub fn is_eclipse_candidate_via_gss(gss_history: &[u64]) -> bool {
    if gss_history.len() < 3 {
        return false;
    }
    gss_history
        .iter()
        .rev()
        .take(3)
        .all(|&gss| gss < GSS_ECLIPSE_THRESHOLD)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn test_gss_empty_peers_returns_zero() {
        assert_eq!(compute_gss_fp(&root(1), &[]), 0);
    }

    #[test]
    fn test_gss_full_sync_max_score() {
        let peers = vec![PeerSyncData {
            smt_root: root(1),
            latency_ms: 0,
            age_seconds: 0,
        }];
        assert_eq!(compute_gss_fp(&root(1), &peers), 1_000_000);
    }

    #[test]
    fn test_gss_root_mismatch_zero_contribution() {
        let peers = vec![PeerSyncData {
            smt_root: root(2),
            latency_ms: 0,
            age_seconds: 0,
        }];
        assert_eq!(compute_gss_fp(&root(1), &peers), 0);
    }

    #[test]
    fn test_gss_high_latency_reduces_score() {
        let peers = vec![PeerSyncData {
            smt_root: root(1),
            latency_ms: MAX_LATENCY_MS,
            age_seconds: 0,
        }];
        assert_eq!(compute_gss_fp(&root(1), &peers), 0);
    }

    #[test]
    fn test_gss_stale_heartbeat_reduces_score() {
        let peers = vec![PeerSyncData {
            smt_root: root(1),
            latency_ms: 0,
            age_seconds: HEARTBEAT_STALENESS_S,
        }];
        assert_eq!(compute_gss_fp(&root(1), &peers), 0);
    }

    #[test]
    fn test_gss_mixed_peers_partial_score() {
        let peers = vec![
            PeerSyncData {
                smt_root: root(1),
                latency_ms: 0,
                age_seconds: 0,
            },
            PeerSyncData {
                smt_root: root(2),
                latency_ms: 0,
                age_seconds: 0,
            },
        ];
        let gss = compute_gss_fp(&root(1), &peers);
        assert!(gss > 0 && gss < 1_000_000);
    }

    #[test]
    fn test_gss_result_bounded() {
        for latency in [0u64, 1000, 10000, 300_000] {
            let peers = vec![PeerSyncData {
                smt_root: root(1),
                latency_ms: latency,
                age_seconds: 0,
            }];
            let gss = compute_gss_fp(&root(1), &peers);
            assert!(gss <= FIXED_POINT_BASIS);
        }
    }

    #[test]
    fn test_peer_sync_summary_deterministic() {
        let s1 = compute_peer_sync_summary(&root(1), 10, 42, 800_000);
        let s2 = compute_peer_sync_summary(&root(1), 10, 42, 800_000);
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_peer_sync_summary_differs_on_gss_change() {
        let s1 = compute_peer_sync_summary(&root(1), 10, 42, 800_000);
        let s2 = compute_peer_sync_summary(&root(1), 10, 42, 500_000);
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_peer_sync_summary_non_zero() {
        let s = compute_peer_sync_summary(&root(1), 1, 1, 1_000_000);
        assert_ne!(s, [0u8; 32]);
    }

    #[test]
    fn test_eclipse_not_detected_high_gss() {
        let history = vec![900_000u64, 850_000, 800_000];
        assert!(!is_eclipse_candidate_via_gss(&history));
    }

    #[test]
    fn test_eclipse_detected_three_low_gss() {
        let history = vec![900_000u64, 300_000, 350_000, 200_000];
        assert!(is_eclipse_candidate_via_gss(&history));
    }

    #[test]
    fn test_eclipse_not_detected_insufficient_history() {
        let history = vec![100_000u64, 200_000];
        assert!(!is_eclipse_candidate_via_gss(&history));
    }

    #[test]
    fn test_eclipse_threshold_boundary() {
        let history = vec![400_000u64, 400_000, 400_000];
        assert!(!is_eclipse_candidate_via_gss(&history));
    }

    #[test]
    fn test_eclipse_one_recovery_breaks_pattern() {
        let history = vec![200_000u64, 300_000, 300_000, 500_000];
        assert!(!is_eclipse_candidate_via_gss(&history));
    }

    #[test]
    fn test_gss_constants_match_spec() {
        assert_eq!(MAX_LATENCY_MS, 300_000);
        assert_eq!(HEARTBEAT_STALENESS_S, 900);
        assert_eq!(GSS_ECLIPSE_THRESHOLD, 400_000);
        assert_eq!(FIXED_POINT_BASIS, 1_000_000);
    }
}
