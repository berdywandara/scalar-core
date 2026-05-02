// File: crates/scalar-emission/src/epoch.rs

use std::collections::HashMap;

/// STEP 1.5: Verifikasi konektivitas jaringan.
/// Node hanya dianggap valid jika terhubung ke >= 67% peer yang diharapkan.
/// Dihitung menggunakan integer math (Zero Floating Point).
pub fn verify_step_1_5_connectivity(connected_peers: usize, total_expected_peers: usize) -> bool {
    if total_expected_peers == 0 {
        return false;
    }
    (connected_peers * 100) / total_expected_peers >= 67
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Announcement {
    pub node_id: [u8; 32],
    pub epoch: u64,
    pub claim_hash: [u8; 32],
}

/// STEP 3.5: Slashing untuk mendeteksi Equivocation.
/// Node akan masuk daftar slash jika memberikan claim yang berbeda pada epoch yang sama.
pub fn verify_step_3_5_slashing(announcements: &[Announcement]) -> Vec<[u8; 32]> {
    let mut node_claims: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
    let mut slashed = Vec::new();

    for ann in announcements {
        let claims = node_claims.entry(ann.node_id).or_default();
        if !claims.contains(&ann.claim_hash) {
            claims.push(ann.claim_hash);
        }
    }

    for (node_id, claims) in node_claims {
        if claims.len() > 1 {
            slashed.push(node_id);
        }
    }

    slashed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::liveness::NodeHeartbeat;

    #[test]
    fn test_step_1_5_connected_with_67_percent_agreement() {
        assert!(verify_step_1_5_connectivity(67, 100));
        assert!(verify_step_1_5_connectivity(80, 100));
    }

    #[test]
    fn test_step_1_5_partitioned_below_67_percent() {
        assert!(!verify_step_1_5_connectivity(66, 100));
        assert!(!verify_step_1_5_connectivity(50, 100));
    }

    #[test]
    fn test_step_1_5_no_peers_is_partitioned() {
        assert!(!verify_step_1_5_connectivity(0, 0));
    }

    #[test]
    fn test_step_3_5_detects_equivocation() {
        let node_id = [1u8; 32];
        let anns = vec![
            Announcement {
                node_id,
                epoch: 1,
                claim_hash: [2u8; 32],
            },
            Announcement {
                node_id,
                epoch: 1,
                claim_hash: [3u8; 32],
            }, // Berbeda = Slash
        ];
        let slashed = verify_step_3_5_slashing(&anns);
        assert_eq!(slashed.len(), 1);
        assert_eq!(slashed[0], node_id);
    }

    #[test]
    fn test_step_3_5_no_slash_for_consistent_announcements() {
        let node_id = [1u8; 32];
        let anns = vec![
            Announcement {
                node_id,
                epoch: 1,
                claim_hash: [2u8; 32],
            },
            Announcement {
                node_id,
                epoch: 1,
                claim_hash: [2u8; 32],
            }, // Konsisten = Aman
        ];
        let slashed = verify_step_3_5_slashing(&anns);
        assert!(slashed.is_empty());
    }

    #[test]
    fn test_node_heartbeat_v5_has_required_fields() {
        let hb = NodeHeartbeat {
            node_id: [0; 32],
            timestamp: 1000,
            seq_num: 42,
            smt_root: [0; 32],
            epoch_id: 1,
            connectivity_proof: [0; 32],
            signature: vec![],
        };
        assert_eq!(hb.seq_num, 42);
        assert_eq!(hb.connectivity_proof, [0; 32]);
    }
}
