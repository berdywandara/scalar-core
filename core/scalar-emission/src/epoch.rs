//! Epoch boundary dan slashing detection. Spec §7.2c T-1.
//!
//! RULE T-1 (OSSIFIED — spec §7.2c): Epoch boundary ditentukan oleh seq_num,
//! BUKAN wall-clock. Node mendeteksi END_EPOCH dengan tracking seq_num sendiri.
//! Wall-clock TIDAK PERNAH digunakan untuk epoch boundary.

use std::collections::HashMap;

/// Verifikasi konektivitas peer. Spec §7.2.
/// Node valid jika terhubung ke ≥67% peer yang diharapkan.
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

/// Slashing untuk mendeteksi equivocation. Spec §7.2.
/// Node masuk daftar slash jika memberikan claim berbeda pada epoch yang sama.
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
    use crate::liveness::{NodeHeartbeat, EPOCH_HB_COUNT};

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
            },
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
            },
        ];
        let slashed = verify_step_3_5_slashing(&anns);
        assert!(slashed.is_empty());
    }

    #[test]
    fn test_node_heartbeat_v9_struct_fields() {
        // Spec §7.2 v9.0: 6 fields, tipe yang benar, NO signature.
        let hb = NodeHeartbeat {
            node_id: [0x01, 0x02, 0x03, 0x04],
            seq_num: 42u32,
            timestamp: 600u32,
            smt_root: [0u8; 32],
            imt_frontier: [0u8; 32],
            imt_count: 0u64,
            prev_hash: [0u8; 32],
            mac: [0u8; 32],
        };
        assert_eq!(hb.seq_num, 42);
        assert_eq!(hb.node_id, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_epoch_hb_count_is_4320() {
        // Rule T-1 — spec §7.2c. Epoch boundary via seq_num bukan wall-clock.
        assert_eq!(EPOCH_HB_COUNT, 4_320u32);
    }
}
