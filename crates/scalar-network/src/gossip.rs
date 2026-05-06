//! ScalarGossipMessage v9.0 — Spec §12 v9.0
//!
//! NodeHeartbeat v9.0: 108 bytes, BLAKE3-MAC, NO SPHINCS+ per-HB.
//! connectivity_proof dihapus dari NodeHeartbeat — diganti peer_sync_summary di GossipMsg.
//! Spec §7.2: node_id [u8;4], seq_num u32, timestamp u32 delta.

pub const MAX_FANOUT: usize = 15; // OSSIFIED §12.5
pub const MAX_MSG_RATE: u32 = 10; // per menit, Layer 2 CONSTRAINED

/// DeltaNullifier v5.0
#[derive(Debug, Clone)]
pub struct DeltaNullifier {
    pub nullifier: [u8; 32],
    pub spend_proof: Vec<u8>,
    pub new_commitment: [u8; 32],
    /// Waktu tx masuk pool — untuk C10 T_MAX_WAIT enforcement.
    pub entry_timestamp: u64,
}

/// ScalarGossipMessage v9.0 — spec §12 v9.0.
///
/// NodeHeartbeat v9.0 sekarang 108 bytes (bukan ~29,900 bytes).
/// connectivity_proof field dihapus dari NodeHeartbeat.
/// peer_sync_summary tetap ada di GossipMessage sebagai GSS commit.
#[derive(Debug, Clone)]
pub struct ScalarGossipMessage {
    pub timestamp: u64,
    /// Monotonic sequence number — anti-replay.
    pub seq_num: u64,
    pub smt_root: [u8; 32],
    pub delta_nullifiers: Vec<DeltaNullifier>,
    /// BLAKE3 commit ke GSS state — spec §12.3 v6.0.
    pub peer_sync_summary: [u8; 32],
    pub sender_signature: Vec<u8>,
}

/// Hitung adaptive fanout berdasarkan GSS_fp. Spec §12.5 v6.0.
/// GSS_fp dalam fixed-point basis 1_000_000.
/// MAX_FANOUT = 15 OSSIFIED §12.5.
pub fn compute_adaptive_fanout(gss_fp: u64) -> usize {
    match gss_fp {
        g if g > 900_000 => 3,
        g if g > 750_000 => 5,
        g if g > 600_000 => 7,
        g if g > 400_000 => 10,
        _ => MAX_FANOUT,
    }
}

/// Deserialise NodeHeartbeat v9.0 dari 108-byte slice. Spec §7.2.
///
/// Returns None jika slice bukan tepat 108 bytes.
/// Hash discipline: BLAKE3 out-circuit untuk MAC verification — spec §2.1.3.
use scalar_emission::liveness::NodeHeartbeat as EmissionNodeHeartbeat;

pub fn deserialize_heartbeat(bytes: &[u8]) -> Option<scalar_emission::liveness::NodeHeartbeat> {
    if bytes.len() != 108 {
        return None;
    }
    let arr: &[u8; 108] = bytes.try_into().ok()?;
    Some(EmissionNodeHeartbeat::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalar_emission::liveness::NodeHeartbeat;

    #[test]
    fn test_max_fanout_ossified_at_15() {
        assert_eq!(MAX_FANOUT, 15, "MAX_FANOUT harus 15 — OSSIFIED");
        for gss in [0u64, 100_000, 500_000, 670_000, 800_000, 950_000, 1_000_000] {
            assert!(
                compute_adaptive_fanout(gss) <= MAX_FANOUT,
                "fanout melebihi MAX pada gss={}",
                gss
            );
        }
    }

    #[test]
    fn test_fanout_sync_network() {
        assert_eq!(compute_adaptive_fanout(970_000), 3);
    }

    #[test]
    fn test_fanout_normal_network() {
        assert_eq!(compute_adaptive_fanout(850_000), 5);
    }

    #[test]
    fn test_fanout_crisis_network() {
        assert_eq!(compute_adaptive_fanout(550_000), 10);
    }

    #[test]
    fn test_fanout_emergency() {
        assert_eq!(compute_adaptive_fanout(100_000), MAX_FANOUT);
    }

    #[test]
    fn test_gossip_message_v9_has_seq_num() {
        let msg = ScalarGossipMessage {
            timestamp: 1_000_000,
            seq_num: 42,
            smt_root: [1u8; 32],
            delta_nullifiers: vec![],
            peer_sync_summary: [0u8; 32],
            sender_signature: vec![],
        };
        assert_eq!(msg.seq_num, 42);
    }

    #[test]
    fn test_delta_nullifier_has_entry_timestamp() {
        let dn = DeltaNullifier {
            nullifier: [1u8; 32],
            spend_proof: vec![0xFF],
            new_commitment: [2u8; 32],
            entry_timestamp: 9999,
        };
        assert_eq!(dn.entry_timestamp, 9999);
    }

    #[test]
    fn test_deserialize_heartbeat_valid_108_bytes() {
        // Spec §7.2: deserialize dari tepat 108 bytes.
        let hb = NodeHeartbeat {
            node_id: [0x01, 0x02, 0x03, 0x04],
            seq_num: 7u32,
            timestamp: 300u32,
            smt_root: [0xAAu8; 32],
            prev_hash: [0xBBu8; 32],
            mac: [0xCCu8; 32],
        };
        let bytes = hb.to_bytes();
        let hb2 = deserialize_heartbeat(&bytes).unwrap();
        assert_eq!(hb2.node_id, [0x01, 0x02, 0x03, 0x04]);
        assert_eq!(hb2.seq_num, 7u32);
        assert_eq!(hb2.timestamp, 300u32);
    }

    #[test]
    fn test_deserialize_heartbeat_wrong_size_returns_none() {
        // Hanya tepat 108 bytes yang valid — spec §7.2.
        assert!(deserialize_heartbeat(&[0u8; 107]).is_none());
        assert!(deserialize_heartbeat(&[0u8; 109]).is_none());
        assert!(deserialize_heartbeat(&[]).is_none());
    }

    #[test]
    fn test_gossip_v9_no_connectivity_proof_field() {
        // v9.0: connectivity_proof DIHAPUS dari GossipMessage — spec §7.2.
        // Test ini compile hanya jika field tidak ada di struct.
        let _ = ScalarGossipMessage {
            timestamp: 0,
            seq_num: 1,
            smt_root: [0u8; 32],
            delta_nullifiers: vec![],
            peer_sync_summary: [0u8; 32],
            sender_signature: vec![],
        };
    }
}
