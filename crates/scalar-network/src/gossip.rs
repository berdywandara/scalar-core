// File: crates/scalar-network/src/gossip.rs
//
// ScalarGossipMessage v6.0 — Spec §12 v6.0
// Kuramoto dihapus. Adaptive fanout berbasis GSS.
// Delta dari v5.0 (KUR-DELTA-02):
//   + peer_sync_summary: [u8;32] — BLAKE3 commit ke GSS state
//   - compute_order_parameter (Kuramoto) DIHAPUS
//   ~ compute_adaptive_fanout: trigger GSS-based (bukan r)

pub const MAX_FANOUT: usize = 15; // OSSIFIED §12
pub const MAX_MSG_RATE: u32 = 10; // per menit, Layer 2 CONSTRAINED

/// DeltaNullifier v5.0
#[derive(Debug, Clone)]
pub struct DeltaNullifier {
    pub nullifier: [u8; 32],
    pub spend_proof: Vec<u8>,
    pub new_commitment: [u8; 32],
    /// Waktu tx masuk pool — untuk C10 T_MAX_WAIT enforcement. DELTA-05.
    pub entry_timestamp: u64,
}

/// ScalarGossipMessage v5.0
#[derive(Debug, Clone)]
pub struct ScalarGossipMessage {
    pub timestamp: u64,
    /// Monotonic sequence number — anti-replay. DELTA-05 + DELTA-09.
    pub seq_num: u64,
    pub smt_root: [u8; 32],
    pub delta_nullifiers: Vec<DeltaNullifier>,
    /// BLAKE3(10 nullifiers terbaru) — Step 1.5 Epoch Consensus. DELTA-09.
    pub connectivity_proof: [u8; 32],
    /// BLAKE3 commit ke GSS state — spec §12.3 v6.0.
    pub peer_sync_summary: [u8; 32],
    pub sender_signature: Vec<u8>,
}

/// Hitung connectivity_proof = BLAKE3(recent_nullifiers).
/// Spec DELTA-09: connectivity_proof = BLAKE3(10 nullifiers terbaru).
pub fn compute_connectivity_proof(recent_nullifiers: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for n in recent_nullifiers {
        hasher.update(n.as_slice());
    }
    *hasher.finalize().as_bytes()
}

/// Hitung adaptive fanout berdasarkan GSS_fp. Spec §12.5 v6.0.
/// GSS_fp dalam fixed-point basis 1_000_000.
/// MAX_FANOUT = 15 OSSIFIED §12.
pub fn compute_adaptive_fanout(gss_fp: u64) -> usize {
    match gss_fp {
        g if g > 900_000 => 3,  // sync excellent
        g if g > 750_000 => 5,  // sync good
        g if g > 600_000 => 7,  // sync degrading
        g if g > 400_000 => 10, // sync poor
        _ => MAX_FANOUT,        // sync critical — emergency mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_gossip_message_v5_has_seq_num() {
        let msg = ScalarGossipMessage {
            timestamp: 1_000_000,
            seq_num: 42,
            smt_root: [1u8; 32],
            delta_nullifiers: vec![],
            connectivity_proof: [0u8; 32],
            peer_sync_summary: [0u8; 32],
            sender_signature: vec![],
        };
        assert_eq!(msg.seq_num, 42);
    }

    #[test]
    fn test_gossip_message_v5_has_connectivity_proof() {
        let msg = ScalarGossipMessage {
            timestamp: 0,
            seq_num: 1,
            smt_root: [0u8; 32],
            delta_nullifiers: vec![],
            connectivity_proof: [9u8; 32],
            peer_sync_summary: [0u8; 32],
            sender_signature: vec![],
        };
        assert_eq!(msg.connectivity_proof, [9u8; 32]);
    }

    #[test]
    fn test_delta_nullifier_v5_has_entry_timestamp() {
        let dn = DeltaNullifier {
            nullifier: [1u8; 32],
            spend_proof: vec![0xFF],
            new_commitment: [2u8; 32],
            entry_timestamp: 9999,
        };
        assert_eq!(dn.entry_timestamp, 9999);
    }

    #[test]
    fn test_connectivity_proof_deterministic() {
        let nullifiers = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let p1 = compute_connectivity_proof(&nullifiers);
        let p2 = compute_connectivity_proof(&nullifiers);
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_connectivity_proof_empty_input() {
        let p = compute_connectivity_proof(&[]);
        // BLAKE3 dari input kosong harus deterministik dan non-zero
        assert_ne!(p, [0u8; 32]);
    }

    #[test]
    fn test_connectivity_proof_different_inputs_differ() {
        let p1 = compute_connectivity_proof(&[[1u8; 32]]);
        let p2 = compute_connectivity_proof(&[[2u8; 32]]);
        assert_ne!(p1, p2);
    }
}
