// File: crates/scalar-network/src/gossip.rs
//
// ScalarGossipMessage v5.0 — Spec §12
// Delta dari v3.0 (DELTA-05, DELTA-09):
//   + seq_num: u64             — monotonic anti-replay
//   + connectivity_proof: [u8;32] — BLAKE3(10 nullifiers terbaru)
//   DeltaNullifier + entry_timestamp — untuk C10 enforcement

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

/// Hitung Kuramoto order parameter dari fase peer.
/// r = fraksi peer aligned ke smt_root mayoritas.
/// r dalam fixed-point basis 1_000_000.
pub fn compute_order_parameter(phases: &[u64]) -> u64 {
    if phases.is_empty() {
        return 0;
    }
    let n = phases.len() as u64;
    let mut counts = std::collections::HashMap::new();
    for &p in phases {
        *counts.entry(p).or_insert(0u64) += 1;
    }
    let max_count = counts.values().copied().max().unwrap_or(0);
    (max_count * 1_000_000) / n
}

/// Hitung adaptive fanout berdasarkan Kuramoto order parameter r.
/// r dalam fixed-point basis 1_000_000.
/// Spec §12: adaptive 3–15, MAX = 15 OSSIFIED.
pub fn compute_adaptive_fanout(order_parameter_r: u64) -> usize {
    match order_parameter_r {
        r if r > 950_000 => 3,
        r if r > 800_000 => 5,
        r if r > 670_000 => 7,
        r if r > 500_000 => 10,
        _ => MAX_FANOUT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_fanout_ossified_at_15() {
        assert_eq!(MAX_FANOUT, 15, "MAX_FANOUT harus 15 — OSSIFIED");
        for r in [0u64, 100_000, 500_000, 670_000, 800_000, 950_000, 1_000_000] {
            assert!(
                compute_adaptive_fanout(r) <= MAX_FANOUT,
                "fanout melebihi MAX pada r={}",
                r
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

    #[test]
    fn test_order_parameter_full_consensus() {
        let phases = vec![100u64; 10];
        assert_eq!(compute_order_parameter(&phases), 1_000_000);
    }

    #[test]
    fn test_order_parameter_50_50_split() {
        let phases = vec![1u64, 1, 2, 2];
        assert_eq!(compute_order_parameter(&phases), 500_000);
    }

    #[test]
    fn test_order_parameter_empty() {
        assert_eq!(compute_order_parameter(&[]), 0);
    }
}
