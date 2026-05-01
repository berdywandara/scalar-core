// File: crates/scalar-emission/src/liveness.rs

pub const EXPECTED_HEARTBEATS_PER_EPOCH: u32 = 4320; // 30 hari * 24 jam * 6 (per 10 menit)

pub fn compute_uptime_weight(
    uptime_ratio: u64,
    root_alignment_score: u64,
    phase_coherence_score: u64,
) -> u64 {
    let component_uptime = (uptime_ratio * 600_000) / 1_000_000;
    let component_align = (root_alignment_score * 300_000) / 1_000_000;
    let component_phase = (phase_coherence_score * 100_000) / 1_000_000;

    // Invariant: Maksimal total weight adalah 1_000_000
    component_uptime + component_align + component_phase
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeHeartbeat {
    pub node_id: [u8; 32],
    pub timestamp: u64,
    pub seq_num: u64,
    pub smt_root: [u8; 32],
    pub epoch_id: u64,
    pub connectivity_proof: [u8; 32],
    pub signature: Vec<u8>,
}

pub fn compute_connectivity_proof(recent_nullifiers: &[[u8; 32]]) -> [u8; 32] {
    assert!(recent_nullifiers.len() <= 10);
    let mut hasher = blake3::Hasher::new();
    for nullifier in recent_nullifiers {
        hasher.update(nullifier);
    }
    *hasher.finalize().as_bytes()
}

pub struct LivenessSMT {
    root: [u8; 32],
}

impl LivenessSMT {
    pub fn new() -> Self {
        Self { root: [0; 32] }
    }

    pub fn insert_heartbeat(&mut self, _hb: &NodeHeartbeat) {
        // Mock
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn compute_uptime_weight_fp(&self, _node_id: [u8; 32], _epoch_id: u64) -> u64 {
        1_000_000 // Mock 100%
    }
}

impl Default for LivenessSMT {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uptime_weight_components() {
        let w = compute_uptime_weight(1_000_000, 1_000_000, 1_000_000);
        assert_eq!(w, 1_000_000, "Semua 100% = total 100%");
    }

    #[test]
    fn test_uptime_weight_max_invariant() {
        let w = compute_uptime_weight(1_000_000, 1_000_000, 1_000_000);
        assert!(
            w <= 1_000_000,
            "Total weight tidak boleh lebih dari 1.000.000 (100%)"
        );
    }
}
