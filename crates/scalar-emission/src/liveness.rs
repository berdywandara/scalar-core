// File: crates/scalar-emission/src/liveness.rs

pub const EXPECTED_HEARTBEATS_PER_EPOCH: u32 = 4320;

pub fn compute_uptime_weight(
    uptime_ratio: u64,
    root_alignment_score: u64,
    phase_coherence_score: u64,
) -> u64 {
    let component_uptime = (uptime_ratio * 600_000) / 1_000_000;
    let component_align = (root_alignment_score * 300_000) / 1_000_000;
    let component_phase = (phase_coherence_score * 100_000) / 1_000_000;
    component_uptime + component_align + component_phase
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeHeartbeat {
    pub node_id: [u8; 32],
    pub timestamp: u64,
    pub seq_num: u64, // V5.0 Requirement
    pub smt_root: [u8; 32],
    pub epoch_id: u64,
    pub connectivity_proof: [u8; 32], // V5.0 Requirement (BLAKE3 Out-circuit)
    pub signature: Vec<u8>,
}

pub fn compute_connectivity_proof(recent_nullifiers: &[[u8; 32]]) -> [u8; 32] {
    // Mematuhi aturan hashing out-circuit: SELALU gunakan BLAKE3
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
    pub fn insert_heartbeat(&mut self, _hb: &NodeHeartbeat) {}
    pub fn root(&self) -> [u8; 32] {
        self.root
    }
    pub fn compute_uptime_weight_fp(&self, _node_id: [u8; 32], _epoch_id: u64) -> u64 {
        1_000_000
    }
}

impl Default for LivenessSMT {
    fn default() -> Self {
        Self::new()
    }
}
