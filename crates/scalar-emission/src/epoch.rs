// File: crates/scalar-emission/src/epoch.rs

use crate::liveness::{LivenessSMT, NodeHeartbeat, EXPECTED_HEARTBEATS_PER_EPOCH};
use crate::manifest::{EpochRewardManifest, EpochStatus, NodeReward};

pub struct EpochProcessor {
    pub current_epoch: u64,
    pub liveness_smt: LivenessSMT,
    pub heartbeats: Vec<NodeHeartbeat>,
}

impl EpochProcessor {
    pub fn new(epoch_id: u64) -> Self {
        Self {
            current_epoch: epoch_id,
            liveness_smt: LivenessSMT::new(),
            heartbeats: Vec::new(),
        }
    }

    /// STEP 1.5: Validasi Konektivitas (Out-circuit: Menggunakan BLAKE3)
    pub fn validate_connectivity(
        &self,
        heartbeat: &NodeHeartbeat,
        network_recent_nullifiers: &[[u8; 32]],
    ) -> bool {
        let expected_proof = crate::liveness::compute_connectivity_proof(network_recent_nullifiers);
        heartbeat.connectivity_proof == expected_proof
    }

    pub fn process_heartbeat(
        &mut self,
        heartbeat: NodeHeartbeat,
        network_recent_nullifiers: &[[u8; 32]],
    ) -> Result<(), &'static str> {
        if heartbeat.epoch_id != self.current_epoch {
            return Err("Invalid epoch ID");
        }
        if !self.validate_connectivity(&heartbeat, network_recent_nullifiers) {
            return Err("Step 1.5: Connectivity validation failed");
        }
        self.liveness_smt.insert_heartbeat(&heartbeat);
        self.heartbeats.push(heartbeat);
        Ok(())
    }

    /// STEP 3.5: Slashing & Manifest generation (Zero Floating Point enforced)
    pub fn finalize_epoch(
        &self,
        total_emission: u64,
        active_nodes: &[[u8; 32]],
    ) -> EpochRewardManifest {
        let mut slashed_nodes = Vec::new();
        let mut total_uptime_weight = 0;
        let mut node_rewards = Vec::new();

        // Threshold Slashing: Minimal 50% dari ekspektasi detak jantung
        let threshold = (EXPECTED_HEARTBEATS_PER_EPOCH / 2) as u64;

        for node_id in active_nodes {
            let node_heartbeats = self
                .heartbeats
                .iter()
                .filter(|hb| hb.node_id == *node_id)
                .count() as u64;

            if node_heartbeats < threshold {
                // Slashing: Node gagal, bobot dihapus total
                slashed_nodes.push(*node_id);
                node_rewards.push(NodeReward {
                    node_id: *node_id,
                    amount: 0,
                });
            } else {
                // Konversi aman ke Integer Fixed-point (Basis 1.000.000)
                let uptime_ratio =
                    (node_heartbeats * 1_000_000) / EXPECTED_HEARTBEATS_PER_EPOCH as u64;

                // Kalkulasi bobot menggunakan formula komponen
                let weight =
                    crate::liveness::compute_uptime_weight(uptime_ratio, 1_000_000, 1_000_000);
                total_uptime_weight += weight;
                node_rewards.push(NodeReward {
                    node_id: *node_id,
                    amount: weight,
                });
            }
        }

        EpochRewardManifest {
            epoch_id: self.current_epoch,
            accepted_liveness_root: self.liveness_smt.root(),
            connectivity_summary: [0; 32],
            total_uptime_weight,
            emission_amount: total_emission,
            equity_gini: 0,
            fee_total: 0,
            slashed_nodes,
            reward_root: EpochRewardManifest::compute_reward_root(&node_rewards),
            previous_emission_total: 0,
            status: EpochStatus::Finalized,
        }
    }
}

impl Default for EpochProcessor {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_step_1_5_connectivity_validation() {
        let mut processor = EpochProcessor::new(1);
        let nullifiers = vec![[1u8; 32], [2u8; 32]];
        let valid_proof = crate::liveness::compute_connectivity_proof(&nullifiers);

        let hb = NodeHeartbeat {
            node_id: [9u8; 32],
            timestamp: 1000,
            seq_num: 1,
            smt_root: [0; 32],
            epoch_id: 1,
            connectivity_proof: valid_proof,
            signature: vec![],
        };

        assert!(processor.process_heartbeat(hb.clone(), &nullifiers).is_ok());

        let mut invalid_hb = hb.clone();
        invalid_hb.connectivity_proof = [0xFF; 32];
        assert!(processor
            .process_heartbeat(invalid_hb, &nullifiers)
            .is_err());
    }

    #[test]
    fn test_step_3_5_slashing() {
        let mut processor = EpochProcessor::new(1);
        let nullifiers = vec![[1u8; 32]];
        let valid_proof = crate::liveness::compute_connectivity_proof(&nullifiers);

        let node_good = [10u8; 32];
        let node_slashed = [11u8; 32];

        // Node baik mengirimkan detak jantung di atas ambang batas (2200 > 2160)
        for i in 0..2200 {
            let hb = NodeHeartbeat {
                node_id: node_good,
                timestamp: i,
                seq_num: i,
                smt_root: [0; 32],
                epoch_id: 1,
                connectivity_proof: valid_proof,
                signature: vec![],
            };
            processor.process_heartbeat(hb, &nullifiers).unwrap();
        }

        // Node buruk mengirim 0 heartbeat
        let manifest = processor.finalize_epoch(1000, &[node_good, node_slashed]);

        // Verifikasi array pemotongan
        assert!(manifest.slashed_nodes.contains(&node_slashed));
        assert!(!manifest.slashed_nodes.contains(&node_good));
    }
}
