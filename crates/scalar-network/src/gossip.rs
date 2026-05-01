// File: crates/scalar-network/src/gossip.rs

use std::collections::HashMap;
use tokio::sync::RwLock;

pub const MAX_MSG_RATE: u32 = 10; // Layer 2 CONSTRAINED: 10 per menit
pub const MAX_FANOUT: usize = 15; // OSSIFIED

#[derive(Clone, Debug, PartialEq)]
pub struct DeltaNullifier {
    pub nullifier: [u8; 32],
    pub spend_proof: Vec<u8>,
    pub new_commitment: [u8; 32],
    pub entry_timestamp: u64, // BARU - untuk C10 enforcement
}

#[derive(Clone, Debug, PartialEq)]
pub struct ScalarGossipMessage {
    pub sender_node_id: [u8; 32],
    pub timestamp: u64,
    pub seq_num: u64, // BARU - monotonic, anti-replay
    pub smt_root: [u8; 32],
    pub delta_nullifiers: Vec<DeltaNullifier>,
    pub connectivity_proof: [u8; 32], // BARU - BLAKE3(10 nullifiers terbaru)
    pub sender_signature: Vec<u8>,
}

pub struct RateLimiter {
    count: u32,
    max_rate: u32,
    window_secs: u64,
    last_reset_timestamp: u64,
}

impl RateLimiter {
    pub fn new(max_rate: u32, window_secs: u64, current_timestamp: u64) -> Self {
        Self {
            count: 0,
            max_rate,
            window_secs,
            last_reset_timestamp: current_timestamp,
        }
    }

    pub fn check(&mut self, current_timestamp: u64) -> bool {
        // Jika waktu melompat lebih dari window_secs, reset count
        if current_timestamp.saturating_sub(self.last_reset_timestamp) > self.window_secs {
            self.count = 0;
            self.last_reset_timestamp = current_timestamp;
        }

        if self.count < self.max_rate {
            self.count += 1;
            true
        } else {
            false
        }
    }
}

pub struct NodeMessageTracker {
    // State per NodeID: last_seen_seq_num
    pub last_seq_num: HashMap<[u8; 32], u64>,
    // Rate limiter: pesan per menit per NodeID
    pub message_rate: HashMap<[u8; 32], RateLimiter>,
    // Counter for testing logic
    pub phase2_execution_count: u32,
}

impl NodeMessageTracker {
    pub fn new() -> Self {
        Self {
            last_seq_num: HashMap::new(),
            message_rate: HashMap::new(),
            phase2_execution_count: 0,
        }
    }
}

impl Default for NodeMessageTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum RelayError {
    ReplayDetected {
        sender: [u8; 32],
        received_seq: u64,
        expected_min: u64,
    },
    RateLimitExceeded {
        sender: [u8; 32],
        limit: u32,
    },
    // Error lainnya disederhanakan untuk scope ini
}

pub struct GossipNode {
    pub tracker: RwLock<NodeMessageTracker>,
}

impl Default for GossipNode {
    fn default() -> Self {
        Self::new()
    }
}

impl GossipNode {
    pub fn new() -> Self {
        Self {
            tracker: RwLock::new(NodeMessageTracker::new()),
        }
    }

    pub async fn validate_and_relay(&self, msg: &ScalarGossipMessage) -> Result<(), RelayError> {
        // ═══════════════════════════════
        // PHASE 1: CHEAP CHECK
        // ═══════════════════════════════

        // BARU (v5.0) — 1f. seq_num monotonic check
        {
            let tracker = self.tracker.read().await;
            if let Some(&last_seq) = tracker.last_seq_num.get(&msg.sender_node_id) {
                if msg.seq_num <= last_seq {
                    // Anti-replay: seq_num harus selalu naik
                    return Err(RelayError::ReplayDetected {
                        sender: msg.sender_node_id,
                        received_seq: msg.seq_num,
                        expected_min: last_seq + 1,
                    });
                }
            }
        }

        // BARU (v5.0) — 1g. Rate limit check
        {
            let mut tracker = self.tracker.write().await;
            let current_ts = msg.timestamp; // Menggunakan timestamp dari pesan

            let limiter = tracker
                .message_rate
                .entry(msg.sender_node_id)
                .or_insert_with(|| RateLimiter::new(MAX_MSG_RATE, 60, current_ts));

            if !limiter.check(current_ts) {
                return Err(RelayError::RateLimitExceeded {
                    sender: msg.sender_node_id,
                    limit: MAX_MSG_RATE,
                });
            }
        }

        // ═══════════════════════════════
        // PHASE 2: EXPENSIVE CHECK (Mocked execution for spec demonstration)
        // ═══════════════════════════════
        {
            let mut tracker = self.tracker.write().await;
            tracker.phase2_execution_count += 1;
        }

        // Pheromone update HANYA terjadi setelah Phase 2 lolos.
        // Update seq_num tracker setelah semua check lolos
        {
            let mut tracker = self.tracker.write().await;
            tracker.last_seq_num.insert(msg.sender_node_id, msg.seq_num);
        }

        Ok(())
    }

    pub async fn phase2_execution_count(&self) -> u32 {
        self.tracker.read().await.phase2_execution_count
    }
}

#[cfg(test)]
mod tests_seq_num_ratelimit {
    use super::*;

    async fn create_test_node() -> GossipNode {
        GossipNode::new()
    }

    fn random_node_id() -> [u8; 32] {
        [42; 32]
    }

    fn build_valid_gossip_message(seq_num: u64) -> ScalarGossipMessage {
        build_valid_gossip_message_ts(random_node_id(), seq_num, 1000)
    }

    fn build_valid_gossip_message_ts(
        sender_node_id: [u8; 32],
        seq_num: u64,
        timestamp: u64,
    ) -> ScalarGossipMessage {
        ScalarGossipMessage {
            sender_node_id,
            timestamp,
            seq_num,
            smt_root: [0; 32],
            delta_nullifiers: vec![],
            connectivity_proof: [0; 32],
            sender_signature: vec![],
        }
    }

    #[tokio::test]
    async fn test_replay_rejected_same_seq_num() {
        let node = create_test_node().await;
        let msg = build_valid_gossip_message(42);

        assert!(node.validate_and_relay(&msg).await.is_ok());

        let result = node.validate_and_relay(&msg).await;
        assert!(matches!(result, Err(RelayError::ReplayDetected { .. })));
    }

    #[tokio::test]
    async fn test_replay_rejected_lower_seq_num() {
        let node = create_test_node().await;

        let msg_100 = build_valid_gossip_message(100);
        node.validate_and_relay(&msg_100).await.unwrap();

        let msg_99 = build_valid_gossip_message(99);
        let result = node.validate_and_relay(&msg_99).await;
        assert!(matches!(result, Err(RelayError::ReplayDetected { .. })));
    }

    #[tokio::test]
    async fn test_monotonic_seq_num_accepted() {
        let node = create_test_node().await;
        for seq in 1..=20 {
            // Majukan timestamp sebesar 10 detik per pesan agar tidak terkena rate limit
            let ts = 1000 + (seq * 10);
            let msg = build_valid_gossip_message_ts(random_node_id(), seq, ts);
            assert!(
                node.validate_and_relay(&msg).await.is_ok(),
                "seq={} harus diterima",
                seq
            );
        }
    }

    #[tokio::test]
    async fn test_rate_limit_enforced_at_10_per_minute() {
        let node = create_test_node().await;
        let sender = random_node_id();

        for i in 1..=10 {
            let msg = build_valid_gossip_message_ts(sender, i, 1000);
            assert!(node.validate_and_relay(&msg).await.is_ok());
        }

        let msg_11 = build_valid_gossip_message_ts(sender, 11, 1000);
        let result = node.validate_and_relay(&msg_11).await;
        assert!(matches!(result, Err(RelayError::RateLimitExceeded { .. })));
    }

    #[tokio::test]
    async fn test_rate_limit_resets_after_one_minute() {
        let node = create_test_node().await;
        let sender = random_node_id();

        for i in 1..=10 {
            let msg = build_valid_gossip_message_ts(sender, i, 1000);
            node.validate_and_relay(&msg).await.unwrap();
        }

        // Kirim pesan ke-11 dengan timestamp 61 detik lebih maju
        let msg = build_valid_gossip_message_ts(sender, 11, 1061);
        assert!(node.validate_and_relay(&msg).await.is_ok());
    }

    #[tokio::test]
    async fn test_phase2_still_not_run_if_phase1_fails() {
        let node = create_test_node().await;
        let msg_replay = build_valid_gossip_message(1);
        node.validate_and_relay(&msg_replay).await.unwrap();
        let phase2_count_before = node.phase2_execution_count().await;

        let _ = node.validate_and_relay(&msg_replay).await;
        let phase2_count_after = node.phase2_execution_count().await;

        assert_eq!(
            phase2_count_before, phase2_count_after,
            "Phase 2 tidak boleh dijalankan jika Phase 1 gagal"
        );
    }
}
