// File: crates/scalar-network/src/relay.rs

use std::collections::HashMap;

pub struct RelayNode {
    /// store seq_num last that validated from each node
    seq_nums: HashMap<[u8; 32], u64>,
    /// store daftar timestamp (in miliseconds) from message that validated per node
    rate_limits: HashMap<[u8; 32], Vec<u64>>,
    /// track execute Phase 2 for toneeand verification pengujian
    pub phase2_run_count: u64,
}

impl RelayNode {
    pub fn new() -> Self {
        Self {
            seq_nums: HashMap::new(),
            rate_limits: HashMap::new(),
            phase2_run_count: 0,
        }
    }

    pub fn validate_and_relay(
        &mut self,
        node_id: [u8; 32],
        seq_num: u64,
        timestamp_ms: u64,
        _payload: &[u8],
    ) -> Result<(), &'static str> {
        // PHASE 1: Monotonic seq_num check
        if let Some(&last_seq) = self.seq_nums.get(&node_id) {
            if seq_num <= last_seq {
                return Err("Phase 1 Failed: seq_num is not strictly monotonic");
            }
        }

        // PHASE 1: Rate limit check (Maksimum 10 pesan per menit / 60.000 ms)
        let timestamps = self.rate_limits.entry(node_id).or_default();
        // Bersihkan timestamp yang lebih tua dari 1 menit (Zero floating point, murni integer math)
        timestamps.retain(|&ts| timestamp_ms.saturating_sub(ts) < 60_000);

        if timestamps.len() >= 10 {
            return Err("Phase 1 Failed: Rate limit exceeded (10 per minute)");
        }

        // --- PHASE 1 LULUS ---
        // Perbarui state node
        self.seq_nums.insert(node_id, seq_num);
        timestamps.push(timestamp_ms);

        // PHASE 2: Logika utama (Mocked sesuai spesifikasi yang tidak berubah)
        self.phase2_run_count += 1;

        Ok(())
    }
}

impl Default for RelayNode {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_rejected_same_seq_num() {
        let mut node = RelayNode::new();
        let id = [1u8; 32];
        assert!(node.validate_and_relay(id, 10, 1000, &[]).is_ok());
        assert!(node.validate_and_relay(id, 10, 2000, &[]).is_err());
    }

    #[test]
    fn test_replay_rejected_lower_seq_num() {
        let mut node = RelayNode::new();
        let id = [1u8; 32];
        assert!(node.validate_and_relay(id, 10, 1000, &[]).is_ok());
        assert!(node.validate_and_relay(id, 5, 2000, &[]).is_err());
    }

    #[test]
    fn test_monotonic_seq_num_accepted() {
        let mut node = RelayNode::new();
        let id = [1u8; 32];
        assert!(node.validate_and_relay(id, 10, 1000, &[]).is_ok());
        assert!(node.validate_and_relay(id, 11, 2000, &[]).is_ok());
    }

    #[test]
    fn test_rate_limit_enforced_at_10_per_minute() {
        let mut node = RelayNode::new();
        let id = [2u8; 32];
        for i in 1..=10 {
            assert!(node.validate_and_relay(id, i, 1000 + i, &[]).is_ok());
        }
        // Pesan ke-11 dalam waktu berdekatan (di bawah 60.000 ms) ditolak
        assert!(node.validate_and_relay(id, 11, 2000, &[]).is_err());
    }

    #[test]
    fn test_rate_limit_resets_after_one_minute() {
        let mut node = RelayNode::new();
        let id = [3u8; 32];
        for i in 1..=10 {
            assert!(node.validate_and_relay(id, i, 1000 + i, &[]).is_ok());
        }
        // Pesan ke-11 ditolak
        assert!(node.validate_and_relay(id, 11, 2000, &[]).is_err());

        // Pesan ke-12 masuk setelah > 1 menit (60.000 ms) dari pesan pertama
        assert!(node.validate_and_relay(id, 12, 65_000, &[]).is_ok());
    }

    #[test]
    fn test_phase2_still_not_run_if_phase1_fails() {
        let mut node = RelayNode::new();
        let id = [4u8; 32];

        node.validate_and_relay(id, 10, 1000, &[]).unwrap();
        let count_before = node.phase2_run_count;

        // Sengaja buat gagal di Phase 1 dengan seq_num yang sama
        let _ = node.validate_and_relay(id, 10, 2000, &[]);
        let count_after = node.phase2_run_count;

        assert_eq!(
            count_before, count_after,
            "Phase 2 dieksekusi padahal Phase 1 gagal"
        );
    }
}
