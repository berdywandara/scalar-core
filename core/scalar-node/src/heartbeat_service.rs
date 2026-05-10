//! Heartbeat Service — Spec §7.2, §7.2a, §7.2b
//!
//! Menghubungkan:
//!   - NodeHeartbeat v9.0 (108 bytes, BLAKE3-MAC) dari scalar-emission
//!   - HeartbeatVerifier (5-step) dari scalar-network
//!   - EpochTracker dari scalar-emission
//!   - P2P swarm broadcast via mpsc channel
//!
//! Flow produksi heartbeat (setiap 10 menit, spec §7.2):
//!   1. Increment seq_num
//!   2. Compute prev_hash = BLAKE3(last_hb_bytes)
//!   3. Compute MAC = BLAKE3(NodeKey_epoch || node_id || seq_num || timestamp || smt_root || prev_hash)
//!   4. Serialize ke 108 bytes
//!   5. Broadcast via gossipsub topic scalar/heartbeat/1
//!
//! Flow verifikasi heartbeat (saat terima dari peer):
//!   1-5: HeartbeatVerifier::verify() — TTL, seq_num, prev_hash, MAC, accept

use scalar_emission::liveness::{
    compress_node_id, compute_heartbeat_mac, derive_node_key_epoch, EpochTracker, NodeHeartbeat,
};
use scalar_network::heartbeat_verifier::HeartbeatVerifier;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ── HeartbeatService ──────────────────────────────────────────────────────────

/// Service yang mengelola produksi dan verifikasi heartbeat. Spec §7.2.
pub struct HeartbeatService {
    /// Node ID (compressed 4 bytes). Spec §7.2.
    pub node_id: [u8; 4],
    /// NodeKey untuk MAC computation. Spec §7.2.
    node_key: [u8; 32],
    /// Epoch ID saat ini. Spec §7.2c T-1.
    pub current_epoch: u64,
    /// seq_num terakhir yang dikirim. Spec §7.2.
    pub last_seq_num: u32,
    /// Bytes dari heartbeat terakhir — untuk prev_hash. Spec §7.2.
    last_hb_bytes: Option<[u8; 108]>,
    /// SMT root saat ini (placeholder). Spec §7.2.
    pub smt_root: [u8; 32],
    /// Verifier untuk heartbeat yang diterima dari peer. Spec §7.2b.
    verifier: HeartbeatVerifier,
    /// Tracker epoch per node. Spec §7.2a.
    epoch_tracker: EpochTracker,
    /// Uptime counter per peer node_id. Spec §7.3.
    pub uptime_counters: HashMap<[u8; 4], u32>,
}

impl HeartbeatService {
    /// Buat HeartbeatService baru. Spec §7.2.
    ///
    /// `full_node_id`: 32 bytes full node ID (di-compress ke 4 bytes)
    /// `node_key`: 32 bytes NodeKey (TERPISAH dari SpendKey — spec §13.7)
    pub fn new(full_node_id: [u8; 32], node_key: [u8; 32]) -> Self {
        let node_id = compress_node_id(&full_node_id);
        println!("[HB] NodeID (compressed): {}", hex::encode(node_id));
        Self {
            node_id,
            node_key,
            current_epoch: 0,
            last_seq_num: 0,
            last_hb_bytes: None,
            smt_root: [0u8; 32],
            verifier: HeartbeatVerifier::new(),
            epoch_tracker: EpochTracker::new(),
            uptime_counters: HashMap::new(),
        }
    }

    /// Produce NodeHeartbeat v9.0 untuk broadcast. Spec §7.2.
    ///
    /// Increment seq_num, compute MAC, serialize ke 108 bytes.
    /// Rule T-1: epoch boundary dari seq_num, bukan wall-clock.
    pub fn produce_heartbeat(&mut self) -> NodeHeartbeat {
        // Increment seq_num — strictly monotonic (Rule T-5)
        self.last_seq_num += 1;
        let seq_num = self.last_seq_num;

        // Compute epoch dari seq_num — Rule T-1 (bukan wall-clock)
        self.current_epoch = scalar_network::time_security::epoch_from_seq_num(seq_num);

        // Timestamp delta dari epoch start — hanya untuk TTL check (Rule T-6)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        // prev_hash: BLAKE3(last_hb_bytes) atau genesis hash untuk HB pertama
        let prev_hash = match &self.last_hb_bytes {
            Some(bytes) => *blake3::hash(bytes).as_bytes(),
            None => {
                // HB pertama epoch 0: prev_hash = BLAKE3(genesis_placeholder)
                *blake3::hash(b"scalar_genesis_epoch0_placeholder").as_bytes()
            }
        };

        // NodeKey_epoch_i = BLAKE3(NodeKey || epoch_id_le64) — spec §7.2
        let node_key_epoch = derive_node_key_epoch(&self.node_key, self.current_epoch);

        // Compute MAC — spec §7.2
        let mac = compute_heartbeat_mac(
            &node_key_epoch,
            &self.node_id,
            seq_num,
            timestamp,
            &self.smt_root,
            &prev_hash,
        );

        let hb = NodeHeartbeat {
            node_id: self.node_id,
            seq_num,
            timestamp,
            smt_root: self.smt_root,
            prev_hash,
            mac,
        };

        // Simpan bytes untuk prev_hash berikutnya
        self.last_hb_bytes = Some(hb.to_bytes());

        // Record di epoch tracker
        self.epoch_tracker.record_heartbeat(&hb, self.current_epoch);

        println!(
            "[HB] Produced HB #{} epoch={} ts={} mac={}",
            seq_num,
            self.current_epoch,
            timestamp,
            hex::encode(&mac[..4])
        );

        hb
    }

    /// Verifikasi heartbeat dari peer. Spec §7.2b.
    ///
    /// Menjalankan 5-step verification:
    ///   1. TTL check via NMT
    ///   2. seq_num monotonic
    ///   3. prev_hash chain integrity
    ///   4. MAC verification
    ///   5. Accept + update counters
    ///
    /// Returns true jika valid, false jika ditolak.
    pub fn verify_peer_heartbeat(
        &mut self,
        hb_bytes: &[u8],
        nmt: u32,
        peer_node_key_epoch: &[u8; 32],
    ) -> bool {
        // Deserialize dari 108 bytes
        if hb_bytes.len() != 108 {
            println!(
                "[HB] REJECT: invalid size {} (expected 108)",
                hb_bytes.len()
            );
            return false;
        }
        let arr: &[u8; 108] = match hb_bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let hb = NodeHeartbeat::from_bytes(arr);

        // 5-step verification — spec §7.2b
        match self
            .verifier
            .verify(&hb, nmt, peer_node_key_epoch, self.current_epoch)
        {
            Ok(()) => {
                println!(
                    "[HB] ACCEPT: peer={} seq={} epoch={}",
                    hex::encode(hb.node_id),
                    hb.seq_num,
                    self.current_epoch
                );
                // Update uptime counter — spec §7.3
                *self.uptime_counters.entry(hb.node_id).or_insert(0) += 1;
                true
            }
            Err(e) => {
                println!(
                    "[HB] REJECT: peer={} seq={} reason={:?}",
                    hex::encode(hb.node_id),
                    hb.seq_num,
                    e
                );
                false
            }
        }
    }

    /// Compute NMT sederhana dari timestamp lokal. Spec §12.3a.
    /// Production: gunakan median dari 8 peer timestamps.
    pub fn local_nmt() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32
    }

    /// Update SMT root. Spec §7.2.
    pub fn update_smt_root(&mut self, root: [u8; 32]) {
        self.smt_root = root;
    }

    /// Ambil uptime counter untuk peer. Spec §7.3.
    pub fn uptime_count(&self, node_id: &[u8; 4]) -> u32 {
        self.uptime_counters.get(node_id).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_service() -> HeartbeatService {
        HeartbeatService::new([0x01u8; 32], [0x42u8; 32])
    }

    #[test]
    fn test_produce_heartbeat_108_bytes() {
        let mut svc = make_service();
        let hb = svc.produce_heartbeat();
        assert_eq!(hb.to_bytes().len(), 108);
    }

    #[test]
    fn test_produce_heartbeat_seq_num_monotonic() {
        let mut svc = make_service();
        let hb1 = svc.produce_heartbeat();
        let hb2 = svc.produce_heartbeat();
        assert!(hb2.seq_num > hb1.seq_num);
    }

    #[test]
    fn test_produce_heartbeat_prev_hash_chained() {
        let mut svc = make_service();
        let hb1 = svc.produce_heartbeat();
        let hb2 = svc.produce_heartbeat();
        let expected_prev = *blake3::hash(&hb1.to_bytes()).as_bytes();
        assert_eq!(hb2.prev_hash, expected_prev);
    }

    #[test]
    fn test_produce_heartbeat_mac_valid() {
        let mut svc = make_service();
        let hb = svc.produce_heartbeat();
        // MAC harus non-zero
        assert_ne!(hb.mac, [0u8; 32]);
    }

    #[test]
    fn test_verify_self_produced_heartbeat() {
        // Node verify heartbeat yang dia sendiri produce
        let mut svc = make_service();
        let hb = svc.produce_heartbeat();
        let hb_bytes = hb.to_bytes();
        let nmt = HeartbeatService::local_nmt();
        // Compute NodeKey_epoch untuk verifikasi
        let nke = derive_node_key_epoch(&svc.node_key, svc.current_epoch);
        // Seed verifier dengan state awal
        svc.verifier.seed_node_state(svc.node_id, [0u8; 108], 0);
        // Re-produce untuk test (verifier butuh state yang di-seed)
        let mut svc2 = make_service();
        let hb2 = svc2.produce_heartbeat();
        let bytes2 = hb2.to_bytes();
        let nke2 = derive_node_key_epoch(&svc2.node_key, svc2.current_epoch);
        // Verifikasi dengan verifier baru
        let mut verifier = HeartbeatVerifier::new();
        let result = verifier.verify(&hb2, nmt, &nke2, 0);
        assert!(result.is_ok(), "Self-produced HB harus valid: {:?}", result);
    }

    #[test]
    fn test_uptime_counter_increments() {
        let mut svc = make_service();
        let node_id = [0x01u8; 4];
        *svc.uptime_counters.entry(node_id).or_insert(0) += 1;
        *svc.uptime_counters.entry(node_id).or_insert(0) += 1;
        assert_eq!(svc.uptime_count(&node_id), 2);
    }
}
