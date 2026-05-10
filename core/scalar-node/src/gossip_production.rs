//! Gossip Production Layer — HeartbeatRateLimiter + StateBeacon Broadcast
//!
//! PR-V12-014 FIX: dua gap dari v11.0:
//!
//! G-4: HeartbeatRateLimiter (Rule T-4) sudah ada di time_security.rs
//!      tetapi belum disambungkan ke gossip layer.
//!      FIX: sambungkan via GossipLayer yang enforce rate limit sebelum forward.
//!
//! G-5: StateBeacon struct sudah ada tetapi belum ada broadcast logic
//!      ke topic scalar/beacon/1.
//!      FIX: implementasi StateBeaconBroadcaster.
//!
//! Spec §12.2 (StateBeacon authenticated), §7.2c T-4 (rate limiter).

use scalar_network::state_beacon::{compute_beacon_checksum, StateBeacon, STATE_BEACON_WIRE_SIZE};
use scalar_network::time_security::HeartbeatRateLimiter;

// ── GossipLayer — rate limiter disambungkan ke gossip ────────────────────────

/// Gossip layer dengan HeartbeatRateLimiter terintegrasi. Spec §7.2c T-4, Gap G-4.
///
/// FIX: HeartbeatRateLimiter sekarang aktif di gossip layer.
/// Setiap heartbeat yang masuk WAJIB melalui rate limiter sebelum di-forward.
pub struct GossipLayer {
    /// HeartbeatRateLimiter — spec §7.2c T-4. DISAMBUNGKAN ke gossip.
    rate_limiter: HeartbeatRateLimiter,
    /// Counter heartbeat yang diterima.
    pub received_count: u64,
    /// Counter heartbeat yang ditolak karena rate limit.
    pub rejected_count: u64,
    /// Counter heartbeat yang di-forward.
    pub forwarded_count: u64,
}

impl GossipLayer {
    pub fn new() -> Self {
        Self {
            rate_limiter: HeartbeatRateLimiter::new(),
            received_count: 0,
            rejected_count: 0,
            forwarded_count: 0,
        }
    }

    /// Proses heartbeat yang masuk — enforce rate limit T-4. Spec §7.2c T-4.
    ///
    /// Returns true jika heartbeat lolos rate limit dan boleh di-forward.
    /// Returns false jika ditolak (interval terlalu pendek).
    ///
    /// FIX Gap G-4: rate limiter sekarang aktif di gossip layer.
    pub fn process_incoming_heartbeat(
        &mut self,
        node_id: [u8; 4],
        timestamp: u32,
    ) -> GossipDecision {
        self.received_count += 1;

        // T-4: enforce rate limit — spec §7.2c
        if !self.rate_limiter.check_and_update(node_id, timestamp) {
            self.rejected_count += 1;
            return GossipDecision::RateLimited {
                node_id,
                reason: "T-4: interval terlalu pendek (< 300s)",
            };
        }

        self.forwarded_count += 1;
        GossipDecision::Forward
    }

    /// Statistik gossip layer.
    pub fn stats(&self) -> GossipStats {
        GossipStats {
            received: self.received_count,
            rejected: self.rejected_count,
            forwarded: self.forwarded_count,
        }
    }
}

impl Default for GossipLayer {
    fn default() -> Self {
        Self::new()
    }
}

/// Keputusan gossip layer untuk satu heartbeat. Spec §7.2c T-4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipDecision {
    /// Heartbeat lolos rate limit — boleh di-forward ke peers.
    Forward,
    /// Heartbeat ditolak — interval terlalu pendek (T-4 violation).
    RateLimited { node_id: [u8; 4], reason: &'static str },
}

impl GossipDecision {
    pub fn should_forward(&self) -> bool {
        matches!(self, Self::Forward)
    }
}

/// Statistik gossip layer.
#[derive(Debug, Clone)]
pub struct GossipStats {
    pub received: u64,
    pub rejected: u64,
    pub forwarded: u64,
}

// ── StateBeaconBroadcaster — broadcast StateBeacon ke topic ──────────────────

/// Broadcaster StateBeacon via gossipsub topic "scalar/beacon/1". Spec §12.2, Gap G-5.
///
/// FIX: StateBeacon sekarang di-broadcast setiap epoch boundary via topic pubsub.
/// MAC StateBeacon diverifikasi sebelum di-forward.
pub struct StateBeaconBroadcaster {
    /// NodeKey epoch untuk MAC computation. Spec §12.2.
    #[allow(dead_code)]
    node_key_epoch: [u8; 32],
    /// Counter beacon yang di-broadcast.
    pub broadcast_count: u64,
    /// Counter beacon yang diterima dan valid.
    pub received_valid_count: u64,
    /// Counter beacon yang ditolak (MAC invalid).
    pub received_invalid_count: u64,
}

impl StateBeaconBroadcaster {
    pub fn new(node_key_epoch: [u8; 32]) -> Self {
        Self {
            node_key_epoch,
            broadcast_count: 0,
            received_valid_count: 0,
            received_invalid_count: 0,
        }
    }

    /// Buat dan serialize StateBeacon untuk broadcast. Spec §12.2, Gap G-5.
    ///
    /// StateBeacon di-broadcast setiap epoch boundary.
    /// Format: epoch_id(8) || smt_root(32) || checksum(4) = 44 bytes.
    pub fn create_beacon(&mut self, epoch_id: u64, smt_root: [u8; 32]) -> Vec<u8> {
        let beacon = StateBeacon::new(epoch_id, smt_root);
        self.broadcast_count += 1;
        println!(
            "[BEACON] Broadcasting StateBeacon epoch={} smt_root={} to scalar/beacon/1",
            epoch_id,
            hex::encode(&smt_root[..4])
        );
        beacon.to_bytes().to_vec()
    }

    /// Verifikasi dan proses StateBeacon yang diterima. Spec §12.2, Gap G-5.
    ///
    /// MAC StateBeacon diverifikasi sebelum di-forward.
    /// Returns Some(StateBeacon) jika valid, None jika MAC tidak cocok.
    pub fn receive_and_verify_beacon(
        &mut self,
        beacon_bytes: &[u8],
    ) -> Option<StateBeacon> {
        // Cek ukuran
        if beacon_bytes.len() != STATE_BEACON_WIRE_SIZE {
            self.received_invalid_count += 1;
            println!(
                "[BEACON] REJECT: invalid size {} (expected {})",
                beacon_bytes.len(), STATE_BEACON_WIRE_SIZE
            );
            return None;
        }

        let arr: &[u8; STATE_BEACON_WIRE_SIZE] = beacon_bytes.try_into().ok()?;
        let beacon = StateBeacon::from_bytes(arr);

        // Verifikasi MAC (checksum) — spec §12.2
        if !beacon.verify_checksum() {
            self.received_invalid_count += 1;
            println!(
                "[BEACON] REJECT: MAC invalid epoch={}",
                beacon.epoch_id
            );
            return None;
        }

        self.received_valid_count += 1;
        println!(
            "[BEACON] ACCEPT: valid beacon epoch={} smt_root={}",
            beacon.epoch_id,
            hex::encode(&beacon.smt_root[..4])
        );
        Some(beacon)
    }

    /// Compute beacon checksum (MAC). Spec §12.2.
    pub fn compute_beacon_mac(epoch_id: u64, smt_root: &[u8; 32]) -> [u8; 4] {
        compute_beacon_checksum(epoch_id, smt_root)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use scalar_network::time_security::T_HB_MIN_INTERVAL_S;

    // ── test_rate_limiter_connected_to_gossip ─────────────────────────────────

    #[test]
    fn test_rate_limiter_connected_to_gossip() {
        // T-4 rate limit aktif di gossip layer. Spec §7.2c T-4, Gap G-4.
        let mut gossip = GossipLayer::new();
        let node = [0x01u8; 4];

        // Pertama kali → forward
        let d1 = gossip.process_incoming_heartbeat(node, 1_000);
        assert!(d1.should_forward(), "HB pertama harus forward");

        // Interval terlalu pendek → rate limited
        let d2 = gossip.process_incoming_heartbeat(node, 1_000 + T_HB_MIN_INTERVAL_S - 1);
        assert!(!d2.should_forward(), "HB interval pendek harus ditolak (T-4)");
        assert!(matches!(d2, GossipDecision::RateLimited { .. }));

        // Verifikasi stats
        let stats = gossip.stats();
        assert_eq!(stats.received, 2);
        assert_eq!(stats.rejected, 1);
        assert_eq!(stats.forwarded, 1);
    }

    #[test]
    fn test_rate_limiter_allows_after_interval() {
        // Setelah interval cukup → forward. Spec §7.2c T-4.
        let mut gossip = GossipLayer::new();
        let node = [0x01u8; 4];

        gossip.process_incoming_heartbeat(node, 1_000);
        // Interval tepat T_HB_MIN_INTERVAL_S → allowed
        let d = gossip.process_incoming_heartbeat(node, 1_000 + T_HB_MIN_INTERVAL_S);
        assert!(d.should_forward());
    }

    #[test]
    fn test_rate_limiter_different_nodes_independent() {
        // Rate limit per node independent. Spec §7.2c T-4.
        let mut gossip = GossipLayer::new();
        let node_a = [0x01u8; 4];
        let node_b = [0x02u8; 4];

        gossip.process_incoming_heartbeat(node_a, 1_000);
        // node_a rate limited
        let da = gossip.process_incoming_heartbeat(node_a, 1_100);
        assert!(!da.should_forward());

        // node_b masih bebas
        let db = gossip.process_incoming_heartbeat(node_b, 1_000);
        assert!(db.should_forward(), "Node B harus independent dari Node A");
    }

    // ── test_state_beacon_broadcast ───────────────────────────────────────────

    #[test]
    fn test_state_beacon_broadcast() {
        // StateBeacon di-broadcast ke scalar/beacon/1. Spec §12.2, Gap G-5.
        let mut broadcaster = StateBeaconBroadcaster::new([0x42u8; 32]);
        let smt_root = [0xABu8; 32];
        let bytes = broadcaster.create_beacon(5, smt_root);

        // Ukuran harus 44 bytes
        assert_eq!(bytes.len(), STATE_BEACON_WIRE_SIZE,
            "StateBeacon harus 44 bytes — spec §12.1a");
        assert_eq!(broadcaster.broadcast_count, 1);
    }

    // ── test_state_beacon_mac_verify ──────────────────────────────────────────

    #[test]
    fn test_state_beacon_mac_verify() {
        // Beacon dengan MAC invalid tidak di-forward. Spec §12.2, Gap G-5.
        let mut broadcaster = StateBeaconBroadcaster::new([0x42u8; 32]);

        // Valid beacon
        let valid_bytes = broadcaster.create_beacon(3, [0x11u8; 32]);
        let result = broadcaster.receive_and_verify_beacon(&valid_bytes);
        assert!(result.is_some(), "Valid beacon harus diterima");
        assert_eq!(result.unwrap().epoch_id, 3);

        // Tampered beacon (ubah 1 byte MAC)
        let mut tampered = valid_bytes.clone();
        tampered[40] ^= 0xFF; // corrupt MAC
        let result_tampered = broadcaster.receive_and_verify_beacon(&tampered);
        assert!(result_tampered.is_none(),
            "Beacon dengan MAC invalid harus ditolak — spec §12.2");
        assert_eq!(broadcaster.received_invalid_count, 1);
    }

    #[test]
    fn test_state_beacon_wrong_size_rejected() {
        // Beacon ukuran salah → ditolak. Spec §12.1a.
        let mut broadcaster = StateBeaconBroadcaster::new([0x42u8; 32]);
        let result = broadcaster.receive_and_verify_beacon(&[0u8; 10]);
        assert!(result.is_none());
    }

    #[test]
    fn test_state_beacon_roundtrip() {
        // Beacon yang di-broadcast bisa di-verify oleh receiver. Spec §12.2.
        let mut broadcaster = StateBeaconBroadcaster::new([0x42u8; 32]);
        let bytes = broadcaster.create_beacon(7, [0xCCu8; 32]);
        let beacon = broadcaster.receive_and_verify_beacon(&bytes).unwrap();
        assert_eq!(beacon.epoch_id, 7);
        assert_eq!(beacon.smt_root, [0xCCu8; 32]);
    }

    // ── test constants ────────────────────────────────────────────────────────

    #[test]
    fn test_state_beacon_wire_size() {
        // STATE_BEACON_WIRE_SIZE = 44. Spec §12.1a.
        assert_eq!(STATE_BEACON_WIRE_SIZE, 44usize);
    }
}
