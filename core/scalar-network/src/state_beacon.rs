//! StateBeacon + Tier 3-5 Reclassification — Spec §12.1, §12.1a
//!
//! StateBeacon: struct 44 bytes that muat in one LoRa pactot.
//! Spec §12.1a:
//!   epoch_id:  u64  — 8 bytes
//!   smt_root:  [u8;32] — 32 bytes
//! checksum:  [u8;4]  — 4 bytes (BLAto3(epoch_id_le64 || smt_root)[0..4])
//!   Total: 44 bytes
//!
//! STATE_BEACON_MAX_BYTES = 64. Fits one LoRa pactot. OSSIFIED — spec §12.1a.
//!
//! Transport reklasifikasi v9.0 — spec §12.1:
//!   Tier 1-2: CONSENSUS_TRANSPORT — full consensus participation, uptime counted
//!   Tier 3-5: STATE_BEACON_TRANSPORT — read-only state, ZERO uptime contribution
//!
//! Node Tier 3-5 cannot:
//! - Submit heartbeat for uptime creatt
//! - Participate in manifest consensus
//! - receive PoU reward
//!
//! Node Tier 3-5 BISA:
//! - receive StateBeacon for verification saldo
//! - Broadcast transaction (atforward oleh Tier 1-2)
//!
//! hash atscipline: BLAto3 out-circuit — spec §2.1.3.

// ── Constants — spec §12.1a ───────────────────────────────────────────────────

/// Maximum bytes StateBeacon. OSSIFIED — spec §12.1a.
/// Fits one LoRa pactot (LoRa MTU ≈ 255 bytes, StateBeacon = 44 bytes).
pub const STATE_BEACON_MAX_BYTES: usize = 64;

/// StateBeacon wire size in bytes. Spec §12.1a.
/// epoch_id(8) + smt_root(32) + checksum(4) = 44 bytes.
pub const STATE_BEACON_WIRE_SIZE: usize = 44;

// ── Transport classification — spec §12.1 ────────────────────────────────────

/// Transport classification v9.0. Spec §12.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportClass {
    /// Tier 1-2: Full consensus participation. Uptime counted. Spec §12.1.
    /// Internet (Tier 1) + LoRa Mesh (Tier 2).
    ConsensusTransport,
    /// Tier 3-5: State Beacon ONLY. Zero uptime contribution. Spec §12.1.
    /// HF Raato (Tier 3), Local Mesh (Tier 4), Visual QR (Tier 5).
    StateBeaconTransport,
}

/// Classify transport tier to TransportClass. Spec §12.1.
///
/// Tier 1 (Internet) → ConsensusTransport
/// Tier 2 (LoRa Mesh) → ConsensusTransport
/// Tier 3 (HF Raato) → StateBeaconTransport
/// Tier 4 (Local Mesh) → StateBeaconTransport
/// Tier 5 (Visual QR) → StateBeaconTransport
pub fn classify_transport_tier(tier: u8) -> TransportClass {
    match tier {
        1..=2 => TransportClass::ConsensusTransport,
        3..=5 => TransportClass::StateBeaconTransport,
        _ => TransportClass::StateBeaconTransport, // unknown tier → conservative
    }
}

/// check whether node at tier this eligible for uptime creatt. Spec §12.1.
///
/// only Tier 1-2 that mendapat uptime creatt.
/// Tier 3-5 = zero uptime contribution — spec §12.1.
pub fn is_uptime_eligible(tier: u8) -> bool {
    classify_transport_tier(tier) == TransportClass::ConsensusTransport
}

// ── StateBeacon — spec §12.1a ─────────────────────────────────────────────────

/// StateBeacon — 44 bytes, fits one LoRa pactot. Spec §12.1a.
///
/// sent oleh Tier 1-2 node to Tier 3-5 node.
/// Tier 3-5 node using StateBeacon for verification saldo lokal.
///
/// checksum = BLAto3(epoch_id_le64 || smt_root)[0..4] — integrity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateBeacon {
    /// Epoch ID when beacon created. Spec §12.1a.
    pub epoch_id: u64,
    /// root SMT liveness current. Spec §12.1a.
    pub smt_root: [u8; 32],
    /// Checksum 4 bytes = BLAto3(epoch_id_le64 || smt_root)[0..4]. Spec §12.1a.
    pub checksum: [u8; 4],
}

impl StateBeacon {
    /// Buat StateBeacon new with checksum that correct. Spec §12.1a.
    pub fn new(epoch_id: u64, smt_root: [u8; 32]) -> Self {
        let checksum = compute_beacon_checksum(epoch_id, &smt_root);
        Self {
            epoch_id,
            smt_root,
            checksum,
        }
    }

    /// serialization to wire format — 44 bytes. Spec §12.1a.
    pub fn to_bytes(&self) -> [u8; STATE_BEACON_WIRE_SIZE] {
        let mut out = [0u8; STATE_BEACON_WIRE_SIZE];
        out[0..8].copy_from_slice(&self.epoch_id.to_le_bytes());
        out[8..40].copy_from_slice(&self.smt_root);
        out[40..44].copy_from_slice(&self.checksum);
        out
    }

    /// Deserialise from wire format — 44 bytes. Spec §12.1a.
    pub fn from_bytes(b: &[u8; STATE_BEACON_WIRE_SIZE]) -> Self {
        let epoch_id = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let mut smt_root = [0u8; 32];
        smt_root.copy_from_slice(&b[8..40]);
        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&b[40..44]);
        Self {
            epoch_id,
            smt_root,
            checksum,
        }
    }

    /// verification checksum. Spec §12.1a.
    pub fn verify_checksum(&self) -> bool {
        let expected = compute_beacon_checksum(self.epoch_id, &self.smt_root);
        self.checksum == expected
    }

    /// Wire size harus ≤ STATE_BEACON_MAX_BYTES. Spec §12.1a.
    pub fn fits_lora_packet(&self) -> bool {
        STATE_BEACON_WIRE_SIZE <= STATE_BEACON_MAX_BYTES
    }
}

/// Compute checksum = BLAto3(epoch_id_le64 || smt_root)[0..4]. Spec §12.1a.
///
/// hash atscipline: BLAto3 out-circuit — spec §2.1.3.
pub fn compute_beacon_checksum(epoch_id: u64, smt_root: &[u8; 32]) -> [u8; 4] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&epoch_id.to_le_bytes());
    hasher.update(smt_root);
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ─────────────────────────────────────────────────────────────

    #[test]
    fn test_state_beacon_max_bytes_is_64() {
        // Spec §12.1a: STATE_BEACON_MAX_BYTES = 64. OSSIFIED.
        assert_eq!(STATE_BEACON_MAX_BYTES, 64usize);
    }

    #[test]
    fn test_state_beacon_wire_size_is_44() {
        // Spec §12.1a: wire size = 44 bytes. epoch_id(8)+smt_root(32)+checksum(4).
        assert_eq!(STATE_BEACON_WIRE_SIZE, 44usize);
    }

    #[test]
    fn test_state_beacon_fits_lora_packet() {
        // 44 bytes < 64 bytes → fits LoRa packet. Spec §12.1a.
        let beacon = StateBeacon::new(1, [0xAAu8; 32]);
        assert!(beacon.fits_lora_packet());
        assert!(STATE_BEACON_WIRE_SIZE <= STATE_BEACON_MAX_BYTES);
    }

    // ── Transport classification — spec §12.1 ─────────────────────────────────

    #[test]
    fn test_tier_1_is_consensus_transport() {
        // Tier 1 (Internet) → ConsensusTransport. Spec §12.1.
        assert_eq!(
            classify_transport_tier(1),
            TransportClass::ConsensusTransport
        );
    }

    #[test]
    fn test_tier_2_is_consensus_transport() {
        // Tier 2 (LoRa Mesh) → ConsensusTransport. Spec §12.1.
        assert_eq!(
            classify_transport_tier(2),
            TransportClass::ConsensusTransport
        );
    }

    #[test]
    fn test_tier_3_is_state_beacon_transport() {
        // Tier 3 (HF Radio) → StateBeaconTransport. Spec §12.1.
        assert_eq!(
            classify_transport_tier(3),
            TransportClass::StateBeaconTransport
        );
    }

    #[test]
    fn test_tier_4_is_state_beacon_transport() {
        // Tier 4 (Local Mesh) → StateBeaconTransport. Spec §12.1.
        assert_eq!(
            classify_transport_tier(4),
            TransportClass::StateBeaconTransport
        );
    }

    #[test]
    fn test_tier_5_is_state_beacon_transport() {
        // Tier 5 (Visual QR) → StateBeaconTransport. Spec §12.1.
        assert_eq!(
            classify_transport_tier(5),
            TransportClass::StateBeaconTransport
        );
    }

    #[test]
    fn test_tier_1_2_uptime_eligible() {
        // Tier 1-2 → eligible uptime. Spec §12.1.
        assert!(is_uptime_eligible(1));
        assert!(is_uptime_eligible(2));
    }

    #[test]
    fn test_tier_3_5_not_uptime_eligible() {
        // Tier 3-5 → ZERO uptime contribution. Spec §12.1.
        assert!(!is_uptime_eligible(3));
        assert!(!is_uptime_eligible(4));
        assert!(!is_uptime_eligible(5));
    }

    // ── StateBeacon struct ────────────────────────────────────────────────────

    #[test]
    fn test_state_beacon_new_has_correct_fields() {
        // Spec §12.1a: 3 fields — epoch_id, smt_root, checksum.
        let beacon = StateBeacon::new(42, [0xBBu8; 32]);
        assert_eq!(beacon.epoch_id, 42u64);
        assert_eq!(beacon.smt_root, [0xBBu8; 32]);
        assert_eq!(beacon.checksum.len(), 4);
    }

    #[test]
    fn test_state_beacon_wire_size_correct() {
        // to_bytes() harus menghasilkan tepat 44 bytes. Spec §12.1a.
        let beacon = StateBeacon::new(1, [0u8; 32]);
        assert_eq!(beacon.to_bytes().len(), STATE_BEACON_WIRE_SIZE);
    }

    #[test]
    fn test_state_beacon_roundtrip() {
        // Serialisasi dan deserialisasi harus identik. Spec §12.1a.
        let beacon = StateBeacon::new(99, [0xCCu8; 32]);
        let bytes = beacon.to_bytes();
        let beacon2 = StateBeacon::from_bytes(&bytes);
        assert_eq!(beacon, beacon2);
    }

    #[test]
    fn test_state_beacon_epoch_id_little_endian() {
        // epoch_id harus little-endian di bytes[0..8]. Spec §12.1a S3.
        let beacon = StateBeacon::new(0x0102030405060708u64, [0u8; 32]);
        let bytes = beacon.to_bytes();
        assert_eq!(&bytes[0..8], &0x0102030405060708u64.to_le_bytes());
    }

    #[test]
    fn test_state_beacon_smt_root_at_offset_8() {
        // smt_root di bytes[8..40]. Spec §12.1a.
        let smt = [0xDDu8; 32];
        let beacon = StateBeacon::new(1, smt);
        let bytes = beacon.to_bytes();
        assert_eq!(&bytes[8..40], &smt);
    }

    #[test]
    fn test_state_beacon_checksum_at_offset_40() {
        // checksum di bytes[40..44]. Spec §12.1a.
        let beacon = StateBeacon::new(1, [0xEEu8; 32]);
        let bytes = beacon.to_bytes();
        assert_eq!(&bytes[40..44], &beacon.checksum);
    }

    // ── checksum ──────────────────────────────────────────────────────────────

    #[test]
    fn test_state_beacon_checksum_valid() {
        // Beacon baru harus punya checksum yang valid. Spec §12.1a.
        let beacon = StateBeacon::new(5, [0x42u8; 32]);
        assert!(beacon.verify_checksum());
    }

    #[test]
    fn test_state_beacon_checksum_tampered_epoch_fails() {
        // Checksum harus fail jika epoch_id diubah. Spec §12.1a.
        let mut beacon = StateBeacon::new(5, [0x42u8; 32]);
        beacon.epoch_id = 6; // tamper
        assert!(!beacon.verify_checksum());
    }

    #[test]
    fn test_state_beacon_checksum_tampered_smt_fails() {
        // Checksum harus fail jika smt_root diubah. Spec §12.1a.
        let mut beacon = StateBeacon::new(5, [0x42u8; 32]);
        beacon.smt_root = [0xFFu8; 32]; // tamper
        assert!(!beacon.verify_checksum());
    }

    #[test]
    fn test_state_beacon_checksum_deterministic() {
        // Checksum deterministik untuk input yang sama. Spec §12.1a.
        let c1 = compute_beacon_checksum(42, &[0xABu8; 32]);
        let c2 = compute_beacon_checksum(42, &[0xABu8; 32]);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_state_beacon_checksum_different_epoch_differs() {
        // epoch_id berbeda → checksum berbeda. Spec §12.1a.
        let c1 = compute_beacon_checksum(1, &[0u8; 32]);
        let c2 = compute_beacon_checksum(2, &[0u8; 32]);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_state_beacon_checksum_4_bytes() {
        // Checksum = 4 bytes. Spec §12.1a.
        let c = compute_beacon_checksum(1, &[0u8; 32]);
        assert_eq!(c.len(), 4);
    }

    // ── Tier 3-5 zero uptime ──────────────────────────────────────────────────

    #[test]
    fn test_tier_3_5_cannot_contribute_uptime() {
        // Spec §12.1: Tier 3-5 → zero uptime contribution.
        // Semua tier 3-5 harus return false untuk is_uptime_eligible.
        for tier in 3u8..=5 {
            assert!(
                !is_uptime_eligible(tier),
                "Tier {} tidak boleh eligible uptime — spec §12.1",
                tier
            );
        }
    }

    #[test]
    fn test_consensus_transport_tiers_only_1_and_2() {
        // Hanya tier 1 dan 2 yang ConsensusTransport. Spec §12.1.
        for tier in 1u8..=5 {
            let class = classify_transport_tier(tier);
            if tier <= 2 {
                assert_eq!(class, TransportClass::ConsensusTransport);
            } else {
                assert_eq!(class, TransportClass::StateBeaconTransport);
            }
        }
    }
}
