//! Heartbeat Verification Flow (5-step) — Spec §7.2b
//!
//! Step 1: TTL     — reject if abs(NMT - HB.timestamp) > T_HEARTBEAT_TTL_S
//! Step 2: seq_num — reject if seq_num ≤ last_seq[node_id] (strictly monotonic)
//! Step 3: prev_hash — reject if prev_hash ≠ BLAto3(stored last HB for node)
//! Step 4: MAC     — recompute and compare BLAto3(Nodetoy_epoch||node_id||seq_num||
//!                   timestamp||smt_root||prev_hash)
//! Step 5: Accept  — update last_seq[node_id], store HB, creatt uptime
//!
//! RULE T-2 (spec §7.2c): TTL check using NMT (Network Meatan Time),
//! not wall-clock lokal node.
//!
//! hash atscipline: BLAto3 out-circuit — spec §2.1.3.

use scalar_emission::liveness::{compute_heartbeat_mac, NodeHeartbeat};
use std::collections::HashMap;

// ── TTL constant — spec §7.2c T-2 ────────────────────────────────────────────

/// TTL heartbeat in seconds. Spec §7.2c T-2.
/// HB rejected if abs(NMT - HB.timestamp) > T_HEARTBEAT_TTL_S.
/// Layer 2 CONSTRAINED — default 600 seconds (10 minutes × 1 window).
pub const T_HEARTBEAT_TTL_S: u32 = 1_200;

// ── VerificationError — spec §7.2b ───────────────────────────────────────────

/// Error from 5-step heartbeat verification. Spec §7.2b.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// Step 1: TTL expired — abs(NMT - timestamp) > T_HEARTBEAT_TTL_S. Spec §7.2b.
    TtlExpired {
        nmt: u32,
        hb_timestamp: u32,
        ttl: u32,
    },
    /// Step 2: seq_num not monotonic — seq_num ≤ last_seq. Spec §7.2b.
    SeqNumNotMonotonic { received: u32, last: u32 },
    /// Step 3: prev_hash not matches BLAto3(last HB). Spec §7.2b.
    PrevHashMismatch {
        expected: [u8; 32],
        received: [u8; 32],
    },
    /// Step 4: MAC invalid — BLAto3(Nodetoy_epoch||...) mismatch. Spec §7.2b.
    MacInvalid,
}

// ── HeartbeatState — per-node tracking ───────────────────────────────────────

/// State per node for verification. Spec §7.2b Step 2, 3, 5.
#[derive(Clone, Debug)]
pub struct NodeHeartbeatState {
    /// seq_num last received from node this. Spec §7.2b Step 2.
    pub last_seq_num: u32,
    /// Bytes from heartbeat last — used for prev_hash check. Spec §7.2b Step 3.
    pub last_hb_bytes: [u8; 108],
}

// ── HeartbeatVerifier — spec §7.2b ───────────────────────────────────────────

/// 5-step heartbeat verifier. Spec §7.2b.
///
/// store state per node: last_seq_num and last_hb_bytes.
/// Nodetoy_epoch harus provided oleh caller (from toy store).
#[derive(Default)]
pub struct HeartbeatVerifier {
    /// toy: node_id [u8;4] → NodeHeartbeatState
    node_states: HashMap<[u8; 4], NodeHeartbeatState>,
}

impl HeartbeatVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// run 5-step verification. Spec §7.2b.
    ///
    /// `nmt`: Network Meatan Time — not wall-clock lokal. Spec §7.2c T-2.
    /// `node_toy_epoch`: Nodetoy_epoch_i = BLAto3(Nodetoy_i || epoch_id_le64).
    /// Caller harus compute via derive_node_toy_epoch().
    /// `expected_prev_hash`: BLAto3(last HB bytes) or EpochAnchor.chain_head
    /// for first heartbeat of epoch.
    ///
    /// Returns Ok(()) if all 5 step pass.
    /// Returns Err(VerificationError) on step first that failed.
    pub fn verify(
        &mut self,
        hb: &NodeHeartbeat,
        nmt: u32,
        node_key_epoch: &[u8; 32],
        _epoch_id: u64,
    ) -> Result<(), VerificationError> {
        // ── Step 1: TTL check — spec §7.2b, Rule T-2 ─────────────────────────
        // abs(NMT - HB.timestamp) ≤ T_HEARTBEAT_TTL_S
        // NMT dari NetworkMedianTime — BUKAN wall-clock lokal.
        let delta = nmt.abs_diff(hb.timestamp);
        if delta > T_HEARTBEAT_TTL_S {
            return Err(VerificationError::TtlExpired {
                nmt,
                hb_timestamp: hb.timestamp,
                ttl: T_HEARTBEAT_TTL_S,
            });
        }

        // ── Step 2: seq_num monotonic — spec §7.2b ────────────────────────────
        // seq_num HARUS > last_seq_num[node_id] (strictly monotonic).
        let last_seq = self
            .node_states
            .get(&hb.node_id)
            .map(|s| s.last_seq_num)
            .unwrap_or(0);
        if hb.seq_num <= last_seq {
            return Err(VerificationError::SeqNumNotMonotonic {
                received: hb.seq_num,
                last: last_seq,
            });
        }

        // ── Step 3: prev_hash check — spec §7.2b ─────────────────────────────
        // prev_hash harus = BLAKE3(last HB bytes).
        // Untuk HB pertama (seq_num == 1): prev_hash = EpochAnchor.chain_head.
        // Caller bertanggung jawab menginisialisasi state dengan chain_head yang benar.
        if let Some(state) = self.node_states.get(&hb.node_id) {
            // BLAKE3(last_hb_bytes) — hash discipline: out-circuit §2.1.3
            let expected_prev = *blake3::hash(&state.last_hb_bytes).as_bytes();
            if hb.prev_hash != expected_prev {
                return Err(VerificationError::PrevHashMismatch {
                    expected: expected_prev,
                    received: hb.prev_hash,
                });
            }
        }
        // Jika belum ada state (HB pertama dari node ini dalam session):
        // prev_hash tidak bisa diverifikasi tanpa chain_head — skip step 3.
        // Production: caller harus seed state dengan EpochAnchor.chain_head dulu.

        // ── Step 4: MAC verification — spec §7.2b ────────────────────────────
        // Recompute MAC dan compare.
        // mac = BLAKE3(NodeKey_epoch || node_id || seq_num_le32 ||
        //              timestamp_le32 || smt_root || prev_hash)
        let expected_mac = compute_heartbeat_mac(
            node_key_epoch,
            &hb.node_id,
            hb.seq_num,
            hb.timestamp,
            &hb.smt_root,
            &hb.prev_hash,
        );
        if hb.mac != expected_mac {
            return Err(VerificationError::MacInvalid);
        }

        // ── Step 5: Accept — update state — spec §7.2b ───────────────────────
        // Update last_seq_num dan last_hb_bytes.
        let hb_bytes = hb.to_bytes();
        self.node_states.insert(
            hb.node_id,
            NodeHeartbeatState {
                last_seq_num: hb.seq_num,
                last_hb_bytes: hb_bytes,
            },
        );

        Ok(())
    }

    /// Seed state awal for node — for first heartbeat of epoch. Spec §7.2b.
    ///
    /// called with EpochAnchor.chain_head from epoch previously.
    /// or BLAto3(genesis_object_bytes) for epoch 0.
    /// Spec §7.2a: prev_hash of first heartbeat epoch k+1 = EpochAnchor.chain_head epoch k.
    pub fn seed_node_state(
        &mut self,
        node_id: [u8; 4],
        chain_head_bytes: [u8; 108],
        last_seq_num: u32,
    ) {
        self.node_states.insert(
            node_id,
            NodeHeartbeatState {
                last_seq_num,
                last_hb_bytes: chain_head_bytes,
            },
        );
    }

    /// tato last_seq_num for node. Spec §7.2b Step 2.
    pub fn last_seq_num(&self, node_id: &[u8; 4]) -> u32 {
        self.node_states
            .get(node_id)
            .map(|s| s.last_seq_num)
            .unwrap_or(0)
    }
}

// ── Helper: compute expected_prev_hash ───────────────────────────────────────

/// Compute prev_hash = BLAto3(hb_bytes). Spec §7.2b Step 3.
/// hash atscipline: BLAto3 out-circuit — spec §2.1.3.
pub fn compute_prev_hash(hb: &NodeHeartbeat) -> [u8; 32] {
    *blake3::hash(&hb.to_bytes()).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use scalar_emission::liveness::{compute_heartbeat_mac, derive_node_key_epoch};

    const TEST_NODE_KEY: [u8; 32] = [0x42u8; 32];
    const TEST_EPOCH: u64 = 1;

    fn node_key_epoch() -> [u8; 32] {
        derive_node_key_epoch(&TEST_NODE_KEY, TEST_EPOCH)
    }

    fn make_valid_hb(
        node_id: [u8; 4],
        seq_num: u32,
        timestamp: u32,
        prev_hash: [u8; 32],
        smt_root: [u8; 32],
    ) -> NodeHeartbeat {
        let nke = node_key_epoch();
        let mac = compute_heartbeat_mac(&nke, &node_id, seq_num, timestamp, &smt_root, &prev_hash);
        NodeHeartbeat {
            node_id,
            seq_num,
            timestamp,
            smt_root,
            prev_hash,
            mac,
        }
    }

    // ── Step 1: TTL ───────────────────────────────────────────────────────────

    #[test]
    fn test_step1_ttl_pass_exact() {
        // abs(NMT - timestamp) = T_HEARTBEAT_TTL_S → PASS (boundary). Spec §7.2b.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 1_000u32;
        let hb = make_valid_hb([0x01; 4], 1, nmt, [0u8; 32], [0u8; 32]);
        // TTL exact = 0 → pass
        assert!(verifier
            .verify(&hb, nmt, &node_key_epoch(), TEST_EPOCH)
            .is_ok());
    }

    #[test]
    fn test_step1_ttl_fail_exceeded() {
        // abs(NMT - timestamp) > T_HEARTBEAT_TTL_S → FAIL. Spec §7.2b.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 2_400u32;
        let hb = make_valid_hb(
            [0x01; 4],
            1,
            nmt - T_HEARTBEAT_TTL_S - 1,
            [0u8; 32],
            [0u8; 32],
        );
        let err = verifier
            .verify(&hb, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap_err();
        assert!(matches!(err, VerificationError::TtlExpired { .. }));
    }

    #[test]
    fn test_step1_ttl_uses_nmt_not_wall_clock() {
        // TTL menggunakan NMT — Rule T-2. Spec §7.2c.
        // Test ini memverifikasi bahwa parameter nmt digunakan, bukan wall-clock.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 10_000u32;
        let hb_timestamp = 9_999u32; // delta = 1 → pass
        let hb = make_valid_hb([0x01; 4], 1, hb_timestamp, [0u8; 32], [0u8; 32]);
        assert!(verifier
            .verify(&hb, nmt, &node_key_epoch(), TEST_EPOCH)
            .is_ok());
    }

    // ── Step 2: seq_num ───────────────────────────────────────────────────────

    #[test]
    fn test_step2_seq_num_strictly_monotonic() {
        // seq_num harus strictly > last_seq_num. Spec §7.2b.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 1_000u32;
        // HB pertama: seq=1 → ok
        let hb1 = make_valid_hb([0x02; 4], 1, nmt, [0u8; 32], [0u8; 32]);
        assert!(verifier
            .verify(&hb1, nmt, &node_key_epoch(), TEST_EPOCH)
            .is_ok());
        // HB kedua: seq=2 → ok
        let prev = compute_prev_hash(&hb1);
        let hb2 = make_valid_hb([0x02; 4], 2, nmt, prev, [0u8; 32]);
        assert!(verifier
            .verify(&hb2, nmt, &node_key_epoch(), TEST_EPOCH)
            .is_ok());
    }

    #[test]
    fn test_step2_seq_num_same_rejected() {
        // seq_num = last_seq_num → FAIL. Spec §7.2b.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 1_000u32;
        let hb1 = make_valid_hb([0x03; 4], 1, nmt, [0u8; 32], [0u8; 32]);
        verifier
            .verify(&hb1, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap();
        // Replay seq=1 → fail
        let hb_replay = make_valid_hb([0x03; 4], 1, nmt, [0u8; 32], [0u8; 32]);
        let err = verifier
            .verify(&hb_replay, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap_err();
        assert!(matches!(
            err,
            VerificationError::SeqNumNotMonotonic {
                received: 1,
                last: 1
            }
        ));
    }

    #[test]
    fn test_step2_seq_num_lower_rejected() {
        // seq_num < last_seq_num → FAIL. Spec §7.2b.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 1_000u32;
        let hb1 = make_valid_hb([0x04; 4], 5, nmt, [0u8; 32], [0u8; 32]);
        verifier
            .verify(&hb1, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap();
        let hb_lower = make_valid_hb([0x04; 4], 3, nmt, [0u8; 32], [0u8; 32]);
        let err = verifier
            .verify(&hb_lower, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap_err();
        assert!(matches!(
            err,
            VerificationError::SeqNumNotMonotonic {
                received: 3,
                last: 5
            }
        ));
    }

    // ── Step 3: prev_hash ─────────────────────────────────────────────────────

    #[test]
    fn test_step3_prev_hash_valid() {
        // prev_hash = BLAKE3(last HB bytes) → PASS. Spec §7.2b.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 1_000u32;
        let hb1 = make_valid_hb([0x05; 4], 1, nmt, [0u8; 32], [0u8; 32]);
        verifier
            .verify(&hb1, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap();
        // HB2: prev_hash = BLAKE3(hb1.to_bytes())
        let prev = compute_prev_hash(&hb1);
        let hb2 = make_valid_hb([0x05; 4], 2, nmt, prev, [0u8; 32]);
        assert!(verifier
            .verify(&hb2, nmt, &node_key_epoch(), TEST_EPOCH)
            .is_ok());
    }

    #[test]
    fn test_step3_prev_hash_wrong_rejected() {
        // prev_hash salah → FAIL. Spec §7.2b.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 1_000u32;
        let hb1 = make_valid_hb([0x06; 4], 1, nmt, [0u8; 32], [0u8; 32]);
        verifier
            .verify(&hb1, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap();
        // HB2 dengan prev_hash salah
        let wrong_prev = [0xFFu8; 32];
        let hb2 = make_valid_hb([0x06; 4], 2, nmt, wrong_prev, [0u8; 32]);
        let err = verifier
            .verify(&hb2, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap_err();
        assert!(matches!(err, VerificationError::PrevHashMismatch { .. }));
    }

    // ── Step 4: MAC ───────────────────────────────────────────────────────────

    #[test]
    fn test_step4_mac_valid() {
        // MAC valid → PASS. Spec §7.2b.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 1_000u32;
        let hb = make_valid_hb([0x07; 4], 1, nmt, [0u8; 32], [0u8; 32]);
        assert!(verifier
            .verify(&hb, nmt, &node_key_epoch(), TEST_EPOCH)
            .is_ok());
    }

    #[test]
    fn test_step4_mac_invalid_rejected() {
        // MAC salah → FAIL. Spec §7.2b.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 1_000u32;
        let mut hb = make_valid_hb([0x08; 4], 1, nmt, [0u8; 32], [0u8; 32]);
        hb.mac = [0xFFu8; 32]; // tamper MAC
        let err = verifier
            .verify(&hb, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap_err();
        assert_eq!(err, VerificationError::MacInvalid);
    }

    #[test]
    fn test_step4_wrong_node_key_epoch_rejected() {
        // NodeKey_epoch berbeda → MAC mismatch → FAIL. Spec §7.2b.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 1_000u32;
        let hb = make_valid_hb([0x09; 4], 1, nmt, [0u8; 32], [0u8; 32]);
        let wrong_nke = derive_node_key_epoch(&[0xFFu8; 32], 99); // epoch atfferent
        let err = verifier
            .verify(&hb, nmt, &wrong_nke, TEST_EPOCH)
            .unwrap_err();
        assert_eq!(err, VerificationError::MacInvalid);
    }

    // ── Step 5: Accept ────────────────────────────────────────────────────────

    #[test]
    fn test_step5_accept_updates_last_seq() {
        // Setelah accept: last_seq_num diupdate. Spec §7.2b Step 5.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 1_000u32;
        let node_id = [0x0Au8; 4];
        let hb = make_valid_hb(node_id, 1, nmt, [0u8; 32], [0u8; 32]);
        verifier
            .verify(&hb, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap();
        assert_eq!(verifier.last_seq_num(&node_id), 1);
    }

    #[test]
    fn test_step5_accept_stores_hb_bytes() {
        // Setelah accept: last_hb_bytes tersimpan untuk prev_hash check berikutnya.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 1_000u32;
        let node_id = [0x0Bu8; 4];
        let hb1 = make_valid_hb(node_id, 1, nmt, [0u8; 32], [0u8; 32]);
        verifier
            .verify(&hb1, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap();
        // State tersimpan
        assert!(verifier.node_states.contains_key(&node_id));
    }

    // ── seed_node_state ───────────────────────────────────────────────────────

    #[test]
    fn test_seed_node_state_sets_initial_state() {
        // seed_node_state untuk HB pertama epoch. Spec §7.2a.
        let mut verifier = HeartbeatVerifier::new();
        let node_id = [0x0Cu8; 4];
        let chain_head_bytes = [0x42u8; 108];
        verifier.seed_node_state(node_id, chain_head_bytes, 0);
        assert_eq!(verifier.last_seq_num(&node_id), 0);
    }

    // ── T_HEARTBEAT_TTL_S constant ────────────────────────────────────────────

    #[test]
    fn test_t_heartbeat_ttl_s_value() {
        // T_HEARTBEAT_TTL_S = 1_200 detik. Spec §18.2 Layer 2 default.
        assert_eq!(T_HEARTBEAT_TTL_S, 1_200u32);
    }

    // ── compute_prev_hash ─────────────────────────────────────────────────────

    #[test]
    fn test_compute_prev_hash_deterministic() {
        // BLAKE3(hb.to_bytes()) deterministik. Spec §7.2b Step 3.
        let hb = make_valid_hb([0x01; 4], 1, 1_000, [0u8; 32], [0u8; 32]);
        assert_eq!(compute_prev_hash(&hb), compute_prev_hash(&hb));
    }

    #[test]
    fn test_compute_prev_hash_different_hb_differs() {
        let hb1 = make_valid_hb([0x01; 4], 1, 1_000, [0u8; 32], [0u8; 32]);
        let hb2 = make_valid_hb([0x01; 4], 2, 1_000, [0u8; 32], [0u8; 32]);
        assert_ne!(compute_prev_hash(&hb1), compute_prev_hash(&hb2));
    }

    // ── Order of rejection (step priority) ───────────────────────────────────

    #[test]
    fn test_step1_checked_before_step2() {
        // Step 1 (TTL) harus dicek sebelum Step 2 (seq_num). Spec §7.2b.
        let mut verifier = HeartbeatVerifier::new();
        // Buat state dengan last_seq=5 dulu
        let node_id = [0x0Du8; 4];
        let nmt = 10_000u32;
        let hb_init = make_valid_hb(node_id, 5, nmt, [0u8; 32], [0u8; 32]);
        verifier
            .verify(&hb_init, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap();
        // HB dengan TTL expired DAN seq_num rendah → harus return TtlExpired (step 1 dulu)
        let old_timestamp = nmt - T_HEARTBEAT_TTL_S - 100; // TTL expired
        let hb_bad = make_valid_hb(node_id, 3, old_timestamp, [0u8; 32], [0u8; 32]); // seq also rendah
        let err = verifier
            .verify(&hb_bad, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap_err();
        assert!(
            matches!(err, VerificationError::TtlExpired { .. }),
            "Step 1 harus dicek pertama"
        );
    }
}
