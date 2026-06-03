//! Heartbeat Verification Flow (5-step) — Spec §7.2b
//!
//! Step 1: Timestamp — reject if HB.timestamp > NMT + T_FUTURE_S (future)
//!                     drop if HB.timestamp < NMT - T_PAST_S (stale past)
//! Step 2: seq_num — reject if seq_num ≤ last_seq[node_id] (strictly monotonic)
//! Step 3: prev_hash — reject if prev_hash ≠ BLAKE3(stored last HB for node)
//! Step 4: MAC     — recompute and compare BLAKE3(NodeKey_epoch||node_id||seq_num||
//!                   timestamp||smt_root||prev_hash)
//! Step 5: Accept  — update last_seq[node_id], store HB, credit uptime
//!
//! RULE T-2 (spec §7.6 T-2): Asymmetric timestamp bounds via NMT:
//!   T_FUTURE_S = 60s  — reject jika HB.timestamp > NMT + T_FUTURE_S
//!   T_PAST_S   = 3600s — drop jika HB.timestamp < NMT - T_PAST_S
//! NMT = Network Median Time — BUKAN wall-clock lokal node.
//!
//! Hash discipline: BLAKE3 out-circuit — spec §2.1.3.

use crate::time_security::{T_FUTURE_TOLERANCE_S, T_PAST_S};
use scalar_emission::liveness::{compute_heartbeat_mac, HeartbeatUnit};
use std::collections::HashMap;

// ── Timestamp bounds — spec §7.6 T-2 ────────────────────────────────────────
// T_FUTURE_S dan T_PAST_S diimport dari time_security.
// T_FUTURE_S = 60s (dari T_FUTURE_TOLERANCE_S)
// T_PAST_S   = 3600s
//
// T_HEARTBEAT_TTL_S dipertahankan untuk backward compat empirical tests.
/// Legacy symmetric TTL — diganti dengan T_FUTURE_S/T_PAST_S asimetris. Spec §7.6 T-2.
/// Dipertahankan hanya untuk referensi empirical test suite.
#[deprecated(note = "Gunakan T_FUTURE_TOLERANCE_S dan T_PAST_S dari time_security")]
pub const T_HEARTBEAT_TTL_S: u32 = 1_200;

// ── VerificationError — spec §7.2b ───────────────────────────────────────────

/// Error dari 5-step heartbeat verification. Spec §7.2b.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// Step 1a: Timestamp terlalu jauh ke depan — HB.timestamp > NMT + T_FUTURE_S. Spec §7.6 T-2.
    TimestampTooFuture {
        nmt: u32,
        hb_timestamp: u32,
        future_tolerance_s: u32,
    },
    /// Step 1b: Timestamp terlalu lama — HB.timestamp < NMT - T_PAST_S. Spec §7.6 T-2.
    TimestampTooOld {
        nmt: u32,
        hb_timestamp: u32,
        past_tolerance_s: u32,
    },
    /// Step 2: seq_num tidak monotonic — seq_num ≤ last_seq. Spec §7.2b.
    SeqNumNotMonotonic { received: u32, last: u32 },
    /// Step 3: prev_hash tidak cocok dengan BLAKE3(last HB). Spec §7.2b.
    PrevHashMismatch {
        expected: [u8; 32],
        received: [u8; 32],
    },
    /// Step 4: MAC tidak valid — BLAKE3(NodeKey_epoch||...) mismatch. Spec §7.2b.
    MacInvalid,
}

// ── HeartbeatState — per-node tracking ───────────────────────────────────────

/// State per node untuk verification. Spec §7.2b Step 2, 3, 5.
#[derive(Clone, Debug)]
pub struct HeartbeatUnitState {
    /// seq_num terakhir yang diterima dari node ini. Spec §7.2b Step 2.
    pub last_seq_num: u32,
    /// Bytes dari heartbeat terakhir — digunakan untuk prev_hash check. Spec §7.2b Step 3.
    pub last_hb_bytes: [u8; 148],
}

// ── HeartbeatVerifier — spec §7.2b ───────────────────────────────────────────

/// 5-step heartbeat verifier. Spec §7.2b.
///
/// Menyimpan state per node: last_seq_num dan last_hb_bytes.
/// NodeKey_epoch harus disediakan oleh caller (dari key store).
#[derive(Default)]
pub struct HeartbeatVerifier {
    /// Key: node_id [u8;4] → HeartbeatUnitState
    node_states: HashMap<[u8; 4], HeartbeatUnitState>,
}

impl HeartbeatVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Jalankan 5-step verification. Spec §7.2b.
    ///
    /// `nmt`: Network Median Time — BUKAN wall-clock lokal. Spec §7.2c T-2.
    /// `node_key_epoch`: NodeKey_epoch_i = BLAKE3(NodeKey_i || epoch_id_le64).
    ///                   Caller harus compute via derive_node_key_epoch().
    /// `expected_prev_hash`: BLAKE3(last HB bytes) atau EpochAnchor.chain_head
    ///                       untuk HB pertama epoch.
    ///
    /// Returns Ok(()) jika semua 5 step pass.
    /// Returns Err(VerificationError) pada step pertama yang gagal.
    pub fn verify(
        &mut self,
        hb: &HeartbeatUnit,
        nmt: u32,
        node_key_epoch: &[u8; 32],
        _epoch_id: u64,
    ) -> Result<(), VerificationError> {
        // ── Step 1: Asymmetric timestamp check — spec §7.6 T-2 ───────────────
        // T_FUTURE_S = 60s:  reject jika HB.timestamp > NMT + T_FUTURE_S
        // T_PAST_S   = 3600s: drop jika HB.timestamp < NMT - T_PAST_S
        // NMT dari NetworkMedianTime — BUKAN wall-clock lokal.
        if hb.timestamp > nmt.saturating_add(T_FUTURE_TOLERANCE_S) {
            return Err(VerificationError::TimestampTooFuture {
                nmt,
                hb_timestamp: hb.timestamp,
                future_tolerance_s: T_FUTURE_TOLERANCE_S,
            });
        }
        if hb.timestamp < nmt.saturating_sub(T_PAST_S) {
            return Err(VerificationError::TimestampTooOld {
                nmt,
                hb_timestamp: hb.timestamp,
                past_tolerance_s: T_PAST_S,
            });
        }

        // ── Step 2: seq_num monotonic — spec §7.2b ────────────────────────────
        // seq_num HARUS > last_seq_num[node_id] (strictly monotonic).
        // Exception: seq_num=1 adalah restart valid (downtime event, spec T-5).
        let last_seq = self
            .node_states
            .get(&hb.node_id)
            .map(|s| s.last_seq_num)
            .unwrap_or(0);
        let is_restart = hb.seq_num == 1 && last_seq > 0;
        if hb.seq_num <= last_seq && !is_restart {
            return Err(VerificationError::SeqNumNotMonotonic {
                received: hb.seq_num,
                last: last_seq,
            });
        }
        // Pada restart: reset state peer sehingga prev_hash chain fresh.
        if is_restart {
            self.node_states.remove(&hb.node_id);
        }

        // ── Step 3: prev_hash check — spec §7.2b ─────────────────────────────
        // prev_hash harus = BLAKE3(last HB bytes).
        // Untuk HB pertama (seq_num == 1): prev_hash = EpochAnchor.chain_head.
        // Caller bertanggung jawab menginisialisasi state dengan chain_head yang benar.
        if let Some(state) = self.node_states.get(&hb.node_id) {
            // Reconstruct prev_hash from stored HB bytes using spec construction.
            // Research Package §3.1.4: prev_hash = BLAKE3(b"scalar_beacon" || fields || mac)
            let last_hb = HeartbeatUnit::from_bytes(&state.last_hb_bytes);
            let expected_prev = scalar_emission::liveness::compute_prev_hash(&last_hb);
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
            &hb.imt_frontier,
            hb.imt_count,
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
            HeartbeatUnitState {
                last_seq_num: hb.seq_num,
                last_hb_bytes: hb_bytes,
            },
        );

        Ok(())
    }

    /// Seed state awal untuk node — untuk HB pertama epoch. Spec §7.2b.
    ///
    /// Dipanggil dengan EpochAnchor.chain_head dari epoch sebelumnya.
    /// Atau BLAKE3(genesis_object_bytes) untuk epoch 0.
    /// Spec §7.2a: prev_hash HB pertama epoch k+1 = EpochAnchor.chain_head epoch k.
    pub fn seed_node_state(
        &mut self,
        node_id: [u8; 4],
        chain_head_bytes: [u8; 148],
        last_seq_num: u32,
    ) {
        self.node_states.insert(
            node_id,
            HeartbeatUnitState {
                last_seq_num,
                last_hb_bytes: chain_head_bytes,
            },
        );
    }

    /// Ambil last_seq_num untuk node. Spec §7.2b Step 2.
    /// Reset seq tracking untuk peer — dipanggil saat peer disconnect/restart.
    pub fn reset_peer(&mut self, node_id: &[u8; 4]) {
        self.node_states.remove(node_id);
    }

    pub fn last_seq_num(&self, node_id: &[u8; 4]) -> u32 {
        self.node_states
            .get(node_id)
            .map(|s| s.last_seq_num)
            .unwrap_or(0)
    }
}

// ── Helper: compute expected_prev_hash ───────────────────────────────────────

/// Compute prev_hash per Research Package §3.1.4. INV-4.4.
///
/// Delegates to scalar_emission::liveness::compute_prev_hash which
/// implements the OSSIFIED construction:
///   BLAKE3(b"scalar_beacon" || node_id || seq_num || timestamp ||
///          smt_root || imt_frontier || imt_count || mac)
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compute_prev_hash(hb: &HeartbeatUnit) -> [u8; 32] {
    scalar_emission::liveness::compute_prev_hash(hb)
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
    ) -> HeartbeatUnit {
        let nke = node_key_epoch();
        let mac = compute_heartbeat_mac(
            &nke, &node_id, seq_num, timestamp, &smt_root, &[0u8; 32], 0u64, &prev_hash,
        );
        HeartbeatUnit {
            node_id,
            seq_num,
            timestamp,
            smt_root,
            imt_frontier: [0u8; 32],
            imt_count: 0u64,
            prev_hash,
            mac,
        }
    }

    // ── Step 1: TTL ───────────────────────────────────────────────────────────

    #[test]
    fn test_step1_timestamp_exact_nmt_pass() {
        // HB.timestamp == NMT → PASS (dalam kedua batas). Spec §7.6 T-2.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 10_000u32;
        let hb = make_valid_hb([0x01; 4], 1, nmt, [0u8; 32], [0u8; 32]);
        assert!(verifier
            .verify(&hb, nmt, &node_key_epoch(), TEST_EPOCH)
            .is_ok());
    }

    #[test]
    fn test_step1_future_boundary_pass() {
        // HB.timestamp = NMT + T_FUTURE_TOLERANCE_S → PASS (batas tepat). Spec §7.6 T-2.
        use crate::time_security::T_FUTURE_TOLERANCE_S;
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 10_000u32;
        let hb = make_valid_hb(
            [0x01; 4],
            1,
            nmt + T_FUTURE_TOLERANCE_S,
            [0u8; 32],
            [0u8; 32],
        );
        assert!(verifier
            .verify(&hb, nmt, &node_key_epoch(), TEST_EPOCH)
            .is_ok());
    }

    #[test]
    fn test_step1_future_exceeded_reject() {
        // HB.timestamp > NMT + T_FUTURE_TOLERANCE_S → REJECT. Spec §7.6 T-2.
        use crate::time_security::T_FUTURE_TOLERANCE_S;
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 10_000u32;
        let hb = make_valid_hb(
            [0x01; 4],
            1,
            nmt + T_FUTURE_TOLERANCE_S + 1,
            [0u8; 32],
            [0u8; 32],
        );
        let err = verifier
            .verify(&hb, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap_err();
        assert!(matches!(err, VerificationError::TimestampTooFuture { .. }));
    }

    #[test]
    fn test_step1_past_boundary_pass() {
        // HB.timestamp = NMT - T_PAST_S → PASS (batas tepat). Spec §7.6 T-2.
        use crate::time_security::T_PAST_S;
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 10_000u32;
        let hb = make_valid_hb([0x01; 4], 1, nmt - T_PAST_S, [0u8; 32], [0u8; 32]);
        assert!(verifier
            .verify(&hb, nmt, &node_key_epoch(), TEST_EPOCH)
            .is_ok());
    }

    #[test]
    fn test_step1_past_exceeded_drop() {
        // HB.timestamp < NMT - T_PAST_S → DROP. Spec §7.6 T-2.
        use crate::time_security::T_PAST_S;
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 10_000u32;
        let hb = make_valid_hb([0x01; 4], 1, nmt - T_PAST_S - 1, [0u8; 32], [0u8; 32]);
        let err = verifier
            .verify(&hb, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap_err();
        assert!(matches!(err, VerificationError::TimestampTooOld { .. }));
    }

    // test_step1_ttl_fail_exceeded digabung ke test_step1_past_exceeded_drop di atas.

    #[test]
    fn test_step1_uses_nmt_not_wall_clock() {
        // Asymmetric check menggunakan NMT — Rule T-2. Spec §7.6 T-2.
        let mut verifier = HeartbeatVerifier::new();
        let nmt = 10_000u32;
        let hb_timestamp = 9_999u32; // dalam batas T_PAST_S → pass
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
        let wrong_nke = derive_node_key_epoch(&[0xFFu8; 32], 99); // epoch berbeda
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
        let chain_head_bytes = [0x42u8; 148];
        verifier.seed_node_state(node_id, chain_head_bytes, 0);
        assert_eq!(verifier.last_seq_num(&node_id), 0);
    }

    // ── Asymmetric timestamp bounds — spec §7.6 T-2 ───────────────────────────

    #[test]
    fn test_t_future_tolerance_value() {
        // T_FUTURE_TOLERANCE_S = 60s. Spec §7.6 T-2.
        use crate::time_security::T_FUTURE_TOLERANCE_S;
        assert_eq!(T_FUTURE_TOLERANCE_S, 60u32);
    }

    #[test]
    fn test_t_past_s_value() {
        // T_PAST_S = 3600s. Spec §7.6 T-2.
        use crate::time_security::T_PAST_S;
        assert_eq!(T_PAST_S, 3_600u32);
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
        // HB dengan timestamp terlalu lama DAN seq_num rendah → harus return TimestampTooOld (step 1 dulu)
        use crate::time_security::T_PAST_S;
        let old_timestamp = nmt - T_PAST_S - 100; // melewati T_PAST_S
        let hb_bad = make_valid_hb(node_id, 3, old_timestamp, [0u8; 32], [0u8; 32]); // seq juga rendah
        let err = verifier
            .verify(&hb_bad, nmt, &node_key_epoch(), TEST_EPOCH)
            .unwrap_err();
        assert!(
            matches!(err, VerificationError::TimestampTooOld { .. }),
            "Step 1 harus dicek pertama"
        );
    }
}
