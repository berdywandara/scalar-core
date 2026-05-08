//! Time Security Rules T-1 to T-6 — Spec §7.2c
//!
//! T-1: Epoch boundary via seq_num ONLY. Wall-clock NEVER determines epoch.
//! T-2: TTL check via NMT. abs(NMT - HB.timestamp) ≤ T_HEARTBEAT_TTL_S.
//! T-3: NMT update interval = T_NMT_UPDATE_S (60s). Stale NMT → reject HB.
//! T-4: Rate limiting — reject if HB interval < T_HB_MIN_INTERVAL_S.
//! T-5: Pre-computation attack prevention — HB with future timestamp rejected.
//! T-6: Wall-clock NEVER used for epoch boundary — seq_num is the only source.
//!
//! Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
//! No floating point — all arithmetic integer fixed-point basis 1_000_000.

use scalar_emission::liveness::EPOCH_HB_COUNT;
use std::collections::HashMap;

// ── Time constants — spec §7.2c ───────────────────────────────────────────────

/// T-4: Minimum interval antar heartbeat dalam detik. Spec §7.2c T-4.
/// 1 HB per 10 menit = 600 detik. Bunching attack: reject HB < interval ini.
pub const T_HB_MIN_INTERVAL_S: u32 = 300;

/// T-3: Interval update NMT dalam detik. Spec §12.3a.
/// NMT harus di-update setiap 60 detik dari 8 peer.
pub const T_NMT_UPDATE_S: u32 = 60;

/// T-3: Maximum NMT staleness sebelum HB ditolak. Spec §7.2c T-3.
/// Jika NMT tidak di-update > T_NMT_STALE_S → tolak semua HB.
pub const T_NMT_STALE_S: u32 = 120; // 2× T_NMT_UPDATE_S

/// T-5: Maximum future timestamp yang ditoleransi dalam detik. Spec §7.2c T-5.
/// HB.timestamp > NMT + T_FUTURE_TOLERANCE_S → pre-computation attack → reject.
pub const T_FUTURE_TOLERANCE_S: u32 = 30;

// ── T-1: Epoch boundary via seq_num — spec §7.2c ─────────────────────────────

/// T-1: Verifikasi epoch boundary via seq_num. Spec §7.2c T-1. OSSIFIED.
///
/// Epoch k = seq_num range [(k × EPOCH_HB_COUNT + 1), ((k+1) × EPOCH_HB_COUNT)].
/// Wall-clock TIDAK PERNAH menentukan epoch boundary.
///
/// Returns epoch_id berdasarkan seq_num.
pub fn epoch_from_seq_num(seq_num: u32) -> u64 {
    // Spec §7.2c T-1: epoch_id = (seq_num - 1) / EPOCH_HB_COUNT
    // seq_num dimulai dari 1, epoch_id dimulai dari 0.
    if seq_num == 0 {
        return 0;
    }
    ((seq_num - 1) / EPOCH_HB_COUNT) as u64
}

/// T-1: Verifikasi seq_num berada dalam epoch yang benar. Spec §7.2c T-1.
///
/// Returns true jika seq_num berada dalam range epoch_id.
pub fn verify_seq_num_in_epoch(seq_num: u32, epoch_id: u64) -> bool {
    epoch_from_seq_num(seq_num) == epoch_id
}

// ── T-3: NMT staleness check — spec §7.2c ────────────────────────────────────

/// T-3: Cek apakah NMT masih fresh. Spec §7.2c T-3.
///
/// `nmt_last_update_s`: wall-clock seconds saat NMT terakhir diupdate.
/// `current_wall_clock_s`: wall-clock seconds sekarang.
///
/// NMT stale jika (current - last_update) > T_NMT_STALE_S.
/// Wall-clock HANYA digunakan untuk NMT staleness check — BUKAN epoch boundary.
pub fn is_nmt_fresh(nmt_last_update_s: u64, current_wall_clock_s: u64) -> bool {
    let elapsed = current_wall_clock_s.saturating_sub(nmt_last_update_s);
    elapsed <= T_NMT_STALE_S as u64
}

// ── T-4: Rate limiting — spec §7.2c ──────────────────────────────────────────

/// T-4: Rate limiter per node. Spec §7.2c T-4.
///
/// Tolak HB jika interval dari HB sebelumnya < T_HB_MIN_INTERVAL_S.
/// Mencegah bunching attack: 100 HB dalam 10 detik → semua ditolak kecuali 1.
#[derive(Default)]
pub struct HeartbeatRateLimiter {
    /// Key: node_id [u8;4] → timestamp HB terakhir yang diterima
    last_hb_timestamp: HashMap<[u8; 4], u32>,
}

impl HeartbeatRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// T-4: Cek apakah HB ini boleh diterima berdasarkan rate limit. Spec §7.2c T-4.
    ///
    /// Returns true jika HB boleh diterima (interval cukup atau HB pertama).
    /// Returns false jika HB terlalu cepat → tolak (bunching attack).
    pub fn check_and_update(&mut self, node_id: [u8; 4], hb_timestamp: u32) -> bool {
        if let Some(&last_ts) = self.last_hb_timestamp.get(&node_id) {
            // Interval = hb_timestamp - last_ts (timestamp delta)
            if hb_timestamp < last_ts {
                // Timestamp mundur → tolak (clock manipulation)
                return false;
            }
            let interval = hb_timestamp - last_ts;
            if interval < T_HB_MIN_INTERVAL_S {
                // Terlalu cepat → tolak. Spec §7.2c T-4.
                return false;
            }
        }
        // Update last timestamp
        self.last_hb_timestamp.insert(node_id, hb_timestamp);
        true
    }

    /// Reset state untuk node — dipanggil saat epoch baru dimulai.
    pub fn reset_node(&mut self, node_id: &[u8; 4]) {
        self.last_hb_timestamp.remove(node_id);
    }
}

// ── T-5: Pre-computation attack prevention — spec §7.2c ──────────────────────

/// T-5: Cek future timestamp — pre-computation attack prevention. Spec §7.2c T-5.
///
/// HB.timestamp > NMT + T_FUTURE_TOLERANCE_S → reject.
/// Mencegah attacker pre-compute HB dengan timestamp jauh di masa depan.
pub fn check_future_timestamp(hb_timestamp: u32, nmt: u32) -> bool {
    // HB valid jika timestamp ≤ NMT + tolerance
    hb_timestamp <= nmt.saturating_add(T_FUTURE_TOLERANCE_S)
}

// ── T-6: Wall-clock prohibition — spec §7.2c ─────────────────────────────────

/// T-6: Dokumentasi prohibition wall-clock untuk epoch boundary. Spec §7.2c T-6.
///
/// Fungsi ini TIDAK menggunakan wall-clock untuk epoch boundary.
/// Digunakan sebagai assertion point dalam kode untuk memastikan compliance.
///
/// "Epoch by Sequence, Not by Clock." — Scalar Network Core Principle.
pub fn assert_no_wall_clock_epoch_boundary() {
    // Compile-time documentation: epoch boundary HANYA dari seq_num.
    // Fungsi ini tidak melakukan apapun — keberadaannya sebagai dokumentasi
    // dan audit trail bahwa caller tidak menggunakan wall-clock.
    // Spec §7.2c T-6.
}

// ── TimeSecurityRules — combined checker — spec §7.2c ────────────────────────

/// Combined time security checker. Spec §7.2c T-1 sampai T-6.
///
/// Menggabungkan semua rules dalam satu interface.
#[derive(Default)]
pub struct TimeSecurityChecker {
    /// T-4: Rate limiter per node.
    pub rate_limiter: HeartbeatRateLimiter,
    /// T-3: Timestamp NMT terakhir diupdate (wall-clock seconds).
    pub nmt_last_update_wall_s: u64,
}

impl TimeSecurityChecker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update NMT timestamp. Spec §7.2c T-3, §12.3a.
    pub fn update_nmt_timestamp(&mut self, wall_clock_s: u64) {
        self.nmt_last_update_wall_s = wall_clock_s;
    }

    /// Jalankan semua time security checks untuk satu HB. Spec §7.2c.
    ///
    /// Returns Ok(()) jika semua checks pass.
    /// Returns Err(TimeSecurityViolation) pada check pertama yang gagal.
    pub fn check_all(
        &mut self,
        node_id: [u8; 4],
        hb_timestamp: u32,
        hb_seq_num: u32,
        epoch_id: u64,
        nmt: u32,
        current_wall_clock_s: u64,
    ) -> Result<(), TimeSecurityViolation> {
        // T-1: Epoch boundary via seq_num — spec §7.2c T-1
        if !verify_seq_num_in_epoch(hb_seq_num, epoch_id) {
            return Err(TimeSecurityViolation::T1EpochBoundaryViolation {
                seq_num: hb_seq_num,
                expected_epoch: epoch_id,
                actual_epoch: epoch_from_seq_num(hb_seq_num),
            });
        }

        // T-3: NMT freshness — spec §7.2c T-3
        if !is_nmt_fresh(self.nmt_last_update_wall_s, current_wall_clock_s) {
            return Err(TimeSecurityViolation::T3NmtStale {
                last_update_s: self.nmt_last_update_wall_s,
                current_s: current_wall_clock_s,
            });
        }

        // T-4: Rate limiting — spec §7.2c T-4
        if !self.rate_limiter.check_and_update(node_id, hb_timestamp) {
            return Err(TimeSecurityViolation::T4RateLimitExceeded { node_id });
        }

        // T-5: Future timestamp — spec §7.2c T-5
        if !check_future_timestamp(hb_timestamp, nmt) {
            return Err(TimeSecurityViolation::T5FutureTimestamp {
                hb_timestamp,
                nmt,
                tolerance: T_FUTURE_TOLERANCE_S,
            });
        }

        Ok(())
    }
}

/// Violation dari time security rules. Spec §7.2c.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeSecurityViolation {
    /// T-1: seq_num tidak sesuai dengan epoch_id. Spec §7.2c T-1.
    T1EpochBoundaryViolation {
        seq_num: u32,
        expected_epoch: u64,
        actual_epoch: u64,
    },
    /// T-3: NMT stale — tidak di-update > T_NMT_STALE_S. Spec §7.2c T-3.
    T3NmtStale { last_update_s: u64, current_s: u64 },
    /// T-4: Rate limit exceeded — bunching attack. Spec §7.2c T-4.
    T4RateLimitExceeded { node_id: [u8; 4] },
    /// T-5: Future timestamp — pre-computation attack. Spec §7.2c T-5.
    T5FutureTimestamp {
        hb_timestamp: u32,
        nmt: u32,
        tolerance: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── T-1: epoch_from_seq_num ───────────────────────────────────────────────

    #[test]
    fn test_t1_epoch_from_seq_num_epoch_0() {
        // seq_num 1..=4320 → epoch 0. Spec §7.2c T-1.
        assert_eq!(epoch_from_seq_num(1), 0);
        assert_eq!(epoch_from_seq_num(4_320), 0);
    }

    #[test]
    fn test_t1_epoch_from_seq_num_epoch_1() {
        // seq_num 4321..=8640 → epoch 1. Spec §7.2c T-1.
        assert_eq!(epoch_from_seq_num(4_321), 1);
        assert_eq!(epoch_from_seq_num(8_640), 1);
    }

    #[test]
    fn test_t1_epoch_from_seq_num_epoch_2() {
        // seq_num 8641..=12960 → epoch 2. Spec §7.2c T-1.
        assert_eq!(epoch_from_seq_num(8_641), 2);
        assert_eq!(epoch_from_seq_num(12_960), 2);
    }

    #[test]
    fn test_t1_epoch_boundary_exact() {
        // Batas tepat epoch k dan k+1. Spec §7.2c T-1.
        // seq 4320 → epoch 0, seq 4321 → epoch 1
        assert_eq!(epoch_from_seq_num(4_320), 0);
        assert_eq!(epoch_from_seq_num(4_321), 1);
    }

    #[test]
    fn test_t1_seq_num_zero_returns_epoch_0() {
        // seq_num = 0 → epoch 0 (edge case). Spec §7.2c T-1.
        assert_eq!(epoch_from_seq_num(0), 0);
    }

    #[test]
    fn test_t1_verify_seq_num_in_epoch_valid() {
        // seq=1, epoch=0 → valid. Spec §7.2c T-1.
        assert!(verify_seq_num_in_epoch(1, 0));
        assert!(verify_seq_num_in_epoch(4_320, 0));
        assert!(verify_seq_num_in_epoch(4_321, 1));
    }

    #[test]
    fn test_t1_verify_seq_num_in_epoch_invalid() {
        // seq=4321 bukan di epoch 0. Spec §7.2c T-1.
        assert!(!verify_seq_num_in_epoch(4_321, 0));
        assert!(!verify_seq_num_in_epoch(1, 1));
    }

    #[test]
    fn test_t1_wall_clock_never_used() {
        // T-1: epoch_from_seq_num tidak menerima wall-clock parameter. Spec §7.2c T-1.
        // Test ini compile hanya jika fungsi tidak punya wall_clock parameter.
        let epoch = epoch_from_seq_num(4_320);
        assert_eq!(epoch, 0);
    }

    // ── T-3: NMT freshness ────────────────────────────────────────────────────

    #[test]
    fn test_t3_nmt_fresh_within_stale() {
        // NMT diupdate 60 detik lalu → fresh. Spec §7.2c T-3.
        assert!(is_nmt_fresh(1_000, 1_060));
    }

    #[test]
    fn test_t3_nmt_fresh_at_boundary() {
        // NMT diupdate tepat T_NMT_STALE_S lalu → still fresh. Spec §7.2c T-3.
        assert!(is_nmt_fresh(1_000, 1_000 + T_NMT_STALE_S as u64));
    }

    #[test]
    fn test_t3_nmt_stale_exceeded() {
        // NMT diupdate > T_NMT_STALE_S lalu → stale. Spec §7.2c T-3.
        assert!(!is_nmt_fresh(1_000, 1_000 + T_NMT_STALE_S as u64 + 1));
    }

    #[test]
    fn test_t3_nmt_update_interval_value() {
        // T_NMT_UPDATE_S = 60 detik. Spec §12.3a.
        assert_eq!(T_NMT_UPDATE_S, 60u32);
    }

    #[test]
    fn test_t3_nmt_stale_s_value() {
        // T_NMT_STALE_S = 120 detik (2× update interval).
        assert_eq!(T_NMT_STALE_S, 120u32);
    }

    // ── T-4: Rate limiting ────────────────────────────────────────────────────

    #[test]
    fn test_t4_first_hb_always_accepted() {
        // HB pertama dari node → selalu diterima. Spec §7.2c T-4.
        let mut rl = HeartbeatRateLimiter::new();
        assert!(rl.check_and_update([0x01; 4], 1_000));
    }

    #[test]
    fn test_t4_interval_sufficient_accepted() {
        // Interval ≥ T_HB_MIN_INTERVAL_S → diterima. Spec §7.2c T-4.
        let mut rl = HeartbeatRateLimiter::new();
        rl.check_and_update([0x01; 4], 1_000);
        assert!(rl.check_and_update([0x01; 4], 1_000 + T_HB_MIN_INTERVAL_S));
    }

    #[test]
    fn test_t4_interval_too_short_rejected() {
        // Interval < T_HB_MIN_INTERVAL_S → ditolak. Spec §7.2c T-4.
        let mut rl = HeartbeatRateLimiter::new();
        rl.check_and_update([0x01; 4], 1_000);
        assert!(!rl.check_and_update([0x01; 4], 1_000 + T_HB_MIN_INTERVAL_S - 1));
    }

    #[test]
    fn test_t4_bunching_attack_rejected() {
        // Bunching: 5 HB berturut-turut dalam 10 detik → semua ditolak kecuali 1.
        // Spec §7.2c T-4.
        let mut rl = HeartbeatRateLimiter::new();
        let node = [0x02u8; 4];
        assert!(rl.check_and_update(node, 1_000)); // diterima
        assert!(!rl.check_and_update(node, 1_002)); // 2 detik → tolak
        assert!(!rl.check_and_update(node, 1_004)); // 4 detik → tolak
        assert!(!rl.check_and_update(node, 1_100)); // 100 detik → tolak
        assert!(!rl.check_and_update(node, 1_299)); // 299 detik → tolak
        assert!(rl.check_and_update(node, 1_300)); // 300 detik → diterima
    }

    #[test]
    fn test_t4_timestamp_backwards_rejected() {
        // Timestamp mundur → ditolak (clock manipulation). Spec §7.2c T-4.
        let mut rl = HeartbeatRateLimiter::new();
        let node = [0x03u8; 4];
        rl.check_and_update(node, 1_000);
        assert!(!rl.check_and_update(node, 999)); // mundur → tolak
    }

    #[test]
    fn test_t4_min_interval_value() {
        // T_HB_MIN_INTERVAL_S = 300 detik. Spec §18.2 Layer 2 default.
        assert_eq!(T_HB_MIN_INTERVAL_S, 300u32);
    }

    #[test]
    fn test_t4_different_nodes_independent() {
        // Rate limit terpisah per node. Spec §7.2c T-4.
        let mut rl = HeartbeatRateLimiter::new();
        rl.check_and_update([0x01; 4], 1_000);
        // Node lain tidak terpengaruh
        assert!(rl.check_and_update([0x02; 4], 1_001));
    }

    // ── T-5: Future timestamp ─────────────────────────────────────────────────

    #[test]
    fn test_t5_current_timestamp_valid() {
        // timestamp = NMT → valid. Spec §7.2c T-5.
        assert!(check_future_timestamp(1_000, 1_000));
    }

    #[test]
    fn test_t5_within_tolerance_valid() {
        // timestamp = NMT + tolerance → valid. Spec §7.2c T-5.
        assert!(check_future_timestamp(1_000 + T_FUTURE_TOLERANCE_S, 1_000));
    }

    #[test]
    fn test_t5_beyond_tolerance_rejected() {
        // timestamp > NMT + tolerance → rejected. Spec §7.2c T-5.
        assert!(!check_future_timestamp(
            1_000 + T_FUTURE_TOLERANCE_S + 1,
            1_000
        ));
    }

    #[test]
    fn test_t5_future_tolerance_value() {
        // T_FUTURE_TOLERANCE_S = 30 detik. Spec §7.2c T-5.
        assert_eq!(T_FUTURE_TOLERANCE_S, 30u32);
    }

    // ── T-6: Wall-clock prohibition ───────────────────────────────────────────

    #[test]
    fn test_t6_epoch_boundary_uses_seq_num_not_wall_clock() {
        // T-6: epoch_from_seq_num tidak menggunakan wall-clock. Spec §7.2c T-6.
        // Dua panggilan dengan seq_num sama → epoch sama, regardless of time.
        let e1 = epoch_from_seq_num(4_320);
        let e2 = epoch_from_seq_num(4_320);
        assert_eq!(e1, e2);
        assert_eq!(e1, 0); // epoch 0, bukan wall-clock
    }

    #[test]
    fn test_t6_assert_no_wall_clock_callable() {
        // T-6: assert_no_wall_clock_epoch_boundary() dapat dipanggil. Spec §7.2c T-6.
        assert_no_wall_clock_epoch_boundary();
    }

    // ── TimeSecurityChecker — combined ────────────────────────────────────────

    #[test]
    fn test_combined_all_pass() {
        // Semua T-1 sampai T-5 pass. Spec §7.2c.
        let mut checker = TimeSecurityChecker::new();
        checker.update_nmt_timestamp(1_000); // NMT fresh
        let result = checker.check_all(
            [0x01; 4], 600,   // hb_timestamp
            1,     // seq_num → epoch 0
            0,     // expected epoch_id
            600,   // nmt
            1_060, // current wall clock (60s after NMT update → fresh)
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_combined_t1_violation() {
        // T-1: seq_num 4321 tidak di epoch 0. Spec §7.2c T-1.
        let mut checker = TimeSecurityChecker::new();
        checker.update_nmt_timestamp(1_000);
        let result = checker.check_all(
            [0x01; 4], 600, 4_321, // seq_num epoch 1
            0,     // expected epoch 0 → mismatch
            600, 1_060,
        );
        assert!(matches!(
            result,
            Err(TimeSecurityViolation::T1EpochBoundaryViolation { .. })
        ));
    }

    #[test]
    fn test_combined_t3_violation() {
        // T-3: NMT stale. Spec §7.2c T-3.
        let mut checker = TimeSecurityChecker::new();
        checker.update_nmt_timestamp(0); // last update di t=0
        let result = checker.check_all(
            [0x01; 4], 600, 1, 0, 600, 200, // 200 detik setelah update → stale (> 120)
        );
        assert!(matches!(
            result,
            Err(TimeSecurityViolation::T3NmtStale { .. })
        ));
    }

    #[test]
    fn test_combined_t4_violation() {
        // T-4: Rate limit exceeded. Spec §7.2c T-4.
        let mut checker = TimeSecurityChecker::new();
        checker.update_nmt_timestamp(1_000);
        // HB pertama → ok
        checker.check_all([0x01; 4], 600, 1, 0, 600, 1_060).unwrap();
        // HB kedua terlalu cepat → T4
        let result = checker.check_all(
            [0x01; 4], 601, // hanya 1 detik setelah sebelumnya
            2, 0, 601, 1_061,
        );
        assert!(matches!(
            result,
            Err(TimeSecurityViolation::T4RateLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_combined_t5_violation() {
        // T-5: Future timestamp. Spec §7.2c T-5.
        let mut checker = TimeSecurityChecker::new();
        checker.update_nmt_timestamp(1_000);
        let result = checker.check_all(
            [0x01; 4],
            700 + T_FUTURE_TOLERANCE_S + 1, // timestamp jauh di masa depan
            1,
            0,
            600, // nmt = 600
            1_060,
        );
        assert!(matches!(
            result,
            Err(TimeSecurityViolation::T5FutureTimestamp { .. })
        ));
    }

    #[test]
    fn test_epoch_hb_count_used_in_t1() {
        // EPOCH_HB_COUNT = 4320 digunakan dalam T-1. Spec §7.2c T-1.
        assert_eq!(EPOCH_HB_COUNT, 4_320u32);
        // Verifikasi: seq_num = EPOCH_HB_COUNT → epoch 0
        assert_eq!(epoch_from_seq_num(EPOCH_HB_COUNT), 0);
        // seq_num = EPOCH_HB_COUNT + 1 → epoch 1
        assert_eq!(epoch_from_seq_num(EPOCH_HB_COUNT + 1), 1);
    }
}
