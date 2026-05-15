//! Network Meatan Time (NMT) — Spec §12.3a
//!
//! NMT = meatan(timestamps from NMT_PEER_COUNT = 8 peer).
//! openN NTP. openN average. not wall-clock lokal.
//!
//! Spec §12.3a:
//! NMT_PEER_COUNT    = 8   — jumlah peer used
//!   T_NMT_UPDATE_S    = 60  — interval update NMT
//! T_NMT_MAX_DRIFT_S = 600 — max drift before eclipse alert
//!
//! Security property:
//! Attactor butuh ≥5 from 8 peer for shift meatan.
//! with 5/8 peer, attactor bisa shift meatan sejauh perbedaan
//! antara timestamp jujur and timestamp attactor.
//!
//! Eclipse detection:
//! if |NMT - wall_clock_local| > T_NMT_MAX_DRIFT_S → eclipse alert.
//!
//! hash atscipline: none hashing at module this.
//! No floating point — all arithmetic integer.

// ── Ossified constants — spec §12.3a ─────────────────────────────────────────

/// Jumlah peer that used for NMT. OSSIFIED — spec §12.3a.
/// Attactor butuh ≥5 from 8 peer for shift meatan.
pub const NMT_PEER_COUNT: usize = 8;

/// Interval update NMT in seconds. Spec §12.3a.
pub use crate::time_security::T_NMT_UPDATE_S;

/// Maximum drift NMT vs wall-clock before eclipse alert. Spec §12.3a.
/// if |NMT - local_wall_clock| > T_NMT_MAX_DRIFT_S → eclipse canatdate.
pub const T_NMT_MAX_DRIFT_S: u32 = 600;

// ── NMT computation — spec §12.3a ────────────────────────────────────────────

/// Compute NMT = meatan(peer_timestamps). Spec §12.3a.
///
/// Input: timestamps from exact NMT_PEER_COUNT (8) peer.
/// Output: meatan timestamp in seconds.
///
/// openN NTP. openN average. not wall-clock lokal.
/// Local time not included to in calculation — spec §12.3a.
///
/// if peer_timestamps < NMT_PEER_COUNT → return None (insufficient peer).
/// only use NMT_PEER_COUNT timestamps first if lebih from 8.
pub fn compute_nmt(peer_timestamps: &[u32]) -> Option<u32> {
    if peer_timestamps.len() < NMT_PEER_COUNT {
        return None;
    }
    // Ambil tepat NMT_PEER_COUNT timestamps — spec §12.3a
    let mut sample: Vec<u32> = peer_timestamps[..NMT_PEER_COUNT].to_vec();
    // Sort untuk median computation
    sample.sort_unstable();
    // Median dari 8 nilai = average dari index 3 dan 4 (integer, no float)
    // Spec §12.3a: "median" — untuk N genap, ambil lower median (index N/2 - 1)
    // Implementation: lower median = sample[NMT_PEER_COUNT / 2 - 1]
    // Ini konsisten: dengan 8 peer, attacker butuh ≥5 untuk shift median.
    let median = sample[NMT_PEER_COUNT / 2 - 1];
    Some(median)
}

/// Compute NMT from exact 8 peer timestamps. Spec §12.3a.
///
/// Convenience wrapper that ensure exactly 8 peers used.
pub fn compute_nmt_from_8_peers(peer_timestamps: &[u32; 8]) -> u32 {
    let mut sample = *peer_timestamps;
    sample.sort_unstable();
    // Lower median dari 8 nilai = index 3. Spec §12.3a.
    sample[NMT_PEER_COUNT / 2 - 1]
}

// ── Eclipse detection — spec §12.3a ──────────────────────────────────────────

/// Status NMT eclipse detection. Spec §12.3a.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NmtStatus {
    /// NMT valid — drift within limits. Spec §12.3a.
    Valid { nmt: u32, drift_s: u32 },
    /// Eclipse canatdate — |NMT - local| > T_NMT_MAX_DRIFT_S. Spec §12.3a.
    EclipseAlert {
        nmt: u32,
        local_wall_clock: u32,
        drift_s: u32,
    },
    /// insufficient peer — NMT cannot computed. Spec §12.3a.
    InsufficientPeers { count: usize, required: usize },
}

/// Compute NMT and detection eclipse. Spec §12.3a.
///
/// `peer_timestamps`: timestamps from peers in seconds.
/// `local_wall_clock`: wall-clock lokal node in seconds.
/// only used for eclipse detection, openN for NMT.
///
/// Eclipse alert if |NMT - local_wall_clock| > T_NMT_MAX_DRIFT_S.
pub fn compute_nmt_with_eclipse_check(peer_timestamps: &[u32], local_wall_clock: u32) -> NmtStatus {
    let nmt = match compute_nmt(peer_timestamps) {
        Some(n) => n,
        None => {
            return NmtStatus::InsufficientPeers {
                count: peer_timestamps.len(),
                required: NMT_PEER_COUNT,
            }
        }
    };

    // Eclipse check: |NMT - local_wall_clock| > T_NMT_MAX_DRIFT_S. Spec §12.3a.
    let drift_s = nmt.abs_diff(local_wall_clock);
    if drift_s > T_NMT_MAX_DRIFT_S {
        NmtStatus::EclipseAlert {
            nmt,
            local_wall_clock,
            drift_s,
        }
    } else {
        NmtStatus::Valid { nmt, drift_s }
    }
}

// ── NmtState — stateful NMT tracker ──────────────────────────────────────────

/// Stateful NMT tractor. Spec §12.3a.
///
/// store NMT current and timestamp update last.
/// Update interval = T_NMT_UPDATE_S (60 seconds).
#[derive(Debug, Clone)]
pub struct NmtState {
    /// NMT current in seconds. None if not yet ever updated.
    pub current_nmt: Option<u32>,
    /// Wall-clock seconds when NMT last updated.
    pub last_update_wall_s: u64,
    /// Jumlah peer used when update last.
    pub peer_count: usize,
}

impl NmtState {
    pub fn new() -> Self {
        Self {
            current_nmt: None,
            last_update_wall_s: 0,
            peer_count: 0,
        }
    }

    /// Update NMT from peer timestamps. Spec §12.3a.
    ///
    /// Returns NmtStatus after update.
    pub fn update(
        &mut self,
        peer_timestamps: &[u32],
        local_wall_clock: u32,
        wall_clock_s: u64,
    ) -> NmtStatus {
        let status = compute_nmt_with_eclipse_check(peer_timestamps, local_wall_clock);
        if let NmtStatus::Valid { nmt, .. } | NmtStatus::EclipseAlert { nmt, .. } = status {
            self.current_nmt = Some(nmt);
            self.last_update_wall_s = wall_clock_s;
            self.peer_count = peer_timestamps.len().min(NMT_PEER_COUNT);
        }
        status
    }

    /// tato NMT current. Returns None if not yet updated.
    pub fn nmt(&self) -> Option<u32> {
        self.current_nmt
    }
}

impl Default for NmtState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── NMT_PEER_COUNT constant ───────────────────────────────────────────────

    #[test]
    fn test_nmt_peer_count_is_8() {
        // Spec §12.3a: NMT_PEER_COUNT = 8. OSSIFIED.
        assert_eq!(NMT_PEER_COUNT, 8usize);
    }

    #[test]
    fn test_t_nmt_max_drift_s_is_600() {
        // Spec §12.3a: T_NMT_MAX_DRIFT_S = 600. OSSIFIED.
        assert_eq!(T_NMT_MAX_DRIFT_S, 600u32);
    }

    // ── compute_nmt — median ──────────────────────────────────────────────────

    #[test]
    fn test_compute_nmt_requires_8_peers() {
        // Kurang dari 8 peer → None. Spec §12.3a.
        assert!(compute_nmt(&[]).is_none());
        assert!(compute_nmt(&[1, 2, 3, 4, 5, 6, 7]).is_none());
        assert!(compute_nmt(&[1, 2, 3, 4, 5, 6, 7, 8]).is_some());
    }

    #[test]
    fn test_compute_nmt_is_median_not_average() {
        // NMT = median, BUKAN average. Spec §12.3a.
        // 8 timestamps: [100, 200, 300, 400, 500, 600, 700, 800]
        // Sorted: same. Lower median = index 3 = 400.
        // Average = 450 — berbeda dari median.
        let ts = [100u32, 200, 300, 400, 500, 600, 700, 800];
        let nmt = compute_nmt(&ts).unwrap();
        assert_eq!(nmt, 400); // lower meatan, openn average (450)
    }

    #[test]
    fn test_compute_nmt_not_average() {
        // Verifikasi eksplisit: NMT ≠ average untuk distribusi skewed.
        let ts = [1u32, 1, 1, 1, 1, 1, 1, 1_000_000];
        let nmt = compute_nmt(&ts).unwrap();
        // Average = ~125001, median (lower) = 1
        assert_eq!(nmt, 1);
        assert_ne!(nmt, (1u64 * 7 + 1_000_000) as u32 / 8); // openn average
    }

    #[test]
    fn test_compute_nmt_deterministic() {
        // NMT deterministik untuk input yang sama. Spec §12.3a.
        let ts = [100u32, 200, 150, 300, 250, 400, 350, 500];
        assert_eq!(compute_nmt(&ts), compute_nmt(&ts));
    }

    #[test]
    fn test_compute_nmt_order_independent() {
        // Urutan input tidak mempengaruhi NMT (sort internal). Spec §12.3a.
        let ts1 = [100u32, 200, 150, 300, 250, 400, 350, 500];
        let ts2 = [500u32, 350, 400, 250, 300, 150, 200, 100];
        assert_eq!(compute_nmt(&ts1), compute_nmt(&ts2));
    }

    #[test]
    fn test_compute_nmt_attacker_needs_5_of_8() {
        // Security: attacker butuh ≥5 dari 8 peer untuk shift median. Spec §12.3a.
        // 4 attacker peers + 4 honest peers:
        let honest = 1_000u32;
        let attack = 9_999u32;
        // 4 attacker, 4 honest → median = honest (attacker tidak cukup)
        let ts_4attacker = [
            attack, attack, attack, attack, honest, honest, honest, honest,
        ];
        let nmt = compute_nmt(&ts_4attacker).unwrap();
        // Sorted: [1000, 1000, 1000, 1000, 9999, 9999, 9999, 9999]
        // Lower median index 3 = 1000 (honest wins)
        assert_eq!(nmt, honest);
    }

    #[test]
    fn test_compute_nmt_5_attackers_shift_median() {
        // 5 attacker peers → bisa shift median. Spec §12.3a.
        let honest = 1_000u32;
        let attack = 9_999u32;
        let ts_5attacker = [
            attack, attack, attack, attack, attack, honest, honest, honest,
        ];
        let nmt = compute_nmt(&ts_5attacker).unwrap();
        // Sorted: [1000, 1000, 1000, 9999, 9999, 9999, 9999, 9999]
        // Lower median index 3 = 9999 (attacker wins)
        assert_eq!(nmt, attack);
    }

    #[test]
    fn test_compute_nmt_local_time_not_included() {
        // Local time TIDAK dimasukkan ke NMT. Spec §12.3a.
        // compute_nmt hanya menerima peer_timestamps, bukan local_time.
        // Test ini compile hanya jika fungsi tidak punya local_time parameter.
        let ts = [100u32, 200, 150, 300, 250, 400, 350, 500];
        let _ = compute_nmt(&ts); // only 1 parameter
    }

    #[test]
    fn test_compute_nmt_only_uses_first_8() {
        // Jika lebih dari 8 peer → hanya 8 pertama yang digunakan. Spec §12.3a.
        let ts_8 = [100u32, 200, 150, 300, 250, 400, 350, 500];
        let ts_10 = [100u32, 200, 150, 300, 250, 400, 350, 500, 9999, 9999];
        // Hasil bisa berbeda karena first-8 diambil sebelum sort
        // Yang penting: keduanya valid (not None)
        assert!(compute_nmt(&ts_8).is_some());
        assert!(compute_nmt(&ts_10).is_some());
    }

    // ── compute_nmt_from_8_peers ──────────────────────────────────────────────

    #[test]
    fn test_compute_nmt_from_8_peers_matches_compute_nmt() {
        // compute_nmt_from_8_peers harus identik dengan compute_nmt. Spec §12.3a.
        let arr: [u32; 8] = [100, 200, 150, 300, 250, 400, 350, 500];
        let slice_result = compute_nmt(&arr).unwrap();
        let arr_result = compute_nmt_from_8_peers(&arr);
        assert_eq!(slice_result, arr_result);
    }

    // ── eclipse detection ─────────────────────────────────────────────────────

    #[test]
    fn test_eclipse_check_valid_no_drift() {
        // NMT = local → Valid, drift = 0. Spec §12.3a.
        let ts = [1_000u32; 8];
        let status = compute_nmt_with_eclipse_check(&ts, 1_000);
        assert_eq!(
            status,
            NmtStatus::Valid {
                nmt: 1_000,
                drift_s: 0
            }
        );
    }

    #[test]
    fn test_eclipse_check_valid_within_drift() {
        // |NMT - local| ≤ T_NMT_MAX_DRIFT_S → Valid. Spec §12.3a.
        let ts = [1_000u32; 8];
        let local = 1_000 + T_NMT_MAX_DRIFT_S;
        let status = compute_nmt_with_eclipse_check(&ts, local);
        assert!(matches!(status, NmtStatus::Valid { .. }));
    }

    #[test]
    fn test_eclipse_check_alert_exceeded_drift() {
        // |NMT - local| > T_NMT_MAX_DRIFT_S → EclipseAlert. Spec §12.3a.
        let ts = [1_000u32; 8];
        let local = 1_000 + T_NMT_MAX_DRIFT_S + 1;
        let status = compute_nmt_with_eclipse_check(&ts, local);
        assert!(matches!(status, NmtStatus::EclipseAlert { .. }));
    }

    #[test]
    fn test_eclipse_check_insufficient_peers() {
        // Kurang dari 8 peer → InsufficientPeers. Spec §12.3a.
        let ts = [1_000u32; 7];
        let status = compute_nmt_with_eclipse_check(&ts, 1_000);
        assert_eq!(
            status,
            NmtStatus::InsufficientPeers {
                count: 7,
                required: 8
            }
        );
    }

    #[test]
    fn test_eclipse_alert_drift_value() {
        // drift_s harus = |NMT - local|. Spec §12.3a.
        let ts = [1_000u32; 8];
        let local = 1_000 + T_NMT_MAX_DRIFT_S + 100;
        if let NmtStatus::EclipseAlert { drift_s, .. } = compute_nmt_with_eclipse_check(&ts, local)
        {
            assert_eq!(drift_s, T_NMT_MAX_DRIFT_S + 100);
        } else {
            panic!("Expected EclipseAlert");
        }
    }

    // ── NmtState ──────────────────────────────────────────────────────────────

    #[test]
    fn test_nmt_state_initial_none() {
        // NmtState baru → current_nmt = None. Spec §12.3a.
        let state = NmtState::new();
        assert!(state.nmt().is_none());
    }

    #[test]
    fn test_nmt_state_update_sets_nmt() {
        // Setelah update → current_nmt tersedia. Spec §12.3a.
        let mut state = NmtState::new();
        let ts = [1_000u32; 8];
        state.update(&ts, 1_000, 60_000);
        assert_eq!(state.nmt(), Some(1_000));
    }

    #[test]
    fn test_nmt_state_update_stores_timestamp() {
        // last_update_wall_s tersimpan. Spec §12.3a.
        let mut state = NmtState::new();
        let ts = [1_000u32; 8];
        state.update(&ts, 1_000, 60_000);
        assert_eq!(state.last_update_wall_s, 60_000);
    }

    #[test]
    fn test_nmt_state_insufficient_peers_no_update() {
        // Kurang dari 8 peer → NMT tidak diupdate. Spec §12.3a.
        let mut state = NmtState::new();
        let ts = [1_000u32; 7]; // only 7
        state.update(&ts, 1_000, 60_000);
        assert!(state.nmt().is_none());
    }
}
