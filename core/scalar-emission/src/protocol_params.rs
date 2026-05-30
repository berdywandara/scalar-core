//! Protocol Parameters — D-027. MAD §4.1, §21.1, §21.2.
//!
//! Semantic constants dengan derived values untuk menghindari drift
//! ketika parameter operasional berubah.
//!
//! OSSIFIED:   tidak bisa berubah tanpa hard fork.
//! CONSTRAINED: bisa berubah via governance COMMIT 75%.
//! DERIVED:    dihitung dari konstanta lain — deterministik.

// ── OSSIFIED semantic anchors ─────────────────────────────────────────────────

/// Hari yang dibutuhkan node untuk maturity penuh. OSSIFIED — D-027, MAD §21.1.
/// Semantic anchor P3: 180 hari = genuine operation yang terbukti.
/// Aligned dengan conviction τ=60 hari (95% conviction di 180 hari).
/// Perubahan memerlukan hard fork.
pub const W_MATURE_DAYS: u64 = 180;

// ── CONSTRAINED operational parameters ───────────────────────────────────────

/// Heartbeat interval dalam detik. CONSTRAINED — D-024, MAD §21.2.
pub const HEARTBEAT_INTERVAL_S: u64 = 120;

/// Durasi satu sub-epoch dalam detik (proving-time based). CONSTRAINED — D-024/D-027.
/// Nilai = proving time baseline dari P3-R9 benchmark (dedicated EPYC).
/// Berbeda dari scalar_network::subepoch::SUBEPOCH_DURATION_S (Research Package §3.2).
pub const SUBEPOCH_PROVING_DURATION_S: u64 = 1_900;

/// Jumlah sub-epoch per epoch. CONSTRAINED — MAD §4.1.
pub const SUBEPOCH_COUNT: u64 = 24;

/// Genesis window dalam hari. CONSTRAINED — D-027, MAD §21.2.
/// Waktu yang tersedia bagi peserta genesis untuk mengirim anchor pertama.
pub const GENESIS_WINDOW_DAYS: u64 = 7;

// ── DERIVED values (pure functions — deterministik di semua node) ─────────────

/// Durasi satu epoch dalam detik. D-027. MAD §4.1.
/// = SUBEPOCH_PROVING_DURATION_S × SUBEPOCH_COUNT = 1_900 × 24 = 45_600s ≈ 12.67 jam
pub fn epoch_duration_s() -> u64 {
    SUBEPOCH_PROVING_DURATION_S * SUBEPOCH_COUNT
}

/// Jumlah epoch yang dibutuhkan untuk maturity penuh. D-027.
/// = ceil(W_MATURE_DAYS × 86_400 / epoch_duration_s()) = ceil(15_552_000 / 45_600) = 342
pub fn w_mature_epochs() -> u64 {
    (W_MATURE_DAYS * 86_400).div_ceil(epoch_duration_s())
}

/// Nilai maturity penuh (denominator gov_weight). D-027.
/// = w_mature_epochs() × heartbeats_per_epoch × FIXED_POINT_BASIS
pub fn w_mature(heartbeats_per_epoch: u64, fp_basis: u64) -> u64 {
    w_mature_epochs() * heartbeats_per_epoch * fp_basis
}

/// Heartbeat deadline untuk genesis anchor. D-027.
/// = ceil(GENESIS_WINDOW_DAYS × 86_400 / HEARTBEAT_INTERVAL_S) = ceil(604_800 / 120) = 5_040
pub fn genesis_anchor_deadline_seq() -> u64 {
    (GENESIS_WINDOW_DAYS * 86_400).div_ceil(HEARTBEAT_INTERVAL_S)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derived_parameters_consistency() {
        // Epoch duration
        assert_eq!(epoch_duration_s(), 45_600);

        // W_MATURE_EPOCHS harus menghasilkan >= 180 hari. D-027.
        let days = w_mature_epochs() * epoch_duration_s() / 86_400;
        assert!(days >= 180, "maturity < 180 days: {days}");
        assert_eq!(w_mature_epochs(), 342);

        // Genesis window >= 7 hari. D-027.
        let genesis_days = genesis_anchor_deadline_seq() * HEARTBEAT_INTERVAL_S / 86_400;
        assert!(genesis_days >= 7, "genesis window < 7 days: {genesis_days}");
        assert_eq!(genesis_anchor_deadline_seq(), 5_040);
    }

    #[test]
    fn test_semantic_anchors_stable() {
        // OSSIFIED: 180 hari tidak boleh berubah tanpa hard fork. D-027.
        assert_eq!(W_MATURE_DAYS, 180);
        // CONSTRAINED: genesis window 7 hari.
        assert_eq!(GENESIS_WINDOW_DAYS, 7);
    }

    #[test]
    fn test_heartbeat_interval() {
        // D-024: HEARTBEAT_INTERVAL_S = 120. CONSTRAINED.
        assert_eq!(HEARTBEAT_INTERVAL_S, 120);
    }

    #[test]
    fn test_w_mature_full_calculation() {
        // W_MATURE dengan EXPECTED_HEARTBEATS_PER_EPOCH=4320, FP=1_000_000
        let wm = w_mature(4_320, 1_000_000);
        assert_eq!(wm, 342 * 4_320 * 1_000_000);
        assert_eq!(wm, 1_477_440_000_000u64);
    }

    #[test]
    fn test_derived_params_robust_to_future_changes() {
        // Jika SUBEPOCH_PROVING_DURATION_S berubah, W_MATURE_DAYS tetap 180.
        assert_eq!(W_MATURE_DAYS, 180);
        assert_eq!(GENESIS_WINDOW_DAYS, 7);
    }
}
