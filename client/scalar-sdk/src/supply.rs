//! Supply Query API — spec §20.2 v11.1-FINAL, Gap G-18
//!
//! PR-V12-SDK-002: Tambahkan fungsi query supply ke scalar-sdk.
//!
//! Spec §20.2 v11.1-FINAL:
//!   query_total_minted() -> u64
//!   query_deferred_pool() -> u64
//!   query_security_fund() -> u64
//!
//! Semua fungsi read-only. Data diambil dari AccountingState via parameter.
//! Tidak ada akses ke scalar-emission internal. Isolasi terjaga.
//!
//! ISOLASI (spec §20.1, §21.1):
//!   scalar-sdk TIDAK boleh import scalar-emission langsung.
//!   Data AccountingState disupply oleh caller dari protocol layer.

// ── AccountingSnapshot — snapshot state untuk query ──────────────────────────

/// Snapshot AccountingState untuk supply queries. Spec §20.2.
///
/// Caller (dari protocol layer) mengisi struct ini dari AccountingState.
/// scalar-sdk tidak mengakses AccountingState langsung — isolasi terjaga.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountingSnapshot {
    /// Total PoU minted dalam sSCL. Spec §20.2.
    pub total_pou_minted_sscl: u64,
    /// Saldo Deferred Emission Pool dalam sSCL. Spec §20.2.
    pub deferred_emission_pool_sscl: u64,
    /// Saldo Security Fund dalam sSCL. Spec §20.2.
    pub security_fund_accumulator_sscl: u64,
    /// Total reserve yang sudah direlease dalam sSCL. Spec §20.2.
    pub total_reserve_released_sscl: u64,
    /// Epoch saat snapshot diambil.
    pub snapshot_epoch: u64,
}

// ── SupplyQueryResult — hasil query supply ────────────────────────────────────

/// Hasil query supply. Spec §20.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplyQueryResult {
    /// Nilai dalam sSCL.
    pub value_sscl: u64,
    /// Epoch saat snapshot.
    pub snapshot_epoch: u64,
    /// Nama field yang di-query.
    pub field: &'static str,
}

// ── Supply Query Functions — spec §20.2 ───────────────────────────────────────

/// Query total PoU minted. Spec §20.2.
///
/// Returns total SCL yang sudah di-mint dari pool emisi S_E.
/// Read-only — tidak mengubah state. Isolasi: tidak import scalar-emission.
pub fn query_total_minted(snapshot: &AccountingSnapshot) -> SupplyQueryResult {
    SupplyQueryResult {
        value_sscl: snapshot.total_pou_minted_sscl,
        snapshot_epoch: snapshot.snapshot_epoch,
        field: "total_pou_minted",
    }
}

/// Query saldo Deferred Emission Pool. Spec §20.2.
///
/// Returns saldo residual yang belum didistribusikan.
/// Read-only — tidak mengubah state. Isolasi: tidak import scalar-emission.
pub fn query_deferred_pool(snapshot: &AccountingSnapshot) -> SupplyQueryResult {
    SupplyQueryResult {
        value_sscl: snapshot.deferred_emission_pool_sscl,
        snapshot_epoch: snapshot.snapshot_epoch,
        field: "deferred_emission_pool",
    }
}

/// Query saldo Security Fund. Spec §20.2.
///
/// Returns saldo Security Fund dari fee residual.
/// Read-only — tidak mengubah state. Isolasi: tidak import scalar-emission.
pub fn query_security_fund(snapshot: &AccountingSnapshot) -> SupplyQueryResult {
    SupplyQueryResult {
        value_sscl: snapshot.security_fund_accumulator_sscl,
        snapshot_epoch: snapshot.snapshot_epoch,
        field: "security_fund",
    }
}

/// Verifikasi supply conservation invariant. Spec §20.2, §15.5.
///
/// Invariant: total_minted + deferred_pool + security_fund ≤ S_E + S_R
/// (semua SCL harus bisa diakuntansi).
///
/// Returns true jika invariant terpenuhi.
pub fn verify_supply_conservation(snapshot: &AccountingSnapshot) -> bool {
    // S_E + S_R = S_MAX = 2_100_000_000_000_000 sSCL (21M SCL)
    const S_MAX_SSCL: u64 = 2_100_000_000_000_000;

    let total_accounted = snapshot
        .total_pou_minted_sscl
        .saturating_add(snapshot.deferred_emission_pool_sscl)
        .saturating_add(snapshot.security_fund_accumulator_sscl);

    total_accounted <= S_MAX_SSCL
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_snapshot() -> AccountingSnapshot {
        AccountingSnapshot {
            total_pou_minted_sscl: 1_000_000_000_000,
            deferred_emission_pool_sscl: 50_000_000_000,
            security_fund_accumulator_sscl: 10_000_000_000,
            total_reserve_released_sscl: 0,
            snapshot_epoch: 5,
        }
    }

    // ── test_query_total_minted ───────────────────────────────────────────────

    #[test]
    fn test_query_total_minted() {
        // query_total_minted() tersedia dan benar. Spec §20.2.
        let snapshot = make_snapshot();
        let result = query_total_minted(&snapshot);
        assert_eq!(
            result.value_sscl, 1_000_000_000_000u64,
            "total_minted harus sesuai snapshot"
        );
        assert_eq!(result.snapshot_epoch, 5);
        assert_eq!(result.field, "total_pou_minted");
    }

    // ── test_query_deferred_pool ──────────────────────────────────────────────

    #[test]
    fn test_query_deferred_pool() {
        // query_deferred_pool() tersedia dan benar. Spec §20.2.
        let snapshot = make_snapshot();
        let result = query_deferred_pool(&snapshot);
        assert_eq!(
            result.value_sscl, 50_000_000_000u64,
            "deferred_pool harus sesuai snapshot"
        );
        assert_eq!(result.field, "deferred_emission_pool");
    }

    // ── test_query_security_fund ──────────────────────────────────────────────

    #[test]
    fn test_query_security_fund() {
        // query_security_fund() tersedia dan benar. Spec §20.2.
        let snapshot = make_snapshot();
        let result = query_security_fund(&snapshot);
        assert_eq!(
            result.value_sscl, 10_000_000_000u64,
            "security_fund harus sesuai snapshot"
        );
        assert_eq!(result.field, "security_fund");
    }

    // ── test_sdk_isolation ────────────────────────────────────────────────────

    #[test]
    fn test_sdk_isolation() {
        // scalar-sdk tidak import scalar-emission langsung. Spec §20.1, §21.1.
        // Test compile → isolation terjaga.
        let snapshot = make_snapshot();
        let _ = query_total_minted(&snapshot);
        let _ = query_deferred_pool(&snapshot);
        let _ = query_security_fund(&snapshot);
    }

    // ── test_supply_conservation ──────────────────────────────────────────────

    #[test]
    fn test_supply_conservation_valid() {
        // Conservation invariant: total ≤ S_MAX. Spec §20.2.
        let snapshot = make_snapshot();
        assert!(
            verify_supply_conservation(&snapshot),
            "Supply conservation harus terpenuhi"
        );
    }

    #[test]
    fn test_supply_conservation_exceeded() {
        // Jika total > S_MAX → invariant dilanggar. Spec §20.2.
        let snapshot = AccountingSnapshot {
            total_pou_minted_sscl: 2_100_000_000_000_000, // S_MAX penuh
            deferred_emission_pool_sscl: 1,               // overflow
            security_fund_accumulator_sscl: 0,
            total_reserve_released_sscl: 0,
            snapshot_epoch: 1,
        };
        assert!(
            !verify_supply_conservation(&snapshot),
            "Overflow S_MAX harus terdeteksi"
        );
    }

    #[test]
    fn test_snapshot_epoch_propagated() {
        // snapshot_epoch harus propagasi ke semua results. Spec §20.2.
        let mut snapshot = make_snapshot();
        snapshot.snapshot_epoch = 42;
        assert_eq!(query_total_minted(&snapshot).snapshot_epoch, 42);
        assert_eq!(query_deferred_pool(&snapshot).snapshot_epoch, 42);
        assert_eq!(query_security_fund(&snapshot).snapshot_epoch, 42);
    }

    #[test]
    fn test_zero_snapshot() {
        // Snapshot dengan semua zero → valid. Spec §20.2.
        let snapshot = AccountingSnapshot {
            total_pou_minted_sscl: 0,
            deferred_emission_pool_sscl: 0,
            security_fund_accumulator_sscl: 0,
            total_reserve_released_sscl: 0,
            snapshot_epoch: 0,
        };
        assert_eq!(query_total_minted(&snapshot).value_sscl, 0);
        assert_eq!(query_deferred_pool(&snapshot).value_sscl, 0);
        assert_eq!(query_security_fund(&snapshot).value_sscl, 0);
        assert!(verify_supply_conservation(&snapshot));
    }
}
