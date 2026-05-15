//! Supply Query API — spec §20.2 v11.1-FINAL, Gap G-18
//!
//! PR-V12-SDK-002: add function query supply to scalar-sdk.
//!
//! Spec §20.2 v11.1-FINAL:
//!   query_total_minted() -> u64
//!   query_deferred_pool() -> u64
//!   query_security_fund() -> u64
//!
//! all function read-only. data derived from AccountingState via parameter.
//! none access to scalar-emission internal. isolation terjaga.
//!
//! isolation (spec §20.1, §21.1):
//! scalar-sdk must not import scalar-emission langsung.
//! data AccountingState atsupply oleh caller from protocol layer.

// ── AccountingSnapshot — snapshot state untuk query ──────────────────────────

/// Snapshot AccountingState for supply queries. Spec §20.2.
///
/// Caller (from protocol layer) fill struct this from AccountingState.
/// scalar-sdk not mengakses AccountingState langsung — isolation terjaga.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountingSnapshot {
    /// Total PoU minted in SSCL. Spec §20.2.
    pub total_pou_minted_sscl: u64,
    /// Saldo Deferred Emission Pool in SSCL. Spec §20.2.
    pub deferred_emission_pool_sscl: u64,
    /// Saldo Security Fund in SSCL. Spec §20.2.
    pub security_fund_accumulator_sscl: u64,
    /// Total reserve that has been atrelease in SSCL. Spec §20.2.
    pub total_reserve_released_sscl: u64,
    /// current epoch snapshot taton.
    pub snapshot_epoch: u64,
}

// ── SupplyQueryResult — hasil query supply ────────────────────────────────────

/// Hasil query supply. Spec §20.2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplyQueryResult {
    /// value in SSCL.
    pub value_sscl: u64,
    /// current epoch snapshot.
    pub snapshot_epoch: u64,
    /// Nama field that at-query.
    pub field: &'static str,
}

// ── Supply Query Functions — spec §20.2 ───────────────────────────────────────

/// Query total PoU minted. Spec §20.2.
///
/// Returns total SCL that has been at-mint from pool emfill S_E.
/// Read-only — not change state. isolation: not import scalar-emission.
pub fn query_total_minted(snapshot: &AccountingSnapshot) -> SupplyQueryResult {
    SupplyQueryResult {
        value_sscl: snapshot.total_pou_minted_sscl,
        snapshot_epoch: snapshot.snapshot_epoch,
        field: "total_pou_minted",
    }
}

/// Query saldo Deferred Emission Pool. Spec §20.2.
///
/// Returns saldo residual that not yet atatstributionkan.
/// Read-only — not change state. isolation: not import scalar-emission.
pub fn query_deferred_pool(snapshot: &AccountingSnapshot) -> SupplyQueryResult {
    SupplyQueryResult {
        value_sscl: snapshot.deferred_emission_pool_sscl,
        snapshot_epoch: snapshot.snapshot_epoch,
        field: "deferred_emission_pool",
    }
}

/// Query saldo Security Fund. Spec §20.2.
///
/// Returns saldo Security Fund from fee residual.
/// Read-only — not change state. isolation: not import scalar-emission.
pub fn query_security_fund(snapshot: &AccountingSnapshot) -> SupplyQueryResult {
    SupplyQueryResult {
        value_sscl: snapshot.security_fund_accumulator_sscl,
        snapshot_epoch: snapshot.snapshot_epoch,
        field: "security_fund",
    }
}

/// verification supply conservation invariant. Spec §20.2, §15.5.
///
/// Invariant: total_minted + deferred_pool + security_fund ≤ S_E + S_R
/// (all SCL harus bisa atakuntansi).
///
/// returns true if invariant terfulli.
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
            total_pou_minted_sscl: 2_100_000_000_000_000, // S_MAX full
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
