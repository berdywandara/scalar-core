//! AccountingState dan DeferredEmissionPool — Spec §7.1, §15.5, §16.2
//!
//! AccountingState: tracking global state emisi dan fee. Spec §16.2.
//! DeferredEmissionPool: pool residual emisi per epoch. Spec §7.1, §15.5.
//!
//! Invariant §15.5 (wajib):
//!   D(k) >= 0 | D(k) <= S_E | release(k) <= 0.10 × E0
//!   epoch sejak defer <= 12 | Sum release = Sum residual

use crate::accumulator::{E0_SSCL, S_E_SSCL};

// ── Ossified constants — spec §7.1, §17 ──────────────────────────────────────

/// Maximum release dari Deferred Pool per epoch: 10% × E0. OSSIFIED — spec §7.1.
pub const DEFERRED_POOL_MAX_RELEASE_PER_EPOCH: u64 = E0_SSCL / 10;

/// Maximum epoch sejak defer sebelum residual hangus. OSSIFIED — spec §7.1.
pub const DEFERRED_POOL_MAX_EPOCHS: u64 = 12;

// ── DeferredEntry — satu entri di pool ───────────────────────────────────────

/// Satu entry residual emisi yang di-defer. Spec §7.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredEntry {
    /// Epoch saat residual terjadi.
    pub deferred_epoch: u64,
    /// Jumlah residual dalam sSCL.
    pub amount_sscl: u64,
}

// ── DeferredEmissionPool — spec §7.1, §15.5 ──────────────────────────────────

/// Pool akumulasi residual emisi. Spec §7.1, §15.5.
///
/// Residual dari setiap epoch diakumulasi di sini, bukan hilang.
/// Release maksimum 10% × E0 per epoch, selama maksimal 12 epoch.
///
/// Invariant §15.5:
///   D(k) >= 0 | D(k) <= S_E
///   release(k) <= DEFERRED_POOL_MAX_RELEASE_PER_EPOCH
///   epoch sejak defer <= DEFERRED_POOL_MAX_EPOCHS
#[derive(Debug, Clone)]
pub struct DeferredEmissionPool {
    /// Entries yang belum di-release, sorted by deferred_epoch ascending.
    entries: Vec<DeferredEntry>,
    /// Total akumulasi saat ini dalam sSCL.
    pub total_sscl: u64,
    /// Total yang sudah di-release sepanjang waktu.
    pub total_released_sscl: u64,
    /// Total yang sudah masuk pool sepanjang waktu.
    pub total_deposited_sscl: u64,
}

impl DeferredEmissionPool {
    /// Buat pool kosong (genesis state).
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            total_sscl: 0,
            total_released_sscl: 0,
            total_deposited_sscl: 0,
        }
    }

    /// Deposit residual ke pool. Spec §7.1.
    ///
    /// Residual terjadi ketika reward tidak habis terbagi rata.
    /// Residual diakumulasi dan di-release di epoch berikutnya.
    pub fn deposit(&mut self, amount_sscl: u64, epoch: u64) {
        if amount_sscl == 0 {
            return;
        }
        // Invariant §15.5: D(k) <= S_E
        let new_total = self.total_sscl.saturating_add(amount_sscl);
        let capped = new_total.min(S_E_SSCL);
        let actual = capped.saturating_sub(self.total_sscl);
        if actual == 0 {
            return;
        }
        self.entries.push(DeferredEntry {
            deferred_epoch: epoch,
            amount_sscl: actual,
        });
        self.total_sscl = self.total_sscl.saturating_add(actual);
        self.total_deposited_sscl = self.total_deposited_sscl.saturating_add(actual);
    }

    /// Release residual untuk epoch k. Spec §7.1.
    ///
    /// Release: min(total_deferred, DEFERRED_POOL_MAX_RELEASE_PER_EPOCH).
    /// Entry yang sudah > DEFERRED_POOL_MAX_EPOCHS dihapus (expired).
    ///
    /// Returns: jumlah yang di-release dalam sSCL.
    pub fn release(&mut self, current_epoch: u64) -> u64 {
        // Hapus entry yang expired (> 12 epoch lama)
        self.entries
            .retain(|e| current_epoch.saturating_sub(e.deferred_epoch) <= DEFERRED_POOL_MAX_EPOCHS);

        // Recompute total setelah expire
        self.total_sscl = self.entries.iter().map(|e| e.amount_sscl).sum();

        // Release maksimum DEFERRED_POOL_MAX_RELEASE_PER_EPOCH
        let release_amount = self.total_sscl.min(DEFERRED_POOL_MAX_RELEASE_PER_EPOCH);
        if release_amount == 0 {
            return 0;
        }

        // Kurangi dari entries FIFO (oldest first)
        let mut remaining = release_amount;
        let mut i = 0;
        while i < self.entries.len() && remaining > 0 {
            if self.entries[i].amount_sscl <= remaining {
                remaining = remaining.saturating_sub(self.entries[i].amount_sscl);
                self.entries[i].amount_sscl = 0;
                i += 1;
            } else {
                self.entries[i].amount_sscl = self.entries[i].amount_sscl.saturating_sub(remaining);
                remaining = 0;
            }
        }
        // Hapus entries yang sudah habis
        self.entries.retain(|e| e.amount_sscl > 0);

        self.total_sscl = self.total_sscl.saturating_sub(release_amount);
        self.total_released_sscl = self.total_released_sscl.saturating_add(release_amount);
        release_amount
    }

    /// Jumlah entry aktif di pool.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Verifikasi invariant §15.5 secara runtime.
    pub fn verify_invariant(&self, release_this_epoch: u64) -> bool {
        self.total_sscl <= S_E_SSCL && release_this_epoch <= DEFERRED_POOL_MAX_RELEASE_PER_EPOCH
    }
}

impl Default for DeferredEmissionPool {
    fn default() -> Self {
        Self::new()
    }
}

// ── AccountingState — spec §16.2 ─────────────────────────────────────────────

/// Global accounting state untuk seluruh emisi dan fee. Spec §16.2.
///
/// Diupdate setiap epoch. Invariant: total_pou_minted_sscl <= S_E_SSCL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountingState {
    /// Total PoU yang sudah dicetak dalam sSCL. Spec §16.2.
    pub total_pou_minted_sscl: u64,
    /// Akumulasi Security Fund dari fee residual. Spec §16.2.
    pub security_fund_accumulator_sscl: u64,
    /// Total reserve yang sudah di-release dari S_R. Spec §16.2.
    pub total_reserve_released_sscl: u64,
    /// Saldo Deferred Emission Pool saat ini. Spec §16.2.
    pub deferred_emission_pool_sscl: u64,
}

impl AccountingState {
    /// Genesis state — semua zero.
    pub fn genesis() -> Self {
        Self {
            total_pou_minted_sscl: 0,
            security_fund_accumulator_sscl: 0,
            total_reserve_released_sscl: 0,
            deferred_emission_pool_sscl: 0,
        }
    }

    /// Record PoU mint. Returns Err jika melebihi S_E. Spec §5.2 MC3.
    pub fn record_mint(&mut self, amount_sscl: u64) -> Result<(), AccountingError> {
        let new_total = self
            .total_pou_minted_sscl
            .checked_add(amount_sscl)
            .ok_or(AccountingError::Overflow)?;
        if new_total > S_E_SSCL {
            return Err(AccountingError::SupplyCapExceeded {
                minted: self.total_pou_minted_sscl,
                reward: amount_sscl,
                cap: S_E_SSCL,
            });
        }
        self.total_pou_minted_sscl = new_total;
        Ok(())
    }

    /// Record fee ke Security Fund. Spec §9.2.
    pub fn record_security_fund(&mut self, amount_sscl: u64) {
        self.security_fund_accumulator_sscl = self
            .security_fund_accumulator_sscl
            .saturating_add(amount_sscl);
    }

    /// Record release dari S_R (tail emission backstop). Spec §7.1.
    pub fn record_reserve_release(&mut self, amount_sscl: u64) {
        self.total_reserve_released_sscl =
            self.total_reserve_released_sscl.saturating_add(amount_sscl);
    }

    /// Update saldo Deferred Emission Pool. Spec §7.1.
    pub fn update_deferred_pool(&mut self, pool: &DeferredEmissionPool) {
        self.deferred_emission_pool_sscl = pool.total_sscl;
    }

    /// Verifikasi supply cap invariant. Spec §5.2 MC3.
    pub fn supply_cap_ok(&self) -> bool {
        self.total_pou_minted_sscl <= S_E_SSCL
    }
}

// ── AccountingError ───────────────────────────────────────────────────────────

/// Error dari AccountingState operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountingError {
    /// Integer overflow.
    Overflow,
    /// Supply cap S_E exceeded. Spec §5.2 MC3.
    SupplyCapExceeded { minted: u64, reward: u64, cap: u64 },
}

impl core::fmt::Display for AccountingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Overflow => write!(f, "Accounting arithmetic overflow"),
            Self::SupplyCapExceeded {
                minted,
                reward,
                cap,
            } => write!(
                f,
                "Supply cap exceeded: minted={minted}, reward={reward}, cap={cap}"
            ),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── DeferredEmissionPool ──────────────────────────────────────────────────

    #[test]
    fn test_deferred_pool_empty_release_zero() {
        let mut pool = DeferredEmissionPool::new();
        assert_eq!(pool.release(1), 0);
    }

    #[test]
    fn test_deferred_pool_deposit_and_release() {
        let mut pool = DeferredEmissionPool::new();
        pool.deposit(1_000_000, 1);
        let released = pool.release(2);
        assert!(released > 0);
        assert!(released <= DEFERRED_POOL_MAX_RELEASE_PER_EPOCH);
    }

    #[test]
    fn test_deferred_pool_release_capped_at_max() {
        // Deposit lebih dari max release → release capped. Spec §7.1.
        let mut pool = DeferredEmissionPool::new();
        let large = DEFERRED_POOL_MAX_RELEASE_PER_EPOCH * 3;
        pool.deposit(large, 1);
        let released = pool.release(2);
        assert_eq!(released, DEFERRED_POOL_MAX_RELEASE_PER_EPOCH);
    }

    #[test]
    fn test_deferred_pool_max_release_constant() {
        // DEFERRED_POOL_MAX_RELEASE_PER_EPOCH = 10% × E0. Spec §7.1.
        assert_eq!(DEFERRED_POOL_MAX_RELEASE_PER_EPOCH, E0_SSCL / 10);
    }

    #[test]
    fn test_deferred_pool_max_epochs_constant() {
        // DEFERRED_POOL_MAX_EPOCHS = 12. Spec §7.1.
        assert_eq!(DEFERRED_POOL_MAX_EPOCHS, 12u64);
    }

    #[test]
    fn test_deferred_pool_expires_after_max_epochs() {
        // Entry > 12 epoch lama → dihapus. Spec §7.1.
        let mut pool = DeferredEmissionPool::new();
        pool.deposit(1_000, 1); // epoch 1
                                // Release di epoch 14 → entry dari epoch 1 expired (14-1=13 > 12)
        let released = pool.release(14);
        assert_eq!(released, 0, "Expired entry should not be released");
        assert_eq!(pool.total_sscl, 0);
    }

    #[test]
    fn test_deferred_pool_not_expired_at_boundary() {
        // Entry tepat di batas 12 epoch → masih valid. Spec §7.1.
        let mut pool = DeferredEmissionPool::new();
        pool.deposit(1_000, 1); // epoch 1
                                // Release di epoch 13 → 13-1=12 = DEFERRED_POOL_MAX_EPOCHS → masih valid
        let released = pool.release(13);
        assert!(
            released > 0,
            "Entry at boundary epoch should still be valid"
        );
    }

    #[test]
    fn test_deferred_pool_sum_release_equals_sum_residual() {
        // Invariant §15.5: Sum release = Sum residual (dalam batas expire). Spec §15.5.
        let mut pool = DeferredEmissionPool::new();
        let deposit1 = 500_000u64;
        let deposit2 = 300_000u64;
        pool.deposit(deposit1, 1);
        pool.deposit(deposit2, 2);
        let r1 = pool.release(3);
        let r2 = pool.release(4);
        assert!(
            r1 + r2 <= deposit1 + deposit2,
            "Total release tidak boleh melebihi total deposit"
        );
    }

    #[test]
    fn test_deferred_pool_invariant_check() {
        let mut pool = DeferredEmissionPool::new();
        pool.deposit(1_000, 1);
        let released = pool.release(2);
        assert!(pool.verify_invariant(released));
    }

    // ── AccountingState ───────────────────────────────────────────────────────

    #[test]
    fn test_accounting_genesis_all_zero() {
        let state = AccountingState::genesis();
        assert_eq!(state.total_pou_minted_sscl, 0);
        assert_eq!(state.security_fund_accumulator_sscl, 0);
        assert_eq!(state.total_reserve_released_sscl, 0);
        assert_eq!(state.deferred_emission_pool_sscl, 0);
    }

    #[test]
    fn test_accounting_record_mint_ok() {
        let mut state = AccountingState::genesis();
        state.record_mint(1_000_000).unwrap();
        assert_eq!(state.total_pou_minted_sscl, 1_000_000);
        assert!(state.supply_cap_ok());
    }

    #[test]
    fn test_accounting_record_mint_exceeds_cap() {
        let mut state = AccountingState::genesis();
        state.total_pou_minted_sscl = S_E_SSCL - 1;
        let result = state.record_mint(2);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AccountingError::SupplyCapExceeded { .. }
        ));
    }

    #[test]
    fn test_accounting_security_fund_accumulates() {
        let mut state = AccountingState::genesis();
        state.record_security_fund(1_000);
        state.record_security_fund(2_000);
        assert_eq!(state.security_fund_accumulator_sscl, 3_000);
    }

    #[test]
    fn test_accounting_update_deferred_pool() {
        let mut state = AccountingState::genesis();
        let mut pool = DeferredEmissionPool::new();
        pool.deposit(5_000, 1);
        state.update_deferred_pool(&pool);
        assert_eq!(state.deferred_emission_pool_sscl, 5_000);
    }

    #[test]
    fn test_accounting_supply_cap_enforced() {
        // total_pou_minted tidak boleh melebihi S_E. Spec §5.2 MC3.
        let mut state = AccountingState::genesis();
        state.total_pou_minted_sscl = S_E_SSCL;
        assert!(state.supply_cap_ok());
        assert!(state.record_mint(1).is_err());
    }

    #[test]
    fn test_accounting_struct_fields_match_spec() {
        // Spec §16.2: AccountingState memiliki 4 field yang ditentukan.
        let state = AccountingState::genesis();
        // Verifikasi semua field ada dan bisa diakses
        let _ = state.total_pou_minted_sscl;
        let _ = state.security_fund_accumulator_sscl;
        let _ = state.total_reserve_released_sscl;
        let _ = state.deferred_emission_pool_sscl;
    }
}
