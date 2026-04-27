//! Coin Selection — Step 2b (fee adequacy) + Fee Reserve (§B.4.6 + §B.4.7)
//!
//! Spesifikasi: Scalar_Master_Technical_Spec.docx §B.4.6 + §B.4.7
//!
//! TAMBAHAN pada algoritma original (§A.2.1) — disisipkan antara Step 2 dan Step 3:
//!
//! Step 2b: FEE ADEQUACY PRE-CHECK
//!   Jika selisih coins yang dipilih < fee_total (shortfall):
//!   → Loop: tambahkan coin terkecil yang menutup shortfall
//!   → Prioritas: denominasi terkecil yang cukup
//!   → Batas: total inputs ≤ MAX_INPUTS (10, OSSIFIED)
//!   → Jika MAX_INPUTS tercapai + masih shortfall: REQUIRES_CONSOLIDATION
//!
//! Step 6: ERROR HANDLING (baru)
//!   REQUIRES_CONSOLIDATION → sarankan konsolidasi coin kecil dulu
//!   Saldo tidak cukup → tolak di wallet sebelum broadcast
//!
//! Fee Reserve (§B.4.7 — rekomendasi, bukan constraint protokol):
//!   Target: ≥5 coins d1–d6, total ≥ 10,000 sSCL
//!   Notifikasi: fee_reserve_total < 1,000 sSCL

/// Maksimum inputs per transaksi. OSSIFIED (Transfer Circuit C8).
pub const MAX_INPUTS: usize = 10;

/// Denominasi fixed Scalar dalam sSCL (17 denominasi, §A.2).
/// Diurutkan ascending untuk coin selection.
pub const DENOMINATIONS: [u64; 17] = [
    1,
    5,
    10,
    50,
    100,
    500,
    1_000,
    5_000,
    10_000,
    50_000,
    100_000,
    500_000,
    1_000_000,
    5_000_000,
    10_000_000,
    50_000_000,
    100_000_000,
];

/// Index denominasi d1–d6 (1–500 sSCL) untuk fee reserve.
/// d1=1, d2=5, d3=10, d4=50, d5=100, d6=500 sSCL.
pub const FEE_RESERVE_DENOM_MAX_IDX: usize = 5; // index 0..=5 dalam DENOMINATIONS

/// Target total fee reserve dalam sSCL (§B.4.7).
pub const FEE_RESERVE_TARGET_SSCL: u64 = 10_000;

/// Trigger notifikasi fee reserve dalam sSCL (§B.4.7).
pub const FEE_RESERVE_NOTIFY_THRESHOLD_SSCL: u64 = 1_000;

/// Coin yang dimiliki wallet — denomination + jumlah yang tersedia.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletCoin {
    /// Nilai coin dalam sSCL (harus salah satu dari DENOMINATIONS)
    pub value: u64,
    /// Jumlah coin denomination ini yang dimiliki
    pub count: u32,
}

/// Hasil coin selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoinSelectionResult {
    /// Coin selection berhasil.
    Ok {
        /// Coins yang dipilih (list nilai, bisa duplikat)
        selected_coins: Vec<u64>,
        /// Total nilai yang dipilih
        total_selected: u64,
        /// Change yang dikembalikan (total_selected - target_value - fee_total)
        change_value: u64,
    },
    /// Perlu konsolidasi coin kecil sebelum transaksi ini bisa dilakukan.
    RequiresConsolidation { message: &'static str },
    /// Saldo tidak mencukupi untuk fee.
    InsufficientBalance { message: &'static str },
}

/// Status fee reserve wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeeReserveStatus {
    /// Fee reserve mencukupi.
    Adequate { total_reserve: u64 },
    /// Fee reserve di bawah threshold notifikasi.
    Low {
        total_reserve: u64,
        message: &'static str,
    },
    /// Fee reserve kosong.
    Empty,
}

/// Step 2b: Fee adequacy pre-check.
///
/// Disisipkan antara Step 2 (privacy randomization) dan Step 3 (greedy selection)
/// dari algoritma original §A.2.1.
///
/// Input:
///   - `selected_so_far`: coins yang sudah dipilih di Step 1-2
///   - `available_coins`: semua coin wallet yang belum dipilih, ascending by value
///   - `target_value`: nilai transfer yang diinginkan
///   - `fee_total`: FLOOR + PREMIUM + PADDING (publik)
///
/// Return: CoinSelectionResult dengan coins final atau error.
pub fn step2b_fee_adequacy_check(
    selected_so_far: Vec<u64>,
    available_coins: &[WalletCoin],
    target_value: u64,
    fee_total: u64,
) -> CoinSelectionResult {
    let total_needed = target_value.saturating_add(fee_total);

    // Hitung total yang sudah dipilih
    let mut selected = selected_so_far;
    let mut total_selected: u64 = selected.iter().sum();

    // Jika sudah cukup — tidak perlu tambahan
    if total_selected >= total_needed {
        let change_value = total_selected.saturating_sub(total_needed);
        return CoinSelectionResult::Ok {
            selected_coins: selected,
            total_selected,
            change_value,
        };
    }

    // Hitung shortfall
    let mut shortfall = total_needed.saturating_sub(total_selected);

    // Buat pool coin yang tersedia, diurutkan ascending by value
    // (prioritas: denominasi terkecil yang menutup shortfall)
    let mut pool: Vec<u64> = available_coins
        .iter()
        .flat_map(|c| std::iter::repeat_n(c.value, c.count as usize))
        .collect();
    pool.sort_unstable();

    // Loop: tambahkan coin terkecil yang menutup shortfall
    // Prioritas: coin terkecil yang nilainya ≥ shortfall (meminimalkan over-selection)
    // Jika tidak ada yang cukup besar: ambil coin terkecil yang tersedia
    while shortfall > 0 {
        if selected.len() >= MAX_INPUTS {
            // Batas MAX_INPUTS tercapai tapi masih shortfall
            return CoinSelectionResult::RequiresConsolidation {
                message: "Perlu konsolidasi coin dahulu: terlalu banyak coin kecil \
                          untuk menutup fee. Lakukan transaksi konsolidasi dulu.",
            };
        }

        if pool.is_empty() {
            // Tidak ada coin lagi — saldo tidak cukup
            return CoinSelectionResult::InsufficientBalance {
                message: "Saldo tidak mencukupi untuk fee.",
            };
        }

        // Cari coin terkecil yang nilainya ≥ shortfall
        let best_idx = pool.partition_point(|&v| v < shortfall);

        let chosen_idx = if best_idx < pool.len() {
            // Ada coin yang nilainya ≥ shortfall — ambil yang terkecil di antara mereka
            best_idx
        } else {
            // Tidak ada coin yang cukup besar — ambil coin terbesar yang tersedia
            pool.len() - 1
        };

        let coin_value = pool.remove(chosen_idx);
        selected.push(coin_value);
        total_selected = total_selected.saturating_add(coin_value);
        shortfall = total_needed.saturating_sub(total_selected);
    }

    let change_value = total_selected.saturating_sub(total_needed);
    CoinSelectionResult::Ok {
        selected_coins: selected,
        total_selected,
        change_value,
    }
}

/// Cek status fee reserve wallet (§B.4.7).
///
/// Fee reserve = total nilai semua coin denominasi d1–d6 (1–500 sSCL).
/// Rekomendasi implementasi — bukan constraint protokol.
pub fn check_fee_reserve(wallet_coins: &[WalletCoin]) -> FeeReserveStatus {
    let max_reserve_denom = DENOMINATIONS[FEE_RESERVE_DENOM_MAX_IDX]; // 500 sSCL

    let total_reserve: u64 = wallet_coins
        .iter()
        .filter(|c| c.value <= max_reserve_denom)
        .map(|c| c.value.saturating_mul(c.count as u64))
        .sum();

    if total_reserve == 0 {
        FeeReserveStatus::Empty
    } else if total_reserve < FEE_RESERVE_NOTIFY_THRESHOLD_SSCL {
        FeeReserveStatus::Low {
            total_reserve,
            message: "Coin kecil menipis — pertimbangkan menerima transaksi kecil.",
        }
    } else {
        FeeReserveStatus::Adequate { total_reserve }
    }
}

/// Hitung total nilai fee reserve saat ini.
pub fn total_fee_reserve(wallet_coins: &[WalletCoin]) -> u64 {
    let max_reserve_denom = DENOMINATIONS[FEE_RESERVE_DENOM_MAX_IDX];
    wallet_coins
        .iter()
        .filter(|c| c.value <= max_reserve_denom)
        .map(|c| c.value.saturating_mul(c.count as u64))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coins(pairs: &[(u64, u32)]) -> Vec<WalletCoin> {
        pairs
            .iter()
            .map(|&(value, count)| WalletCoin { value, count })
            .collect()
    }

    // ── Step 2b: Fee adequacy ─────────────────────────────────────────

    #[test]
    fn test_already_sufficient_no_addition() {
        // Sudah cukup dari step sebelumnya — tidak perlu tambahan
        let selected = vec![10_000u64, 5_000]; // 15_000 sSCL
        let available = coins(&[(100, 5)]);
        let result = step2b_fee_adequacy_check(selected, &available, 10_000, 100);

        match result {
            CoinSelectionResult::Ok {
                selected_coins,
                change_value,
                ..
            } => {
                assert_eq!(selected_coins.len(), 2);
                assert_eq!(change_value, 4_900); // 15_000 - 10_000 - 100
            }
            _ => panic!("Harus Ok"),
        }
    }

    #[test]
    fn test_shortfall_resolved_with_small_coin() {
        // selected = 10_000, target=10_000, fee=100 → shortfall=100
        // available: coin 100 sSCL
        let selected = vec![10_000u64];
        let available = coins(&[(100, 5)]);
        let result = step2b_fee_adequacy_check(selected, &available, 10_000, 100);

        match result {
            CoinSelectionResult::Ok {
                selected_coins,
                change_value,
                ..
            } => {
                assert!(selected_coins.contains(&100));
                assert_eq!(change_value, 0); // tepat
            }
            _ => panic!("Harus Ok"),
        }
    }

    #[test]
    fn test_shortfall_prefers_exact_denomination() {
        // shortfall=100, available: 50, 100, 500
        // Harus pilih 100 (terkecil yang ≥ shortfall), bukan 500
        let selected = vec![10_000u64];
        let available = coins(&[(50, 2), (100, 1), (500, 1)]);
        let result = step2b_fee_adequacy_check(selected, &available, 10_000, 100);

        match result {
            CoinSelectionResult::Ok { selected_coins, .. } => {
                // Coin yang ditambahkan harus 100, bukan 500
                let added: Vec<u64> = selected_coins
                    .iter()
                    .filter(|&&v| v != 10_000)
                    .copied()
                    .collect();
                assert_eq!(added, vec![100], "Harus pilih coin 100 yang paling efisien");
            }
            _ => panic!("Harus Ok"),
        }
    }

    #[test]
    fn test_max_inputs_exceeded_requires_consolidation() {
        // 10 coins sudah dipilih, masih shortfall → REQUIRES_CONSOLIDATION
        let selected = vec![1u64; MAX_INPUTS]; // 10 coins @ 1 sSCL = 10 sSCL
        let available = coins(&[(1, 100)]); // banyak coin kecil tapi MAX_INPUTS sudah tercapai
        let result = step2b_fee_adequacy_check(selected, &available, 100, 40);

        assert!(
            matches!(result, CoinSelectionResult::RequiresConsolidation { .. }),
            "Harus RequiresConsolidation saat MAX_INPUTS tercapai"
        );
    }

    #[test]
    fn test_insufficient_balance() {
        // Tidak ada coin sama sekali — saldo tidak cukup
        let selected = vec![10u64];
        let available = vec![]; // tidak ada coin lagi
        let result = step2b_fee_adequacy_check(selected, &available, 1_000, 100);

        assert!(
            matches!(result, CoinSelectionResult::InsufficientBalance { .. }),
            "Harus InsufficientBalance saat tidak ada coin"
        );
    }

    #[test]
    fn test_multiple_small_coins_to_cover_shortfall() {
        // shortfall=150, tersedia: coin-coin 50 sSCL
        // Harus ambil 3 coin 50 untuk menutup
        let selected = vec![10_000u64];
        let available = coins(&[(50, 10)]);
        let result = step2b_fee_adequacy_check(selected, &available, 10_000, 150);

        match result {
            CoinSelectionResult::Ok {
                selected_coins,
                change_value,
                ..
            } => {
                let count_50 = selected_coins.iter().filter(|&&v| v == 50).count();
                assert_eq!(count_50, 3, "Harus 3 coin 50 sSCL");
                assert_eq!(change_value, 0); // 10_000 + 150 = 10_150, selected = 10_150
            }
            _ => panic!("Harus Ok"),
        }
    }

    #[test]
    fn test_zero_fee_no_change_needed() {
        // fee=0 (tidak mungkin di produksi tapi logika harus handle)
        let selected = vec![1_000u64];
        let available = coins(&[(100, 5)]);
        let result = step2b_fee_adequacy_check(selected, &available, 1_000, 0);

        match result {
            CoinSelectionResult::Ok { change_value, .. } => {
                assert_eq!(change_value, 0);
            }
            _ => panic!("Harus Ok"),
        }
    }

    // ── Fee reserve ───────────────────────────────────────────────────

    #[test]
    fn test_fee_reserve_adequate() {
        // 20 coin × 500 sSCL = 10_000 sSCL (tepat target)
        let wallet = coins(&[(500, 20)]);
        match check_fee_reserve(&wallet) {
            FeeReserveStatus::Adequate { total_reserve } => {
                assert_eq!(total_reserve, 10_000);
            }
            s => panic!("Harus Adequate, dapat: {:?}", s),
        }
    }

    #[test]
    fn test_fee_reserve_low_notification() {
        // 5 coin × 100 sSCL = 500 sSCL < threshold 1_000
        let wallet = coins(&[(100, 5)]);
        assert!(matches!(
            check_fee_reserve(&wallet),
            FeeReserveStatus::Low { .. }
        ));
    }

    #[test]
    fn test_fee_reserve_empty() {
        // Tidak ada coin kecil sama sekali
        let wallet = coins(&[(1_000_000, 5)]); // hanya coin besar (d7+)
        assert!(matches!(
            check_fee_reserve(&wallet),
            FeeReserveStatus::Empty
        ));
    }

    #[test]
    fn test_fee_reserve_excludes_large_denominations() {
        // Coin 1_000 sSCL (d7) tidak termasuk fee reserve
        let wallet = coins(&[(1_000, 100), (500, 5)]);
        let reserve = total_fee_reserve(&wallet);
        // Hanya 500×5 = 2_500 (coin 1_000 tidak termasuk)
        assert_eq!(reserve, 2_500);
    }

    #[test]
    fn test_fee_reserve_mixed_denominations() {
        // Mix d1–d6: 1×10 + 5×10 + 10×10 + 50×5 + 100×3 + 500×2
        // = 10 + 50 + 100 + 250 + 300 + 1000 = 1710 sSCL
        let wallet = coins(&[(1, 10), (5, 10), (10, 10), (50, 5), (100, 3), (500, 2)]);
        assert_eq!(total_fee_reserve(&wallet), 1_710);
        // 1_710 > 1_000 threshold → Adequate
        assert!(matches!(
            check_fee_reserve(&wallet),
            FeeReserveStatus::Adequate { .. }
        ));
    }

    #[test]
    fn test_max_inputs_constant() {
        // Verifikasi MAX_INPUTS = 10 sesuai circuit constraint C8
        assert_eq!(MAX_INPUTS, 10);
    }
}

// ── Backward compatibility — API lama dari transaction.rs ────────────

/// Mode privasi untuk coin selection (API lama).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivacyMode {
    /// Prioritas kecepatan — pilih coin paling efisien
    Speed,
    /// Prioritas privasi — shuffle order
    Privacy,
    /// Maksimum privasi
    Maximum,
}

/// CoinSelector — wrapper coin selection dengan API lama.
/// Step 2b (fee adequacy) sudah terintegrasi di dalamnya.
pub struct CoinSelector;

impl CoinSelector {
    /// API lama yang digunakan transaction.rs.
    /// wallet_coins: HashMap<denomination, count>
    /// total_needed: target_value + fee_total (sudah digabung oleh pemanggil)
    pub fn select_coins(
        wallet_coins: &std::collections::HashMap<u64, usize>,
        total_needed: u64,
        _mode: PrivacyMode,
    ) -> Result<Vec<u64>, &'static str> {
        // Konversi HashMap ke Vec<WalletCoin> ascending by value
        let mut available: Vec<WalletCoin> = wallet_coins
            .iter()
            .map(|(&value, &count)| WalletCoin {
                value,
                count: count as u32,
            })
            .collect();
        available.sort_unstable_by_key(|c| c.value);

        // Jalankan Step 2b dengan pre-selection kosong
        // total_needed sudah mencakup fee — set fee_total=0 agar tidak double-count
        match step2b_fee_adequacy_check(vec![], &available, total_needed, 0) {
            CoinSelectionResult::Ok { selected_coins, .. } => Ok(selected_coins),
            CoinSelectionResult::RequiresConsolidation { message } => Err(message),
            CoinSelectionResult::InsufficientBalance { message } => Err(message),
        }
    }
}
