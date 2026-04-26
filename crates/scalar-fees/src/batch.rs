//! Batch Protocol — §B.4.3 + §B.4.4
//!
//! Intra-batch priority:
//!   score(tx) = PREMIUM / complexity_weight
//!   complexity_weight = 1 + (num_inputs + num_outputs) × 0.1
//!   [OSSIFIED §B.6 — formula tidak bisa diubah tanpa fork]
//!
//! Inter-batch: aggregator prove batch dengan batch_value tertinggi.
//!
//! Tie-breaking (OSSIFIED §B.6):
//!   winner = argmin(Poseidon2(batch_root ∥ node_id))
//!
//! Fairness slot (§B.4.3, Layer 2):
//!   Setiap N=10 batch, wajib sertakan ≥1 tx dengan score terendah.

use scalar_crypto::poseidon2::hash_2_to_1;

// ── Konstanta (sebagian ossified) ────────────────────────────────────

/// N fairness slot — setiap N batch, satu slot wajib tx score terendah.
/// Layer 2 CONSTRAINED, default: 10, range: 5–50.
pub const FAIRNESS_N_DEFAULT: u32 = 10;

/// Timeout multiplier untuk batch prove time estimate.
/// Layer 2 CONSTRAINED, default: 3×, range: 2×–10×.
pub const TIMEOUT_MULTIPLIER_DEFAULT: u32 = 3;

/// Fixed-point basis untuk score computation (menghindari float).
/// score_fp = (PREMIUM × SCORE_FP_BASIS) / complexity_weight_fp
const SCORE_FP_BASIS: u128 = 1_000_000;

// ── Score computation (OSSIFIED) ─────────────────────────────────────

/// Representasi transaksi dalam batch untuk scoring.
#[derive(Debug, Clone)]
pub struct TxForBatch {
    pub tx_id:       [u8; 32],
    pub premium:     u64,  // sSCL
    pub num_inputs:  u32,
    pub num_outputs: u32,
    pub fee_total:   u64,  // untuk batch_value computation
}

/// Hitung intra-batch priority score untuk satu transaksi.
///
/// score(tx) = PREMIUM / complexity_weight
/// complexity_weight = 1 + (num_inputs + num_outputs) × 0.1
///
/// Implementasi fixed-point (basis 1_000_000) sesuai prinsip
/// "no floating point" untuk determinisme antar platform.
///
/// OSSIFIED: formula ini tidak bisa diubah tanpa fork (§B.6).
pub fn compute_score_fp(tx: &TxForBatch) -> u128 {
    // complexity_weight_fp = (1 + (inputs + outputs) × 0.1) × 1_000_000
    // = 1_000_000 + (inputs + outputs) × 100_000
    let io_sum = (tx.num_inputs + tx.num_outputs) as u128;
    let complexity_weight_fp = 1_000_000u128 + io_sum * 100_000;

    // score_fp = (premium × SCORE_FP_BASIS) / complexity_weight_fp
    (tx.premium as u128)
        .saturating_mul(SCORE_FP_BASIS)
        .checked_div(complexity_weight_fp)
        .unwrap_or(0)
}

/// Sort transaksi dalam batch: score tertinggi di depan.
/// Tx dengan score sama: tx_id lebih kecil di depan (tie-break deterministik).
pub fn sort_batch_by_score(txs: &mut Vec<TxForBatch>) {
    txs.sort_unstable_by(|a, b| {
        let score_a = compute_score_fp(a);
        let score_b = compute_score_fp(b);
        // Descending score, ascending tx_id untuk tie-break
        score_b
            .cmp(&score_a)
            .then_with(|| a.tx_id.cmp(&b.tx_id))
    });
}

// ── Batch value (inter-batch priority) ───────────────────────────────

/// Hitung batch_value = Σ fee_total semua tx dalam batch.
/// Aggregator prove batch dengan batch_value tertinggi dahulu.
pub fn compute_batch_value(txs: &[TxForBatch]) -> u64 {
    txs.iter().map(|tx| tx.fee_total).sum()
}

// ── Tie-breaking (OSSIFIED) ──────────────────────────────────────────

/// BatchAnnouncement — broadcast saat aggregator mulai prove (§B.4.4).
#[derive(Debug, Clone)]
pub struct BatchAnnouncement {
    /// Merkle root semua tx dalam batch
    pub batch_root: [u8; 32],
    /// NodeID aggregator
    pub node_id:    [u8; 32],
    pub timestamp:  u64,
}

/// Hitung tie-breaking score untuk satu aggregator.
///
/// score = Poseidon2(batch_root_lo, node_id_lo)
/// winner = argmin(score)
///
/// OSSIFIED: formula ini tidak bisa diubah tanpa fork (§B.6).
pub fn tiebreak_score(ann: &BatchAnnouncement) -> u64 {
    let batch_root_lo = u64::from_le_bytes(ann.batch_root[0..8].try_into().unwrap());
    let node_id_lo    = u64::from_le_bytes(ann.node_id[0..8].try_into().unwrap());
    hash_2_to_1(batch_root_lo, node_id_lo)
}

/// Pilih pemenang dari beberapa BatchAnnouncement dengan batch_root sama.
///
/// winner = argmin(Poseidon2(batch_root ∥ node_id))
/// Deterministik — setiap node menghitung sendiri tanpa koordinasi.
pub fn select_winner(announcements: &[BatchAnnouncement]) -> Option<&BatchAnnouncement> {
    announcements.iter().min_by_key(|ann| tiebreak_score(ann))
}

// ── Fairness slot (§B.4.3) ───────────────────────────────────────────

/// Cek apakah batch ke-`batch_number` adalah fairness slot.
///
/// Fairness slot: setiap N batch, aggregator WAJIB menyertakan
/// ≥1 tx dengan score terendah (censorship resistance).
///
/// batch_number dimulai dari 1.
pub fn is_fairness_slot(batch_number: u32, fairness_n: u32) -> bool {
    fairness_n > 0 && batch_number % fairness_n == 0
}

/// Untuk fairness slot: kembalikan tx dengan score terendah dari pool.
/// Tx ini WAJIB disertakan dalam batch.
pub fn fairness_tx<'a>(tx_pool: &'a [TxForBatch]) -> Option<&'a TxForBatch> {
    tx_pool.iter().min_by_key(|tx| compute_score_fp(tx))
}

// ── Timeout computation ───────────────────────────────────────────────

/// Estimasi timeout batch dalam detik.
///
/// T_timeout = prove_time_estimasi × multiplier
/// prove_time_estimasi = batch_size × complexity_avg_ms / 1000
///
/// Untuk implementasi produksi: K_hardware_ref dari genesis benchmark.
/// Di sini menggunakan estimasi sederhana per tx.
pub fn compute_batch_timeout_secs(
    batch_size:          u32,
    prove_time_per_tx_ms: u64,
    multiplier:          u32,
) -> u64 {
    let prove_time_secs = (batch_size as u64 * prove_time_per_tx_ms)
        .saturating_add(999) / 1000; // ceiling division
    prove_time_secs.saturating_mul(multiplier as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(id_byte: u8, premium: u64, inputs: u32, outputs: u32) -> TxForBatch {
        let mut tx_id = [0u8; 32]; tx_id[0] = id_byte;
        TxForBatch {
            tx_id,
            premium,
            num_inputs:  inputs,
            num_outputs: outputs,
            fee_total:   40 + premium,
        }
    }

    fn ann(batch_byte: u8, node_byte: u8) -> BatchAnnouncement {
        let mut batch_root = [0u8; 32]; batch_root[0] = batch_byte;
        let mut node_id    = [0u8; 32]; node_id[0]    = node_byte;
        BatchAnnouncement { batch_root, node_id, timestamp: 0 }
    }

    // ── Score ─────────────────────────────────────────────────────────

    #[test]
    fn test_score_zero_premium() {
        // PREMIUM=0 → score=0
        assert_eq!(compute_score_fp(&tx(1, 0, 2, 2)), 0);
    }

    #[test]
    fn test_score_higher_premium_higher_score() {
        let s_low  = compute_score_fp(&tx(1, 100, 2, 2));
        let s_high = compute_score_fp(&tx(2, 500, 2, 2));
        assert!(s_high > s_low);
    }

    #[test]
    fn test_score_complex_tx_lower_score_same_premium() {
        // Tx kompleks (10in/10out) vs sederhana (1in/1out), premium sama
        let s_simple  = compute_score_fp(&tx(1, 100, 1, 1));
        let s_complex = compute_score_fp(&tx(2, 100, 10, 10));
        assert!(s_simple > s_complex,
            "Tx sederhana harus punya score lebih tinggi untuk premium yang sama");
    }

    #[test]
    fn test_sort_batch_by_score_descending() {
        let mut batch = vec![
            tx(1, 50, 2, 2),
            tx(2, 200, 2, 2),
            tx(3, 10, 2, 2),
        ];
        sort_batch_by_score(&mut batch);
        // Urutan: premium 200, 50, 10 (score tertinggi di depan)
        assert_eq!(batch[0].premium, 200);
        assert_eq!(batch[1].premium, 50);
        assert_eq!(batch[2].premium, 10);
    }

    #[test]
    fn test_batch_value_sum() {
        let batch = vec![tx(1, 60, 2, 2), tx(2, 100, 2, 2)];
        // fee_total masing-masing: 40+60=100, 40+100=140. Sum=240
        assert_eq!(compute_batch_value(&batch), 240);
    }

    // ── Tie-breaking ──────────────────────────────────────────────────

    #[test]
    fn test_tiebreak_deterministic() {
        let a1 = ann(1, 10);
        let a2 = ann(1, 10);
        assert_eq!(tiebreak_score(&a1), tiebreak_score(&a2));
    }

    #[test]
    fn test_tiebreak_different_nodes() {
        // Node berbeda dengan batch_root sama → score berbeda
        let a1 = ann(1, 10);
        let a2 = ann(1, 20);
        assert_ne!(tiebreak_score(&a1), tiebreak_score(&a2));
    }

    #[test]
    fn test_select_winner_picks_min_score() {
        let announcements = vec![ann(5, 1), ann(5, 2), ann(5, 3)];
        let winner = select_winner(&announcements).unwrap();
        // Winner adalah yang punya tiebreak_score terendah
        let min_score = announcements.iter().map(tiebreak_score).min().unwrap();
        assert_eq!(tiebreak_score(winner), min_score);
    }

    #[test]
    fn test_select_winner_empty() {
        assert!(select_winner(&[]).is_none());
    }

    // ── Fairness slot ─────────────────────────────────────────────────

    #[test]
    fn test_fairness_slot_every_n() {
        // N=10: batch 10, 20, 30 adalah fairness slot
        assert!( is_fairness_slot(10, 10));
        assert!( is_fairness_slot(20, 10));
        assert!(!is_fairness_slot(11, 10));
        assert!(!is_fairness_slot(9,  10));
    }

    #[test]
    fn test_fairness_slot_n_zero_never() {
        // N=0: tidak pernah fairness slot (guard div-by-zero)
        assert!(!is_fairness_slot(10, 0));
    }

    #[test]
    fn test_fairness_tx_picks_lowest_score() {
        let pool = vec![
            tx(1, 500, 2, 2),
            tx(2, 10,  2, 2), // score terendah
            tx(3, 200, 2, 2),
        ];
        let fairness = fairness_tx(&pool).unwrap();
        assert_eq!(fairness.premium, 10, "Fairness tx harus yang score terendah");
    }

    #[test]
    fn test_fairness_tx_zero_premium_lowest() {
        let pool = vec![tx(1, 100, 2, 2), tx(2, 0, 2, 2), tx(3, 50, 2, 2)];
        let fairness = fairness_tx(&pool).unwrap();
        assert_eq!(fairness.premium, 0);
    }

    // ── Timeout ───────────────────────────────────────────────────────

    #[test]
    fn test_timeout_computation() {
        // 10 tx, 1000ms/tx, multiplier 3 → prove=10s, timeout=30s
        let t = compute_batch_timeout_secs(10, 1000, 3);
        assert_eq!(t, 30);
    }

    #[test]
    fn test_timeout_ceiling_division() {
        // 1 tx, 500ms, multiplier 3 → prove=1s (ceiling), timeout=3s
        let t = compute_batch_timeout_secs(1, 500, 3);
        assert_eq!(t, 3);
    }
}
