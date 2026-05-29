//! Proof-of-Inclusion — Spec §9.2, §4.3 C10
//!
//! Aggregator yang tidak bisa prove bahwa mereka tidak exclude tx eligible
//! kehilangan 25% reward untuk batch tersebut. Reward hangus ke relay pool.
//!
//! Spec §9.2:
//!   Proof-of-Inclusion valid → aggregator dapat 25%
//!   Proof-of-Inclusion gagal → aggregator = 0, relay mendapat bagian agg
//!
//! Spec §4.3 C10 (Censorship Resistance):
//!   Aggregator HARUS prove: tidak ada tx di known_pool dengan
//!   entry_timestamp < tx.entry_timestamp - T_MAX_WAIT yang di-exclude.
//!
//! T_MAX_WAIT = 1_800_000 ms (30 menit). Layer 2 CONSTRAINED.

// ── Constants ────────────────────────────────────────────────────────────────

/// T_MAX_WAIT dalam milliseconds. CONSTRAINED — D-026, MAD §21.2.
/// Anti-stale constraint: tx ditolak jika entry_timestamp terlalu lama.
/// Default: 30 menit = 1_800_000 ms. Range: 5-120 menit.
pub const T_MAX_WAIT_MS: u64 = 1_800_000;

// ── Structs ───────────────────────────────────────────────────────────────────

/// Representasi tx di pool untuk Proof-of-Inclusion check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolTx {
    /// ID transaksi (BLAKE3 hash). Out-circuit — spec §4.3.
    pub tx_id: [u8; 32],
    /// Timestamp saat tx masuk pool (Unix ms). Spec §4.3 C10.
    pub entry_timestamp_ms: u64,
}

/// Claim Proof-of-Inclusion dari aggregator untuk satu batch.
/// Spec §9.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionClaim {
    /// BLAKE3 hash dari semua tx yang di-include dalam batch.
    /// Spec §9.4: tx_list_hash = BLAKE3(sorted tx_ids).
    pub tx_list_hash: [u8; 32],
    /// Timestamp batch dibuat (Unix ms).
    pub batch_timestamp_ms: u64,
    /// NodeID aggregator.
    pub aggregator_id: [u8; 32],
}

/// Hasil verifikasi Proof-of-Inclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InclusionVerdict {
    /// Proof valid — aggregator berhak dapat 25% reward.
    Valid,
    /// Ada tx eligible (waiting > T_MAX_WAIT) yang di-exclude.
    /// Aggregator kehilangan 25% reward batch ini.
    ExcludedEligibleTx {
        /// Jumlah tx eligible yang di-exclude.
        excluded_count: usize,
    },
}

// ── Verification Logic ────────────────────────────────────────────────────────

/// Hitung tx_list_hash = BLAKE3(tx_id_0 ∥ tx_id_1 ∥ ... sorted ascending).
/// Spec §9.4.
pub fn compute_tx_list_hash(included_tx_ids: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted = included_tx_ids.to_vec();
    sorted.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    for tx_id in &sorted {
        hasher.update(tx_id);
    }
    *hasher.finalize().as_bytes()
}

/// Verifikasi Proof-of-Inclusion. Spec §9.2, §4.3 C10.
///
/// Check: tidak ada tx di `known_pool` dengan
///   entry_timestamp_ms < batch_timestamp_ms - T_MAX_WAIT_MS
/// yang tidak ada dalam `included_tx_ids`.
///
/// Jika ada tx eligible yang di-exclude → ExcludedEligibleTx.
/// Jika semua tx eligible di-include → Valid.
///
/// `t_max_wait_ms`: configurable untuk testing, default T_MAX_WAIT_MS.
pub fn verify_inclusion(
    claim: &InclusionClaim,
    known_pool: &[PoolTx],
    included_tx_ids: &[[u8; 32]],
    t_max_wait_ms: u64,
) -> InclusionVerdict {
    // Threshold: tx yang sudah menunggu lebih dari T_MAX_WAIT wajib di-include
    let threshold = claim.batch_timestamp_ms.saturating_sub(t_max_wait_ms);

    // Kumpulkan tx eligible: entry_timestamp < threshold
    let eligible: Vec<&PoolTx> = known_pool
        .iter()
        .filter(|tx| tx.entry_timestamp_ms < threshold)
        .collect();

    // Cek apakah semua eligible tx ada dalam included_tx_ids
    let excluded_count = eligible
        .iter()
        .filter(|tx| !included_tx_ids.contains(&tx.tx_id))
        .count();

    if excluded_count > 0 {
        InclusionVerdict::ExcludedEligibleTx { excluded_count }
    } else {
        InclusionVerdict::Valid
    }
}

/// Cek apakah tx_list_hash dalam claim cocok dengan included_tx_ids.
/// Spec §9.4.
pub fn verify_tx_list_hash(claim: &InclusionClaim, included_tx_ids: &[[u8; 32]]) -> bool {
    compute_tx_list_hash(included_tx_ids) == claim.tx_list_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx_id(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    fn pool_tx(b: u8, entry_ms: u64) -> PoolTx {
        PoolTx {
            tx_id: tx_id(b),
            entry_timestamp_ms: entry_ms,
        }
    }

    fn claim(batch_ms: u64, included: &[[u8; 32]]) -> InclusionClaim {
        InclusionClaim {
            tx_list_hash: compute_tx_list_hash(included),
            batch_timestamp_ms: batch_ms,
            aggregator_id: [0u8; 32],
        }
    }

    // ── T_MAX_WAIT constant ───────────────────────────────────────────────────

    #[test]
    fn test_t_max_wait_is_30_minutes() {
        // D-026: T_MAX_WAIT = 30 menit = 1_800_000 ms. CONSTRAINED (not OSSIFIED).
        assert_eq!(T_MAX_WAIT_MS, 1_800_000u64);
    }

    // ── verify_inclusion ─────────────────────────────────────────────────────

    #[test]
    fn test_no_eligible_tx_is_valid() {
        // Tidak ada tx di pool → valid
        let c = claim(10_000_000, &[tx_id(1)]);
        let verdict = verify_inclusion(&c, &[], &[tx_id(1)], T_MAX_WAIT_MS);
        assert_eq!(verdict, InclusionVerdict::Valid);
    }

    #[test]
    fn test_eligible_tx_included_is_valid() {
        // Tx eligible (waiting > T_MAX_WAIT) dan di-include → Valid
        let batch_ms = 10_000_000u64;
        let entry_ms = batch_ms - T_MAX_WAIT_MS - 1; // eligible
        let pool = vec![pool_tx(1, entry_ms)];
        let included = vec![tx_id(1)];
        let c = claim(batch_ms, &included);
        let verdict = verify_inclusion(&c, &pool, &included, T_MAX_WAIT_MS);
        assert_eq!(verdict, InclusionVerdict::Valid);
    }

    #[test]
    fn test_eligible_tx_excluded_fails() {
        // Tx eligible tapi tidak di-include → ExcludedEligibleTx
        let batch_ms = 10_000_000u64;
        let entry_ms = batch_ms - T_MAX_WAIT_MS - 1; // eligible
        let pool = vec![pool_tx(1, entry_ms)];
        let included = vec![tx_id(2)]; // tx 1 tidak di-include!
        let c = claim(batch_ms, &included);
        let verdict = verify_inclusion(&c, &pool, &included, T_MAX_WAIT_MS);
        assert_eq!(
            verdict,
            InclusionVerdict::ExcludedEligibleTx { excluded_count: 1 }
        );
    }

    #[test]
    fn test_tx_exactly_at_threshold_not_eligible() {
        // entry_timestamp == batch_ms - T_MAX_WAIT → TIDAK eligible (strict <)
        let batch_ms = 10_000_000u64;
        let entry_ms = batch_ms - T_MAX_WAIT_MS; // tepat di threshold, bukan eligible
        let pool = vec![pool_tx(1, entry_ms)];
        let included = vec![tx_id(2)]; // tx 1 tidak di-include
        let c = claim(batch_ms, &included);
        let verdict = verify_inclusion(&c, &pool, &included, T_MAX_WAIT_MS);
        // Tx di threshold TIDAK eligible → Valid
        assert_eq!(verdict, InclusionVerdict::Valid);
    }

    #[test]
    fn test_multiple_excluded_eligible_tx() {
        let batch_ms = 10_000_000u64;
        let entry_ms = batch_ms - T_MAX_WAIT_MS - 500;
        let pool = vec![
            pool_tx(1, entry_ms),
            pool_tx(2, entry_ms),
            pool_tx(3, entry_ms),
        ];
        let included = vec![tx_id(4)]; // semua 3 eligible di-exclude!
        let c = claim(batch_ms, &included);
        let verdict = verify_inclusion(&c, &pool, &included, T_MAX_WAIT_MS);
        assert_eq!(
            verdict,
            InclusionVerdict::ExcludedEligibleTx { excluded_count: 3 }
        );
    }

    #[test]
    fn test_recent_tx_not_eligible() {
        // Tx baru (entry < T_MAX_WAIT yang lalu) tidak eligible — boleh di-exclude
        let batch_ms = 10_000_000u64;
        let entry_ms = batch_ms - 1_000; // baru 1 detik lalu
        let pool = vec![pool_tx(1, entry_ms)];
        let included = vec![tx_id(2)]; // tx 1 tidak di-include, tapi tidak apa
        let c = claim(batch_ms, &included);
        let verdict = verify_inclusion(&c, &pool, &included, T_MAX_WAIT_MS);
        assert_eq!(verdict, InclusionVerdict::Valid);
    }

    // ── tx_list_hash ─────────────────────────────────────────────────────────

    #[test]
    fn test_tx_list_hash_deterministic() {
        let ids = vec![tx_id(1), tx_id(2), tx_id(3)];
        let h1 = compute_tx_list_hash(&ids);
        let h2 = compute_tx_list_hash(&ids);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_tx_list_hash_order_independent() {
        // Sort sebelum hash → urutan input tidak mempengaruhi hasil
        let ids1 = vec![tx_id(1), tx_id(2), tx_id(3)];
        let ids2 = vec![tx_id(3), tx_id(1), tx_id(2)];
        assert_eq!(compute_tx_list_hash(&ids1), compute_tx_list_hash(&ids2));
    }

    #[test]
    fn test_verify_tx_list_hash_valid() {
        let included = vec![tx_id(1), tx_id(2)];
        let c = claim(10_000_000, &included);
        assert!(verify_tx_list_hash(&c, &included));
    }

    #[test]
    fn test_verify_tx_list_hash_tampered() {
        let included = vec![tx_id(1), tx_id(2)];
        let c = claim(10_000_000, &included);
        let tampered = vec![tx_id(1), tx_id(3)]; // tx 2 diganti tx 3
        assert!(!verify_tx_list_hash(&c, &tampered));
    }
}
