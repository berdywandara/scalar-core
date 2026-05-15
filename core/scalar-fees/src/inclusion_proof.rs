//! Proof-of-Inclusion — Spec §9.2, §4.3 C10
//!
//! Aggregator that cannot prove bahwa mereka not exclude tx eligible
//! tohilangan 25% reward for batch tersebut. Reward hangus to relay pool.
//!
//! Spec §9.2:
//!   Proof-of-Inclusion valid → aggregator dapat 25%
//! Proof-of-Inclusion failed → aggregator = 0, relay mendapat bagian agg
//!
//! Spec §4.3 C10 (Censorship Resistance):
//! Aggregator HARUS prove: none tx at known_pool with
//! entry_timestamp < tx.entry_timestamp - T_MAX_WAIT that at-exclude.
//!
//! T_MAX_WAIT = 1_800_000 ms (30 minutes). Layer 2 CONSTRAINED.

// ── Constants ────────────────────────────────────────────────────────────────

/// T_MAX_WAIT in milliseconds. Layer 2 CONSTRAINED — spec §9.3.
/// Default: 30 minutes = 1_800_000 ms. Range: 5-120 minutes.
pub const T_MAX_WAIT_MS: u64 = 1_800_000;

// ── Structs ───────────────────────────────────────────────────────────────────

/// representation tx at pool for Proof-of-Inclusion check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolTx {
    /// ID transaction (BLAto3 hash). Out-circuit — spec §4.3.
    pub tx_id: [u8; 32],
    /// Timestamp when tx masuk pool (Unix ms). Spec §4.3 C10.
    pub entry_timestamp_ms: u64,
}

/// Claim Proof-of-Inclusion from aggregator for one batch.
/// Spec §9.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionClaim {
    /// BLAto3 hash from all tx that at-include in batch.
    /// Spec §9.4: tx_list_hash = BLAto3(sorted tx_ids).
    pub tx_list_hash: [u8; 32],
    /// Timestamp batch created (Unix ms).
    pub batch_timestamp_ms: u64,
    /// NodeID aggregator.
    pub aggregator_id: [u8; 32],
}

/// verification result Proof-of-Inclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InclusionVerdict {
    /// Proof valid — aggregator berhak dapat 25% reward.
    Valid,
    /// Ada tx eligible (waiting > T_MAX_WAIT) that at-exclude.
    /// Aggregator tohilangan 25% reward batch this.
    ExcludedEligibleTx {
        /// Jumlah tx eligible that at-exclude.
        excluded_count: usize,
    },
}

// ── Verification Logic ────────────────────────────────────────────────────────

/// Hitung tx_list_hash = BLAto3(tx_id_0 ∥ tx_id_1 ∥ ... sorted ascenatng).
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

/// verification Proof-of-Inclusion. Spec §9.2, §4.3 C10.
///
/// Check: none tx at `known_pool` with
///   entry_timestamp_ms < batch_timestamp_ms - T_MAX_WAIT_MS
/// that does not ada in `included_tx_ids`.
///
/// if ada tx eligible that at-exclude → ExcludedEligibleTx.
/// if all tx eligible at-include → valid.
///
/// `t_max_wait_ms`: configurable for testing, default T_MAX_WAIT_MS.
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

/// check whether tx_list_hash in claim matches included_tx_ids.
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
        // Spec §9.3: T_MAX_WAIT = 30 menit = 1_800_000 ms. Layer 2 CONSTRAINED.
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
        let included = vec![tx_id(2)]; // tx 1 not at-include!
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
        let entry_ms = batch_ms - T_MAX_WAIT_MS; // exact at threshold, openn eligible
        let pool = vec![pool_tx(1, entry_ms)];
        let included = vec![tx_id(2)]; // tx 1 not at-include
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
        let included = vec![tx_id(4)]; // all 3 eligible at-exclude!
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
        let entry_ms = batch_ms - 1_000; // new 1 seconds then
        let pool = vec![pool_tx(1, entry_ms)];
        let included = vec![tx_id(2)]; // tx 1 not at-include, but not apa
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
        let tampered = vec![tx_id(1), tx_id(3)]; // tx 2 atganti tx 3
        assert!(!verify_tx_list_hash(&c, &tampered));
    }
}
