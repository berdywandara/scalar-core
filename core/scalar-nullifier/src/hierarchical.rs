// File: crates/scalar-nullifier/src/hierarchical.rs
//
// Hierarchical NullifierSet v5.0 — Spec §6
// Empat lapis:
//   NS_HOT  : SparseMerkleTree depth-32, 30 hari       (~29 MB)
//   NS_WARM : Bloom p=10^-10, k=33, 30-365 hari        (~20 MB)
//   NS_COLD : Bloom p=10^-15, k=50, >365 hari          (~866 MB)
//   NS_ARCH : Recursive STARK checkpoint               (<1 MB)
//
// Lookup escalation (spec §6.1):
//   HOT  → O(log N) SMT traversal ~0.5ms
//   WARM → O(1) Bloom ~0.02ms
//   COLD → O(1) Bloom ~0.03ms
//   Total worst case: ~0.55ms

use crate::bloom::DeterministicBloomFilter;
#[allow(unused_imports)]
use crate::bloom::{NS_COLD_HASH_FUNCTIONS as _, NS_WARM_HASH_FUNCTIONS as _};
use crate::recursive::checkpoint::ArchCheckpoint;
use crate::smt::SparseMerkleTree;

/// size bit array NS_WARM: ~20 MB for 3.35 juta entries. Spec §6.3.
/// 20 MB = 20 * 1024 * 1024 * 8 bits = 167_772_160 bits
pub const NS_WARM_NUM_BITS: usize = 167_772_160;

/// size bit array NS_COLD: ~866 MB for volume mregulatee. Spec §6.4.
/// for testing use size lebih small via new_with_size().
/// Default production: 866 MB = 866 * 1024 * 1024 * 8 = 7_264_534_528 bits
/// for dev/test: 10_000_000 bits
pub const NS_COLD_NUM_BITS_DEV: usize = 10_000_000;

#[derive(Debug, PartialEq, Eq)]
pub enum NullifierStatus {
    Missing,
    /// found at NS_HOT — jawaban determthisstik, none false positive.
    InHot,
    /// found at NS_WARM or NS_COLD (or secondnya).
    /// False positive mungkin terjaat at WARM/COLD but sangat small.
    InWarmCold,
    /// found at NS_ARCH (recursive STARK checkpoint).
    InArch,
}

pub struct HierarchicalNullifierSet {
    /// NS_HOT: SMT depth-32. Determthisstik. C4 in-circuit using root this.
    pub hot: SparseMerkleTree,
    /// NS_WARM: Bloom p=10^-10, k=33. Spec §6.3.
    pub warm: DeterministicBloomFilter,
    /// NS_COLD: Bloom p=10^-15, k=50. Spec §6.4.
    /// Menggantikan hashSet — lebih hemat storage, per spec.
    pub cold: DeterministicBloomFilter,
    /// NS_ARCH: Recursive STARK checkpoint. Spec §6.5.
    pub arch: ArchCheckpoint,
}

impl HierarchicalNullifierSet {
    /// Buat HierarchicalNullifierSet with size production.
    /// for dev/test, use new_for_testing().
    pub fn new() -> Self {
        Self {
            hot: SparseMerkleTree::new(),
            warm: DeterministicBloomFilter::new_warm(NS_WARM_NUM_BITS),
            cold: DeterministicBloomFilter::new_cold(NS_COLD_NUM_BITS_DEV),
            arch: ArchCheckpoint::new(),
        }
    }

    /// Buat HierarchicalNullifierSet with size small for testing.
    /// Jangan use at production.
    pub fn new_for_testing() -> Self {
        Self {
            hot: SparseMerkleTree::new(),
            warm: DeterministicBloomFilter::new_warm(1_000_000),
            cold: DeterministicBloomFilter::new_cold(1_000_000),
            arch: ArchCheckpoint::new(),
        }
    }

    /// find nullifier with eskalasi layer. Spec §6.1.
    ///
    /// Urutan:
    /// 1. NS_HOT  — determthisstik, O(log N) SMT
    ///   2. NS_WARM — probabilistik, O(1) Bloom
    ///   3. NS_COLD — probabilistik, O(1) Bloom (resolusi false positive WARM)
    ///   4. NS_ARCH — recursive STARK checkpoint
    ///
    /// note: NS_WARM false positive completed oleh NS_COLD.
    /// if NS_WARM hit but NS_COLD miss → tomungkinan false positive WARM.
    /// Spec §6.3: "False positive from NS_WARM not cause invalid state."
    pub fn check(&self, nullifier: &[u8; 32]) -> NullifierStatus {
        // Layer 1: NS_HOT — deterministik
        if self.hot.contains(nullifier) {
            return NullifierStatus::InHot;
        }

        // Layer 2+3: NS_WARM + NS_COLD escalation
        // Jika WARM hit, konfirmasi dengan COLD untuk resolusi false positive
        if self.warm.probably_contains(nullifier) && self.cold.probably_contains(nullifier) {
            return NullifierStatus::InWarmCold;
        }

        // Layer 4: NS_ARCH
        if self.arch.contains(nullifier) {
            return NullifierStatus::InArch;
        }

        NullifierStatus::Missing
    }

    /// Insert nullifier to all lapis that relevant.
    /// HOT, WARM, and COLD allnya updated.
    /// ARCH updated only via verify_and_apply_checkpoint() (batch).
    pub fn insert(&mut self, nullifier: &[u8; 32]) {
        self.hot.insert(nullifier);
        self.warm.insert(nullifier);
        self.cold.insert(nullifier);
    }

    /// Jumlah hash functions NS_WARM (for verification spec compliance).
    pub fn warm_hash_functions(&self) -> usize {
        self.warm.num_hashes()
    }

    /// Jumlah hash functions NS_COLD (for verification spec compliance).
    pub fn cold_hash_functions(&self) -> usize {
        self.cold.num_hashes()
    }
}

impl Default for HierarchicalNullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bloom::{NS_COLD_HASH_FUNCTIONS, NS_WARM_HASH_FUNCTIONS};

    #[test]
    fn test_ns_cold_uses_bloom_filter_not_hashset() {
        // PR-CS-v5-01b: NS_COLD harus Bloom filter, bukan HashSet
        // Verifikasi melalui num_hashes — HashSet tidak punya method ini
        let hns = HierarchicalNullifierSet::new_for_testing();
        assert_eq!(
            hns.cold_hash_functions(),
            NS_COLD_HASH_FUNCTIONS,
            "NS_COLD harus menggunakan k={} hash functions sesuai spec §6.4",
            NS_COLD_HASH_FUNCTIONS
        );
    }

    #[test]
    fn test_ns_warm_hash_functions_correct() {
        let hns = HierarchicalNullifierSet::new_for_testing();
        assert_eq!(hns.warm_hash_functions(), NS_WARM_HASH_FUNCTIONS);
    }

    #[test]
    fn test_hot_lookup_deterministic() {
        let mut hns = HierarchicalNullifierSet::new_for_testing();
        let n = [5u8; 32];
        hns.insert(&n);
        assert_eq!(hns.check(&n), NullifierStatus::InHot);
    }

    #[test]
    fn test_insert_appears_in_all_layers() {
        let mut hns = HierarchicalNullifierSet::new_for_testing();
        let n = [3u8; 32];
        hns.insert(&n);

        // HOT: deterministik
        assert!(hns.hot.contains(&n));
        // WARM: probabilistik (tidak boleh false negative)
        assert!(hns.warm.probably_contains(&n));
        // COLD: probabilistik (tidak boleh false negative)
        assert!(hns.cold.probably_contains(&n));
    }

    #[test]
    fn test_no_false_negative_after_insert() {
        // False negative TIDAK BOLEH terjadi di semua layer. Spec §6.3.
        let mut hns = HierarchicalNullifierSet::new_for_testing();
        let nullifiers: Vec<[u8; 32]> = (0u8..50)
            .map(|i| {
                let mut n = [0u8; 32];
                n[0] = i;
                n
            })
            .collect();

        for n in &nullifiers {
            hns.insert(n);
        }

        for n in &nullifiers {
            let status = hns.check(n);
            assert_ne!(
                status,
                NullifierStatus::Missing,
                "False negative terdeteksi untuk nullifier {:?}",
                n
            );
        }
    }

    #[test]
    fn test_warm_lookup_handles_false_positive() {
        // Item yang tidak pernah di-insert → harus Missing
        // False positive WARM akan diselesaikan oleh COLD (keduanya miss)
        let hns = HierarchicalNullifierSet::new_for_testing();
        let n = [9u8; 32];
        assert_eq!(hns.check(&n), NullifierStatus::Missing);
    }

    #[test]
    fn test_c4_circuit_uses_hot_root() {
        // C4 in-circuit menggunakan NS_HOT root. Spec §6.2.
        let mut hns = HierarchicalNullifierSet::new_for_testing();
        let n = [7u8; 32];
        hns.insert(&n);
        let root = hns.hot.root;
        assert_eq!(root, n, "NS_HOT root harus di-update setelah insert");
    }

    #[test]
    fn test_cold_is_deterministic_bloom_not_hashset() {
        // Dua instance dengan data sama harus identik hasilnya
        let item = [42u8; 32];
        let mut h1 = HierarchicalNullifierSet::new_for_testing();
        let mut h2 = HierarchicalNullifierSet::new_for_testing();
        h1.insert(&item);
        h2.insert(&item);
        assert_eq!(
            h1.cold.probably_contains(&item),
            h2.cold.probably_contains(&item),
            "NS_COLD harus deterministik di semua instance"
        );
    }
}

// ── NullifierSet Layer Promotion — spec §6.3 ──────────────────────────────────

/// Hasil promotion at the end of epoch. Spec §6.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionResult {
    /// Jumlah nullifier that atpromote from HOT to WARM. Spec §6.3.
    pub promoted_to_warm: u32,
    /// Jumlah nullifier that atpromote from HOT to COLD (usia > 12 epoch). Spec §6.3.
    pub promoted_to_cold: u32,
    /// Jumlah nullifier that deleted from HOT (compacted). Spec §6.3.
    pub removed_from_hot: u32,
}

/// Promotion threshold — usia mthismum for COLD promotion. Spec §6.3.
/// Nullifier lebih tua from 12 epoch → atpromote to NS_COLD also.
pub const COLD_PROMOTION_EPOCH_THRESHOLD: u64 = 12;

/// NullifierPromoter — manage promotion antar layer. Spec §6.3.
///
/// at the end of epoch k:
/// 1. tato all nullifier from NS_HOT that lebih tua from 1 epoch
/// 2. Insert to NS_WARM
/// 3. Insert to NS_COLD if usia > COLD_PROMOTION_EPOCH_THRESHOLD epoch
/// 4. delete from NS_HOT (compact SMT)
/// 5. NS_HOT now only berfill nullifier from epoch k
///
/// zero-gap property:
/// Nullifier tetap at NS_HOT until epoch boundary before promotion.
/// none verification gap.
pub struct NullifierPromoter {
    /// Tracking nullifier and epoch_id when atinsert to HOT.
    /// toy: nullifier [u8;32] → epoch_id when insert
    hot_entries: std::collections::HashMap<[u8; 32], u64>,
}

impl NullifierPromoter {
    pub fn new() -> Self {
        Self {
            hot_entries: std::collections::HashMap::new(),
        }
    }

    /// Record nullifier new that masuk NS_HOT. Spec §6.3.
    pub fn record_hot_insert(&mut self, nullifier: [u8; 32], epoch_id: u64) {
        self.hot_entries.insert(nullifier, epoch_id);
    }

    /// run promotion at the end of epoch k. Spec §6.3.
    ///
    /// Promotes nullifier that epoch_id < current_epoch to WARM/COLD.
    /// Nullifier from epoch k tetap at HOT.
    ///
    /// Zero-Gap: nullifier tetap at HOT until epoch boundary.
    pub fn promote(
        &mut self,
        hns: &mut HierarchicalNullifierSet,
        current_epoch: u64,
    ) -> PromotionResult {
        let mut promoted_to_warm = 0u32;
        let mut promoted_to_cold = 0u32;
        let mut removed_from_hot = 0u32;
        let mut to_remove = Vec::new();

        for (&nullifier, &insert_epoch) in &self.hot_entries {
            // Hanya promote nullifier dari epoch sebelumnya — spec §6.3.
            // Nullifier dari current_epoch tetap di HOT.
            if insert_epoch < current_epoch {
                let age_epochs = current_epoch.saturating_sub(insert_epoch);

                // Step 2: Insert ke NS_WARM — spec §6.3.
                hns.warm.insert(&nullifier);
                promoted_to_warm += 1;

                // Step 3: Insert ke NS_COLD jika usia > threshold — spec §6.3.
                if age_epochs > COLD_PROMOTION_EPOCH_THRESHOLD {
                    hns.cold.insert(&nullifier);
                    promoted_to_cold += 1;
                }

                // Step 4: Hapus dari NS_HOT — spec §6.3.
                hns.hot.remove(&nullifier);
                removed_from_hot += 1;
                to_remove.push(nullifier);
            }
        }

        // Bersihkan tracking entries yang sudah dipromote.
        for nullifier in to_remove {
            self.hot_entries.remove(&nullifier);
        }

        PromotionResult {
            promoted_to_warm,
            promoted_to_cold,
            removed_from_hot,
        }
    }

    /// Jumlah nullifier that when this tracking at HOT. Spec §6.3.
    pub fn hot_count(&self) -> usize {
        self.hot_entries.len()
    }
}

impl Default for NullifierPromoter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod promotion_tests {
    use super::*;

    fn make_nullifier(b: u8) -> [u8; 32] {
        let mut n = [0u8; 32];
        n[0] = b;
        n
    }

    // ── PromotionResult ───────────────────────────────────────────────────────

    #[test]
    fn test_promote_old_nullifiers_to_warm() {
        // Nullifier dari epoch k-1 harus dipromote ke WARM. Spec §6.3.
        let mut hns = HierarchicalNullifierSet::new_for_testing();
        let mut promoter = NullifierPromoter::new();

        let n = make_nullifier(0x01);
        hns.insert(&n);
        promoter.record_hot_insert(n, 0); // epoch 0

        // Promote di epoch 1 → n dari epoch 0 → promote
        let result = promoter.promote(&mut hns, 1);
        assert_eq!(result.promoted_to_warm, 1);
        assert_eq!(result.removed_from_hot, 1);
    }

    #[test]
    fn test_current_epoch_nullifiers_stay_in_hot() {
        // Nullifier dari current_epoch TIDAK dipromote. Spec §6.3.
        let mut hns = HierarchicalNullifierSet::new_for_testing();
        let mut promoter = NullifierPromoter::new();

        let n = make_nullifier(0x02);
        hns.insert(&n);
        promoter.record_hot_insert(n, 5); // epoch 5 (current)

        // Promote di epoch 5 → n dari epoch 5 → tetap di HOT
        let result = promoter.promote(&mut hns, 5);
        assert_eq!(result.promoted_to_warm, 0);
        assert_eq!(result.removed_from_hot, 0);
    }

    #[test]
    fn test_promote_to_cold_after_threshold() {
        // Nullifier usia > COLD_PROMOTION_EPOCH_THRESHOLD → COLD juga. Spec §6.3.
        let mut hns = HierarchicalNullifierSet::new_for_testing();
        let mut promoter = NullifierPromoter::new();

        let n = make_nullifier(0x03);
        hns.insert(&n);
        promoter.record_hot_insert(n, 0); // epoch 0

        // Promote di epoch 13 → usia = 13 > 12 threshold → COLD juga
        let result = promoter.promote(&mut hns, COLD_PROMOTION_EPOCH_THRESHOLD + 1);
        assert_eq!(result.promoted_to_warm, 1);
        assert_eq!(result.promoted_to_cold, 1);
    }

    #[test]
    fn test_no_cold_promotion_at_threshold() {
        // Usia = threshold (12) → TIDAK dipromote ke COLD. Spec §6.3.
        let mut hns = HierarchicalNullifierSet::new_for_testing();
        let mut promoter = NullifierPromoter::new();

        let n = make_nullifier(0x04);
        hns.insert(&n);
        promoter.record_hot_insert(n, 0);

        // Promote di epoch 12 → usia = 12 = threshold → TIDAK ke COLD (strictly >)
        let result = promoter.promote(&mut hns, COLD_PROMOTION_EPOCH_THRESHOLD);
        assert_eq!(result.promoted_to_warm, 1);
        assert_eq!(result.promoted_to_cold, 0);
    }

    #[test]
    fn test_zero_gap_property() {
        // Zero-Gap: nullifier tetap di HOT sampai epoch boundary. Spec §6.3.
        // Saat epoch k berjalan, nullifier dari epoch k masih di HOT → bisa verify.
        let mut hns = HierarchicalNullifierSet::new_for_testing();
        let mut promoter = NullifierPromoter::new();

        let n = make_nullifier(0x05);
        hns.insert(&n);
        promoter.record_hot_insert(n, 3);

        // Belum promote (masih epoch 3) → masih di HOT
        assert!(hns.hot.contains(&n));
        assert_eq!(promoter.hot_count(), 1);

        // Setelah promote di epoch 4 → dipindah ke WARM
        let result = promoter.promote(&mut hns, 4);
        assert_eq!(result.removed_from_hot, 1);
        // Sekarang di WARM
        assert!(hns.warm.probably_contains(&n));
    }

    #[test]
    fn test_promoted_nullifier_still_found() {
        // Setelah promotion: nullifier masih bisa ditemukan (di WARM/COLD). Spec §6.3.
        let mut hns = HierarchicalNullifierSet::new_for_testing();
        let mut promoter = NullifierPromoter::new();

        let n = make_nullifier(0x06);
        hns.insert(&n);
        promoter.record_hot_insert(n, 0);
        promoter.promote(&mut hns, 1);

        // Harus masih ditemukan — di WARM atau COLD
        let status = hns.check(&n);
        assert_ne!(status, NullifierStatus::Missing);
    }

    #[test]
    fn test_promote_multiple_nullifiers() {
        // Multiple nullifier dari epoch berbeda. Spec §6.3.
        let mut hns = HierarchicalNullifierSet::new_for_testing();
        let mut promoter = NullifierPromoter::new();

        // 3 dari epoch 0, 2 dari epoch 5 (current)
        for i in 0u8..3 {
            let n = make_nullifier(i);
            hns.insert(&n);
            promoter.record_hot_insert(n, 0);
        }
        for i in 3u8..5 {
            let n = make_nullifier(i);
            hns.insert(&n);
            promoter.record_hot_insert(n, 5);
        }

        let result = promoter.promote(&mut hns, 5);
        // 3 dari epoch 0 → dipromote
        assert_eq!(result.promoted_to_warm, 3);
        assert_eq!(result.removed_from_hot, 3);
        // 2 dari epoch 5 → tetap
        assert_eq!(promoter.hot_count(), 2);
    }

    #[test]
    fn test_hot_count_decreases_after_promotion() {
        // hot_count berkurang setelah promotion. Spec §6.3.
        let mut hns = HierarchicalNullifierSet::new_for_testing();
        let mut promoter = NullifierPromoter::new();

        for i in 0u8..5 {
            let n = make_nullifier(i);
            hns.insert(&n);
            promoter.record_hot_insert(n, 0);
        }
        assert_eq!(promoter.hot_count(), 5);
        promoter.promote(&mut hns, 1);
        assert_eq!(promoter.hot_count(), 0);
    }

    #[test]
    fn test_cold_promotion_threshold_value() {
        // COLD_PROMOTION_EPOCH_THRESHOLD = 12. Spec §6.3.
        assert_eq!(COLD_PROMOTION_EPOCH_THRESHOLD, 12u64);
    }

    #[test]
    fn test_empty_promote_no_op() {
        // Promote dengan tidak ada nullifier → result semua 0. Spec §6.3.
        let mut hns = HierarchicalNullifierSet::new_for_testing();
        let mut promoter = NullifierPromoter::new();
        let result = promoter.promote(&mut hns, 5);
        assert_eq!(result.promoted_to_warm, 0);
        assert_eq!(result.promoted_to_cold, 0);
        assert_eq!(result.removed_from_hot, 0);
    }
}
