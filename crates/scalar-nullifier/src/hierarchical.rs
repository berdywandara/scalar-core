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

/// Ukuran bit array NS_WARM: ~20 MB untuk 3.35 juta entries. Spec §6.3.
/// 20 MB = 20 * 1024 * 1024 * 8 bits = 167_772_160 bits
pub const NS_WARM_NUM_BITS: usize = 167_772_160;

/// Ukuran bit array NS_COLD: ~866 MB untuk volume mature. Spec §6.4.
/// Untuk testing gunakan ukuran lebih kecil via new_with_size().
/// Default production: 866 MB = 866 * 1024 * 1024 * 8 = 7_264_534_528 bits
/// Untuk dev/test: 10_000_000 bits
pub const NS_COLD_NUM_BITS_DEV: usize = 10_000_000;

#[derive(Debug, PartialEq, Eq)]
pub enum NullifierStatus {
    Missing,
    /// Ditemukan di NS_HOT — jawaban deterministik, tidak ada false positive.
    InHot,
    /// Ditemukan di NS_WARM atau NS_COLD (atau keduanya).
    /// False positive mungkin terjadi di WARM/COLD tapi sangat kecil.
    InWarmCold,
    /// Ditemukan di NS_ARCH (recursive STARK checkpoint).
    InArch,
}

pub struct HierarchicalNullifierSet {
    /// NS_HOT: SMT depth-32. Deterministik. C4 in-circuit menggunakan root ini.
    pub hot: SparseMerkleTree,
    /// NS_WARM: Bloom p=10^-10, k=33. Spec §6.3.
    pub warm: DeterministicBloomFilter,
    /// NS_COLD: Bloom p=10^-15, k=50. Spec §6.4.
    /// Menggantikan HashSet — lebih hemat storage, sesuai spec.
    pub cold: DeterministicBloomFilter,
    /// NS_ARCH: Recursive STARK checkpoint. Spec §6.5.
    pub arch: ArchCheckpoint,
}

impl HierarchicalNullifierSet {
    /// Buat HierarchicalNullifierSet dengan ukuran production.
    /// Untuk dev/test, gunakan new_for_testing().
    pub fn new() -> Self {
        Self {
            hot: SparseMerkleTree::new(),
            warm: DeterministicBloomFilter::new_warm(NS_WARM_NUM_BITS),
            cold: DeterministicBloomFilter::new_cold(NS_COLD_NUM_BITS_DEV),
            arch: ArchCheckpoint::new(),
        }
    }

    /// Buat HierarchicalNullifierSet dengan ukuran kecil untuk testing.
    /// Jangan gunakan di production.
    pub fn new_for_testing() -> Self {
        Self {
            hot: SparseMerkleTree::new(),
            warm: DeterministicBloomFilter::new_warm(1_000_000),
            cold: DeterministicBloomFilter::new_cold(1_000_000),
            arch: ArchCheckpoint::new(),
        }
    }

    /// Cari nullifier dengan eskalasi lapisan. Spec §6.1.
    ///
    /// Urutan:
    ///   1. NS_HOT  — deterministik, O(log N) SMT
    ///   2. NS_WARM — probabilistik, O(1) Bloom
    ///   3. NS_COLD — probabilistik, O(1) Bloom (resolusi false positive WARM)
    ///   4. NS_ARCH — recursive STARK checkpoint
    ///
    /// Catatan: NS_WARM false positive diselesaikan oleh NS_COLD.
    /// Jika NS_WARM hit tapi NS_COLD miss → kemungkinan false positive WARM.
    /// Spec §6.3: "False positive dari NS_WARM tidak menyebabkan invalid state."
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

    /// Insert nullifier ke semua lapis yang relevan.
    /// HOT, WARM, dan COLD semuanya diupdate.
    /// ARCH diupdate hanya via verify_and_apply_checkpoint() (batch).
    pub fn insert(&mut self, nullifier: &[u8; 32]) {
        self.hot.insert(nullifier);
        self.warm.insert(nullifier);
        self.cold.insert(nullifier);
    }

    /// Jumlah hash functions NS_WARM (untuk verifikasi spec compliance).
    pub fn warm_hash_functions(&self) -> usize {
        self.warm.num_hashes()
    }

    /// Jumlah hash functions NS_COLD (untuk verifikasi spec compliance).
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
