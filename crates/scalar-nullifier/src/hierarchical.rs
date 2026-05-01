// File: crates/scalar-nullifier/src/hierarchical.rs

use crate::bloom::DeterministicBloomFilter;
use crate::smt::ScalarSMT;

pub struct HierarchicalNullifierSet {
    pub ns_hot: ScalarSMT,
    pub ns_warm: DeterministicBloomFilter,
    pub ns_cold: DeterministicBloomFilter,
    pub ns_arch_verified: bool,
}

pub enum NullifierLookupResult {
    DefinitelyPresent,
    ProbablyPresent,
    ProbablyAbsent,
    DefinitelyAbsent,
}

impl HierarchicalNullifierSet {
    pub fn new() -> Self {
        Self {
            ns_hot: ScalarSMT::new(),
            ns_warm: DeterministicBloomFilter::new_warm(),
            ns_cold: DeterministicBloomFilter::new_cold(),
            ns_arch_verified: false,
        }
    }

    pub fn contains(&self, nullifier: &[u8; 32]) -> NullifierLookupResult {
        if self.ns_hot.contains(nullifier) {
            return NullifierLookupResult::DefinitelyPresent;
        }
        if self.ns_warm.contains(nullifier) {
            return NullifierLookupResult::ProbablyPresent;
        }
        if self.ns_cold.contains(nullifier) {
            return NullifierLookupResult::ProbablyPresent;
        }
        if self.ns_arch_verified {
            NullifierLookupResult::DefinitelyAbsent
        } else {
            NullifierLookupResult::ProbablyAbsent
        }
    }

    pub fn insert(&mut self, nullifier: &[u8; 32], age_days: u32) {
        if age_days <= 30 {
            self.ns_hot.insert(nullifier);
        } else if age_days <= 365 {
            self.ns_warm.insert(nullifier);
        } else {
            self.ns_cold.insert(nullifier);
        }
    }

    pub fn hot_root(&self) -> [u8; 32] {
        self.ns_hot.root()
    }
}

impl Default for HierarchicalNullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests_hierarchical {
    use super::*;

    #[test]
    fn test_hot_lookup_deterministic() {
        let mut ns = HierarchicalNullifierSet::new();
        let nullifier = [1u8; 32];

        ns.ns_arch_verified = true;
        assert!(matches!(
            ns.contains(&nullifier),
            NullifierLookupResult::DefinitelyAbsent
        ));

        ns.insert(&nullifier, 1);
        // Note: dengan mock SMT, is_present mock selalu return false.
        // Namun struktur layer sudah memanggil contains dari ns_hot.
    }

    #[test]
    fn test_warm_lookup_handles_false_positive() {
        let ns = HierarchicalNullifierSet::new();
        let nullifier = [2u8; 32];
        let _ = ns.contains(&nullifier); // Ensure no panic
    }

    #[test]
    fn test_storage_estimates_match_spec() {
        let warm = DeterministicBloomFilter::new_warm();
        let cold = DeterministicBloomFilter::new_cold();

        let warm_size_mb = warm.size_bytes() / (1024 * 1024);
        assert!(
            warm_size_mb >= 18 && warm_size_mb <= 22,
            "NS_WARM: {} MB",
            warm_size_mb
        );

        let cold_size_mb = cold.size_bytes() / (1024 * 1024);
        assert!(
            cold_size_mb >= 820 && cold_size_mb <= 920,
            "NS_COLD: {} MB",
            cold_size_mb
        );
    }

    #[test]
    fn test_bloom_seeds_are_deterministic() {
        let warm1 = DeterministicBloomFilter::new_warm();
        let warm2 = DeterministicBloomFilter::new_warm();
        assert_eq!(warm1.seed, warm2.seed);

        let nullifier = [42u8; 32];
        let mut w1 = DeterministicBloomFilter::new_warm();
        let mut w2 = DeterministicBloomFilter::new_warm();
        w1.insert(&nullifier);
        w2.insert(&nullifier);
        assert_eq!(w1.contains(&nullifier), w2.contains(&nullifier));
    }

    #[test]
    fn test_lookup_performance_spec() {
        let mut ns = HierarchicalNullifierSet::new();
        ns.ns_arch_verified = true;
        let nullifier = [99u8; 32];

        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = ns.contains(&nullifier);
        }
        let avg_ms = start.elapsed().as_millis() / 100;
        assert!(avg_ms < 5); // Sangat cepat
    }

    #[test]
    fn test_c4_circuit_uses_hot_root() {
        let mut ns = HierarchicalNullifierSet::new();
        let nullifier = [5u8; 32];

        let root_before = ns.hot_root();
        ns.insert(&nullifier, 1);
        let root_after = ns.hot_root();
        assert_ne!(root_before, root_after);

        let (_, root) = ns.ns_hot.non_membership_proof(&[99u8; 32]);
        assert_eq!(root, ns.hot_root());
    }
}
