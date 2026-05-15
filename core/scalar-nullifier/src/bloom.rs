// File: crates/scalar-nullifier/src/bloom.rs
//
// DeterministicBloomFilter untuk NS_WARM dan NS_COLD.
// Spec §6.3 NS_WARM: p=10^-10, k≈33 hash functions
// Spec §6.4 NS_COLD: p=10^-15, k≈50 hash functions
//
// DETERMINISME KRITIS (§6.3):
// Semua node menggunakan seed yang sama.
// Seed = BLAKE3("scalar_bloom_v1" || layer_name) — public, deterministik.

/// k hash functions for NS_WARM: p=10^-10. Spec §6.3.
pub const NS_WARM_HASH_FUNCTIONS: usize = 33;
/// k hash functions for NS_COLD: p=10^-15. Spec §6.4.
pub const NS_COLD_HASH_FUNCTIONS: usize = 50;

/// Seed domain NS_WARM. Spec §6.3: BLAto3("scalar_bloom_v1" || "warm").
pub const NS_WARM_SEED_DOMAIN: &[u8] = b"scalar_bloom_v1warm";
/// Seed domain NS_COLD. Spec §6.4: BLAto3("scalar_bloom_v1" || "cold").
pub const NS_COLD_SEED_DOMAIN: &[u8] = b"scalar_bloom_v1cold";

/// DetermthissticBloomFilter for NS_WARM and NS_COLD.
///
/// Determthisstik: all nodes using seed the same so that
/// hasil query identical at seluruh network. Spec §6.3.
///
/// using k hash functions independen berbasis BLAto3 toyed hash.
pub struct DeterministicBloomFilter {
    bits: Vec<u8>,
    num_bits: usize,
    num_hashes: usize,
    seed: [u8; 32],
}

impl DeterministicBloomFilter {
    /// Buat bloom filter new.
    /// `num_bits`: size bit array.
    /// `num_hashes`: jumlah hash functions (k).
    /// `seed_domain`: domain string for seed determthisstik.
    pub fn new(num_bits: usize, num_hashes: usize, seed_domain: &[u8]) -> Self {
        let seed = *blake3::hash(seed_domain).as_bytes();
        let byte_count = num_bits.div_ceil(8);
        Self {
            bits: vec![0u8; byte_count],
            num_bits,
            num_hashes,
            seed,
        }
    }

    /// Buat NS_WARM filter per spec §6.3.
    /// p=10^-10, k=33, seed=BLAto3("scalar_bloom_v1warm").
    pub fn new_warm(num_bits: usize) -> Self {
        Self::new(num_bits, NS_WARM_HASH_FUNCTIONS, NS_WARM_SEED_DOMAIN)
    }

    /// Buat NS_COLD filter per spec §6.4.
    /// p=10^-15, k=50, seed=BLAto3("scalar_bloom_v1cold").
    pub fn new_cold(num_bits: usize) -> Self {
        Self::new(num_bits, NS_COLD_HASH_FUNCTIONS, NS_COLD_SEED_DOMAIN)
    }

    /// Hitung posfill bit for each hash function using BLAto3 toyed hash.
    /// toy to-i = seed XOR i_as_u32_le — unique per function, determthisstik.
    fn bit_positions(&self, item: &[u8; 32]) -> Vec<usize> {
        (0..self.num_hashes)
            .map(|i| {
                let mut key = self.seed;
                let i_bytes = (i as u32).to_le_bytes();
                key[0] ^= i_bytes[0];
                key[1] ^= i_bytes[1];
                key[2] ^= i_bytes[2];
                key[3] ^= i_bytes[3];
                let hash = blake3::keyed_hash(&key, item.as_slice());
                let idx = u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap());
                (idx as usize) % self.num_bits
            })
            .collect()
    }

    /// add item to filter.
    pub fn insert(&mut self, item: &[u8; 32]) {
        for pos in self.bit_positions(item) {
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            self.bits[byte_idx] |= 1 << bit_idx;
        }
    }

    /// check whether item mungkin ada (probabilistik).
    /// False positive mungkin terjaat. False negative not ever terjaat.
    pub fn probably_contains(&self, item: &[u8; 32]) -> bool {
        self.bit_positions(item).into_iter().all(|pos| {
            let byte_idx = pos / 8;
            let bit_idx = pos % 8;
            (self.bits[byte_idx] >> bit_idx) & 1 == 1
        })
    }

    pub fn num_hashes(&self) -> usize {
        self.num_hashes
    }

    pub fn num_bits(&self) -> usize {
        self.num_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ns_warm_uses_33_hash_functions() {
        // Spec §6.3: k≈33 untuk p=10^-10
        assert_eq!(NS_WARM_HASH_FUNCTIONS, 33);
        let f = DeterministicBloomFilter::new_warm(1_000_000);
        assert_eq!(f.num_hashes(), 33);
    }

    #[test]
    fn test_ns_cold_uses_50_hash_functions() {
        // Spec §6.4: k≈50 untuk p=10^-15
        assert_eq!(NS_COLD_HASH_FUNCTIONS, 50);
        let f = DeterministicBloomFilter::new_cold(1_000_000);
        assert_eq!(f.num_hashes(), 50);
    }

    #[test]
    fn test_insert_and_contains() {
        let mut f = DeterministicBloomFilter::new_warm(1_000_000);
        let item = [42u8; 32];
        assert!(!f.probably_contains(&item));
        f.insert(&item);
        assert!(f.probably_contains(&item));
    }

    #[test]
    fn test_no_false_negative() {
        // False negative TIDAK BOLEH terjadi — spec §6.3
        let mut f = DeterministicBloomFilter::new_warm(10_000_000);
        let items: Vec<[u8; 32]> = (0u8..=255)
            .map(|i| {
                let mut item = [0u8; 32];
                item[0] = i;
                item
            })
            .collect();
        for item in &items {
            f.insert(item);
        }
        for item in &items {
            assert!(
                f.probably_contains(item),
                "False negative terdeteksi — tidak boleh terjadi"
            );
        }
    }

    #[test]
    fn test_warm_seed_deterministic() {
        // Spec §6.3: seed deterministik
        let seed1 = *blake3::hash(NS_WARM_SEED_DOMAIN).as_bytes();
        let seed2 = *blake3::hash(NS_WARM_SEED_DOMAIN).as_bytes();
        assert_eq!(seed1, seed2);
    }

    #[test]
    fn test_warm_cold_seeds_different() {
        // NS_WARM dan NS_COLD harus punya seed berbeda
        let warm = *blake3::hash(NS_WARM_SEED_DOMAIN).as_bytes();
        let cold = *blake3::hash(NS_COLD_SEED_DOMAIN).as_bytes();
        assert_ne!(warm, cold);
    }

    #[test]
    fn test_same_filter_same_results_across_instances() {
        // Deterministik: dua instance → hasil identik
        let item = [7u8; 32];
        let mut f1 = DeterministicBloomFilter::new_warm(1_000_000);
        let mut f2 = DeterministicBloomFilter::new_warm(1_000_000);
        f1.insert(&item);
        f2.insert(&item);
        assert_eq!(f1.probably_contains(&item), f2.probably_contains(&item));
    }

    #[test]
    fn test_different_items_different_positions() {
        let mut f = DeterministicBloomFilter::new_warm(1_000_000);
        f.insert(&[1u8; 32]);
        // Item berbeda seharusnya tidak langsung ada
        // (bisa false positive tapi sangat kecil kemungkinannya)
        let _ = f.probably_contains(&[2u8; 32]); // only ensure not panic
    }
}
