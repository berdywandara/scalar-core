// File: crates/scalar-nullifier/src/bloom.rs

/// NS_WARM: Deterministic Bloom Filter menggunakan BLAKE3 hashing
pub struct DeterministicBloomFilter {
    bitset: Vec<bool>,
    size: usize,
}

impl DeterministicBloomFilter {
    pub fn new(size: usize) -> Self {
        Self {
            bitset: vec![false; size],
            size,
        }
    }

    /// Hashing elemen menggunakan BLAKE3 untuk out-circuit
    pub fn insert(&mut self, item: &[u8; 32]) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(item);
        let hash = hasher.finalize();

        let idx =
            (u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap()) as usize) % self.size;
        self.bitset[idx] = true;
    }

    pub fn probably_contains(&self, item: &[u8; 32]) -> bool {
        let mut hasher = blake3::Hasher::new();
        hasher.update(item);
        let hash = hasher.finalize();

        let idx =
            (u64::from_le_bytes(hash.as_bytes()[0..8].try_into().unwrap()) as usize) % self.size;
        self.bitset[idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_seeds_are_deterministic() {
        let mut filter = DeterministicBloomFilter::new(1000);
        let item = [1u8; 32];
        filter.insert(&item);
        assert!(
            filter.probably_contains(&item),
            "Item yang dimasukkan harus terdeteksi"
        );
        assert!(
            !filter.probably_contains(&[2u8; 32]),
            "Item lain seharusnya tidak terdeteksi (kecuali collision)"
        );
    }
}
