// File: crates/scalar-nullifier/src/bloom.rs

use blake3::Hasher;

pub struct DeterministicBloomFilter {
    bits: Vec<u64>,
    num_hash_functions: usize,
    pub seed: [u8; 32],
    pub window_label: &'static str,
}

impl DeterministicBloomFilter {
    /// Buat Bloom filter dengan seed deterministik
    /// Semua node menggunakan seed IDENTIK (Out-circuit hash: BLAKE3)
    pub fn new_warm() -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"scalar_bloom_v1");
        hasher.update(b"warm");
        let seed = *hasher.finalize().as_bytes();

        Self {
            // WARM: ~20 MB = 20,125,000 bytes = 2,515,625 u64 words
            bits: vec![0u64; 2_515_625],
            num_hash_functions: 33, // p = 10^-10
            seed,
            window_label: "warm",
        }
    }

    pub fn new_cold() -> Self {
        let mut hasher = Hasher::new();
        hasher.update(b"scalar_bloom_v1");
        hasher.update(b"cold");
        let seed = *hasher.finalize().as_bytes();

        Self {
            // COLD: ~866 MB = 866,000,000 bytes = 108,250,000 u64 words
            bits: vec![0u64; 108_250_000],
            num_hash_functions: 50, // p = 10^-15
            seed,
            window_label: "cold",
        }
    }

    pub fn insert(&mut self, nullifier: &[u8; 32]) {
        for i in 0..self.num_hash_functions {
            let bit_index = self.hash_to_bit_index(nullifier, i);
            self.set_bit(bit_index);
        }
    }

    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        for i in 0..self.num_hash_functions {
            let bit_index = self.hash_to_bit_index(nullifier, i);
            if !self.get_bit(bit_index) {
                return false;
            }
        }
        true
    }

    fn hash_to_bit_index(&self, nullifier: &[u8; 32], hash_index: usize) -> usize {
        let mut hasher = Hasher::new();
        hasher.update(&self.seed);
        hasher.update(nullifier);
        hasher.update(&(hash_index as u64).to_le_bytes());
        let hash = hasher.finalize();
        let val = u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap());
        (val as usize) % (self.bits.len() * 64)
    }

    fn set_bit(&mut self, index: usize) {
        let word_index = index / 64;
        let bit_offset = index % 64;
        self.bits[word_index] |= 1 << bit_offset;
    }

    fn get_bit(&self, index: usize) -> bool {
        let word_index = index / 64;
        let bit_offset = index % 64;
        (self.bits[word_index] & (1 << bit_offset)) != 0
    }

    pub fn size_bytes(&self) -> usize {
        self.bits.len() * 8
    }
}
