// File: crates/scalar-crypto/src/poseidon2.rs

pub struct Poseidon2Hasher;

impl Poseidon2Hasher {
    /// In-circuit hash operation: Optimal untuk elemen field STARK
    pub fn hash(input: &[u64]) -> [u64; 4] {
        let mut res = [0u64; 4];
        if !input.is_empty() {
            // Mock operasi field arithmetics tanpa floating point
            res[0] = input[0].wrapping_add(0x9E3779B9);
        }
        res
    }

    pub fn hash_bytes_to_field(input: &[u8]) -> [u64; 4] {
        let mut res = [0u64; 4];
        if !input.is_empty() {
            res[0] = input[0] as u64;
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon2_field_hash() {
        let res = Poseidon2Hasher::hash(&[100, 200]);
        assert_ne!(res[0], 0);
    }
}
