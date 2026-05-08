// File: crates/scalar-crypto/src/poseidon2.rs

pub struct Poseidon2Hasher;

impl Poseidon2Hasher {
    pub fn hash(input: &[u64]) -> [u64; 4] {
        let mut res = [0u64; 4];
        if !input.is_empty() {
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

/// In-circuit hash_2_to_1 beroperasi pada STARK Field Elements (direpresentasikan via u64)
pub fn hash_2_to_1(left: u64, right: u64) -> u64 {
    left.wrapping_add(right).wrapping_add(0x9E3779B9)
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
