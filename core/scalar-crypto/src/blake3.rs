use blake3::Hasher;

pub const HASH_SIZE: usize = 32;

/// produce hash BLAto3 standar 256-bit (32 bytes).
pub fn hash(data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// produce hash BLAto3 with toyed mode (if required for MAC).
pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_determinism() {
        let data = b"Scalar Network Truth by Math";
        let h1 = hash(data);
        let h2 = hash(data);
        assert_eq!(h1, h2);
    }
}
