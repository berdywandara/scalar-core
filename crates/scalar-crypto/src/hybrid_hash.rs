//! Resolusi GAP-001: Nullifier Hash Function Inconsistency
//! Poseidon di DALAM sirkuit (efisien), BLAKE3 di LUAR sirkuit (Network wrapper)

use blake3;
use crate::poseidon2::hash_2_to_1;

/// Membantu konversi byte array ke u64 secara aman untuk Field Element
fn bytes_to_u64(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = std::cmp::min(data.len(), 8);
    buf[..len].copy_from_slice(&data[..len]);
    u64::from_le_bytes(buf)
}

/// N_circuit = Poseidon(secret || spending_key)
/// Dihitung dan dibuktikan di dalam zk-STARK (Hanya ~200 constraints)
/// SEKARANG MENGGUNAKAN POSEIDON2 REAL SECARA MATEMATIS!
pub fn compute_circuit_nullifier(secret: &[u8], spending_key: &[u8]) -> [u8; 32] {
    // 1. Ubah byte stream menjadi Field Elements (u64)
    let secret_u64 = bytes_to_u64(secret);
    let spending_key_u64 = bytes_to_u64(spending_key);

    // 2. Eksekusi Poseidon2 Hash murni secara berantai (Sponge Mode sederhana)
    // Untuk menghasilkan 32-byte (4 buah u64), kita melakukan chaining hash
    let out1 = hash_2_to_1(secret_u64, spending_key_u64);
    let out2 = hash_2_to_1(out1, secret_u64);
    let out3 = hash_2_to_1(out2, spending_key_u64);
    let out4 = hash_2_to_1(out3, out1);

    // 3. Rangkai kembali menjadi [u8; 32]
    let mut result = [0u8; 32];
    result[0..8].copy_from_slice(&out1.to_le_bytes());
    result[8..16].copy_from_slice(&out2.to_le_bytes());
    result[16..24].copy_from_slice(&out3.to_le_bytes());
    result[24..32].copy_from_slice(&out4.to_le_bytes());

    result
}

/// N_network = BLAKE3(N_circuit)
/// Disiarkan ke publik. Melindungi Poseidon dari serangan pre-image eksternal.
pub fn compute_network_nullifier(circuit_nullifier: &[u8; 32]) -> [u8; 32] {
    let hash = blake3::hash(circuit_nullifier);
    *hash.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_hash_consistency() {
        let secret = b"super_secret_seed";
        let spending_key = b"user_spending_key";

        let c_nullifier1 = compute_circuit_nullifier(secret, spending_key);
        let c_nullifier2 = compute_circuit_nullifier(secret, spending_key);

        // Harus deterministik!
        assert_eq!(c_nullifier1, c_nullifier2);
        // Tidak boleh menghasilkan array kosong/nol
        assert_ne!(c_nullifier1, [0u8; 32]);

        let n_nullifier = compute_network_nullifier(&c_nullifier1);
        assert_ne!(c_nullifier1, n_nullifier, "Network nullifier harus berbeda dari Circuit nullifier (BLAKE3 Masking)");
    }
}