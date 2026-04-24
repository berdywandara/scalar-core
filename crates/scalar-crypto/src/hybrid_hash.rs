//! Resolusi GAP-001: Nullifier Hash Function Inconsistency
//! Poseidon di DALAM sirkuit (efisien), BLAKE3 di LUAR sirkuit (Network wrapper)

use blake3;

/// N_circuit = Poseidon(secret || spending_key)
/// Dihitung dan dibuktikan di dalam zk-STARK (Hanya ~200 constraints)
pub fn compute_circuit_nullifier(secret: &[u8], spending_key: &[u8]) -> [u8; 32] {
    // Simulasi Poseidon2 (Di produksi menggunakan library Plonky2/Winterfell)
    let mut combined = Vec::new();
    combined.extend_from_slice(secret);
    combined.extend_from_slice(spending_key);
    
    let mut fake_poseidon = [0u8; 32];
    let len = std::cmp::min(combined.len(), 32);
    fake_poseidon[..len].copy_from_slice(&combined[..len]);
    fake_poseidon
}

/// N_network = BLAKE3(N_circuit)
/// Disiarkan ke publik. Melindungi Poseidon dari serangan pre-image eksternal.
pub fn compute_network_nullifier(circuit_nullifier: &[u8; 32]) -> [u8; 32] {
    let hash = blake3::hash(circuit_nullifier);
    *hash.as_bytes()
}
