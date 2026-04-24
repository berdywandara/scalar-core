//! C1 & C7: Commitment Validity
//! Memastikan nilai, secret, dan kepemilikan sesuai dengan komitmen on-chain.

use scalar_crypto::poseidon2::hash_2_to_1;

/// Memverifikasi bahwa komitmen output / input dibentuk secara benar.
/// Poseidon2(secret || amount || pubkey_commitment) == expected_commitment
pub fn enforce_commitment(
    secret: u64, 
    amount: u64, 
    pubkey_commitment: u64, 
    expected_commitment: u64
) -> bool {
    // Karena hash_2_to_1 hanya menerima 2 input, kita menggunakan nested hashing:
    // H( H(secret, amount), pubkey_commitment )
    let inner_hash = hash_2_to_1(secret, amount);
    let computed_commitment = hash_2_to_1(inner_hash, pubkey_commitment);
    
    computed_commitment == expected_commitment
}
