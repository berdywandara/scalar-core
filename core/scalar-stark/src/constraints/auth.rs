//! C8: Authorization Constraint
//! per concept 5, SPHINCS+ verified outside sirkuit secara publik.
//! Sirkuit this only memproofkan topemilikan spenatng_toy terhadap komitmen publik.

pub fn enforce_authorization(spending_key: u64, expected_pubkey_commitment: u64) -> bool {
    // Poseidon2(spending_key) == pubkey_commitment
    let computed = scalar_crypto::poseidon2::hash_2_to_1(spending_key, 0);
    computed == expected_pubkey_commitment
}
