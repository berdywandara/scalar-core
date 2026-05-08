//! C8: Authorization Constraint
//! Sesuai Concept 5, SPHINCS+ diverifikasi di luar sirkuit secara publik.
//! Sirkuit ini hanya membuktikan kepemilikan spending_key terhadap komitmen publik.

pub fn enforce_authorization(spending_key: u64, expected_pubkey_commitment: u64) -> bool {
    // Poseidon2(spending_key) == pubkey_commitment
    let computed = scalar_crypto::poseidon2::hash_2_to_1(spending_key, 0);
    computed == expected_pubkey_commitment
}
