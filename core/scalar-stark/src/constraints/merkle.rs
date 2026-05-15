//! C3 & C4: Merkle Tree Membership & Non-Membership Constraints
//! used for verification Genesis (C3) and Anti-Double-Spend (C4).

// Di sirkuit nyata, fungsi ini diterjemahkan menjadi batasan polinomial.
// Untuk tahap ini, kita merepresentasikan validasi logikanya menggunakan Poseidon2.

use scalar_crypto::poseidon2::hash_2_to_1;

/// verify jalur Merkle (Merkle path) from leaf menuju root
pub fn enforce_merkle_path(leaf: u64, root: u64, path: &[u64], mut index: u64) -> bool {
    let mut current_hash = leaf;

    // Evaluasi dari daun ke akar (Bottom-up)
    for &sibling in path {
        // Jika bit LSB dari index adalah 0, node saat ini di kiri, sibling di kanan.
        // Jika bit LSB adalah 1, node saat ini di kanan, sibling di kiri.
        if index & 1 == 0 {
            current_hash = hash_2_to_1(current_hash, sibling);
        } else {
            current_hash = hash_2_to_1(sibling, current_hash);
        }
        index >>= 1; // Geser bit to kanan for level next
    }

    // Pastikan hasil perhitungan persis sama dengan root publik
    current_hash == root
}
