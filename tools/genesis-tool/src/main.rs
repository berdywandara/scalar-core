//! Genesis Tool untuk Scalar Network
//! Architect & Original Founder: Berdy Wandara

use scalar_crypto::blake3::hash;

fn main() {
    println!("Memulai Upacara Genesis Scalar Network...");

    // Pesan abadi yang akan di-hash menjadi akar (root) pertama dari seluruh jaringan
    let genesis_memo = b"Scalar Network Initialized. Architect: Berdy Wandara. Truth by Mathematics, Not by Majority.";
    let genesis_hash = hash(genesis_memo);

    println!("Genesis Memo: {}", String::from_utf8_lossy(genesis_memo));
    println!("Genesis Root Hash: {}", hex::encode(genesis_hash.as_bytes()));
    println!("Hash ini akan menjadi pondasi Sparse Merkle Tree (SMT) selamanya.");
}
