//! Genesis Tool untuk Scalar Network
//! Architect & Original Founder: Berdy Wandara

fn main() {
    println!("Memulai Upacara Genesis Scalar Network...");

    let genesis_memo = b"Scalar Network Initialized. Architect: Berdy Wandara. Truth by Mathematics, Not by Majority.";
    let genesis_hash = blake3::hash(genesis_memo);

    println!("Genesis Memo: {}", String::from_utf8_lossy(genesis_memo));
    println!(
        "Genesis Root Hash: {}",
        hex::encode(genesis_hash.as_bytes())
    );
    println!("Hash ini akan menjadi pondasi Sparse Merkle Tree (SMT) selamanya.");
}
