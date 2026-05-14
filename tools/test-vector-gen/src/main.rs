//! Test Vector Generator — Scalar Network v11.1-FINAL
//! Spec §Appendix B

fn main() {
    println!("=== SCALAR NETWORK TEST VECTORS v11.1-FINAL ===\n");
    println!("── B.2.3 Domain Separators ──");
    verify_domain_separators();
    println!("\n── B.3 BLAKE3 Hash Vectors ──");
    blake3_vectors();
    println!("\n── B.4 Poseidon2 Hash Vectors ──");
    poseidon2_vectors();
    println!("\n── B.5 SLH-DSA-SHAKE-128s ──");
    slhdsa_vectors();
    println!("\n── B.7 Canonical Serialization ──");
    canonical_serialization_vectors();
    println!("\n=== SELESAI ===");
}

fn verify_domain_separators() {
    use scalar_crypto::domain::*;
    let domains: &[(&str, &[u8])] = &[
        ("DOMAIN_NULLIFIER", DOMAIN_NULLIFIER),
        ("DOMAIN_UTXO_COMMITMENT", DOMAIN_UTXO_COMMITMENT),
        ("DOMAIN_SALT", DOMAIN_SALT),
        ("DOMAIN_SEED", DOMAIN_SEED),
        ("DOMAIN_NMT", DOMAIN_NMT),
        ("DOMAIN_NODE_SHORT", DOMAIN_NODE_SHORT),
        ("DOMAIN_ANCHOR", DOMAIN_ANCHOR),
        ("DOMAIN_VOTE", DOMAIN_VOTE),
        ("DOMAIN_GENESIS_BOOTSTRAP", DOMAIN_GENESIS_BOOTSTRAP),
        ("DOMAIN_STARK_FS", DOMAIN_STARK_FS),
        ("DOMAIN_CHECKPOINT_FS", DOMAIN_CHECKPOINT_FS),
        ("DOMAIN_BEACON", DOMAIN_BEACON),
        ("DOMAIN_SEED_KDF", DOMAIN_SEED_KDF),
        ("DOMAIN_TX_ORDER", DOMAIN_TX_ORDER),
    ];
    for (name, bytes) in domains {
        println!(" {}: {} ({} bytes)", name, hex::encode(bytes), bytes.len());
    }
}

fn blake3_vectors() {
    let h0 = blake3::hash(b"");
    println!(
        " TV-BLAKE3-001 (empty): {}",
        hex::encode(h0.as_bytes())
    );

    let h1 = blake3::hash(scalar_crypto::domain::DOMAIN_NULLIFIER);
    println!(
        "  TV-BLAKE3-002 (DOMAIN_NULLIFIER): {}",
        hex::encode(h1.as_bytes())
    );

    let h2 = blake3::hash(scalar_crypto::domain::DOMAIN_SEED);
    println!(
        "  TV-BLAKE3-003 (DOMAIN_SEED): {}",
        hex::encode(h2.as_bytes())
    );

    let tx_hash = [0xABu8; 32];
    let epoch_id: u64 = 1;
    let mut hasher = blake3::Hasher::new();
    hasher.update(scalar_crypto::domain::DOMAIN_TX_ORDER);
    hasher.update(&tx_hash);
    hasher.update(&epoch_id.to_le_bytes());
    let h3 = hasher.finalize();
    println!(
        "  TV-BLAKE3-004 (tx_ordering_key, epoch=1, tx=ab*32): {}",
        hex::encode(h3.as_bytes())
    );

    let manifest_hash = [0x42u8; 32];
    let mut hasher2 = blake3::Hasher::new();
    hasher2.update(scalar_crypto::domain::DOMAIN_SEED);
    hasher2.update(&manifest_hash);
    let h4 = hasher2.finalize();
    println!(
        "  TV-BLAKE3-005 (seed_k, manifest=42*32): {}",
        hex::encode(h4.as_bytes())
    );

    let node_id = [0x01u8; 32];
    let seed_k = [0x99u8; 32];
    let mut hasher3 = blake3::Hasher::new();
    hasher3.update(scalar_crypto::domain::DOMAIN_NMT);
    hasher3.update(&node_id);
    hasher3.update(&seed_k);
    let h5 = hasher3.finalize();
    println!(
        "  TV-BLAKE3-006 (nmt_rank, node=01*32, seed=99*32): {}",
        hex::encode(h5.as_bytes())
    );
}

fn poseidon2_vectors() {
    use scalar_crypto::poseidon2::hash_2_to_1;
    let h0 = hash_2_to_1(0, 0);
    println!(" TV-POSEIDON2-001 hash(0,0): 0x{:016x}", h0);
    let h1 = hash_2_to_1(1, 0);
    println!(" TV-POSEIDON2-002 hash(1,0): 0x{:016x}", h1);
    let h2 = hash_2_to_1(u64::MAX, u64::MAX);
    println!(" TV-POSEIDON2-003 hash(MAX,MAX): 0x{:016x}", h2);
    let secret_u64 = u64::from_le_bytes([0x02u8; 8]);
    let spending_key_u64 = u64::from_le_bytes([0x03u8; 8]);
    let nullifier = hash_2_to_1(secret_u64, spending_key_u64);
    println!(
        " TV-POSEIDON2-004 nullifier(s=028, sk=038): 0x{:016x}",
        nullifier
    );
}

fn slhdsa_vectors() {
    use scalar_crypto::sphincs::{
        generate_keypair, sign_message, verify_signature, SPHINCS_PK_BYTES, SPHINCS_SIG_BYTES,
        SPHINCS_SK_BYTES,
    };
    println!(" PK size : {} bytes", SPHINCS_PK_BYTES);
    println!(" SK size : {} bytes", SPHINCS_SK_BYTES);
    println!(" Sig size: {} bytes", SPHINCS_SIG_BYTES);
    let kp = generate_keypair().expect("keygen failed");
    let message = b"scalar_anchor_v1_test_vector_001";
    let sig = sign_message(message, &kp.secret).expect("sign failed");
    let valid = verify_signature(message, &sig, &kp.public).unwrap();
    println!(" message : {}", hex::encode(message));
    println!(" pk[0..16]: {}...", hex::encode(&kp.public[..16]));
    println!(" sig size: {} bytes", sig.len());
    println!(" verify : {}", valid);
    println!(" [keypair non-deterministic — nilai berbeda tiap run]");
}

fn canonical_serialization_vectors() {
    use scalar_emission::accumulator::{E0_SSCL, E_TAIL_SSCL, S_E_SSCL, S_MAX_SSCL, S_R_SSCL};
    println!(" TV-SERIAL-001: Supply constants (little-endian u64 hex)");
    println!(" S_MAX : {}", hex::encode(S_MAX_SSCL.to_le_bytes()));
    println!(" S_E : {}", hex::encode(S_E_SSCL.to_le_bytes()));
    println!(" S_R : {}", hex::encode(S_R_SSCL.to_le_bytes()));
    println!(" E0 : {}", hex::encode(E0_SSCL.to_le_bytes()));
    println!(" E_TAIL: {}", hex::encode(E_TAIL_SSCL.to_le_bytes()));

    println!("  TV-SERIAL-002: HeartbeatUnit canonical bytes");
    let mut hb = Vec::new();
    hb.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    hb.extend_from_slice(&1u32.to_le_bytes());
    hb.extend_from_slice(&1000u32.to_le_bytes());
    hb.extend_from_slice(&[0xaau8; 32]);
    hb.extend_from_slice(&[0xbbu8; 32]);
    hb.extend_from_slice(&[0xccu8; 32]);
    hb.push(0x00);
    println!("    total : {} bytes", hb.len());
    println!("    hex   : {}", hex::encode(&hb));
    println!("    blake3: {}", hex::encode(blake3::hash(&hb).as_bytes()));
}
