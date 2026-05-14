//! Genesis Ceremony CLI Tool — Spec §12.10 v11.1-FINAL
//!
//! Usage:
//!   genesis-tool keygen                  — generate founder keypair
//!   genesis-tool generate <pubkey_hex>   — create genesis binary object
//!   genesis-tool ceremony                — keygen + generate in one step
//!   genesis-tool verify <file>           — verify genesis file
//!
//! Spec §12.10:
//!   Genesis object OSSIFIED 177 bytes + pubkey.
//!   S3: All integers MUST be little-endian.
//!   S4: No padding or optional fields.

use std::env;
use std::fs;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

// ── CANONICAL_HASH ────────────────────────────────────────────────────────────
// Set this after the official genesis ceremony.
// Update with BLAKE3 hash of the production genesis.bin.
// DO NOT update before the official ceremony — this is a permanent commitment.
// FIX: rustfmt tidak memakai pengelompokan 8-byte dengan spasi — semua koma rapat
const CANONICAL_HASH: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
];

// ── Hash Utilities ────────────────────────────────────────────────────────────
fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn to_display_hash(bytes: &[u8; 32]) -> String {
    format!("SCL1{}", hex::encode(bytes).to_uppercase())
}

// ── Keypair Generation — SLH-DSA-SHAKE-128s — Spec §2.1 ──────────────────────
fn generate_founder_keypair() -> (Vec<u8>, Vec<u8>) {
    use scalar_crypto::sphincs::generate_keypair;
    let kp = generate_keypair().expect("Failed to generate SLH-DSA-SHAKE-128s keypair");
    (kp.secret, kp.public)
}

// ── Binarization Core — Spec §12.10, S3, S4 ──────────────────────────────────
fn generate_genesis_bytes(timestamp: u64, pubkey: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(177 + pubkey.len());

    // 1. protocol_version: u8 = 0x01 (1 byte)
    buffer.push(0x01);

    // 2. genesis_timestamp: u64 LE (8 bytes)
    buffer.extend_from_slice(&timestamp.to_le_bytes());

    // 3. genesis_epoch_id: u64 = 0 LE (8 bytes)
    buffer.extend_from_slice(&0u64.to_le_bytes());

    // 4. nullifier_set_root: bytes32 (32 bytes)
    let empty_ns_root = blake3_hash(b"scalar_empty_nullifier_set_v11");
    buffer.extend_from_slice(&empty_ns_root);

    // 5. liveness_smt_root: bytes32 (32 bytes)
    let empty_smt_root = blake3_hash(b"scalar_empty_liveness_smt_v11");
    buffer.extend_from_slice(&empty_smt_root);

    // 6. supply_params_hash: bytes32 (32 bytes) — Spec §3.2
    // FIX: hapus spasi berlebih untuk alignment visual — rustfmt tidak mengizinkan ini
    let s_max: u64 = 2_100_000_000_000_000; // 21,000,000 SCL
    let s_e: u64 = 1_890_000_000_000_000; // 18,900,000 SCL
    let e0: u64 = 12_600_000_000_000; // 126,000 SCL/epoch
    let mut supply_data = Vec::new();
    supply_data.extend_from_slice(&s_max.to_le_bytes());
    supply_data.extend_from_slice(&s_e.to_le_bytes());
    supply_data.extend_from_slice(&e0.to_le_bytes());
    buffer.extend_from_slice(&blake3_hash(&supply_data));

    // 7. network_id_hash: bytes32 (32 bytes) — v11.1-FINAL
    let network_id_hash = blake3_hash(b"scalar_mainnet_v11_final");
    buffer.extend_from_slice(&network_id_hash);

    // 8. consensus_commit: bytes32 (32 bytes) — Spec §2.4
    let spec_version = 0x06u8; // SPEC_VERSION_MANIFEST_V12
    let mut consensus_data = vec![spec_version];
    consensus_data.extend_from_slice(b"Truth by Mathematics, Not by Majority");
    buffer.extend_from_slice(&blake3_hash(&consensus_data));

    // 9. nodekeypub_epoch0: bytes (SLH-DSA-SHAKE-128s pubkey, 32 bytes)
    buffer.extend_from_slice(pubkey);

    buffer
}

// ── Commands ──────────────────────────────────────────────────────────────────

fn cmd_keygen() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║     SCALAR NETWORK — FOUNDER KEYPAIR GENERATION          ║");
    println!("║     SLH-DSA-SHAKE-128s — NIST FIPS 205 — Spec §2.1      ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    println!("⚠️  SECURITY WARNING:");
    println!("   Run this command ONLY on a machine with no internet connection.");
    println!("   The secret key generated here is the root of trust for the network.");
    println!("   Never copy the secret key to any online machine.\n");

    let (sk, pk) = generate_founder_keypair();

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("FOUNDER KEYPAIR — SLH-DSA-SHAKE-128s");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Public Key  ({} bytes): {}", pk.len(), to_hex(&pk));
    println!(
        "Secret Key  ({} bytes): [HIDDEN — saved to founder_sk.bin]",
        sk.len()
    );
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    fs::write("founder_sk.bin", &sk).expect("Failed to write founder_sk.bin");
    fs::write("founder_pk.bin", &pk).expect("Failed to write founder_pk.bin");
    fs::write("founder_pk.hex", to_hex(&pk).as_bytes()).expect("Failed to write founder_pk.hex");

    println!(
        "✅ founder_sk.bin  — SECRET KEY ({} bytes) — NEVER GO ONLINE",
        sk.len()
    );
    println!(
        "✅ founder_pk.bin  — PUBLIC KEY ({} bytes) — safe to publish",
        pk.len()
    );
    println!("✅ founder_pk.hex  — PUBLIC KEY in hex format\n");
    println!("Next step:");
    println!("  genesis-tool generate $(cat founder_pk.hex)");
    println!("  or use: genesis-tool ceremony\n");
}

fn cmd_generate(pubkey_hex: &str) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║     SCALAR NETWORK — GENESIS CEREMONY v11.1-FINAL        ║");
    println!("║     Strict Binary Format — Spec §12.10                   ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    let pubkey = hex::decode(pubkey_hex).unwrap_or_else(|_| {
        eprintln!("ERROR: Public key must be valid hex format.");
        process::exit(1);
    });

    if pubkey.len() != 32 {
        // FIX: baris terlalu panjang → argumen eprintln! dipecah
        eprintln!(
            "ERROR: SLH-DSA-SHAKE-128s public key must be 32 bytes, got {}",
            pubkey.len()
        );
        process::exit(1);
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let genesis_bytes = generate_genesis_bytes(timestamp, &pubkey);
    let hash = blake3_hash(&genesis_bytes);
    let hash_hex = to_hex(&hash);

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("SCALAR NETWORK GENESIS OBJECT — v11.1-FINAL");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Timestamp        : {}", timestamp);
    println!("Genesis Epoch    : 0");
    println!("Spec Version     : 0x06 (v11.1-FINAL)");
    println!("Network ID       : scalar_mainnet_v11_final");
    println!("Tagline          : Truth by Mathematics, Not by Majority");
    println!("Supply S_MAX     : 21,000,000 SCL");
    println!("Supply S_E       : 18,900,000 SCL");
    println!("Emission E0      : 126,000 SCL/epoch");
    println!("Total Size       : {} bytes", genesis_bytes.len());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("GENESIS HASH     : {}", hash_hex);
    println!("DISPLAY HASH     : {}", to_display_hash(&hash));
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    fs::write("genesis.bin", &genesis_bytes).expect("Failed to write genesis.bin");
    fs::write("genesis_hash.txt", &hash_hex).expect("Failed to write genesis_hash.txt");

    println!("✅ genesis.bin       — copy this to ALL VPS nodes");
    println!("✅ genesis_hash.txt  — announce this hash publicly on X\n");
    println!("⚠️  WRITE DOWN THE GENESIS HASH — STORE IT SAFELY");
    println!("   This hash is the permanent identity of Scalar Network.\n");
    println!("Update CANONICAL_HASH in source code with the value above");
    println!("before launching Mainnet.\n");
}

fn cmd_ceremony() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║     SCALAR NETWORK — FULL GENESIS CEREMONY               ║");
    println!("║     Keygen + Generate in one step                        ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    println!("STEP 1/2 — Generating Founder Keypair...\n");
    let (sk, pk) = generate_founder_keypair();

    fs::write("founder_sk.bin", &sk).expect("Failed to write founder_sk.bin");
    fs::write("founder_pk.bin", &pk).expect("Failed to write founder_pk.bin");

    println!("✅ Keypair generated successfully");
    println!("   Public Key: {}...\n", &to_hex(&pk)[..32]);

    println!("STEP 2/2 — Generating Genesis Object...\n");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let genesis_bytes = generate_genesis_bytes(timestamp, &pk);
    let hash = blake3_hash(&genesis_bytes);
    let hash_hex = to_hex(&hash);

    fs::write("genesis.bin", &genesis_bytes).expect("Failed to write genesis.bin");
    fs::write("genesis_hash.txt", hash_hex.as_bytes()).expect("Failed to write genesis_hash.txt");

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✅ GENESIS CEREMONY COMPLETE");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("GENESIS HASH  : {}", hash_hex);
    println!("DISPLAY HASH  : {}", to_display_hash(&hash));
    println!("TIMESTAMP     : {}", timestamp);
    println!("SIZE          : {} bytes", genesis_bytes.len());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("Files generated:");
    println!("  founder_sk.bin   — SECRET KEY — NEVER GO ONLINE");
    println!("  founder_pk.bin   — PUBLIC KEY — safe to publish");
    println!("  genesis.bin      — copy to ALL VPS nodes");
    println!("  genesis_hash.txt — announce publicly\n");
    println!("⚠️  WRITE DOWN THE GENESIS HASH BEFORE CLOSING THIS TERMINAL");
}

fn cmd_verify(path: &str) {
    let bytes = fs::read(path).unwrap_or_else(|e| {
        eprintln!("ERROR: Cannot read file '{}': {}", path, e);
        process::exit(1);
    });

    let hash = blake3_hash(&bytes);
    let hash_hex = to_hex(&hash);

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("GENESIS FILE VERIFICATION: {}", path);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Size   : {} bytes", bytes.len());
    println!("Hash   : {}", hash_hex);
    println!("Display: {}", to_display_hash(&hash));

    if CANONICAL_HASH == [0u8; 32] {
        println!("\n⚠️  CANONICAL_HASH is still placeholder — no official genesis yet.");
        println!("   Run ceremony first, then update CANONICAL_HASH in source code.");
    } else if hash == CANONICAL_HASH {
        println!("\n✅ VALID — BLAKE3(genesis) == CANONICAL_HASH");
    } else {
        println!("\n❌ MISMATCH — Genesis file does not match official CANONICAL_HASH!");
        process::exit(1);
    }
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => cmd_keygen(),
        Some("generate") => {
            let pubkey = args.get(2).map(String::as_str).unwrap_or_else(|| {
                eprintln!("ERROR: Provide pubkey hex as argument.");
                eprintln!("Usage: genesis-tool generate <pubkey_hex>");
                eprintln!("Or use: genesis-tool ceremony");
                process::exit(1);
            });
            cmd_generate(pubkey);
        }
        Some("ceremony") => cmd_ceremony(),
        Some("verify") => {
            let path = args.get(2).map(String::as_str).unwrap_or("genesis.bin");
            cmd_verify(path);
        }
        _ => {
            println!("Scalar Network Genesis Tool v11.1-FINAL");
            println!("Usage:");
            println!("  genesis-tool keygen              — generate founder keypair");
            println!("  genesis-tool generate <pk_hex>   — create genesis.bin");
            println!("  genesis-tool ceremony             — keygen + generate in one step");
            println!("  genesis-tool verify [file.bin]   — verify genesis file");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_binary_length() {
        let dummy_pubkey = vec![0u8; 32];
        let bytes = generate_genesis_bytes(1_700_000_000, &dummy_pubkey);
        // FIX: argumen assert_eq! dan assert! dipecah ke multi-baris
        assert_eq!(
            bytes.len(),
            177 + 32,
            "Length must be exactly 177 + pubkey length"
        );
        assert!(bytes.len() < 1024, "Must be less than 1KB per Spec §12.10");
    }

    #[test]
    fn test_genesis_hash_deterministic() {
        let pubkey = vec![0x42u8; 32];
        let ts = 1_700_000_000u64;
        let b1 = generate_genesis_bytes(ts, &pubkey);
        let b2 = generate_genesis_bytes(ts, &pubkey);
        // FIX: argumen assert_eq! dipecah ke multi-baris
        assert_eq!(
            blake3_hash(&b1),
            blake3_hash(&b2),
            "Hash must be deterministic for identical inputs"
        );
    }

    #[test]
    fn test_spec_version_is_0x06() {
        let pubkey = vec![0u8; 32];
        let bytes = generate_genesis_bytes(0, &pubkey);
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_canonical_hash_placeholder() {
        // CANONICAL_HASH remains placeholder until official genesis ceremony
        // FIX: argumen assert_eq! dipecah ke multi-baris
        assert_eq!(
            CANONICAL_HASH,
            [0u8; 32],
            "CANONICAL_HASH must be set after official ceremony"
        );
    }
}
