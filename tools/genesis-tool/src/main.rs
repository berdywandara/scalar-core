//! Genesis Ceremony CLI Tool — Spec §12.10
//!
//! Usage:
//!   genesis-tool generate <pubkey_hex>   — buat genesis object biner baru
//!   genesis-tool verify <file>           — verifikasi genesis file (.bin)
//!
//! Spec §12.10:
//!   Genesis object OSSIFIED 177 bytes + pubkey.
//!   Aturan S3: Semua integer WAJIB little-endian.
//!   Aturan S4: Tidak ada padding/optional fields.

use std::env;
use std::fs;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

// ── Canonical Hash — Spec §12.10 ─────────────────────────────────────────────
// OSSIFIED setelah genesis ceremony resmi.
// Hash ini = BLAKE3(genesis_object_bytes) dari ceremony pertama.
// Placeholder sementara:
const CANONICAL_HASH: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

// ── Binarization Core — Spec §12.10 & S3, S4 ──────────────────────────────────

fn generate_genesis_bytes(timestamp: u64, pubkey: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(177 + pubkey.len());

    // 1. protocol_version: u8 = 0x01 (1 byte)
    buffer.push(0x01);

    // 2. genesis_timestamp: u64 (8 bytes, Little Endian)
    buffer.extend_from_slice(&timestamp.to_le_bytes());

    // 3. genesis_epoch_id: u64 = 0 (8 bytes, Little Endian)
    buffer.extend_from_slice(&0u64.to_le_bytes());

    // 4. nullifier_set_root: bytes32 (32 bytes)
    let empty_ns_root = blake3_hash(b"empty_nullifier_set");
    buffer.extend_from_slice(&empty_ns_root);

    // 5. liveness_smt_root: bytes32 (32 bytes)
    let empty_smt_root = blake3_hash(b"empty_liveness_smt");
    buffer.extend_from_slice(&empty_smt_root);

    // 6. supply_params_hash: bytes32 (32 bytes)
    let s_max: u64 = 2_100_000_000_000_000;
    let s_e: u64 = 1_890_000_000_000_000;
    let e0: u64 = 12_600_000_000_000;
    let mut supply_data = Vec::new();
    supply_data.extend_from_slice(&s_max.to_le_bytes());
    supply_data.extend_from_slice(&s_e.to_le_bytes());
    supply_data.extend_from_slice(&e0.to_le_bytes());
    buffer.extend_from_slice(&blake3_hash(&supply_data));

    // 7. network_id_hash: bytes32 (32 bytes)
    let network_id_hash = blake3_hash(b"scalar_mainnet_v9_nodes");
    buffer.extend_from_slice(&network_id_hash);

    // 8. consensus_commit: bytes32 (32 bytes)
    let spec_version = 0x02u8; // Manifest spec version
    let mut consensus_data = vec![spec_version];
    consensus_data.extend_from_slice(b"Truth by Mathematics, Not by Majority");
    buffer.extend_from_slice(&blake3_hash(&consensus_data));

    // 9. nodekeypub_epoch0: bytes (variable, SPHINCS+ pubkey)
    buffer.extend_from_slice(pubkey);

    buffer
}

// ── Commands ─────────────────────────────────────────────────────────────────

fn cmd_generate(pubkey_hex: &str) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          SCALAR NETWORK — GENESIS CEREMONY v9.0          ║");
    println!("║          Strict Binary Format — Spec §12.10              ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    let pubkey = hex::decode(pubkey_hex).unwrap_or_else(|_| {
        eprintln!("ERROR: Pubkey harus berupa format hex yang valid!");
        process::exit(1);
    });

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let genesis_bytes = generate_genesis_bytes(timestamp, &pubkey);

    // Validasi ukuran ketat (177 bytes + pubkey length)
    let expected_len = 177 + pubkey.len();
    if genesis_bytes.len() != expected_len {
        eprintln!(
            "FATAL ERROR: Ukuran byte tidak sesuai spec (Expected: {}, Got: {})",
            expected_len,
            genesis_bytes.len()
        );
        process::exit(1);
    }

    if genesis_bytes.len() >= 1024 {
        eprintln!("ERROR: Ukuran melebihi batas OSSIFIED 1KB.");
        process::exit(1);
    }

    let hash = blake3_hash(&genesis_bytes);
    let hash_hex = to_hex(&hash);

    println!("Total Ukuran Biner : {} bytes", genesis_bytes.len());
    println!("BLAKE3 Hash (hex)  : {}", hash_hex);
    println!("Display Hash       : {}", to_display_hash(&hash));
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    let output_path = "genesis.bin";
    match fs::write(output_path, &genesis_bytes) {
        Ok(_) => println!(
            "✅ Genesis object ditulis dalam format biner ke: {}",
            output_path
        ),
        Err(e) => eprintln!("WARNING: Gagal tulis file: {}", e),
    }

    println!("\nUpdate CANONICAL_HASH di source code Anda dengan nilai BLAKE3 Hash di atas sebelum meluncurkan Mainnet.");
}

fn cmd_verify(path: &str) {
    let bytes = fs::read(path).unwrap_or_else(|e| {
        eprintln!("ERROR: Tidak bisa baca file '{}': {}", path, e);
        process::exit(1);
    });

    let hash = blake3_hash(&bytes);

    println!("Verifikasi File: {}", path);
    println!("Ukuran : {} bytes", bytes.len());
    println!("Hash   : {}", to_hex(&hash));

    if hash == CANONICAL_HASH {
        println!("✅ VALID — BLAKE3(genesis) == CANONICAL_HASH");
    } else {
        println!("❌ MISMATCH — BLAKE3(genesis) ≠ CANONICAL_HASH");
        println!("(Atau CANONICAL_HASH di kode ini masih placeholder)");
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("generate") => {
            let pubkey = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
            cmd_generate(pubkey);
        }
        Some("verify") => {
            let path = args.get(2).map(String::as_str).unwrap_or("genesis.bin");
            cmd_verify(path);
        }
        _ => {
            println!("Usage:");
            println!("  genesis-tool generate <pubkey_hex>  — buat genesis.bin");
            println!("  genesis-tool verify [file.bin]      — verifikasi genesis");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_binary_length() {
        // Pubkey dummy 32 byte
        let dummy_pubkey = vec![0u8; 32];
        let bytes = generate_genesis_bytes(1600000000, &dummy_pubkey);
        assert_eq!(
            bytes.len(),
            177 + 32,
            "Panjang byte harus tepat 177 + panjang pubkey"
        );
        assert!(
            bytes.len() < 1024,
            "Harus kurang dari 1KB sesuai Spec 12.10"
        );
    }
}
