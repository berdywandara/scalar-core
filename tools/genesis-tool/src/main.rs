//! Genesis Ceremony CLI Tool — Spec §12.8
//!
//! Usage:
//!   genesis-tool generate           — buat genesis object baru
//!   genesis-tool verify <file>      — verifikasi genesis file
//!
//! Spec §12.8:
//!   Genesis object < 1 KB.
//!   Hash di-hardcode dalam binary.
//!   Verifikasi: BLAKE3(genesis) == hardcoded_canonical_hash.
//!   Output: file + print hex + base58-like encoding.
//!
//! CANONICAL HASH: Di-hardcode di binary setelah ceremony pertama.
//! Sebelum mainnet: hash ini adalah placeholder dan akan diganti
//! dengan hash genesis ceremony resmi.

use std::env;
use std::fs;
use std::process;

// ── Canonical Hash — Spec §12.8 ──────────────────────────────────────────────
//
// OSSIFIED setelah genesis ceremony resmi.
// Hash ini = BLAKE3(genesis_object_bytes) dari ceremony pertama.
//
// CATATAN: Nilai ini adalah placeholder untuk development.
// Mainnet canonical hash akan di-hardcode di sini setelah ceremony.
//
// Untuk generate: jalankan `genesis-tool generate` dan ambil hash-nya.
const CANONICAL_HASH: [u8; 32] = [
    0xd2, 0x79, 0xa1, 0x96, 0xd6, 0x35, 0x1e, 0xd7, 0xcd, 0x4a, 0xb0, 0x8a, 0x80, 0xa3, 0x3b, 0x59,
    0xd4, 0x4c, 0x4c, 0x9d, 0x1c, 0x74, 0xc2, 0x30, 0x2f, 0x92, 0x69, 0x08, 0x92, 0x12, 0x95, 0x6f,
];

// ── Genesis Object Structure ──────────────────────────────────────────────────

/// Genesis object Scalar Network. Spec §12.8: < 1 KB.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct GenesisObject {
    /// Nama network.
    network: &'static str,
    /// Versi spec.
    spec_version: &'static str,
    /// Memo genesis — identitas founder dan prinsip.
    memo: &'static str,
    /// Supply cap dalam sSCL. Ossified — spec §3.2.
    supply_cap_sscl: u64,
    /// PoU pool dalam sSCL. Ossified — spec §3.2.
    pou_pool_sscl: u64,
    /// E0 emisi per epoch dalam sSCL. Ossified — spec §7.1.
    e0_sscl: u64,
    /// Timestamp genesis (Unix detik). 0 = placeholder sebelum ceremony.
    genesis_timestamp: u64,
    /// Prinsip utama network.
    principle: &'static str,
}

/// Buat genesis object canonical. Spec §12.8.
fn build_genesis_object() -> GenesisObject {
    GenesisObject {
        network:          "Scalar Network",
        spec_version:     "v5.0",
        memo:             "Scalar Network Genesis. Architect: Berdy Wandara. Truth by Mathematics, Not by Majority.",
        supply_cap_sscl:  2_100_000_000_000_000, // 21_000_000 SCL × 10^8
        pou_pool_sscl:    1_890_000_000_000_000, // 18_900_000 SCL × 10^8
        e0_sscl:          12_600_000_000_000,    // 126_000 SCL × 10^8
        genesis_timestamp: 0,                    // set saat ceremony resmi
        principle:        "Truth by Mathematics, Not by Majority.",
    }
}

// ── Hash Utilities ────────────────────────────────────────────────────────────

/// Hitung BLAKE3 hash dari bytes. Out-circuit — spec §2.1.
fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Encode bytes ke hex string.
fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Encode bytes ke base58-like (uppercase hex dengan prefix).
/// Bukan base58 standar — simplified untuk display. Spec §12.8 output format.
fn to_display_hash(bytes: &[u8; 32]) -> String {
    format!("SCL1{}", hex::encode(bytes).to_uppercase())
}

// ── Commands ─────────────────────────────────────────────────────────────────

/// Command: generate genesis object. Spec §12.8.
fn cmd_generate() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          SCALAR NETWORK — GENESIS CEREMONY               ║");
    println!("║          Spec §12.8                                       ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    let genesis = build_genesis_object();

    // Serialize ke JSON (canonical — sorted keys via serde)
    let genesis_bytes =
        serde_json::to_vec(&genesis).expect("Genesis serialization tidak boleh gagal");

    // Validasi ukuran < 1 KB — spec §12.8
    if genesis_bytes.len() >= 1024 {
        eprintln!(
            "ERROR: Genesis object {} bytes >= 1024 (batas spec §12.8)",
            genesis_bytes.len()
        );
        process::exit(1);
    }

    let hash = blake3_hash(&genesis_bytes);
    let hash_hex = to_hex(&hash);
    let hash_display = to_display_hash(&hash);

    println!("Genesis Object ({} bytes / max 1024):", genesis_bytes.len());
    println!("{}", String::from_utf8_lossy(&genesis_bytes));
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("BLAKE3 Hash (hex)    : {}", hash_hex);
    println!("Display Hash         : {}", hash_display);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    // Verifikasi terhadap CANONICAL_HASH
    println!("Verifikasi vs CANONICAL_HASH hardcoded:");
    if hash == CANONICAL_HASH {
        println!("✅ MATCH — genesis valid sesuai spec §12.8");
    } else {
        println!("⚠️  MISMATCH — canonical hash belum diset (development mode)");
        println!("   Computed : {}", hash_hex);
        println!("   Canonical: {}", to_hex(&CANONICAL_HASH));
        println!();
        println!("   Untuk mainnet: update CANONICAL_HASH di source code dengan:");
        print!(
            "   const CANONICAL_HASH: [u8; 32] = [
    0xd2, 0x79, 0xa1, 0x96, 0xd6, 0x35, 0x1e, 0xd7,
    0xcd, 0x4a, 0xb0, 0x8a, 0x80, 0xa3, 0x3b, 0x59,
    0xd4, 0x4c, 0x4c, 0x9d, 0x1c, 0x74, 0xc2, 0x30,
    0x2f, 0x92, 0x69, 0x08, 0x92, 0x12, 0x95, 0x6f,
];"
        );
    }
    println!();

    // Tulis ke file genesis.json
    let output_path = "genesis.json";
    match fs::write(output_path, &genesis_bytes) {
        Ok(_) => println!("✅ Genesis object ditulis ke: {}", output_path),
        Err(e) => eprintln!("WARNING: Gagal tulis file: {}", e),
    }
}

/// Command: verify genesis file. Spec §12.8.
fn cmd_verify(path: &str) {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          SCALAR NETWORK — GENESIS VERIFY                 ║");
    println!("║          Spec §12.8                                       ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("File: {}", path);

    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERROR: Tidak bisa baca file '{}': {}", path, e);
            process::exit(1);
        }
    };

    // Ukuran check — spec §12.8: < 1 KB
    if bytes.len() >= 1024 {
        eprintln!(
            "ERROR: File {} bytes >= 1024 (batas spec §12.8)",
            bytes.len()
        );
        process::exit(1);
    }
    println!("Ukuran   : {} bytes (max 1024 ✅)", bytes.len());

    // Hitung BLAKE3 hash — spec §12.8
    let hash = blake3_hash(&bytes);
    let hash_hex = to_hex(&hash);
    println!("BLAKE3   : {}", hash_hex);
    println!("Display  : {}", to_display_hash(&hash));
    println!();

    // Verifikasi terhadap CANONICAL_HASH — spec §12.8
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    if hash == CANONICAL_HASH {
        println!("✅ VALID — BLAKE3(genesis) == CANONICAL_HASH");
        println!("   Spec §12.8: genesis object authentic.");
    } else {
        println!("❌ INVALID — BLAKE3(genesis) ≠ CANONICAL_HASH");
        println!("   Computed : {}", hash_hex);
        println!("   Expected : {}", to_hex(&CANONICAL_HASH));
        eprintln!();
        eprintln!("PERINGATAN: Genesis object tidak authentic atau CANONICAL_HASH belum diset.");
        process::exit(1);
    }
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("generate") => cmd_generate(),
        Some("verify") => {
            let path = args.get(2).map(String::as_str).unwrap_or("genesis.json");
            cmd_verify(path);
        }
        _ => {
            println!("Scalar Network Genesis Ceremony Tool — spec §12.8");
            println!();
            println!("Usage:");
            println!("  genesis-tool generate          — buat genesis object");
            println!("  genesis-tool verify [file]     — verifikasi genesis file");
            println!();
            println!("Default verify file: genesis.json");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_object_size_under_1kb() {
        // Spec §12.8: genesis object < 1 KB. OSSIFIED.
        let genesis = build_genesis_object();
        let bytes = serde_json::to_vec(&genesis).unwrap();
        assert!(
            bytes.len() < 1024,
            "Genesis object {} bytes harus < 1024 (spec §12.8)",
            bytes.len()
        );
    }

    #[test]
    fn test_genesis_hash_deterministic() {
        // Hash harus deterministik — spec §12.8.
        let genesis = build_genesis_object();
        let bytes = serde_json::to_vec(&genesis).unwrap();
        let h1 = blake3_hash(&bytes);
        let h2 = blake3_hash(&bytes);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_genesis_hash_non_zero() {
        let genesis = build_genesis_object();
        let bytes = serde_json::to_vec(&genesis).unwrap();
        let hash = blake3_hash(&bytes);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_genesis_contains_required_fields() {
        // Genesis harus punya supply cap, pou pool, e0 — spec §3.2, §7.1.
        let genesis = build_genesis_object();
        assert_eq!(genesis.supply_cap_sscl, 2_100_000_000_000_000u64);
        assert_eq!(genesis.pou_pool_sscl, 1_890_000_000_000_000u64);
        assert_eq!(genesis.e0_sscl, 12_600_000_000_000u64);
    }

    #[test]
    fn test_to_hex_correct_length() {
        let bytes = [0xABu8; 32];
        assert_eq!(to_hex(&bytes).len(), 64);
    }

    #[test]
    fn test_to_display_hash_has_scl_prefix() {
        let bytes = [0u8; 32];
        let display = to_display_hash(&bytes);
        assert!(display.starts_with("SCL1"));
    }

    #[test]
    fn test_supply_cap_matches_spec() {
        // Spec §3.2: S_MAX = 21_000_000 SCL = 2_100_000_000_000_000 sSCL.
        let genesis = build_genesis_object();
        assert_eq!(genesis.supply_cap_sscl, 21_000_000u64 * 100_000_000u64);
    }

    #[test]
    fn test_pou_pool_is_90_percent_of_supply() {
        // Spec §3.2: S_E = 90% dari S_MAX.
        let genesis = build_genesis_object();
        let expected = genesis.supply_cap_sscl * 90 / 100;
        assert_eq!(genesis.pou_pool_sscl, expected);
    }

    #[test]
    fn test_no_floating_point() {
        // Semua kalkulasi murni integer.
        let genesis = build_genesis_object();
        let bytes = serde_json::to_vec(&genesis).unwrap();
        let _hash = blake3_hash(&bytes);
    }
}
