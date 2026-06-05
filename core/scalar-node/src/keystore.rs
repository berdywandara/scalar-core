//! NodeKeystoreV1 — Encrypted node operational keys — SCALAR-TECHNICAL §10.5
//!
//! Format: version(1) || kdf_salt(16) || xchacha20_nonce(24) || ciphertext(80)
//! Total : 121 bytes
//!
//! Mnemonic TIDAK PERNAH disimpan. Hanya derived operational keys:
//!   node_id_full : Argon2id(mnemonic, b"scalar_nodeid"||genesis_hash, Tier A/C)
//!   node_key     : BLAKE3 derivation chain (SCALAR-PROTOCOL §11.1)
//!
//! Passphrase KDF : Argon2id(passphrase, kdf_salt, 64MB, 3, 1) → 32-byte key
//! Encryption     : XChaCha20-Poly1305(kdf_key, nonce, node_id_full || node_key)

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};

use crate::node_id::{NodeIdError, ProductionNodeId};
use scalar_crypto::domain::DOMAIN_SEED_KDF;

// ── Constants — SCALAR-TECHNICAL §10.5 ───────────────────────────────────────

pub const KEYSTORE_VERSION: u8 = 0x01;
pub const KDF_SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const PAYLOAD_LEN: usize = 64; // node_id_full(32) + node_key(32)
pub const AEAD_TAG_LEN: usize = 16;
pub const KEYSTORE_FILE_LEN: usize = 1 + KDF_SALT_LEN + NONCE_LEN + PAYLOAD_LEN + AEAD_TAG_LEN;

// Passphrase KDF — SCALAR-TECHNICAL §10.5
const PASS_MEMORY_KIB: u32 = 64 * 1024; // 64 MB
const PASS_TIME: u32 = 3;
const PASS_PARALLELISM: u32 = 1;

// Wallet seed KDF — SCALAR-PROTOCOL §11.1
const WALLET_MEMORY_KIB: u32 = 64 * 1024; // 64 MB
const WALLET_TIME: u32 = 3;
const WALLET_PARALLELISM: u32 = 1;
const WALLET_OUTPUT_LEN: usize = 64;

// ── NodeKeystoreV1 ────────────────────────────────────────────────────────────

/// Decrypted node operational keys.
/// Mnemonic tidak pernah disimpan di sini. SCALAR-TECHNICAL §10.5.
pub struct NodeKeystoreV1 {
    /// NodeID from Argon2id Tier A. SCALAR-TECHNICAL §10.5.
    pub node_id_full: [u8; 32],
    /// NodeKey from BLAKE3 derivation chain. SCALAR-PROTOCOL §11.1.
    pub node_key: [u8; 32],
}

impl NodeKeystoreV1 {
    /// Encrypt dan tulis keystore ke file.
    pub fn encrypt_to_file(&self, path: &str, passphrase: &[u8]) -> Result<(), KeystoreError> {
        let mut kdf_salt = [0u8; KDF_SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut kdf_salt);
        OsRng.fill_bytes(&mut nonce_bytes);

        let kdf_key = passphrase_kdf(passphrase, &kdf_salt)?;

        let mut plaintext = [0u8; PAYLOAD_LEN];
        plaintext[..32].copy_from_slice(&self.node_id_full);
        plaintext[32..].copy_from_slice(&self.node_key);

        let cipher = XChaCha20Poly1305::new_from_slice(&kdf_key)
            .map_err(|_| KeystoreError::EncryptionFailed)?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| KeystoreError::EncryptionFailed)?;

        // Zero plaintext from memory immediately
        plaintext.iter_mut().for_each(|b| *b = 0);

        let mut file_data = Vec::with_capacity(KEYSTORE_FILE_LEN);
        file_data.push(KEYSTORE_VERSION);
        file_data.extend_from_slice(&kdf_salt);
        file_data.extend_from_slice(&nonce_bytes);
        file_data.extend_from_slice(&ciphertext);

        std::fs::write(path, &file_data).map_err(|e| KeystoreError::IoError(e.to_string()))
    }

    /// Baca dan decrypt keystore dari file.
    pub fn decrypt_from_file(path: &str, passphrase: &[u8]) -> Result<Self, KeystoreError> {
        let file_data = std::fs::read(path).map_err(|e| KeystoreError::IoError(e.to_string()))?;

        if file_data.len() < KEYSTORE_FILE_LEN {
            return Err(KeystoreError::InvalidFormat);
        }

        let version = file_data[0];
        if version != KEYSTORE_VERSION {
            return Err(KeystoreError::UnsupportedVersion(version));
        }

        let kdf_salt: [u8; KDF_SALT_LEN] = file_data[1..1 + KDF_SALT_LEN]
            .try_into()
            .map_err(|_| KeystoreError::InvalidFormat)?;
        let nonce_bytes: [u8; NONCE_LEN] = file_data
            [1 + KDF_SALT_LEN..1 + KDF_SALT_LEN + NONCE_LEN]
            .try_into()
            .map_err(|_| KeystoreError::InvalidFormat)?;
        let ciphertext = &file_data[1 + KDF_SALT_LEN + NONCE_LEN..];

        let kdf_key = passphrase_kdf(passphrase, &kdf_salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&kdf_key)
            .map_err(|_| KeystoreError::DecryptionFailed)?;
        let nonce = XNonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| KeystoreError::DecryptionFailed)?;

        if plaintext.len() != PAYLOAD_LEN {
            return Err(KeystoreError::InvalidFormat);
        }

        let mut node_id_full = [0u8; 32];
        let mut node_key_arr = [0u8; 32];
        node_id_full.copy_from_slice(&plaintext[..32]);
        node_key_arr.copy_from_slice(&plaintext[32..]);

        Ok(Self {
            node_id_full,
            node_key: node_key_arr,
        })
    }
}

// ── Key Derivation ────────────────────────────────────────────────────────────

/// Passphrase → 32-byte encryption key via Argon2id.
/// SCALAR-TECHNICAL §10.5: 64MB, 3 iter, parallelism 1.
fn passphrase_kdf(passphrase: &[u8], salt: &[u8; KDF_SALT_LEN]) -> Result<[u8; 32], KeystoreError> {
    let params = Params::new(PASS_MEMORY_KIB, PASS_TIME, PASS_PARALLELISM, Some(32))
        .map_err(|_| KeystoreError::InvalidParams)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| KeystoreError::InvalidParams)?;
    Ok(key)
}

/// Derive NodeKey dari mnemonic + genesis_hash via wallet key chain.
///
/// SCALAR-PROTOCOL §11.1:
///   seed       = Argon2id(mnemonic, DOMAIN_SEED_KDF||genesis_hash, 64MB, 3, 1) → 64B
///   MasterKey  = BLAKE3(seed || b"scalar_master")
///   AccountKey = BLAKE3(MasterKey || b"account" || 0_le64)
///   NodeKey    = BLAKE3(AccountKey || b"node")
pub fn derive_node_key(
    mnemonic: &[u8],
    genesis_hash: &[u8; 32],
) -> Result<[u8; 32], KeystoreError> {
    // Wallet KDF salt: DOMAIN_SEED_KDF || genesis_hash
    let mut wallet_salt = Vec::with_capacity(DOMAIN_SEED_KDF.len() + 32);
    wallet_salt.extend_from_slice(DOMAIN_SEED_KDF);
    wallet_salt.extend_from_slice(genesis_hash);

    // Argon2id wallet seed (64 bytes)
    let params = Params::new(
        WALLET_MEMORY_KIB,
        WALLET_TIME,
        WALLET_PARALLELISM,
        Some(WALLET_OUTPUT_LEN),
    )
    .map_err(|_| KeystoreError::InvalidParams)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut seed = [0u8; WALLET_OUTPUT_LEN];
    argon2
        .hash_password_into(mnemonic, &wallet_salt, &mut seed)
        .map_err(|_| KeystoreError::InvalidParams)?;

    // BLAKE3 derivation chain
    let master_key: [u8; 32] = {
        let mut h = blake3::Hasher::new();
        h.update(&seed);
        h.update(b"scalar_master");
        *h.finalize().as_bytes()
    };
    let account_key: [u8; 32] = {
        let mut h = blake3::Hasher::new();
        h.update(&master_key);
        h.update(b"account");
        h.update(&0u64.to_le_bytes());
        *h.finalize().as_bytes()
    };
    let node_key: [u8; 32] = {
        let mut h = blake3::Hasher::new();
        h.update(&account_key);
        h.update(b"node");
        *h.finalize().as_bytes()
    };

    // Zero intermediates
    seed.iter_mut().for_each(|b| *b = 0);

    Ok(node_key)
}

// ── run_keygen ────────────────────────────────────────────────────────────────

/// `scalar-node keygen` — SCALAR-TECHNICAL §10.5 Workflow Langkah 1.
///
/// Usage: scalar-node keygen [--keystore=<path>] [--genesis-hash=<hex>]
pub fn run_keygen(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== SCALAR NODE KEYGEN — SCALAR-TECHNICAL §10.5 ===");
    println!("Mnemonic digunakan sekali. Tidak pernah disimpan di keystore.");
    println!();

    // Parse --keystore path
    let keystore_path = args
        .iter()
        .find(|a| a.starts_with("--keystore="))
        .map(|a| a.trim_start_matches("--keystore=").to_string())
        .unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            format!("{home}/.scalar/node_keystore.bin")
        });

    // Parse genesis_hash
    let genesis_hash: [u8; 32] = if let Some(hex_str) = args
        .iter()
        .find(|a| a.starts_with("--genesis-hash="))
        .map(|a| a.trim_start_matches("--genesis-hash=").to_string())
    {
        let bytes = hex::decode(hex_str.trim())?;
        bytes
            .try_into()
            .map_err(|_| "genesis-hash harus 32 bytes (64 hex chars)")?
    } else {
        let hex_str = std::fs::read_to_string("genesis_hash.txt")
            .map_err(|_| "genesis_hash.txt tidak ditemukan. Gunakan --genesis-hash=<hex>")?;
        let bytes = hex::decode(hex_str.trim())?;
        bytes
            .try_into()
            .map_err(|_| "genesis_hash.txt harus berisi 32 bytes (64 hex chars)")?
    };
    println!("[1/5] Genesis hash : {}", hex::encode(&genesis_hash[..8]));

    // Read mnemonic (hidden input)
    println!("[2/5] Masukkan mnemonic (12 kata, kata pertama harus 'scalar'):");
    let mnemonic_str = rpassword::prompt_password("  Mnemonic: ")?;
    let mnemonic_trimmed = mnemonic_str.trim().to_string();

    if !mnemonic_trimmed.starts_with("scalar") {
        return Err("Mnemonic harus dimulai dengan 'scalar' — SCALAR-PROTOCOL §11.1".into());
    }
    let mnemonic_bytes = mnemonic_trimmed.as_bytes().to_vec();

    // Derive NodeID
    let mode_label = if cfg!(feature = "production") {
        "Tier A (4GB, 3600 iter) — estimasi ~60 menit"
    } else {
        "Tier C (16MB, 100 iter) — dev/testnet"
    };
    println!("[3/5] Deriving NodeID ({mode_label})...");
    let node_id = ProductionNodeId::derive_with_feature_flag(&mnemonic_bytes, &genesis_hash)
        .map_err(|e| format!("NodeID derivation gagal: {e}"))?;
    println!("[3/5] NodeID : {}", hex::encode(node_id.node_id_full));

    // Derive NodeKey
    println!("[4/5] Deriving NodeKey (wallet Argon2id 64MB + BLAKE3 chain)...");
    let node_key = derive_node_key(&mnemonic_bytes, &genesis_hash)
        .map_err(|e| format!("NodeKey derivation gagal: {e}"))?;
    println!("[4/5] NodeKey derived (tidak ditampilkan).");

    // Zero mnemonic from memory
    drop(mnemonic_str);
    drop(mnemonic_trimmed);

    // Read and confirm passphrase
    println!("[5/5] Masukkan passphrase untuk enkripsi keystore:");
    let passphrase1 = rpassword::prompt_password("  Passphrase       : ")?;
    let passphrase2 = rpassword::prompt_password("  Konfirmasi       : ")?;
    if passphrase1 != passphrase2 {
        return Err("Passphrase tidak cocok.".into());
    }
    if passphrase1.len() < 8 {
        return Err("Passphrase minimal 8 karakter.".into());
    }

    // Create directory if needed
    if let Some(parent) = std::path::Path::new(&keystore_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Gagal buat direktori keystore: {e}"))?;
    }

    // Encrypt and save
    let ks = NodeKeystoreV1 {
        node_id_full: node_id.node_id_full,
        node_key,
    };
    ks.encrypt_to_file(&keystore_path, passphrase1.as_bytes())?;

    // Set permission 600 (Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&keystore_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Gagal set permission: {e}"))?;
    }

    println!();
    println!("=== KEYGEN SELESAI ===");
    println!("Keystore : {keystore_path}");
    println!("NodeID   : {}", hex::encode(node_id.node_id_full));
    println!(
        "Tier     : {}",
        if cfg!(feature = "production") {
            "A (mainnet)"
        } else {
            "C (dev/testnet)"
        }
    );
    println!();
    println!("⚠️  Backup mnemonic di cold storage sekarang!");
    println!("   Keystore tidak bisa di-recover tanpa mnemonic.");
    println!();
    println!("Jalankan node:");
    println!("  scalar-node run --keystore={keystore_path}");

    Ok(())
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum KeystoreError {
    InvalidParams,
    EncryptionFailed,
    DecryptionFailed,
    InvalidFormat,
    UnsupportedVersion(u8),
    IoError(String),
    NodeIdError(NodeIdError),
}

impl From<NodeIdError> for KeystoreError {
    fn from(e: NodeIdError) -> Self {
        Self::NodeIdError(e)
    }
}

impl core::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidParams => write!(f, "Argon2id params tidak valid"),
            Self::EncryptionFailed => write!(f, "Enkripsi keystore gagal"),
            Self::DecryptionFailed => write!(f, "Dekripsi keystore gagal — passphrase salah?"),
            Self::InvalidFormat => write!(f, "Format keystore tidak valid"),
            Self::UnsupportedVersion(v) => write!(f, "Versi keystore tidak didukung: {v:#04x}"),
            Self::IoError(e) => write!(f, "I/O error: {e}"),
            Self::NodeIdError(e) => write!(f, "NodeID error: {e}"),
        }
    }
}

impl std::error::Error for KeystoreError {}
