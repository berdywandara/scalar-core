//! Seed Derivation — SCL-SPEC-SEED-001 §3.1 (menggantikan §13.1 Master Spec v7.0)
//!
//! Full key derivation chain dari mnemonic:
//!
//!   seed = Argon2id(
//!       password = UTF8(mnemonic),
//!       salt     = b"scalar_wallet_kdf" || genesis_hash,
//!       m        = 65536 KiB (64 MB),
//!       t        = 3,
//!       p        = 1,
//!       len      = 64 bytes
//!   )
//!   MasterKey    = BLAKE3(seed || "scalar_master")
//!   AccountKey_i = BLAKE3(MasterKey || "account" || i_le64)
//!   SpendKey     = BLAKE3(AccountKey || "spend")
//!   ViewKey      = BLAKE3(AccountKey || "view")
//!   NodeKey      = BLAKE3(AccountKey || "node")
//!   DuressKey    = BLAKE3(AccountKey || "duress" || index_le64)
//!   GovernanceID = BLAKE3(ViewKey || "governance_scalar_v1")
//!
//! OSSIFIED (SCL-SPEC-SEED-001 §8.1):
//! - KDF: Argon2id (RFC 9106)
//! - memory: 65536 KiB = 64 MB (minimum absolut)
//! - iterations: 3 (minimum absolut)
//! - parallelism: 1
//! - output: 64 bytes
//! - salt prefix: b"scalar_wallet_kdf"
//! - SEED_VERSION: 0x02
//! - Kata pertama mnemonic WAJIB "scalar"

use argon2::{Algorithm, Argon2, Params, Version};
use blake3::Hasher;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Ossified Constants — SCL-SPEC-SEED-001 §8.1 ──────────────────────────────

/// Memory Argon2id dalam KiB (64 MB). OSSIFIED — SCL-SPEC-SEED-001 §8.1.
pub const SEED_ARGON2_MEMORY_KIB: u32 = 65536;

/// Iterasi Argon2id. OSSIFIED — SCL-SPEC-SEED-001 §8.1.
pub const SEED_ARGON2_ITERATIONS: u32 = 3;

/// Parallelism Argon2id. OSSIFIED — SCL-SPEC-SEED-001 §8.1.
pub const SEED_ARGON2_PARALLEL: u32 = 1;

/// Output length Argon2id dalam bytes. OSSIFIED — SCL-SPEC-SEED-001 §8.1.
pub const SEED_ARGON2_OUTPUT_LEN: usize = 64;

/// Salt prefix versi v2. OSSIFIED — SCL-SPEC-SEED-001 §8.1.
pub const SEED_SALT_PREFIX: &[u8] = b"scalar_wallet_kdf";

/// Versi seed derivation. OSSIFIED — SCL-SPEC-SEED-001 §8.1.
pub const SEED_VERSION: u8 = 0x02;

/// Kata pertama mnemonic yang wajib. OSSIFIED — §13.1.
pub const MNEMONIC_FIRST_WORD: &str = "scalar";

/// Domain separator MasterKey. OSSIFIED — §13.1.
pub const MASTER_KEY_DOMAIN: &[u8] = b"scalar_master";

/// Domain separator AccountKey. OSSIFIED — §13.1.
pub const ACCOUNT_KEY_DOMAIN: &[u8] = b"account";

/// Domain separator SpendKey. OSSIFIED — §13.1.
pub const SPEND_KEY_DOMAIN: &[u8] = b"spend";

/// Domain separator ViewKey. OSSIFIED — §13.1.
pub const VIEW_KEY_DOMAIN: &[u8] = b"view";

/// Domain separator NodeKey. OSSIFIED — §13.1.
pub const NODE_KEY_DOMAIN: &[u8] = b"node";

/// Domain separator DuressKey. OSSIFIED — §13.1.
pub const DURESS_KEY_DOMAIN: &[u8] = b"duress";

/// Domain separator GovernanceID. OSSIFIED — §13.1.
pub const GOVERNANCE_ID_DOMAIN: &[u8] = b"governance_scalar_v1";

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error derivasi seed. SCL-SPEC-SEED-001 §3.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedError {
    /// Kata pertama mnemonic bukan "scalar". §13.1.
    InvalidMnemonicFirstWord,
    /// Mnemonic kosong.
    EmptyMnemonic,
    /// Argon2 parameter error.
    Argon2Params(argon2::Error),
    /// Argon2 hash error (hash_password_into).
    Argon2Hash(argon2::Error),
}

impl core::fmt::Display for SeedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidMnemonicFirstWord => {
                write!(f, "Kata pertama mnemonic harus 'scalar' — §13.1")
            }
            Self::EmptyMnemonic => write!(f, "Mnemonic tidak boleh kosong"),
            Self::Argon2Params(e) => write!(f, "Argon2 params error: {e}"),
            Self::Argon2Hash(e) => write!(f, "Argon2 hash error: {e}"),
        }
    }
}

// ── SeedMaterial — zeroized on drop ──────────────────────────────────────────

/// Hasil derivasi seed. Di-zeroize saat di-drop. SCL-SPEC-SEED-001 §3.1.
///
/// seed: 64 bytes (Argon2id output — SCL-SPEC-SEED-001 §8.1)
/// master_key: 32 bytes (BLAKE3)
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SeedMaterial {
    /// seed = Argon2id(mnemonic, salt, m=65536, t=3, p=1, len=64)
    /// SCL-SPEC-SEED-001 §3.1
    pub seed: [u8; 64],
    /// MasterKey = BLAKE3(seed || "scalar_master") — §13.1
    pub master_key: [u8; 32],
}

// ── Derivation Functions ──────────────────────────────────────────────────────

/// Validasi mnemonic — kata pertama WAJIB "scalar". §13.1.
pub fn validate_mnemonic(mnemonic: &str) -> Result<(), SeedError> {
    let first_word = mnemonic
        .split_whitespace()
        .next()
        .ok_or(SeedError::EmptyMnemonic)?;
    if first_word != MNEMONIC_FIRST_WORD {
        return Err(SeedError::InvalidMnemonicFirstWord);
    }
    Ok(())
}

/// Derive seed dari mnemonic menggunakan Argon2id. SCL-SPEC-SEED-001 §3.1.
///
/// seed = Argon2id(
///     password = UTF8(mnemonic),
///     salt     = b"scalar_wallet_kdf" || genesis_hash,
///     m        = 65536, t = 3, p = 1, len = 64
/// )
///
/// Kata pertama mnemonic WAJIB "scalar".
/// genesis_hash = BLAKE3(genesis_object) — §12.9.
pub fn derive_seed(mnemonic: &str, genesis_hash: &[u8; 32]) -> Result<SeedMaterial, SeedError> {
    validate_mnemonic(mnemonic)?;

    // Konstruksi salt: b"scalar_wallet_kdf" || genesis_hash = 49 bytes
    // SCL-SPEC-SEED-001 §3.3
    let mut salt = [0u8; 49];
    salt[..17].copy_from_slice(SEED_SALT_PREFIX);
    salt[17..].copy_from_slice(genesis_hash);

    // Parameter Argon2id — OSSIFIED SCL-SPEC-SEED-001 §8.1
    let params = Params::new(
        SEED_ARGON2_MEMORY_KIB,
        SEED_ARGON2_ITERATIONS,
        SEED_ARGON2_PARALLEL,
        Some(SEED_ARGON2_OUTPUT_LEN),
    )
    .map_err(SeedError::Argon2Params)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut seed = [0u8; 64];
    argon2
        .hash_password_into(mnemonic.as_bytes(), &salt, &mut seed)
        .map_err(SeedError::Argon2Hash)?;

    // MasterKey = BLAKE3(seed || "scalar_master") — §13.1
    let mut hasher = Hasher::new();
    hasher.update(&seed);
    hasher.update(MASTER_KEY_DOMAIN);
    let master_key = *hasher.finalize().as_bytes();

    Ok(SeedMaterial { seed, master_key })
}

/// Derive AccountKey_i dari MasterKey. §13.1.
///
/// AccountKey_i = BLAKE3(MasterKey || "account" || i_le64)
pub fn derive_account_key(master_key: &[u8; 32], account_index: u64) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(master_key);
    hasher.update(ACCOUNT_KEY_DOMAIN);
    hasher.update(&account_index.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Derive SpendKey dari AccountKey. §13.1.
pub fn derive_spend_key(account_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(account_key);
    hasher.update(SPEND_KEY_DOMAIN);
    *hasher.finalize().as_bytes()
}

/// Derive ViewKey dari AccountKey. §13.1.
pub fn derive_view_key(account_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(account_key);
    hasher.update(VIEW_KEY_DOMAIN);
    *hasher.finalize().as_bytes()
}

/// Derive NodeKey dari AccountKey. §13.1. TERPISAH dari SpendKey by design.
pub fn derive_node_key(account_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(account_key);
    hasher.update(NODE_KEY_DOMAIN);
    *hasher.finalize().as_bytes()
}

/// Derive DuressKey dari AccountKey. §13.1.
pub fn derive_duress_key(account_key: &[u8; 32], index: u64) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(account_key);
    hasher.update(DURESS_KEY_DOMAIN);
    hasher.update(&index.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Derive GovernanceID dari ViewKey. §13.1.
pub fn derive_governance_id(view_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(view_key);
    hasher.update(GOVERNANCE_ID_DOMAIN);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// genesis_hash = [0x00; 32] untuk semua test (test vector, bukan mainnet).
    const TEST_GENESIS: [u8; 32] = [0u8; 32];

    // ── Konstanta OSSIFIED ────────────────────────────────────────────────────

    #[test]
    fn test_seed_argon2_memory_kib_ossified() {
        // SCL-SPEC-SEED-001 §8.1: memory = 65536 KiB. OSSIFIED.
        assert_eq!(SEED_ARGON2_MEMORY_KIB, 65536u32);
    }

    #[test]
    fn test_seed_argon2_iterations_ossified() {
        // SCL-SPEC-SEED-001 §8.1: iterations = 3. OSSIFIED.
        assert_eq!(SEED_ARGON2_ITERATIONS, 3u32);
    }

    #[test]
    fn test_seed_argon2_parallel_ossified() {
        // SCL-SPEC-SEED-001 §8.1: parallelism = 1. OSSIFIED.
        assert_eq!(SEED_ARGON2_PARALLEL, 1u32);
    }

    #[test]
    fn test_seed_argon2_output_len_ossified() {
        // SCL-SPEC-SEED-001 §8.1: output = 64 bytes. OSSIFIED.
        assert_eq!(SEED_ARGON2_OUTPUT_LEN, 64usize);
    }

    #[test]
    fn test_seed_salt_prefix_ossified() {
        // SCL-SPEC-SEED-001 §8.1: prefix = b"scalar_wallet_kdf". OSSIFIED.
        assert_eq!(SEED_SALT_PREFIX, b"scalar_wallet_kdf");
    }

    #[test]
    fn test_seed_version_ossified() {
        // SCL-SPEC-SEED-001 §8.1: SEED_VERSION = 0x02. OSSIFIED.
        assert_eq!(SEED_VERSION, 0x02u8);
    }

    #[test]
    fn test_salt_total_length() {
        // SCL-SPEC-SEED-001 §3.3: salt = 17 bytes prefix + 32 bytes genesis = 49 bytes.
        assert_eq!(SEED_SALT_PREFIX.len() + 32, 49);
    }

    #[test]
    fn test_mnemonic_first_word_ossified() {
        // §13.1: kata pertama WAJIB "scalar". OSSIFIED.
        assert_eq!(MNEMONIC_FIRST_WORD, "scalar");
    }

    // ── validate_mnemonic ─────────────────────────────────────────────────────

    #[test]
    fn test_valid_mnemonic_accepted() {
        assert!(validate_mnemonic("scalar test mnemonic words").is_ok());
    }

    #[test]
    fn test_invalid_first_word_rejected() {
        let err = validate_mnemonic("bitcoin test mnemonic").unwrap_err();
        assert_eq!(err, SeedError::InvalidMnemonicFirstWord);
    }

    #[test]
    fn test_empty_mnemonic_rejected() {
        let err = validate_mnemonic("").unwrap_err();
        assert_eq!(err, SeedError::EmptyMnemonic);
    }

    #[test]
    fn test_scalar_single_word_valid() {
        assert!(validate_mnemonic("scalar").is_ok());
    }

    // ── derive_seed ───────────────────────────────────────────────────────────

    #[test]
    fn test_derive_seed_deterministic() {
        let m1 = derive_seed("scalar test mnemonic", &TEST_GENESIS).unwrap();
        let m2 = derive_seed("scalar test mnemonic", &TEST_GENESIS).unwrap();
        assert_eq!(m1.seed, m2.seed);
        assert_eq!(m1.master_key, m2.master_key);
    }

    #[test]
    fn test_derive_seed_output_64_bytes() {
        // SCL-SPEC-SEED-001 §8.1: output = 64 bytes.
        let m = derive_seed("scalar test mnemonic", &TEST_GENESIS).unwrap();
        assert_eq!(m.seed.len(), 64);
    }

    #[test]
    fn test_derive_seed_different_mnemonics() {
        let m1 = derive_seed("scalar mnemonic one", &TEST_GENESIS).unwrap();
        let m2 = derive_seed("scalar mnemonic two", &TEST_GENESIS).unwrap();
        assert_ne!(m1.seed, m2.seed);
        assert_ne!(m1.master_key, m2.master_key);
    }

    #[test]
    fn test_derive_seed_rejects_wrong_first_word() {
        let err = derive_seed("wrong first word", &TEST_GENESIS).unwrap_err();
        assert_eq!(err, SeedError::InvalidMnemonicFirstWord);
    }

    #[test]
    fn test_derive_seed_different_genesis_hash() {
        // SCL-SPEC-SEED-001 §3.3: genesis_hash binding.
        let hash_a = [0x00u8; 32];
        let hash_b = [0x01u8; 32];
        let m1 = derive_seed("scalar test mnemonic", &hash_a).unwrap();
        let m2 = derive_seed("scalar test mnemonic", &hash_b).unwrap();
        assert_ne!(m1.seed, m2.seed);
    }

    #[test]
    fn test_seed_non_zero() {
        let m = derive_seed("scalar test mnemonic", &TEST_GENESIS).unwrap();
        assert_ne!(m.seed, [0u8; 64]);
    }

    #[test]
    fn test_master_key_non_zero() {
        let m = derive_seed("scalar test mnemonic", &TEST_GENESIS).unwrap();
        assert_ne!(m.master_key, [0u8; 32]);
    }

    // ── derive_account_key ────────────────────────────────────────────────────

    #[test]
    fn test_derive_account_key_deterministic() {
        let m = derive_seed("scalar test mnemonic", &TEST_GENESIS).unwrap();
        let a1 = derive_account_key(&m.master_key, 0);
        let a2 = derive_account_key(&m.master_key, 0);
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_derive_account_key_different_index() {
        let m = derive_seed("scalar test mnemonic", &TEST_GENESIS).unwrap();
        let a0 = derive_account_key(&m.master_key, 0);
        let a1 = derive_account_key(&m.master_key, 1);
        assert_ne!(a0, a1);
    }

    // ── full chain integration ────────────────────────────────────────────────

    #[test]
    fn test_full_key_chain_non_zero() {
        // §13.1: semua key dalam chain harus non-zero.
        let m = derive_seed("scalar integration test full chain", &TEST_GENESIS).unwrap();
        let account = derive_account_key(&m.master_key, 0);
        let spend = derive_spend_key(&account);
        let view = derive_view_key(&account);
        let node = derive_node_key(&account);
        let duress = derive_duress_key(&account, 0);
        let gov_id = derive_governance_id(&view);
        assert_ne!(spend, [0u8; 32]);
        assert_ne!(view, [0u8; 32]);
        assert_ne!(node, [0u8; 32]);
        assert_ne!(duress, [0u8; 32]);
        assert_ne!(gov_id, [0u8; 32]);
    }

    #[test]
    fn test_node_key_different_from_spend_key() {
        // §13.1: NodeKey TERPISAH dari SpendKey by design.
        let m = derive_seed("scalar integration test", &TEST_GENESIS).unwrap();
        let account = derive_account_key(&m.master_key, 0);
        let spend = derive_spend_key(&account);
        let node = derive_node_key(&account);
        assert_ne!(spend, node, "NodeKey harus berbeda dari SpendKey — §13.1");
    }

    #[test]
    fn test_governance_id_from_view_not_spend() {
        // §13.1: GovernanceID dari ViewKey, bukan SpendKey.
        let m = derive_seed("scalar integration test", &TEST_GENESIS).unwrap();
        let account = derive_account_key(&m.master_key, 0);
        let view = derive_view_key(&account);
        let spend = derive_spend_key(&account);
        let gov_from_view = derive_governance_id(&view);
        let gov_from_spend = derive_governance_id(&spend);
        assert_ne!(gov_from_view, gov_from_spend);
    }

    // ── test vector — SCL-SPEC-SEED-001 §6.3 ─────────────────────────────────
    // Vector di-generate dari implementasi ini (referensi pertama).
    // Harus diverifikasi implementasi kedua sebelum ossifikasi (§15).

    #[test]
    fn test_vector_spec_mnemonic_produces_64_bytes() {
        // SCL-SPEC-SEED-001 §6.3 test vector.
        let mnemonic =
            "scalar abandon ability able about above absent absorb abstract absurd abuse";
        let m = derive_seed(mnemonic, &TEST_GENESIS).unwrap();
        assert_eq!(m.seed.len(), 64);
        assert_ne!(m.seed, [0u8; 64]);
    }
}
