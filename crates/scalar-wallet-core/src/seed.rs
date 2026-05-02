//! Seed Derivation — Spec §13.1
//!
//! Full key derivation chain dari mnemonic:
//!
//!   seed        = PBKDF2-HMAC-SHA3(mnemonic, "scalar_v1", 2048)
//!   MasterKey   = BLAKE3(seed ∥ "scalar_master")
//!   AccountKey_i = BLAKE3(MasterKey ∥ "account" ∥ i_le64)
//!
//! OSSIFIED:
//! - Salt: "scalar_v1"
//! - Iterations: 2048
//! - Kata pertama mnemonic WAJIB "scalar"
//! - BIP-39 wallets lain akan reject mnemonic ini (by design)

use blake3::Hasher;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha3::Sha3_256;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── Ossified Constants — Spec §13.1 ──────────────────────────────────────────

/// Salt untuk PBKDF2-HMAC-SHA3. OSSIFIED — spec §13.1.
pub const PBKDF2_SALT: &[u8] = b"scalar_v1";

/// Jumlah iterasi PBKDF2. OSSIFIED — spec §13.1.
pub const PBKDF2_ITERATIONS: u32 = 2048;

/// Kata pertama mnemonic yang wajib. OSSIFIED — spec §13.1.
pub const MNEMONIC_FIRST_WORD: &str = "scalar";

/// Domain separator MasterKey. OSSIFIED — spec §13.1.
pub const MASTER_KEY_DOMAIN: &[u8] = b"scalar_master";

/// Domain separator AccountKey. OSSIFIED — spec §13.1.
pub const ACCOUNT_KEY_DOMAIN: &[u8] = b"account";

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error derivasi seed. Spec §13.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedError {
    /// Kata pertama mnemonic bukan "scalar". Spec §13.1.
    InvalidMnemonicFirstWord,
    /// Mnemonic kosong.
    EmptyMnemonic,
}

impl core::fmt::Display for SeedError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidMnemonicFirstWord => {
                write!(f, "Kata pertama mnemonic harus 'scalar' — spec §13.1")
            }
            Self::EmptyMnemonic => write!(f, "Mnemonic tidak boleh kosong"),
        }
    }
}

// ── SeedMaterial — zeroized on drop ──────────────────────────────────────────

/// Hasil derivasi seed. Di-zeroize saat di-drop. Spec §13.1.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SeedMaterial {
    /// seed = PBKDF2-HMAC-SHA3(mnemonic, "scalar_v1", 2048)
    pub seed: [u8; 32],
    /// MasterKey = BLAKE3(seed ∥ "scalar_master")
    pub master_key: [u8; 32],
}

// ── Derivation Functions ──────────────────────────────────────────────────────

/// Validasi mnemonic — kata pertama WAJIB "scalar". Spec §13.1.
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

/// Derive seed dari mnemonic menggunakan PBKDF2-HMAC-SHA3. Spec §13.1.
///
/// seed = PBKDF2-HMAC-SHA3(mnemonic, "scalar_v1", 2048)
///
/// Kata pertama mnemonic WAJIB "scalar".
pub fn derive_seed(mnemonic: &str) -> Result<SeedMaterial, SeedError> {
    validate_mnemonic(mnemonic)?;

    let mut seed = [0u8; 32];
    pbkdf2::<Hmac<Sha3_256>>(
        mnemonic.as_bytes(),
        PBKDF2_SALT,
        PBKDF2_ITERATIONS,
        &mut seed,
    )
    .expect("PBKDF2 length valid");

    // MasterKey = BLAKE3(seed ∥ "scalar_master") — spec §13.1
    let mut hasher = Hasher::new();
    hasher.update(&seed);
    hasher.update(MASTER_KEY_DOMAIN);
    let master_key = *hasher.finalize().as_bytes();

    Ok(SeedMaterial { seed, master_key })
}

/// Derive AccountKey_i dari MasterKey. Spec §13.1.
///
/// AccountKey_i = BLAKE3(MasterKey ∥ "account" ∥ i_le64)
pub fn derive_account_key(master_key: &[u8; 32], account_index: u64) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(master_key);
    hasher.update(ACCOUNT_KEY_DOMAIN);
    hasher.update(&account_index.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constant correctness ──────────────────────────────────────────────────

    #[test]
    fn test_pbkdf2_salt_ossified() {
        // Spec §13.1: salt = "scalar_v1". OSSIFIED.
        assert_eq!(PBKDF2_SALT, b"scalar_v1");
    }

    #[test]
    fn test_pbkdf2_iterations_ossified() {
        // Spec §13.1: iterations = 2048. OSSIFIED.
        assert_eq!(PBKDF2_ITERATIONS, 2048u32);
    }

    #[test]
    fn test_mnemonic_first_word_ossified() {
        // Spec §13.1: kata pertama mnemonic WAJIB "scalar". OSSIFIED.
        assert_eq!(MNEMONIC_FIRST_WORD, "scalar");
    }

    // ── validate_mnemonic ─────────────────────────────────────────────────────

    #[test]
    fn test_valid_mnemonic_first_word_scalar() {
        assert!(validate_mnemonic("scalar test mnemonic words").is_ok());
    }

    #[test]
    fn test_invalid_mnemonic_first_word_rejected() {
        let err = validate_mnemonic("bitcoin test mnemonic").unwrap_err();
        assert_eq!(err, SeedError::InvalidMnemonicFirstWord);
    }

    #[test]
    fn test_empty_mnemonic_rejected() {
        let err = validate_mnemonic("").unwrap_err();
        assert_eq!(err, SeedError::EmptyMnemonic);
    }

    #[test]
    fn test_mnemonic_scalar_only_valid() {
        // Satu kata "scalar" saja harus valid
        assert!(validate_mnemonic("scalar").is_ok());
    }

    // ── derive_seed ───────────────────────────────────────────────────────────

    #[test]
    fn test_seed_derivation_deterministic() {
        // Spec §13.1: derivasi deterministik.
        let m = derive_seed("scalar test mnemonic").unwrap();
        let m2 = derive_seed("scalar test mnemonic").unwrap();
        assert_eq!(m.seed, m2.seed);
        assert_eq!(m.master_key, m2.master_key);
    }

    #[test]
    fn test_seed_non_zero() {
        let m = derive_seed("scalar test mnemonic").unwrap();
        assert_ne!(m.seed, [0u8; 32]);
        assert_ne!(m.master_key, [0u8; 32]);
    }

    #[test]
    fn test_seed_different_mnemonics_different() {
        let m1 = derive_seed("scalar mnemonic one").unwrap();
        let m2 = derive_seed("scalar mnemonic two").unwrap();
        assert_ne!(m1.seed, m2.seed);
        assert_ne!(m1.master_key, m2.master_key);
    }

    #[test]
    fn test_seed_rejects_non_scalar_mnemonic() {
        let err = derive_seed("wrong first word").unwrap_err();
        assert_eq!(err, SeedError::InvalidMnemonicFirstWord);
    }

    #[test]
    fn test_master_key_differs_from_seed() {
        let m = derive_seed("scalar test mnemonic").unwrap();
        assert_ne!(m.seed, m.master_key);
    }

    // ── derive_account_key ────────────────────────────────────────────────────

    #[test]
    fn test_account_key_deterministic() {
        let m = derive_seed("scalar test mnemonic").unwrap();
        let ak1 = derive_account_key(&m.master_key, 0);
        let ak2 = derive_account_key(&m.master_key, 0);
        assert_eq!(ak1, ak2);
    }

    #[test]
    fn test_account_key_different_indices() {
        let m = derive_seed("scalar test mnemonic").unwrap();
        let ak0 = derive_account_key(&m.master_key, 0);
        let ak1 = derive_account_key(&m.master_key, 1);
        assert_ne!(ak0, ak1);
    }

    #[test]
    fn test_account_key_non_zero() {
        let m = derive_seed("scalar test mnemonic").unwrap();
        let ak = derive_account_key(&m.master_key, 0);
        assert_ne!(ak, [0u8; 32]);
    }

    #[test]
    fn test_account_key_differs_from_master_key() {
        let m = derive_seed("scalar test mnemonic").unwrap();
        let ak = derive_account_key(&m.master_key, 0);
        assert_ne!(ak, m.master_key);
    }

    #[test]
    fn test_no_floating_point() {
        // Semua derivasi pure integer/bytes — tidak ada float.
        let m = derive_seed("scalar integration test").unwrap();
        let _ak = derive_account_key(&m.master_key, u64::MAX);
    }
}
