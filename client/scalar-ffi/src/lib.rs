// File: crates/scalar-ffi/src/lib.rs
//
// Scalar FFI — UniFFI-style Safe Bindings untuk Flutter/Mobile
// Spec §16.2: scalar-ffi depends on scalar-wallet-core
//
// Arsitektur:
//   Flutter (Dart) → C ABI → scalar-ffi → scalar-wallet-core
//
// Safety model:
//   - Semua fungsi unsafe C ABI dibungkus dengan safe Rust inner functions
//   - Pointer NULL selalu dicek sebelum dereference
//   - Memory ownership: string yang dialokasikan Rust WAJIB dibebaskan
//     via scalar_free_string()
//   - Zeroize: kunci sensitif di-zero sebelum drop

use scalar_wallet_core::key_management::{derive_all_keys, WalletKeys};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use zeroize::Zeroize;

// ── Versi API ─────────────────────────────────────────────────────────

/// Versi FFI API. Flutter bisa query ini untuk feature detection.
pub const FFI_API_VERSION: u32 = 1;

// ── Domain Separator ─────────────────────────────────────────────────

/// Verifikasi domain separator mnemonic Scalar Network.
/// Spec §13.1: kata PERTAMA mnemonic WAJIB "scalar".
/// BIP-39 wallets lain akan reject mnemonic ini.
///
/// Safe inner function — tidak ada pointer.
pub fn verify_domain_separator(phrase: &str) -> bool {
    let first_word = phrase.trim().to_lowercase();
    let first_word = first_word.split_whitespace().next().unwrap_or("");
    first_word == "scalar"
}

/// FFI wrapper untuk verify_domain_separator.
///
/// # Safety
/// - `phrase_ptr` tidak boleh NULL
/// - `phrase_ptr` harus menunjuk ke valid null-terminated C string
/// - String harus tetap valid selama fungsi berjalan
#[no_mangle]
pub unsafe extern "C" fn scalar_verify_domain_separator(phrase_ptr: *const c_char) -> bool {
    if phrase_ptr.is_null() {
        return false;
    }
    let c_str = CStr::from_ptr(phrase_ptr);
    match c_str.to_str() {
        Ok(s) => verify_domain_separator(s),
        Err(_) => false,
    }
}

// ── Key Derivation ────────────────────────────────────────────────────

/// Hasil derivasi kunci untuk FFI — menggunakan hex strings agar
/// aman melewati batas Rust/C tanpa raw pointer ke secret bytes.
pub struct FfiWalletKeys {
    /// SpendKey sebagai hex string 64 karakter.
    pub spend_key_hex: String,
    /// ViewKey sebagai hex string 64 karakter.
    pub view_key_hex: String,
    /// NodeKey sebagai hex string 64 karakter.
    pub node_key_hex: String,
    /// GovernanceID sebagai hex string 64 karakter. Spec §13.1 v5.0.
    pub governance_id_hex: String,
}

impl Drop for FfiWalletKeys {
    fn drop(&mut self) {
        // Zeroize hex strings saat drop untuk keamanan memori
        self.spend_key_hex.zeroize();
        self.view_key_hex.zeroize();
        self.node_key_hex.zeroize();
        self.governance_id_hex.zeroize();
    }
}

/// Encode bytes ke hex string.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Derive semua kunci dari account_key (32 bytes).
/// Safe inner function.
pub fn derive_ffi_keys(account_key: &[u8; 32]) -> FfiWalletKeys {
    let keys: WalletKeys = derive_all_keys(account_key);
    FfiWalletKeys {
        spend_key_hex: to_hex(&keys.spend_key),
        view_key_hex: to_hex(&keys.view_key),
        node_key_hex: to_hex(&keys.node_key),
        governance_id_hex: to_hex(&keys.governance_id),
    }
}

/// FFI: derive GovernanceID dari account_key (32 bytes raw).
/// Returns hex string yang dialokasikan di heap Rust.
/// Caller WAJIB memanggil scalar_free_string() setelah selesai.
///
/// # Safety
/// - `account_key_ptr` tidak boleh NULL
/// - `account_key_ptr` harus menunjuk ke buffer ≥ 32 bytes
#[no_mangle]
pub unsafe extern "C" fn scalar_derive_governance_id(account_key_ptr: *const u8) -> *mut c_char {
    if account_key_ptr.is_null() {
        return std::ptr::null_mut();
    }
    let key_slice = std::slice::from_raw_parts(account_key_ptr, 32);
    let mut account_key = [0u8; 32];
    account_key.copy_from_slice(key_slice);

    let ffi_keys = derive_ffi_keys(&account_key);
    let gov_id = ffi_keys.governance_id_hex.clone();

    account_key.zeroize();

    match CString::new(gov_id) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// FFI: derive SpendKey hex dari account_key (32 bytes raw).
/// Returns hex string. Caller WAJIB memanggil scalar_free_string().
///
/// # Safety
/// - `account_key_ptr` tidak boleh NULL
/// - `account_key_ptr` harus menunjuk ke buffer ≥ 32 bytes
#[no_mangle]
pub unsafe extern "C" fn scalar_derive_spend_key(account_key_ptr: *const u8) -> *mut c_char {
    if account_key_ptr.is_null() {
        return std::ptr::null_mut();
    }
    let key_slice = std::slice::from_raw_parts(account_key_ptr, 32);
    let mut account_key = [0u8; 32];
    account_key.copy_from_slice(key_slice);

    let ffi_keys = derive_ffi_keys(&account_key);
    let spend_key = ffi_keys.spend_key_hex.clone();

    account_key.zeroize();

    match CString::new(spend_key) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ── Address Generation ────────────────────────────────────────────────

/// Generate stub wallet address dari spend_key_hex.
/// Spec §13.1: production akan menggunakan SPHINCS+ dari scalar-crypto.
///
/// Safe inner function.
pub fn generate_address_from_spend_key(spend_key_hex: &str) -> String {
    // Stub: prefix "scl1_" + 8 karakter pertama spend key hex
    // Production: SPHINCS+ public key derivation dari scalar-crypto
    let suffix = &spend_key_hex[..8.min(spend_key_hex.len())];
    format!("scl1_{}", suffix)
}

/// FFI: generate wallet address.
/// Returns C string. Caller WAJIB memanggil scalar_free_string().
///
/// # Safety
/// - `account_key_ptr` tidak boleh NULL
/// - `account_key_ptr` harus menunjuk ke buffer ≥ 32 bytes
#[no_mangle]
pub unsafe extern "C" fn scalar_generate_address(account_key_ptr: *const u8) -> *mut c_char {
    if account_key_ptr.is_null() {
        return std::ptr::null_mut();
    }
    let key_slice = std::slice::from_raw_parts(account_key_ptr, 32);
    let mut account_key = [0u8; 32];
    account_key.copy_from_slice(key_slice);

    let ffi_keys = derive_ffi_keys(&account_key);
    let address = generate_address_from_spend_key(&ffi_keys.spend_key_hex);

    account_key.zeroize();

    match CString::new(address) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ── Memory Management ─────────────────────────────────────────────────

/// FFI: bebaskan string yang dialokasikan oleh fungsi Scalar FFI.
/// WAJIB dipanggil untuk setiap string yang dikembalikan oleh FFI.
/// Mencegah memory leak di sisi Flutter.
///
/// # Safety
/// - `s` harus pointer yang dikembalikan oleh fungsi Scalar FFI
/// - `s` tidak boleh sudah di-free sebelumnya (no double-free)
/// - Setelah dipanggil, `s` tidak boleh digunakan lagi
#[no_mangle]
pub unsafe extern "C" fn scalar_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    drop(CString::from_raw(s));
}

/// FFI: query versi API.
#[no_mangle]
pub extern "C" fn scalar_ffi_version() -> u32 {
    FFI_API_VERSION
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Domain Separator ──────────────────────────────────────────────

    #[test]
    fn test_domain_separator_valid() {
        assert!(verify_domain_separator("scalar test mnemonic words here"));
    }

    #[test]
    fn test_domain_separator_valid_with_leading_space() {
        assert!(verify_domain_separator("  scalar test mnemonic"));
    }

    #[test]
    fn test_domain_separator_invalid_other_word() {
        assert!(!verify_domain_separator("bitcoin test mnemonic"));
    }

    #[test]
    fn test_domain_separator_invalid_empty() {
        assert!(!verify_domain_separator(""));
    }

    #[test]
    fn test_domain_separator_case_insensitive() {
        assert!(verify_domain_separator("SCALAR test mnemonic"));
        assert!(verify_domain_separator("Scalar test mnemonic"));
    }

    // ── Key Derivation ────────────────────────────────────────────────

    #[test]
    fn test_derive_ffi_keys_non_zero() {
        let account_key = [1u8; 32];
        let keys = derive_ffi_keys(&account_key);
        assert_ne!(keys.spend_key_hex, "0".repeat(64));
        assert_ne!(keys.governance_id_hex, "0".repeat(64));
    }

    #[test]
    fn test_derive_ffi_keys_deterministic() {
        let account_key = [42u8; 32];
        let keys1 = derive_ffi_keys(&account_key);
        let keys2 = derive_ffi_keys(&account_key);
        assert_eq!(keys1.spend_key_hex, keys2.spend_key_hex);
        assert_eq!(keys1.governance_id_hex, keys2.governance_id_hex);
    }

    #[test]
    fn test_derive_ffi_keys_all_different() {
        let account_key = [7u8; 32];
        let keys = derive_ffi_keys(&account_key);
        // Semua kunci harus berbeda satu sama lain
        assert_ne!(keys.spend_key_hex, keys.view_key_hex);
        assert_ne!(keys.spend_key_hex, keys.node_key_hex);
        assert_ne!(keys.spend_key_hex, keys.governance_id_hex);
        assert_ne!(keys.view_key_hex, keys.governance_id_hex);
    }

    #[test]
    fn test_derive_ffi_keys_hex_length() {
        let account_key = [0u8; 32];
        let keys = derive_ffi_keys(&account_key);
        // Setiap key hex harus tepat 64 karakter (32 bytes × 2)
        assert_eq!(keys.spend_key_hex.len(), 64);
        assert_eq!(keys.view_key_hex.len(), 64);
        assert_eq!(keys.node_key_hex.len(), 64);
        assert_eq!(keys.governance_id_hex.len(), 64);
    }

    #[test]
    fn test_governance_id_matches_wallet_core() {
        use scalar_wallet_core::key_management::derive_all_keys;
        let account_key = [55u8; 32];
        let wallet_keys = derive_all_keys(&account_key);
        let ffi_keys = derive_ffi_keys(&account_key);
        // FFI governance_id_hex harus cocok dengan wallet-core governance_id
        assert_eq!(
            ffi_keys.governance_id_hex,
            to_hex(&wallet_keys.governance_id)
        );
    }

    // ── Address Generation ────────────────────────────────────────────

    #[test]
    fn test_generate_address_prefix() {
        let spend_key_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let addr = generate_address_from_spend_key(spend_key_hex);
        assert!(addr.starts_with("scl1_"));
    }

    #[test]
    fn test_generate_address_deterministic() {
        let account_key = [99u8; 32];
        let keys = derive_ffi_keys(&account_key);
        let addr1 = generate_address_from_spend_key(&keys.spend_key_hex);
        let addr2 = generate_address_from_spend_key(&keys.spend_key_hex);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_generate_address_different_keys_different_addresses() {
        let keys1 = derive_ffi_keys(&[1u8; 32]);
        let keys2 = derive_ffi_keys(&[2u8; 32]);
        let addr1 = generate_address_from_spend_key(&keys1.spend_key_hex);
        let addr2 = generate_address_from_spend_key(&keys2.spend_key_hex);
        assert_ne!(addr1, addr2);
    }

    // ── FFI Version ───────────────────────────────────────────────────

    #[test]
    fn test_ffi_version() {
        assert_eq!(scalar_ffi_version(), FFI_API_VERSION);
        assert_eq!(FFI_API_VERSION, 1);
    }

    // ── FFI Unsafe Wrappers ───────────────────────────────────────────

    #[test]
    fn test_ffi_verify_domain_separator_valid() {
        let phrase = std::ffi::CString::new("scalar test words").unwrap();
        let result = unsafe { scalar_verify_domain_separator(phrase.as_ptr()) };
        assert!(result);
    }

    #[test]
    fn test_ffi_verify_domain_separator_null() {
        let result = unsafe { scalar_verify_domain_separator(std::ptr::null()) };
        assert!(!result);
    }

    #[test]
    fn test_ffi_derive_governance_id_roundtrip() {
        let account_key = [33u8; 32];
        let ptr = unsafe { scalar_derive_governance_id(account_key.as_ptr()) };
        assert!(!ptr.is_null());
        let result = unsafe { CStr::from_ptr(ptr).to_str().unwrap().to_string() };
        unsafe { scalar_free_string(ptr) };
        // Harus 64 karakter hex
        assert_eq!(result.len(), 64);
    }

    #[test]
    fn test_ffi_derive_governance_id_null_returns_null() {
        let ptr = unsafe { scalar_derive_governance_id(std::ptr::null()) };
        assert!(ptr.is_null());
    }

    #[test]
    fn test_ffi_generate_address_roundtrip() {
        let account_key = [77u8; 32];
        let ptr = unsafe { scalar_generate_address(account_key.as_ptr()) };
        assert!(!ptr.is_null());
        let addr = unsafe { CStr::from_ptr(ptr).to_str().unwrap().to_string() };
        unsafe { scalar_free_string(ptr) };
        assert!(addr.starts_with("scl1_"));
    }

    #[test]
    fn test_ffi_free_string_null_safe() {
        // Memanggil free_string dengan NULL tidak boleh crash
        unsafe { scalar_free_string(std::ptr::null_mut()) };
    }
}
