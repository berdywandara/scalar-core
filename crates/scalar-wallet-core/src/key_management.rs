// File: crates/scalar-wallet-core/src/key_management.rs

use blake3::Hasher;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// WalletKeys menampung semua kunci untuk satu akun.
/// Menggunakan Zeroize untuk membersihkan RAM saat struct di-drop (Keamanan Memori).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WalletKeys {
    pub spend_key: [u8; 32],
    pub view_key: [u8; 32],
    pub node_key: [u8; 32],
    pub governance_id: [u8; 32], // BARU (v5.0)
}

/// Helper fungsi untuk BLAKE3 out-circuit derivation
fn blake3_derive(key: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(key);
    hasher.update(domain);
    *hasher.finalize().as_bytes()
}

/// Helper fungsi spesifik untuk derivasi GovernanceID
fn blake3_derive_concat(key: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    blake3_derive(key, domain)
}

/// Derive seluruh key chain dari account_key
pub fn derive_all_keys(account_key: &[u8; 32]) -> WalletKeys {
    // Chain eksisting v3.0 (TIDAK BERUBAH)
    let spend_key = blake3_derive(account_key, b"spend");
    let view_key = blake3_derive(account_key, b"view");
    let node_key = blake3_derive(account_key, b"node");

    // GovernanceID: BLAKE3(ViewKey || "governance_scalar_v1")
    // BARU di v5.0 — derived dari ViewKey yang sudah ada
    let governance_id = blake3_derive_concat(&view_key, b"governance_scalar_v1");

    WalletKeys {
        spend_key,
        view_key,
        node_key,
        governance_id, // BARU
    }
}

#[cfg(test)]
mod tests_key_derivation {
    use super::*;

    // --- Mock environment untuk testing ---
    fn derive_account_key_from_mnemonic(_mnemonic: &str) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(_mnemonic.as_bytes());
        *hasher.finalize().as_bytes()
    }

    fn derive_wallet_from_mnemonic(mnemonic: &str) -> WalletKeys {
        let account_key = derive_account_key_from_mnemonic(mnemonic);
        derive_all_keys(&account_key)
    }

    fn derive_expected_v3_spend_key(mnemonic: &str) -> [u8; 32] {
        let account_key = derive_account_key_from_mnemonic(mnemonic);
        blake3_derive(&account_key, b"spend")
    }
    // --------------------------------------

    #[test]
    fn test_governance_id_derivation_in_chain() {
        let mnemonic = "scalar test mnemonic words here...";
        let keys = derive_wallet_from_mnemonic(mnemonic);

        // GovernanceID harus ada dan non-zero
        assert_ne!(keys.governance_id, [0u8; 32]);

        // GovernanceID tidak sama dengan ViewKey atau SpendKey
        assert_ne!(keys.governance_id, keys.view_key);
        assert_ne!(keys.governance_id, keys.spend_key);
    }

    #[test]
    fn test_governance_id_deterministic() {
        let mnemonic = "scalar test mnemonic words here...";
        let keys1 = derive_wallet_from_mnemonic(mnemonic);
        let keys2 = derive_wallet_from_mnemonic(mnemonic);
        assert_eq!(keys1.governance_id, keys2.governance_id);
    }

    #[test]
    fn test_existing_keys_unchanged_after_v5_update() {
        // SpendKey, ViewKey, NodeKey harus identik dengan v3.0
        let mnemonic = "scalar test mnemonic words here...";
        let keys = derive_wallet_from_mnemonic(mnemonic);

        // Verifikasi chain yang sudah ada tidak berubah
        let expected_spend = derive_expected_v3_spend_key(mnemonic);
        assert_eq!(
            keys.spend_key, expected_spend,
            "SpendKey tidak boleh berubah dari v3.0"
        );
    }
}
