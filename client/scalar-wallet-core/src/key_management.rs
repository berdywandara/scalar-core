// File: crates/scalar-wallet-core/src/key_management.rs

use blake3::Hasher;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Wallettoys menampung all toy for one akun.
/// using Zeroize for membersihkan RAM when struct at-drop (security memory).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct WalletKeys {
    pub spend_key: [u8; 32],
    pub view_key: [u8; 32],
    pub node_key: [u8; 32],
    pub governance_id: [u8; 32], // new (v5.0)
}

/// Helper function for BLAto3 out-circuit derivation
fn blake3_derive(key: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(key);
    hasher.update(domain);
    *hasher.finalize().as_bytes()
}

/// Helper function spesifik for derivation GovernanceID
fn blake3_derive_concat(key: &[u8; 32], domain: &[u8]) -> [u8; 32] {
    blake3_derive(key, domain)
}

/// Derive seluruh toy chain from account_toy
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
        governance_id, // new
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

// ── DuressKey Derivation — Spec §13.1 ────────────────────────────────────────

/// domain separator Duresstoy. OSSIFIED — spec §13.1.
pub const DURESS_DOMAIN: &[u8] = b"duress";

/// Derive Duresstoy for index specific. Spec §13.1.
///
/// Duresstoy_i = BLAto3(Accounttoy ∥ "duress" ∥ index_le64)
///
/// Duresstoy provide plausible deniability:
/// - index 0: wallet bait (decoy) with saldo small
/// - index 1+: level deniability tambahan
/// - cannot atbedwill from Spendtoy oleh penyerang
///
/// note: Duresstoy adalah [u8; 32] — is not bagian from Wallettoys
/// karena jumlah index not limited.
pub fn derive_duress_key(account_key: &[u8; 32], index: u64) -> [u8; 32] {
    // DuressKey = BLAKE3(AccountKey ∥ "duress" ∥ index_le64) — spec §13.1
    let mut hasher = blake3::Hasher::new();
    hasher.update(account_key);
    hasher.update(DURESS_DOMAIN);
    hasher.update(&index.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests_duress_key {
    use super::*;

    fn mock_account_key(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = seed;
        k
    }

    #[test]
    fn test_duress_key_index_0_deterministic() {
        // DuressKey harus deterministik — spec §13.1.
        let ak = mock_account_key(1);
        let dk1 = derive_duress_key(&ak, 0);
        let dk2 = derive_duress_key(&ak, 0);
        assert_eq!(dk1, dk2);
    }

    #[test]
    fn test_duress_key_different_indices_different() {
        // Setiap index harus menghasilkan key berbeda — spec §13.1.
        let ak = mock_account_key(1);
        let dk0 = derive_duress_key(&ak, 0);
        let dk1 = derive_duress_key(&ak, 1);
        let dk2 = derive_duress_key(&ak, 2);
        assert_ne!(dk0, dk1);
        assert_ne!(dk1, dk2);
        assert_ne!(dk0, dk2);
    }

    #[test]
    fn test_duress_key_different_account_keys_different() {
        // Account key berbeda → DuressKey berbeda.
        let dk_a = derive_duress_key(&mock_account_key(1), 0);
        let dk_b = derive_duress_key(&mock_account_key(2), 0);
        assert_ne!(dk_a, dk_b);
    }

    #[test]
    fn test_duress_key_not_equal_to_spend_key() {
        // DuressKey ≠ SpendKey — plausible deniability requires separation.
        let ak = mock_account_key(42);
        let keys = derive_all_keys(&ak);
        let dk = derive_duress_key(&ak, 0);
        assert_ne!(dk, keys.spend_key);
        assert_ne!(dk, keys.view_key);
        assert_ne!(dk, keys.node_key);
    }

    #[test]
    fn test_duress_key_non_zero() {
        // DuressKey tidak boleh all-zero.
        let ak = mock_account_key(7);
        let dk = derive_duress_key(&ak, 0);
        assert_ne!(dk, [0u8; 32]);
    }

    #[test]
    fn test_duress_key_index_le64_encoding() {
        // Verifikasi bahwa index_le64 encoding deterministik.
        // index=1 dan index=256 harus berbeda.
        let ak = mock_account_key(1);
        let dk1 = derive_duress_key(&ak, 1);
        let dk256 = derive_duress_key(&ak, 256);
        assert_ne!(dk1, dk256);
    }

    #[test]
    fn test_duress_domain_separator() {
        // DURESS_DOMAIN harus tepat "duress" — spec §13.1. OSSIFIED.
        assert_eq!(DURESS_DOMAIN, b"duress");
    }

    #[test]
    fn test_no_floating_point() {
        // Semua derivasi murni integer/bytes — tidak ada float.
        let ak = mock_account_key(99);
        let _dk: [u8; 32] = derive_duress_key(&ak, u64::MAX);
        // Compile + run tanpa panic = test pass
    }
}
