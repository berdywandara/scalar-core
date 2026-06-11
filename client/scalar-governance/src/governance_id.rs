// File: crates/scalar-governance/src/governance_id.rs

use blake3::Hasher;

/// GovernanceID derivation — delegates to the OSSIFIED single source of truth in
/// `scalar-crypto`. GovernanceID_pub = SLH-DSA-SHAKE-128s public key derived from
/// BLAKE3(AccountKey || "governance"). Spec §11.1/§13.1.
///
/// Properti kritis:
/// - SpendKey rotation → GovernanceID TIDAK berubah (terikat ke AccountKey)
/// - Tidak mengekspos SCL balance
/// - GovernanceID_pub adalah SLH-DSA public key (bukan hash)
pub fn derive_governance_id(account_key: &[u8; 32]) -> [u8; 32] {
    scalar_crypto::governance_key::governance_keypair_from_account_key(account_key).public
}

/// Fungsi helper untuk simulasi derive ViewKey dari AccountKey.
pub fn derive_view_key(account_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(account_key);
    hasher.update(b"view");
    *hasher.finalize().as_bytes()
}

/// Verifikasi bahwa GovernanceID stabil untuk AccountKey yang sama. Spec §11.1/§11.5.
///
/// GovernanceID terikat ke AccountKey; SpendKey rotation tidak mengubahnya.
/// Memverifikasi determinisme: AccountKey sama → GovernanceID sama.
pub fn verify_governance_id_stability(account_key: &[u8; 32]) -> bool {
    let gov_id_1 = derive_governance_id(account_key);
    let gov_id_2 = derive_governance_id(account_key);
    gov_id_1 == gov_id_2
}
