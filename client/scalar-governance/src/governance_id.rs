// File: crates/scalar-governance/src/governance_id.rs

use blake3::Hasher;

/// GovernanceID derivation chain
/// Properti kritis:
/// - SpendKey rotation → GovernanceID TIDAK berubah
/// - Tidak mengekspos SCL balance
/// - Tidak bisa di-link ke transaksi individual
pub fn derive_governance_id(view_key: &[u8; 32]) -> [u8; 32] {
    // GovernanceID = BLAKE3(ViewKey || "governance_scalar_v1")
    let mut hasher = Hasher::new();
    hasher.update(view_key);
    hasher.update(b"governance_scalar_v1");
    *hasher.finalize().as_bytes()
}

/// Fungsi helper untuk simulasi derive ViewKey dari AccountKey
pub fn derive_view_key(account_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(account_key);
    hasher.update(b"view");
    *hasher.finalize().as_bytes()
}

/// Verifikasi bahwa GovernanceID konsisten
pub fn verify_governance_id_stability(
    view_key_before_rotation: &[u8; 32],
    view_key_after_rotation: &[u8; 32],
) -> bool {
    let gov_id_before = derive_governance_id(view_key_before_rotation);
    let gov_id_after = derive_governance_id(view_key_after_rotation);

    gov_id_before == gov_id_after
}
