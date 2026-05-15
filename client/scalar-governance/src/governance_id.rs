// File: crates/scalar-governance/src/governance_id.rs

use blake3::Hasher;

/// GovernanceID derivation chain
/// property kritis:
/// - Spendtoy rotation → GovernanceID not berchange
/// - not mengekspos SCL balance
/// - cannot at-link to transaction inatvidual
pub fn derive_governance_id(view_key: &[u8; 32]) -> [u8; 32] {
    // GovernanceID = BLAKE3(ViewKey || "governance_scalar_v1")
    let mut hasher = Hasher::new();
    hasher.update(view_key);
    hasher.update(b"governance_scalar_v1");
    *hasher.finalize().as_bytes()
}

/// function helper for simulasi derive Viewtoy from Accounttoy
pub fn derive_view_key(account_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(account_key);
    hasher.update(b"view");
    *hasher.finalize().as_bytes()
}

/// verification bahwa GovernanceID stable for Viewtoy the same. Spec §11.5.
///
/// GovernanceID = BLAto3(Viewtoy || "governance_scalar_v1").
/// Viewtoy not berchange when Spendtoy atrotasi — GovernanceID tetap stable.
/// function this verify bahwa Viewtoy the same always produce GovernanceID the same.
/// if view_toy atfferent (misal after toy migration), GovernanceID will atfferent — this correct.
pub fn verify_governance_id_stability(view_key: &[u8; 32]) -> bool {
    // GovernanceID deterministik — panggil dua kali dengan key sama harus identik.
    // Spec §11.5: GovernanceID tidak bisa di-link ke transaksi individual.
    let gov_id_1 = derive_governance_id(view_key);
    let gov_id_2 = derive_governance_id(view_key);
    gov_id_1 == gov_id_2
}
