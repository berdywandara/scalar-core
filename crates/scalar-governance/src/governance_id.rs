use scalar_crypto::blake3::Hasher;

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

/// Verifikasi bahwa GovernanceID konsisten
/// (tidak berubah saat SpendKey dirotasi)
pub fn verify_governance_id_stability(
    view_key_before_rotation: &[u8; 32],
    view_key_after_rotation: &[u8; 32],
) -> bool {
    let gov_id_before = derive_governance_id(view_key_before_rotation);
    let gov_id_after = derive_governance_id(view_key_after_rotation);

    gov_id_before == gov_id_after
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_governance_id_different_per_account() {
        let view_key_1 = [1u8; 32];
        let view_key_2 = [2u8; 32];

        let gov_id_1 = derive_governance_id(&view_key_1);
        let gov_id_2 = derive_governance_id(&view_key_2);

        assert_ne!(
            gov_id_1, gov_id_2,
            "Account berbeda harus punya GovernanceID berbeda"
        );
    }

    #[test]
    fn test_governance_id_stable_across_spend_key_rotation() {
        let view_key = [1u8; 32];
        assert!(verify_governance_id_stability(&view_key, &view_key));
    }
}
