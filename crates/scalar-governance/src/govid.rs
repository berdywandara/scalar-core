// File: crates/scalar-governance/src/govid.rs

pub const FIXED_POINT_BASIS: u64 = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovId {
    pub identity_hash: [u8; 32],
    pub reputation_score: u64,
}

impl GovId {
    /// Menghasilkan GovID yang stabil. Rotasi kunci (nonce) tidak mengubah core identitas.
    pub fn generate_from_account(account_pubkey: &[u8; 32], _rotation_nonce: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"scalar_govid_v5");
        hasher.update(account_pubkey);
        *hasher.finalize().as_bytes()
    }

    pub fn new(account_pubkey: &[u8; 32], reputation_score: u64) -> Self {
        Self {
            identity_hash: Self::generate_from_account(account_pubkey, 0),
            reputation_score,
        }
    }

    pub fn multiplier(&self) -> u64 {
        let bonus = (self.reputation_score * 100_000) / FIXED_POINT_BASIS;
        (FIXED_POINT_BASIS + bonus).min(2 * FIXED_POINT_BASIS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_governance_id_stable_across_rotation() {
        let pubkey = [1u8; 32];
        let id_rot_0 = GovId::generate_from_account(&pubkey, 0);
        let id_rot_1 = GovId::generate_from_account(&pubkey, 1);
        let id_rot_99 = GovId::generate_from_account(&pubkey, 99);

        assert_eq!(id_rot_0, id_rot_1, "GovID harus stabil lintas rotasi");
        assert_eq!(id_rot_1, id_rot_99, "GovID harus stabil lintas rotasi");
    }

    #[test]
    fn test_governance_id_different_per_account() {
        let pubkey1 = [1u8; 32];
        let pubkey2 = [2u8; 32];

        let id1 = GovId::generate_from_account(&pubkey1, 0);
        let id2 = GovId::generate_from_account(&pubkey2, 0);

        assert_ne!(id1, id2, "Akun berbeda harus memiliki GovID berbeda");
    }
}
