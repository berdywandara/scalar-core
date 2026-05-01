// File: crates/scalar-governance/src/govid.rs

pub const FIXED_POINT_BASIS: u64 = 1_000_000;

/// GovID memberikan bobot tambahan berdasarkan reputasi/identitas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovId {
    pub identity_hash: [u8; 32],
    pub reputation_score: u64, // Dalam basis 1_000_000
}

impl GovId {
    pub fn new(identity_hash: [u8; 32], reputation_score: u64) -> Self {
        Self {
            identity_hash,
            reputation_score,
        }
    }

    /// Menghitung multiplier dari GovID.
    /// Base: 1.0x (1_000_000). Maksimal Cap: 2.0x (2_000_000).
    pub fn multiplier(&self) -> u64 {
        let bonus = (self.reputation_score * 100_000) / FIXED_POINT_BASIS;
        (FIXED_POINT_BASIS + bonus).min(2 * FIXED_POINT_BASIS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_govid_multiplier() {
        let govid = GovId::new([0; 32], 5_000_000); // 5.0 reputation -> 0.5x bonus -> 1.5x multiplier
        assert_eq!(govid.multiplier(), 1_500_000);

        let govid_max = GovId::new([0; 32], 20_000_000); // Capped at 2.0x multiplier
        assert_eq!(govid_max.multiplier(), 2_000_000);
    }
}
