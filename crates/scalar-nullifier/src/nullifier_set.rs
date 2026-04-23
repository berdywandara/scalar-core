use crate::smt::{ScalarSMT, RootHash};
use crate::NullifierError;
use std::collections::HashSet;

/// Struktur utama yang menggantikan fungsi Blockchain di Scalar Network
pub struct NullifierSet {
    pub tree: ScalarSMT,
    /// Untuk efisiensi look-up O(1) sebelum memverifikasi Merkle Proof
    spent_registry: HashSet<RootHash>,
}

impl Default for NullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

impl NullifierSet {
    pub fn new() -> Self {
        Self { 
            tree: ScalarSMT::new(),
            spent_registry: HashSet::new(),
        }
    }

    /// Cek cepat (O(1)) apakah nullifier sudah ada
    pub fn is_spent(&self, nullifier: &[u8; 32]) -> bool {
        self.spent_registry.contains(nullifier)
    }

    /// Mendaftarkan nullifier ke dalam set (Mencegah Double Spend)
    pub fn add(&mut self, nullifier: [u8; 32]) -> Result<(), NullifierError> {
        if self.is_spent(&nullifier) {
            return Err(NullifierError::AlreadySpent);
        }
        
        // Tambahkan ke look-up cepat
        self.spent_registry.insert(nullifier);
        
        // Todo: Update tree.root secara matematis menyusuri Merkle Path ke atas
        // (Logika re-kalkulasi 256 level SMT akan diintegrasikan di iterasi berikutnya)

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_spend_prevention() {
        let mut nullifier_set = NullifierSet::new();
        let test_nullifier = [9u8; 32];

        // Pengeluaran pertama harus berhasil
        assert!(nullifier_set.add(test_nullifier).is_ok());
        
        // Pengeluaran kedua dengan nullifier yang sama harus ditolak (Double Spend!)
        let double_spend_attempt = nullifier_set.add(test_nullifier);
        assert!(matches!(double_spend_attempt, Err(NullifierError::AlreadySpent)));
    }
}