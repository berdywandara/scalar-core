//! GAP A-004: Consensus Engine Refactor
//! Menghapus HashSet mandiri dan menggunakan ScalarSMT sebagai Single Source of Truth.

use scalar_nullifier::smt::ScalarSMT;

pub struct ConsensusEngine {
    /// Single Source of Truth untuk state transaksi
    pub nullifier_set: ScalarSMT,
}

impl ConsensusEngine {
    pub fn new() -> Self {
        Self {
            nullifier_set: ScalarSMT::new(),
        }
    }

    /// Memverifikasi kebenaran matematis (Truth by Mathematics, not Majority)
    pub fn verify_mathematical_truth(&mut self, nullifier_index: u64, nullifier_hash: u64) -> Result<(), &'static str> {
        // 1. Cek apakah nullifier sudah ada (Double Spend Prevention)
        if self.nullifier_set.contains(nullifier_index) {
            return Err("REJECTED: Transaksi Double Spend Terdeteksi (Nullifier sudah ada di SMT)");
        }

        // 2. Jika valid secara matematis, masukkan ke SMT
        self.nullifier_set.insert(nullifier_index, nullifier_hash);

        Ok(())
    }
}
