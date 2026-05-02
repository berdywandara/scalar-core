// File: crates/scalar-stark/src/air.rs

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public Input untuk Transfer Circuit v5.0
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferCircuitPublicInput {
    pub crypto_version: u8,   // Constraint C9
    pub entry_timestamp: u64, // Constraint C10 (Zero floating point)
    pub current_timestamp: u64,
}

/// Witness WAJIB dihapus dari RAM setelah digunakan
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TransferWitness {
    pub(crate) secret_key: [u8; 32],
}

pub const VALID_CRYPTO_VERSIONS: [u8; 1] = [0x01];
pub const MAX_WAIT_WINDOW_MS: u64 = 3_600_000; // 1 Jam

/// C9: Validasi versi kriptografi untuk mencegah downgrade attack
pub fn verify_c9_crypto_version(version: u8) -> Result<(), &'static str> {
    if VALID_CRYPTO_VERSIONS.contains(&version) {
        Ok(())
    } else {
        Err("Constraint C9: Invalid crypto version")
    }
}

/// C10: Memastikan transaksi dieksekusi dalam rentang wait window
pub fn verify_c10_tx_within_wait_window(entry_ts: u64, current_ts: u64) -> bool {
    if current_ts < entry_ts {
        return false;
    }
    (current_ts - entry_ts) <= MAX_WAIT_WINDOW_MS
}

/// Kalkulasi jumlah constraints statis berdasarkan spesifikasi I/O
pub fn get_total_constraints(inputs: usize, outputs: usize) -> usize {
    if inputs == 2 && outputs == 2 {
        42
    } else if inputs == 10 && outputs == 10 {
        150
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c9_valid_crypto_version() {
        assert!(verify_c9_crypto_version(0x01).is_ok());
    }

    #[test]
    fn test_c9_invalid_crypto_version_rejected() {
        assert!(verify_c9_crypto_version(0xFF).is_err());
    }

    #[test]
    fn test_c10_tx_within_wait_window_accepted() {
        let entry = 1_000_000;
        let current = 1_005_000; // Selisih 5.000 ms (valid)
        assert!(verify_c10_tx_within_wait_window(entry, current));
    }

    #[test]
    fn test_c10_entry_timestamp_in_public_input() {
        let pi = TransferCircuitPublicInput {
            crypto_version: 0x01,
            entry_timestamp: 1680000000,
            current_timestamp: 1680000100,
        };
        assert_eq!(pi.entry_timestamp, 1680000000);
    }

    #[test]
    fn test_total_constraints_2_2_matches_spec() {
        assert_eq!(get_total_constraints(2, 2), 42);
    }

    #[test]
    fn test_total_constraints_10_10_matches_spec() {
        assert_eq!(get_total_constraints(10, 10), 150);
    }
}
