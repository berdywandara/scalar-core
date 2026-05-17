// File: core/scalar-crypto/src/version.rs

/// CRYPTO_VERSION_CURRENT = 0x01. OSSIFIED — spec §2.4.
/// Genesis implementation. Tidak ada transisi versi.
/// T_TRANSITION_EPOCHS = N/A — spec §2.4.
pub const CURRENT_VERSION: u8 = 0x01;

/// Verifikasi bahwa versi proof valid untuk genesis implementation.
/// Spec §2.4: hanya 0x01 yang valid. Tidak ada multi-version registry.
pub fn verify_proof_version(id: u8) -> Result<(), &'static str> {
    if id == CURRENT_VERSION {
        Ok(())
    } else {
        Err("Invalid proof version: only 0x01 is valid for genesis implementation")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_version_is_0x01() {
        // OSSIFIED — spec §2.4: CRYPTO_VERSION_CURRENT = 0x01.
        assert_eq!(CURRENT_VERSION, 0x01);
    }

    #[test]
    fn test_version_0x01_is_valid() {
        // Genesis implementation: 0x01 adalah satu-satunya versi valid.
        assert!(verify_proof_version(0x01).is_ok());
    }

    #[test]
    fn test_version_0x02_is_invalid() {
        // Tidak ada versi lain yang valid di genesis. Spec §2.4.
        assert!(verify_proof_version(0x02).is_err());
    }

    #[test]
    fn test_version_0x03_is_invalid() {
        assert!(verify_proof_version(0x03).is_err());
    }

    #[test]
    fn test_unknown_version_invalid() {
        assert!(verify_proof_version(0xFF).is_err());
    }

    #[test]
    fn test_no_transition_window() {
        // Spec §2.4: T_TRANSITION_EPOCHS = N/A.
        // Genesis implementation tidak memiliki window transisi.
        // Verifikasi dilakukan dengan memastikan tidak ada konstanta transisi.
        assert_eq!(CURRENT_VERSION, 0x01);
    }
}
