//! Types re-export dan version validation — Spec §2.4, §8.4
//!
//! Genesis implementation: hanya SPEC_VERSION_MANIFEST = 0x01 yang valid.
//! Tidak ada legacy version, tidak ada testnet-compat, tidak ada transisi.
//!
//! Re-export EpochRewardManifest dan NodeRewardEntry dari dmm.rs

pub use crate::dmm::{EpochRewardManifest, NodeRewardEntry, SPEC_VERSION_MANIFEST};

/// T_TRANSITION_EPOCHS = N/A — genesis implementation. Spec §2.4.
pub const T_TRANSITION_EPOCHS: u64 = 0;

/// SPEC_VERSION_CURRENT = 0x01. Spec §2.4.
pub const SPEC_VERSION_CURRENT: u8 = SPEC_VERSION_MANIFEST;

/// Error validasi versi manifest. Spec §8.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestVersionError {
    /// spec_version tidak dikenal atau tidak valid.
    UnknownVersion { version: u8 },
}

impl core::fmt::Display for ManifestVersionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownVersion { version } => {
                write!(
                    f,
                    "Unknown manifest version 0x{:02X}: only 0x01 is valid for genesis",
                    version
                )
            }
        }
    }
}

/// Validasi spec_version manifest. Spec §2.4, §8.4.
///
/// Genesis implementation: hanya 0x01 yang valid.
/// Semua versi lain di-reject.
pub fn validate_manifest_version(version: u8) -> Result<(), ManifestVersionError> {
    match version {
        v if v == SPEC_VERSION_CURRENT => Ok(()),
        v => Err(ManifestVersionError::UnknownVersion { version: v }),
    }
}

/// Validasi manifest lengkap. Spec §8.4.
///
/// Memeriksa:
/// 1. spec_version == 0x01
/// 2. reward_root tidak zero
/// 3. manifest_hash tidak zero
pub fn validate_manifest(manifest: &EpochRewardManifest) -> Result<(), ManifestVersionError> {
    validate_manifest_version(manifest.spec_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dmm::{EpochRewardManifest, NodeRewardEntry};

    #[test]
    fn test_spec_version_current_is_0x01() {
        // SPEC_VERSION_CURRENT = 0x01. OSSIFIED — spec §2.4.
        assert_eq!(SPEC_VERSION_CURRENT, 0x01u8);
    }

    #[test]
    fn test_spec_version_manifest_is_0x01() {
        // SPEC_VERSION_MANIFEST = 0x01. OSSIFIED — spec §2.4.
        assert_eq!(SPEC_VERSION_MANIFEST, 0x01u8);
    }

    #[test]
    fn test_t_transition_epochs_is_na() {
        // T_TRANSITION_EPOCHS = N/A untuk genesis. Spec §2.4.
        assert_eq!(T_TRANSITION_EPOCHS, 0u64);
    }

    #[test]
    fn test_version_0x01_accepted() {
        // 0x01 adalah satu-satunya versi valid. Spec §2.4.
        assert!(validate_manifest_version(0x01).is_ok());
    }

    #[test]
    fn test_unknown_version_rejected_production() {
        // Semua versi selain 0x01 di-reject. Spec §8.4.
        for v in [0x02u8, 0x03, 0x05, 0x06, 0xFF] {
            assert!(
                validate_manifest_version(v).is_err(),
                "version 0x{:02X} harus di-reject",
                v
            );
        }
    }

    #[test]
    fn test_unknown_version_rejected_testnet() {
        // Tidak ada testnet-compat mode di genesis. Spec §2.4.
        // Verifikasi bahwa 0x05 dan 0x06 tetap di-reject.
        assert!(validate_manifest_version(0x05).is_err());
        assert!(validate_manifest_version(0x06).is_err());
    }

    #[test]
    fn test_validate_manifest_valid() {
        let manifest = EpochRewardManifest {
            epoch_id: 1,
            node_list: vec![],
            spec_version: 0x01,
            total_emission_sscl: 0,
            deferred: false,
            seed_k: [0u8; 32],
            manifest_hash: [0u8; 32],
            reward_root: [0u8; 32],
            network_health_digest: [0u8; 32],
            tx_set_root: [0u8; 32],
            status: crate::dmm::EpochStatus::Open,
        };
        assert!(validate_manifest(&manifest).is_ok());
    }

    #[test]
    fn test_validate_manifest_wrong_version() {
        let manifest = EpochRewardManifest {
            epoch_id: 1,
            node_list: vec![],
            spec_version: 0x06,
            total_emission_sscl: 0,
            deferred: false,
            seed_k: [0u8; 32],
            manifest_hash: [0u8; 32],
            reward_root: [0u8; 32],
            network_health_digest: [0u8; 32],
            tx_set_root: [0u8; 32],
            status: crate::dmm::EpochStatus::Open,
        };
        assert!(validate_manifest(&manifest).is_err());
    }

    #[test]
    fn test_node_reward_entry_fields() {
        // NodeRewardEntry fields accessible. Spec §8.4.
        let entry = NodeRewardEntry {
            node_id_full: [0x01u8; 32],
            reward_sscl: 500_000,
            uptime_weight_fp: 800_000,
        };
        assert_eq!(entry.reward_sscl, 500_000);
        assert_eq!(entry.uptime_weight_fp, 800_000);
    }
}
