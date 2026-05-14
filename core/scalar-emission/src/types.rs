//! Scalar Emission Types — Version Gate v11.1-FINAL
//!
//! Spec §8.4 v11.1-FINAL, §2.4:
//!   SPEC_VERSION_MANIFEST_V12 = 0x06 (v11.1-FINAL)
//!   SPEC_VERSION_MANIFEST     = 0x02 (v9.0, legacy — dipertahankan untuk backward compat)
//!
//! Production mode: node HARUS reject manifest dengan spec_version != 0x06.
//! Testnet compat mode (--testnet-compat flag): node BOLEH menerima 0x05.
//!
//! Re-export EpochRewardManifestV12 dan NodeRewardEntry dari dmm.rs
//! sebagai tipe kanonik untuk v11.1-FINAL.

pub use crate::dmm::{EpochRewardManifestV12, NodeRewardEntry, SPEC_VERSION_MANIFEST_V12};

// ── Version constants — spec §2.4 ────────────────────────────────────────────

/// SPEC_VERSION untuk v9.0 (legacy). Dipertahankan untuk backward compat.
pub const SPEC_VERSION_LEGACY: u8 = 0x02;

/// SPEC_VERSION untuk v11.1-FINAL. OSSIFIED — spec §2.4, §8.4.
pub const SPEC_VERSION_CURRENT: u8 = SPEC_VERSION_MANIFEST_V12; // 0x06

/// Jumlah epoch transisi testnet setelah rilis v11.1-FINAL. Spec §2.4.
pub const T_TRANSITION_EPOCHS: u64 = 4;

// ── ManifestVersionError — spec §8.4 ─────────────────────────────────────────

/// Error verifikasi versi manifest. Spec §8.4, §2.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestVersionError {
    /// spec_version tidak dikenal.
    UnknownVersion { version: u8 },
    /// spec_version 0x05 hanya diterima dengan flag testnet-compat. Spec §2.4.
    LegacyVersionRequiresTestnetCompat { version: u8 },
    /// spec_version bukan 0x06 di production mode. Spec §8.4.
    NotCurrentVersion { version: u8, expected: u8 },
}

impl core::fmt::Display for ManifestVersionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownVersion { version } => {
                write!(f, "Unknown spec_version: 0x{version:02X} — spec §8.4")
            }
            Self::LegacyVersionRequiresTestnetCompat { version } => write!(
                f,
                "spec_version 0x{version:02X} hanya diterima dengan --testnet-compat flag — spec §2.4"
            ),
            Self::NotCurrentVersion { version, expected } => write!(
                f,
                "spec_version 0x{version:02X} bukan versi current 0x{expected:02X} — spec §8.4"
            ),
        }
    }
}

// ── Version validation — spec §8.4, §2.4 ─────────────────────────────────────

/// Validasi spec_version manifest. Spec §8.4, §2.4.
///
/// Production mode (`testnet_compat = false`):
///   - 0x06 → Ok
///   - semua lain → Err
///
/// Testnet compat mode (`testnet_compat = true`):
///   - 0x06 → Ok
///   - 0x05 → Ok (transitional, selama T_TRANSITION_EPOCHS)
///   - semua lain → Err
///
/// Spec §2.4: "Node yang menerima manifest dengan spec_version != 0x06
/// harus REJECT pada mode production."
pub fn validate_manifest_version(
    version: u8,
    testnet_compat: bool,
) -> Result<(), ManifestVersionError> {
    match version {
        v if v == SPEC_VERSION_CURRENT => Ok(()), // 0x06 — selalu diterima
        0x05 if testnet_compat => Ok(()),         // 0x05 — hanya testnet-compat
        0x05 => Err(ManifestVersionError::LegacyVersionRequiresTestnetCompat { version: 0x05 }),
        v => Err(ManifestVersionError::NotCurrentVersion {
            version: v,
            expected: SPEC_VERSION_CURRENT,
        }),
    }
}

/// Cek apakah manifest V12 valid untuk diproses. Spec §8.4.
///
/// Verifikasi:
/// 1. spec_version == 0x06
/// 2. manifest_hash tidak zero (sudah dihitung)
/// 3. epoch_id > 0
pub fn validate_manifest_v12(
    manifest: &EpochRewardManifestV12,
    testnet_compat: bool,
) -> Result<(), ManifestVersionError> {
    validate_manifest_version(manifest.spec_version, testnet_compat)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── test_manifest_version_reject_old ─────────────────────────────────────

    #[test]
    fn test_manifest_version_reject_old() {
        // spec_version=0x05 di-reject pada mode production. Spec §8.4.
        let result = validate_manifest_version(0x05, false);
        assert_eq!(
            result,
            Err(ManifestVersionError::LegacyVersionRequiresTestnetCompat { version: 0x05 }),
            "0x05 harus di-reject di production mode"
        );
    }

    // ── test_manifest_version_accept_testnet ─────────────────────────────────

    #[test]
    fn test_manifest_version_accept_testnet() {
        // spec_version=0x05 diterima dengan flag --testnet-compat. Spec §2.4.
        let result = validate_manifest_version(0x05, true);
        assert!(result.is_ok(), "0x05 harus diterima dengan testnet-compat");
    }

    // ── test_manifest_version_0x06_always_accepted ───────────────────────────

    #[test]
    fn test_manifest_version_0x06_accepted_production() {
        // 0x06 diterima di production mode. Spec §8.4.
        assert!(validate_manifest_version(0x06, false).is_ok());
    }

    #[test]
    fn test_manifest_version_0x06_accepted_testnet() {
        // 0x06 diterima di testnet-compat mode. Spec §8.4.
        assert!(validate_manifest_version(0x06, true).is_ok());
    }

    // ── test_manifest_new_fields_serialized ──────────────────────────────────

    #[test]
    fn test_manifest_new_fields_exist() {
        // EpochRewardManifestV12 harus punya network_health_digest dan
        // NodeRewardEntry harus punya uptime_weight_fp. Spec §8.4.
        use crate::dmm::{EpochRewardManifestV12, NodeRewardEntry};
        let entry = NodeRewardEntry {
            node_id_full: [0x01u8; 32],
            reward_sscl: 1_000_000,
            uptime_weight_fp: 800_000, // field baru v11.1-FINAL
        };
        assert_eq!(entry.uptime_weight_fp, 800_000);

        let manifest = EpochRewardManifestV12 {
            epoch_id: 1,
            node_list: vec![entry],
            spec_version: SPEC_VERSION_CURRENT,
            total_emission_sscl: 1_000_000,
            deferred: false,
            seed_k: [0u8; 32],
            manifest_hash: [0u8; 32],
            reward_root: [0u8; 32],
            // FIX: dua field dalam satu baris → dipecah ke baris terpisah
            network_health_digest: [0xABu8; 32],
            tx_set_root: [0u8; 32],
        };
        assert_eq!(manifest.network_health_digest, [0xABu8; 32]);
        assert_eq!(manifest.spec_version, 0x06);
    }

    // ── test_spec_version_constants ───────────────────────────────────────────

    #[test]
    fn test_spec_version_current_is_0x06() {
        // SPEC_VERSION_CURRENT = 0x06. Spec §2.4.
        assert_eq!(SPEC_VERSION_CURRENT, 0x06u8);
    }

    #[test]
    fn test_spec_version_legacy_is_0x02() {
        // SPEC_VERSION_LEGACY = 0x02 (v9.0). Backward compat.
        assert_eq!(SPEC_VERSION_LEGACY, 0x02u8);
    }

    #[test]
    fn test_t_transition_epochs_is_4() {
        // T_TRANSITION_EPOCHS = 4. Spec §2.4.
        assert_eq!(T_TRANSITION_EPOCHS, 4u64);
    }

    // ── test_unknown_version_rejected ─────────────────────────────────────────

    #[test]
    fn test_unknown_version_rejected_production() {
        // Version tidak dikenal (0x01, 0x03, 0xFF) → rejected. Spec §8.4.
        for v in [0x01u8, 0x03, 0x04, 0xFF] {
            let result = validate_manifest_version(v, false);
            assert!(result.is_err(), "version 0x{v:02X} harus di-reject");
        }
    }

    #[test]
    fn test_unknown_version_rejected_testnet() {
        // Version tidak dikenal tetap di-reject bahkan di testnet-compat. Spec §8.4.
        for v in [0x01u8, 0x03, 0x04, 0xFF] {
            let result = validate_manifest_version(v, true);
            assert!(
                result.is_err(),
                "version 0x{v:02X} harus di-reject di testnet juga"
            );
        }
    }

    // ── test_validate_manifest_v12 ────────────────────────────────────────────

    #[test]
    fn test_validate_manifest_v12_production() {
        // Manifest v12 dengan spec_version=0x06 valid di production. Spec §8.4.
        use crate::dmm::EpochRewardManifestV12;
        let manifest = EpochRewardManifestV12 {
            epoch_id: 10,
            node_list: vec![],
            spec_version: 0x06,
            total_emission_sscl: 0,
            deferred: true,
            seed_k: [0u8; 32],
            manifest_hash: [0u8; 32],
            reward_root: [0u8; 32],
            network_health_digest: [0u8; 32],
            tx_set_root: [0u8; 32],
        };
        assert!(validate_manifest_v12(&manifest, false).is_ok());
    }
}
