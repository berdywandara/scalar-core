// File: crates/scalar-crypto/src/version.rs

use std::collections::BTreeMap;

pub const CURRENT_VERSION: u8 = 0x01;
pub const TRANSITION_WINDOW_EPOCHS: u64 = 10; // Periode transisi/overlap (contoh: 10 epoch)

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CryptoVersion {
    pub id: u8,
    pub activation_epoch: u64,
    pub deprecation_epoch: Option<u64>,
}

pub struct CryptoRegistry {
    versions: BTreeMap<u8, CryptoVersion>,
    current_epoch: u64,
}

impl CryptoRegistry {
    pub fn new(current_epoch: u64) -> Self {
        let mut versions = BTreeMap::new();
        // Versi genesis selalu 0x01, aktif sejak epoch 0
        versions.insert(
            0x01,
            CryptoVersion {
                id: 0x01,
                activation_epoch: 0,
                deprecation_epoch: None,
            },
        );
        Self {
            versions,
            current_epoch,
        }
    }

    pub fn set_current_epoch(&mut self, epoch: u64) {
        self.current_epoch = epoch;
    }

    /// Menambahkan versi kriptografi baru (Upgrade tanpa hardfork)
    pub fn add_version(&mut self, id: u8, activation_epoch: u64) -> Result<(), &'static str> {
        let latest_id = self.versions.keys().last().copied().unwrap_or(0);

        if id <= latest_id {
            return Err("Version ID must be monotonic");
        }
        if activation_epoch <= self.current_epoch {
            return Err("Activation epoch must be in the future");
        }

        // Set deprecation epoch untuk versi sebelumnya agar tercipta transition window
        if let Some(latest_ver) = self.versions.get_mut(&latest_id) {
            latest_ver.deprecation_epoch = Some(activation_epoch + TRANSITION_WINDOW_EPOCHS);
        }

        self.versions.insert(
            id,
            CryptoVersion {
                id,
                activation_epoch,
                deprecation_epoch: None,
            },
        );

        Ok(())
    }

    pub fn is_valid_at(&self, id: u8, epoch: u64) -> bool {
        if let Some(ver) = self.versions.get(&id) {
            if epoch < ver.activation_epoch {
                return false;
            }
            if let Some(dep_epoch) = ver.deprecation_epoch {
                if epoch > dep_epoch {
                    return false;
                }
            }
            return true;
        }
        false
    }

    pub fn verify_proof_version(&self, id: u8) -> Result<(), &'static str> {
        if self.is_valid_at(id, self.current_epoch) {
            Ok(())
        } else {
            Err("Invalid or deprecated proof version")
        }
    }
}

impl Default for CryptoRegistry {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_current_version_is_0x01() {
        assert_eq!(CURRENT_VERSION, 0x01);
    }

    #[test]
    fn test_version_0x01_valid_at_epoch_0() {
        let registry = CryptoRegistry::new(0);
        assert!(registry.is_valid_at(0x01, 0));
    }

    #[test]
    fn test_unknown_version_invalid() {
        let registry = CryptoRegistry::new(0);
        assert!(!registry.is_valid_at(0xFF, 0));
    }

    #[test]
    fn test_version_id_must_be_monotonic() {
        let mut registry = CryptoRegistry::new(0);
        assert!(registry.add_version(0x01, 10).is_err());
        assert!(registry.add_version(0x02, 10).is_ok());
    }

    #[test]
    fn test_activation_epoch_must_be_future() {
        let mut registry = CryptoRegistry::new(10);
        assert!(registry.add_version(0x02, 5).is_err());
        assert!(registry.add_version(0x02, 10).is_err());
        assert!(registry.add_version(0x02, 11).is_ok());
    }

    #[test]
    fn test_transition_window_both_versions_valid() {
        let mut registry = CryptoRegistry::new(0);
        registry.add_version(0x02, 20).unwrap();

        // Pada epoch 25, transition window masih berlangsung (sampai epoch 30).
        // Oleh karena itu, 0x01 dan 0x02 keduanya valid.
        assert!(registry.is_valid_at(0x01, 25));
        assert!(registry.is_valid_at(0x02, 25));

        // Pada epoch 31, versi 0x01 sudah ditutup (deprecated).
        assert!(!registry.is_valid_at(0x01, 31));
        assert!(registry.is_valid_at(0x02, 31));
    }

    #[test]
    fn test_proof_version_verification() {
        let mut registry = CryptoRegistry::new(5);
        assert!(registry.verify_proof_version(0x01).is_ok());
        assert!(registry.verify_proof_version(0x02).is_err());

        registry.add_version(0x02, 10).unwrap();
        registry.set_current_epoch(15);
        assert!(registry.verify_proof_version(0x01).is_ok()); // Masih valid dalam window transisi
        assert!(registry.verify_proof_version(0x02).is_ok()); // Versi baru mulai valid
    }
}
