#[derive(Clone, Debug, PartialEq)]
pub struct CryptoVersion {
    pub version_id: u8,
    pub in_circuit_hash: u8,
    pub out_circuit_hash: u8,
    pub signature_scheme: u8,
    pub stark_field: u8,
    pub activated_epoch: u64,
}

impl CryptoVersion {
    pub const CURRENT: Self = Self {
        version_id: 0x01,
        in_circuit_hash: 0x01,
        out_circuit_hash: 0x01,
        signature_scheme: 0x01,
        stark_field: 0x01,
        activated_epoch: 0,
    };
}

pub struct CryptoVersionRegistry {
    versions: Vec<CryptoVersion>,
    pub current_epoch: u64,
}

impl CryptoVersionRegistry {
    pub fn new() -> Self {
        Self {
            versions: vec![CryptoVersion::CURRENT],
            current_epoch: 0,
        }
    }

    pub fn is_valid_version(&self, version_id: u8, at_epoch: u64) -> bool {
        const T_TRANSITION_EPOCHS: u64 = 2;
        let current_max = self.current_version().version_id;

        for version in &self.versions {
            if version.version_id == version_id {
                if at_epoch < version.activated_epoch {
                    return false;
                }
                if version.version_id == current_max {
                    return true;
                }
                if let Some(next_version) = self.versions.iter().find(|v| v.version_id > version_id)
                {
                    let transition_end = next_version.activated_epoch + T_TRANSITION_EPOCHS;
                    return at_epoch < transition_end;
                }
            }
        }
        false
    }

    pub fn current_version(&self) -> &CryptoVersion {
        self.versions
            .last()
            .expect("Registry harus selalu punya >=1 versi")
    }

    pub fn register_new_version(&mut self, new_version: CryptoVersion) -> Result<(), VersionError> {
        let current_max = self.current_version().version_id;
        if new_version.version_id <= current_max {
            return Err(VersionError::NonMonotonicVersionId {
                current: current_max,
                attempted: new_version.version_id,
            });
        }
        if new_version.activated_epoch <= self.current_epoch {
            return Err(VersionError::ActivationInPast {
                current_epoch: self.current_epoch,
                attempted_epoch: new_version.activated_epoch,
            });
        }
        self.versions.push(new_version);
        Ok(())
    }

    pub fn verify_proof_version(
        &self,
        version_id: u8,
        proof_epoch: u64,
    ) -> Result<&CryptoVersion, VersionError> {
        if !self.is_valid_version(version_id, proof_epoch) {
            return Err(VersionError::InvalidVersionForEpoch {
                version_id,
                epoch: proof_epoch,
            });
        }
        self.versions
            .iter()
            .find(|v| v.version_id == version_id)
            .ok_or(VersionError::VersionNotFound { version_id })
    }
}

impl Default for CryptoVersionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum VersionError {
    NonMonotonicVersionId {
        current: u8,
        attempted: u8,
    },
    ActivationInPast {
        current_epoch: u64,
        attempted_epoch: u64,
    },
    InvalidVersionForEpoch {
        version_id: u8,
        epoch: u64,
    },
    VersionNotFound {
        version_id: u8,
    },
}

#[cfg(test)]
mod tests_crypto_version {
    use super::*;

    #[test]
    fn test_current_version_is_0x01() {
        let registry = CryptoVersionRegistry::new();
        assert_eq!(registry.current_version().version_id, 0x01);
    }

    #[test]
    fn test_version_0x01_valid_at_epoch_0() {
        let registry = CryptoVersionRegistry::new();
        assert!(registry.is_valid_version(0x01, 0));
        assert!(registry.is_valid_version(0x01, 100));
        assert!(registry.is_valid_version(0x01, 99999));
    }

    #[test]
    fn test_unknown_version_invalid() {
        let registry = CryptoVersionRegistry::new();
        assert!(!registry.is_valid_version(0xFF, 0));
        assert!(!registry.is_valid_version(0x02, 0));
    }

    #[test]
    fn test_version_id_must_be_monotonic() {
        let mut registry = CryptoVersionRegistry::new();
        let bad_version = CryptoVersion {
            version_id: 0x01,
            activated_epoch: 100,
            ..CryptoVersion::CURRENT
        };
        assert!(registry.register_new_version(bad_version).is_err());
    }

    #[test]
    fn test_activation_epoch_must_be_future() {
        let mut registry = CryptoVersionRegistry::new();
        registry.current_epoch = 50;
        let bad_version = CryptoVersion {
            version_id: 0x02,
            activated_epoch: 30,
            ..CryptoVersion::CURRENT
        };
        assert!(registry.register_new_version(bad_version).is_err());
    }

    #[test]
    fn test_transition_window_both_versions_valid() {
        let mut registry = CryptoVersionRegistry::new();
        let version_2 = CryptoVersion {
            version_id: 0x02,
            activated_epoch: 100,
            ..CryptoVersion::CURRENT
        };
        registry.register_new_version(version_2).unwrap();
        assert!(registry.is_valid_version(0x02, 100));
        assert!(registry.is_valid_version(0x01, 99));
        assert!(!registry.is_valid_version(0x02, 99));
        assert!(registry.is_valid_version(0x01, 101));
        assert!(!registry.is_valid_version(0x01, 102));
    }

    #[test]
    fn test_proof_version_verification() {
        let registry = CryptoVersionRegistry::new();
        let result = registry.verify_proof_version(0x01, 42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().version_id, 0x01);
        let result = registry.verify_proof_version(0xFF, 42);
        assert!(result.is_err());
    }
}
