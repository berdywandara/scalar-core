//! Crypto-Agility Framework (D-014). MAD §1.1, §21.2.
//!
//! CryptoSuite registry (append-only) + version negotiation + dual-version window.
//!
//! Rules (OSSIFIED):
//!   - Suite V1 (0x01) is GENESIS and IMMUTABLE — never removed.
//!   - New suites added via governance COMMIT 75% — append-only.
//!   - DOWNGRADE is FORBIDDEN — version IDs monotonically increasing.
//!   - Dual-version window: max DUAL_VERSION_WINDOW_EPOCHS (12) epochs.
//!   - Both old and new suite valid during transition window.
//!
//! CONSTRAINED parameters (MAD §21.2):
//!   - Crypto suite registry: append-only
//!   - Default active suite: V1 → can upgrade via governance
//!   - Dual-version window length: max 12 epoch

// ── CONSTRAINED parameters — MAD §21.2 ───────────────────────────────────────

/// Maximum epochs both old and new suite are simultaneously valid. CONSTRAINED — MAD §21.2.
/// After this window, old suite is rejected.
pub const DUAL_VERSION_WINDOW_EPOCHS: u64 = 12;

// ── Suite IDs ─────────────────────────────────────────────────────────────────

/// Genesis crypto suite version. OSSIFIED — MAD §1.1.
pub const SUITE_V1: u8 = 0x01;

// ── Algorithm identifiers ─────────────────────────────────────────────────────

/// Hash function identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashFunction {
    /// Poseidon2 Goldilocks (t=8, alpha=7, R_F=8, R_P=22). OSSIFIED suite V1.
    Poseidon2Goldilocks,
}

/// Signature scheme identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureScheme {
    /// SLH-DSA (SPHINCS+ per NIST FIPS 205). OSSIFIED suite V1.
    SlhDsa,
}

/// Proof system identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofSystem {
    /// Plonky3 FRI (Goldilocks field). OSSIFIED suite V1.
    Plonky3Fri,
}

/// P2P key exchange identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pKeyExchange {
    /// Hybrid X25519 + ML-KEM-768. OSSIFIED suite V1.
    HybridX25519MlKem768,
}

// ── CryptoSuite descriptor ────────────────────────────────────────────────────

/// Complete descriptor for one crypto suite. MAD §1.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoSuiteDescriptor {
    /// Suite version ID. Monotonically increasing.
    pub version: u8,
    /// Hash function used in-circuit and out-of-circuit.
    pub hash_function: HashFunction,
    /// Node signature scheme (heartbeat + anchor).
    pub signature_scheme: SignatureScheme,
    /// ZK proof system.
    pub proof_system: ProofSystem,
    /// P2P transport key exchange.
    pub p2p_key_exchange: P2pKeyExchange,
    /// Human-readable label (not used for any protocol logic).
    pub label: &'static str,
}

impl CryptoSuiteDescriptor {
    /// Genesis suite V1. OSSIFIED — MAD §1.1.
    pub const fn v1() -> Self {
        Self {
            version: SUITE_V1,
            hash_function: HashFunction::Poseidon2Goldilocks,
            signature_scheme: SignatureScheme::SlhDsa,
            proof_system: ProofSystem::Plonky3Fri,
            p2p_key_exchange: P2pKeyExchange::HybridX25519MlKem768,
            label: "CRYPTO_SUITE_V1 (GENESIS)",
        }
    }
}

// ── CryptoSuiteRegistry ───────────────────────────────────────────────────────

/// Append-only registry of crypto suites. MAD §21.2 D-014.
///
/// Invariants:
///   - Suite V1 always at index 0 (OSSIFIED).
///   - Suite IDs are strictly increasing (no downgrade).
///   - New suites appended via governance only.
pub struct CryptoSuiteRegistry {
    suites: Vec<CryptoSuiteDescriptor>,
}

/// Error from CryptoSuiteRegistry operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("Downgrade forbidden: new suite version {new} <= current max {current}")]
    DowngradeForbidden { new: u8, current: u8 },

    #[error("Suite V1 is OSSIFIED and cannot be removed")]
    CannotRemoveV1,

    #[error("Suite version {0} not found in registry")]
    NotFound(u8),

    #[error("Registry is empty — V1 must always be present")]
    Empty,
}

impl CryptoSuiteRegistry {
    /// Create registry with V1 pre-loaded. MAD §1.1.
    pub fn new() -> Self {
        Self {
            suites: vec![CryptoSuiteDescriptor::v1()],
        }
    }

    /// Append a new suite. Governance COMMIT 75% required before calling.
    ///
    /// Enforces: version must be strictly greater than all existing versions.
    /// Returns Err if downgrade attempted.
    pub fn append(&mut self, suite: CryptoSuiteDescriptor) -> Result<(), RegistryError> {
        let max_version = self.suites.iter().map(|s| s.version).max().unwrap_or(0);
        if suite.version <= max_version {
            return Err(RegistryError::DowngradeForbidden {
                new: suite.version,
                current: max_version,
            });
        }
        self.suites.push(suite);
        Ok(())
    }

    /// Get suite descriptor by version ID.
    pub fn get(&self, version: u8) -> Option<&CryptoSuiteDescriptor> {
        self.suites.iter().find(|s| s.version == version)
    }

    /// Highest version in registry (= current active suite).
    pub fn active_version(&self) -> u8 {
        self.suites
            .iter()
            .map(|s| s.version)
            .max()
            .unwrap_or(SUITE_V1)
    }

    /// All registered versions, sorted ascending.
    pub fn all_versions(&self) -> Vec<u8> {
        let mut v: Vec<u8> = self.suites.iter().map(|s| s.version).collect();
        v.sort_unstable();
        v
    }

    /// Number of suites in registry.
    pub fn len(&self) -> usize {
        self.suites.len()
    }

    /// Is the registry empty? (invariant: always false — V1 always present)
    pub fn is_empty(&self) -> bool {
        self.suites.is_empty()
    }

    /// Is V1 still present? (invariant: always true)
    pub fn has_v1(&self) -> bool {
        self.suites.iter().any(|s| s.version == SUITE_V1)
    }
}

impl Default for CryptoSuiteRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Version negotiation ───────────────────────────────────────────────────────

/// Negotiate the highest mutually supported suite version. MAD D-014.
///
/// `local_versions`: versions supported by this node.
/// `remote_versions`: versions supported by remote peer.
///
/// Returns the highest version both support, or None if no overlap.
pub fn negotiate_version(local_versions: &[u8], remote_versions: &[u8]) -> Option<u8> {
    local_versions
        .iter()
        .filter(|v| remote_versions.contains(v))
        .copied()
        .max()
}

// ── Dual-version window ───────────────────────────────────────────────────────

/// Dual-version window enforcement. MAD §21.2 D-014.
///
/// During a suite upgrade, both old and new suites are valid for up to
/// DUAL_VERSION_WINDOW_EPOCHS (12) epochs. After that, old suite is rejected.
#[derive(Debug, Clone)]
pub struct DualVersionWindow {
    /// The old (outgoing) suite version.
    pub old_version: u8,
    /// The new (incoming) suite version.
    pub new_version: u8,
    /// Epoch when the transition started.
    pub transition_started_epoch: u64,
}

impl DualVersionWindow {
    /// Create a new dual-version window at the start of a transition.
    pub fn new(
        old_version: u8,
        new_version: u8,
        current_epoch: u64,
    ) -> Result<Self, RegistryError> {
        if new_version <= old_version {
            return Err(RegistryError::DowngradeForbidden {
                new: new_version,
                current: old_version,
            });
        }
        Ok(Self {
            old_version,
            new_version,
            transition_started_epoch: current_epoch,
        })
    }

    /// Is a given suite version valid in the current epoch? MAD §21.2.
    ///
    /// - new_version: always valid.
    /// - old_version: valid only within DUAL_VERSION_WINDOW_EPOCHS.
    /// - anything else: invalid.
    pub fn is_version_valid(&self, version: u8, current_epoch: u64) -> bool {
        if version == self.new_version {
            return true;
        }
        if version == self.old_version {
            let elapsed = current_epoch.saturating_sub(self.transition_started_epoch);
            return elapsed < DUAL_VERSION_WINDOW_EPOCHS;
        }
        false
    }

    /// Epochs remaining in the transition window for old_version.
    pub fn epochs_remaining(&self, current_epoch: u64) -> u64 {
        let elapsed = current_epoch.saturating_sub(self.transition_started_epoch);
        DUAL_VERSION_WINDOW_EPOCHS.saturating_sub(elapsed)
    }

    /// Is the transition window expired? Old suite must be rejected after this.
    pub fn is_expired(&self, current_epoch: u64) -> bool {
        self.epochs_remaining(current_epoch) == 0
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ─────────────────────────────────────────────────────

    #[test]
    fn test_suite_v1_ossified() {
        assert_eq!(SUITE_V1, 0x01);
        assert_eq!(DUAL_VERSION_WINDOW_EPOCHS, 12);
    }

    #[test]
    fn test_v1_descriptor_correct() {
        let v1 = CryptoSuiteDescriptor::v1();
        assert_eq!(v1.version, 0x01);
        assert_eq!(v1.hash_function, HashFunction::Poseidon2Goldilocks);
        assert_eq!(v1.signature_scheme, SignatureScheme::SlhDsa);
        assert_eq!(v1.proof_system, ProofSystem::Plonky3Fri);
        assert_eq!(v1.p2p_key_exchange, P2pKeyExchange::HybridX25519MlKem768);
    }

    // ── Registry ──────────────────────────────────────────────────────

    #[test]
    fn test_registry_has_v1_on_creation() {
        let r = CryptoSuiteRegistry::new();
        assert!(r.has_v1());
        assert_eq!(r.active_version(), SUITE_V1);
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn test_registry_append_v2_succeeds() {
        let mut r = CryptoSuiteRegistry::new();
        let v2 = CryptoSuiteDescriptor {
            version: 0x02,
            hash_function: HashFunction::Poseidon2Goldilocks,
            signature_scheme: SignatureScheme::SlhDsa,
            proof_system: ProofSystem::Plonky3Fri,
            p2p_key_exchange: P2pKeyExchange::HybridX25519MlKem768,
            label: "CRYPTO_SUITE_V2 (hypothetical)",
        };
        r.append(v2).unwrap();
        assert_eq!(r.active_version(), 0x02);
        assert_eq!(r.len(), 2);
        assert!(r.has_v1(), "V1 must remain after append");
    }

    #[test]
    fn test_registry_downgrade_forbidden() {
        let mut r = CryptoSuiteRegistry::new();
        let v0 = CryptoSuiteDescriptor {
            version: 0x00, // downgrade attempt
            hash_function: HashFunction::Poseidon2Goldilocks,
            signature_scheme: SignatureScheme::SlhDsa,
            proof_system: ProofSystem::Plonky3Fri,
            p2p_key_exchange: P2pKeyExchange::HybridX25519MlKem768,
            label: "INVALID",
        };
        assert!(matches!(
            r.append(v0).unwrap_err(),
            RegistryError::DowngradeForbidden { .. }
        ));
    }

    #[test]
    fn test_registry_duplicate_version_forbidden() {
        let mut r = CryptoSuiteRegistry::new();
        let dup = CryptoSuiteDescriptor {
            version: 0x01, // duplicate V1
            hash_function: HashFunction::Poseidon2Goldilocks,
            signature_scheme: SignatureScheme::SlhDsa,
            proof_system: ProofSystem::Plonky3Fri,
            p2p_key_exchange: P2pKeyExchange::HybridX25519MlKem768,
            label: "DUP",
        };
        assert!(r.append(dup).is_err());
    }

    #[test]
    fn test_registry_all_versions_sorted() {
        let mut r = CryptoSuiteRegistry::new();
        let v2 = CryptoSuiteDescriptor {
            version: 0x02,
            ..CryptoSuiteDescriptor::v1()
        };
        let v3 = CryptoSuiteDescriptor {
            version: 0x03,
            ..CryptoSuiteDescriptor::v1()
        };
        r.append(v2).unwrap();
        r.append(v3).unwrap();
        assert_eq!(r.all_versions(), vec![0x01, 0x02, 0x03]);
    }

    // ── Version negotiation ───────────────────────────────────────────

    #[test]
    fn test_negotiate_common_version() {
        let local = [0x01u8, 0x02];
        let remote = [0x01u8, 0x02];
        assert_eq!(negotiate_version(&local, &remote), Some(0x02));
    }

    #[test]
    fn test_negotiate_picks_highest_common() {
        let local = [0x01u8, 0x02, 0x03];
        let remote = [0x01u8, 0x02];
        assert_eq!(negotiate_version(&local, &remote), Some(0x02));
    }

    #[test]
    fn test_negotiate_no_overlap_returns_none() {
        let local = [0x02u8];
        let remote = [0x01u8];
        assert_eq!(negotiate_version(&local, &remote), None);
    }

    #[test]
    fn test_negotiate_both_v1_only() {
        assert_eq!(negotiate_version(&[0x01], &[0x01]), Some(0x01));
    }

    // ── Dual-version window ───────────────────────────────────────────

    #[test]
    fn test_dual_window_new_valid() {
        let w = DualVersionWindow::new(0x01, 0x02, 100).unwrap();
        assert_eq!(w.old_version, 0x01);
        assert_eq!(w.new_version, 0x02);
        assert_eq!(w.transition_started_epoch, 100);
    }

    #[test]
    fn test_dual_window_downgrade_rejected() {
        assert!(DualVersionWindow::new(0x02, 0x01, 0).is_err());
    }

    #[test]
    fn test_dual_window_new_version_always_valid() {
        let w = DualVersionWindow::new(0x01, 0x02, 100).unwrap();
        assert!(w.is_version_valid(0x02, 200)); // far future
    }

    #[test]
    fn test_dual_window_old_valid_within_window() {
        let w = DualVersionWindow::new(0x01, 0x02, 100).unwrap();
        assert!(w.is_version_valid(0x01, 100)); // same epoch
        assert!(w.is_version_valid(0x01, 111)); // epoch 100+11
    }

    #[test]
    fn test_dual_window_old_invalid_after_window() {
        let w = DualVersionWindow::new(0x01, 0x02, 100).unwrap();
        // epoch 100+12 = expired
        assert!(!w.is_version_valid(0x01, 112));
        assert!(!w.is_version_valid(0x01, 200));
    }

    #[test]
    fn test_dual_window_unknown_version_invalid() {
        let w = DualVersionWindow::new(0x01, 0x02, 0).unwrap();
        assert!(!w.is_version_valid(0x03, 0));
        assert!(!w.is_version_valid(0xFF, 0));
    }

    #[test]
    fn test_dual_window_epochs_remaining() {
        let w = DualVersionWindow::new(0x01, 0x02, 100).unwrap();
        assert_eq!(w.epochs_remaining(100), 12);
        assert_eq!(w.epochs_remaining(106), 6);
        assert_eq!(w.epochs_remaining(112), 0);
    }

    #[test]
    fn test_dual_window_expired() {
        let w = DualVersionWindow::new(0x01, 0x02, 0).unwrap();
        assert!(!w.is_expired(11));
        assert!(w.is_expired(12));
        assert!(w.is_expired(100));
    }
}
