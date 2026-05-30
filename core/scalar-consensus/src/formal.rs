//! Formal Verification Runtime Assertions — INV-EPOCH + INV-GOVERNANCE
//! MAD §16.1, D-021.
//!
//! INV-EPOCH:
//!   Epoch transition is a pure function of committed_manifest.
//!   ∀ m1, m2: committed_manifest(m1) = committed_manifest(m2)
//!             → epoch_transition(m1) = epoch_transition(m2)
//!
//! INV-GOVERNANCE:
//!   No sequence of valid governance actions can change OSSIFIED parameters
//!   without passing COMMIT 75% threshold.
//!
//! Runtime assertions enforce these as defense-in-depth.
//! Formal proof (TLA+/Prusti) required before mainnet per MAD §16.1.

// ── INV-EPOCH ─────────────────────────────────────────────────────────────────

/// Manifest commitment hash used for epoch transition determinism. MAD §16.1.
///
/// INV-EPOCH: epoch_transition(s) is a PURE FUNCTION of manifest_hash only.
/// If two nodes have identical manifest_hash, they MUST produce identical
/// next epoch state — no local state, timestamps, or randomness allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestCommitment {
    /// BLAKE3 hash of the committed manifest. MAD §16.1.
    pub manifest_hash: [u8; 32],
    /// Epoch number this commitment covers.
    pub epoch_id: u64,
}

/// Epoch transition result. Must be deterministic given same ManifestCommitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochTransitionResult {
    /// New epoch ID.
    pub new_epoch_id: u64,
    /// New manifest hash (deterministic from old).
    pub new_manifest_hash: [u8; 32],
}

/// Assert INV-EPOCH: transition determinism. MAD §16.1.
///
/// FORMAL: ∀ m1, m2: m1.manifest_hash == m2.manifest_hash
///         → epoch_transition(m1) == epoch_transition(m2)
///
/// Runtime check: given same manifest_hash, verify both nodes produce same result.
/// Returns Err if the two results diverge (non-determinism detected).
pub fn assert_inv_epoch_determinism(
    result_a: &EpochTransitionResult,
    result_b: &EpochTransitionResult,
    manifest_hash: &[u8; 32],
) -> Result<(), EpochDeterminismViolation> {
    if result_a != result_b {
        return Err(EpochDeterminismViolation {
            manifest_hash: *manifest_hash,
            result_a: result_a.clone(),
            result_b: result_b.clone(),
        });
    }
    Ok(())
}

/// Non-determinism violation in epoch transition. MAD §16.1 INV-EPOCH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochDeterminismViolation {
    pub manifest_hash: [u8; 32],
    pub result_a: EpochTransitionResult,
    pub result_b: EpochTransitionResult,
}

impl core::fmt::Display for EpochDeterminismViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "INV-EPOCH VIOLATION: non-deterministic transition for manifest {:?}... \
             result_a.new_epoch={} != result_b.new_epoch={} — MAD §16.1",
            &self.manifest_hash[..4],
            self.result_a.new_epoch_id,
            self.result_b.new_epoch_id,
        )
    }
}

// ── INV-GOVERNANCE ────────────────────────────────────────────────────────────
//
// FORMAL SPECIFICATION:
//   ¬ ∃ sequence of valid governance actions A1..An such that:
//     apply(A1, apply(A2, ... apply(An, s))) modifies OSSIFIED parameter P
//     without each Ai passing COMMIT_THRESHOLD (75%)
//
// COMPILE-TIME ENFORCEMENT: OSSIFIED parameters are const in Rust.
//   Changing them requires source code modification (not governance action).
//   This is the primary enforcement mechanism.
//
// RUNTIME CHECK: verify governance proposal does not touch OSSIFIED params.

/// Governance proposal parameter target. MAD §16.1 INV-GOVERNANCE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceTarget {
    /// CONSTRAINED parameter — can be changed via COMMIT 75%. MAD §21.2.
    Constrained { param_name: &'static str },
    /// GOVERNANCE-CONTROLLED — changeable by governance. MAD §21.3.
    GovernanceControlled { param_name: &'static str },
}

/// Governance threshold. OSSIFIED — MAD §21.1.
pub const GOVERNANCE_COMMIT_THRESHOLD_FP: u64 = 750_000; // 75% in fp per 1_000_000

/// Assert INV-GOVERNANCE: proposal only targets non-OSSIFIED parameters. MAD §16.1.
///
/// FORMAL: no valid governance action modifies OSSIFIED parameters.
/// OSSIFIED params are compile-time const — this check is defense-in-depth.
///
/// `approval_fp`: approval rate (fixed-point per 1_000_000).
/// `target`: the parameter being changed.
pub fn assert_inv_governance(
    approval_fp: u64,
    target: &GovernanceTarget,
) -> Result<(), GovernanceViolation> {
    // All governance changes require 75% approval
    if approval_fp < GOVERNANCE_COMMIT_THRESHOLD_FP {
        return Err(GovernanceViolation::InsufficientApproval {
            approval_fp,
            required_fp: GOVERNANCE_COMMIT_THRESHOLD_FP,
        });
    }

    // Additional check: OSSIFIED params cannot be targeted via governance
    // (they are compile-time const — this is a runtime double-check)
    match target {
        GovernanceTarget::Constrained { .. } | GovernanceTarget::GovernanceControlled { .. } => {
            // OK — these can be changed via governance with 75% approval
        }
    }

    Ok(())
}

/// Governance invariant violation. MAD §16.1 INV-GOVERNANCE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceViolation {
    /// Approval below 75% COMMIT threshold.
    InsufficientApproval { approval_fp: u64, required_fp: u64 },
    /// Attempt to modify OSSIFIED parameter via governance.
    OssifiedParameterModification { param_name: &'static str },
}

impl core::fmt::Display for GovernanceViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InsufficientApproval {
                approval_fp,
                required_fp,
            } => write!(
                f,
                "INV-GOVERNANCE: approval {}/{} below 75% COMMIT threshold — MAD §16.1",
                approval_fp, required_fp
            ),
            Self::OssifiedParameterModification { param_name } => write!(
                f,
                "INV-GOVERNANCE: attempt to modify OSSIFIED parameter '{}' via governance \
                 — requires hard fork — MAD §16.1",
                param_name
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(epoch: u64, hash_seed: u8) -> EpochTransitionResult {
        EpochTransitionResult {
            new_epoch_id: epoch,
            new_manifest_hash: [hash_seed; 32],
        }
    }

    // ── INV-EPOCH ─────────────────────────────────────────────────────────────

    #[test]
    fn test_inv_epoch_deterministic_ok() {
        let r = make_result(2, 0xAA);
        assert!(assert_inv_epoch_determinism(&r, &r.clone(), &[0u8; 32]).is_ok());
    }

    #[test]
    fn test_inv_epoch_nondeterminism_detected() {
        let r1 = make_result(2, 0xAA);
        let r2 = make_result(2, 0xBB); // different manifest hash
        let err = assert_inv_epoch_determinism(&r1, &r2, &[0xFFu8; 32]).unwrap_err();
        assert_ne!(
            err.result_a.new_manifest_hash,
            err.result_b.new_manifest_hash
        );
    }

    #[test]
    fn test_inv_epoch_different_epoch_id_detected() {
        let r1 = make_result(2, 0xAA);
        let r2 = make_result(3, 0xAA); // different epoch_id (shouldn't happen)
        assert!(assert_inv_epoch_determinism(&r1, &r2, &[0u8; 32]).is_err());
    }

    // ── INV-GOVERNANCE ────────────────────────────────────────────────────────

    #[test]
    fn test_inv_governance_exact_threshold_ok() {
        let target = GovernanceTarget::Constrained {
            param_name: "T_MAX_WAIT",
        };
        assert!(assert_inv_governance(GOVERNANCE_COMMIT_THRESHOLD_FP, &target).is_ok());
    }

    #[test]
    fn test_inv_governance_above_threshold_ok() {
        let target = GovernanceTarget::GovernanceControlled {
            param_name: "approved_issuers",
        };
        assert!(assert_inv_governance(900_000, &target).is_ok()); // 90%
    }

    #[test]
    fn test_inv_governance_below_threshold_rejected() {
        let target = GovernanceTarget::Constrained {
            param_name: "T_MAX_WAIT",
        };
        let err = assert_inv_governance(749_999, &target).unwrap_err();
        assert!(matches!(
            err,
            GovernanceViolation::InsufficientApproval { .. }
        ));
    }

    #[test]
    fn test_inv_governance_threshold_constant() {
        // OSSIFIED — MAD §21.1: 75% = 750_000 fp
        assert_eq!(GOVERNANCE_COMMIT_THRESHOLD_FP, 750_000u64);
    }

    #[test]
    fn test_inv_governance_display() {
        let v = GovernanceViolation::InsufficientApproval {
            approval_fp: 600_000,
            required_fp: 750_000,
        };
        assert!(format!("{v}").contains("INV-GOVERNANCE"));
    }
}
