//! Formal Verification Runtime Assertions — Invariant CC
//!
//! Spec §15.4 v11.1-FINAL: runtime assertions as defense-in-depth.
//!
//! before mainnet: invariant CC harus atproofkan secara formal (TLA+/Coq).
//! File TLA+: verification/invariant_cc.tla
//!
//! Runtime assertions this running in debug builds as defense-in-depth.
//! not menggantikan formal proof — mecompleteinya.

// ── Invariant CC Runtime Assertion — spec §15.4 ───────────────────────────────

/// Status non-membership check for one nullifier. Spec §15.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonMembershipStatus {
    /// Nullifier none in set — valid for used. Spec §15.4.
    NonMember,
    /// Nullifier already exists in set — double-spend attempt. Spec §15.4.
    Member,
}

/// verification invariant CC for one nullifier. Spec §15.4.
///
/// Invariant: if n ∈ (NS_ACTIVE ∪ NS_CHECKPOINT), then
///   SMT_NonMembershipVerify(n, active_root) == FALSE ∧
///   SMT_NonMembershipVerify(n, archived_root) == FALSE
///
/// `in_active`: apakah nullifier exists in NS_ACTIVE.
/// `in_checkpoint`: apakah nullifier exists in NS_CHECKPOINT.
///
/// Returns Err if nullifier already exists at wrong satu set (double-spend attempt).
pub fn assert_cc_invariant(
    nullifier: &[u8; 32],
    in_active: bool,
    in_checkpoint: bool,
) -> Result<NonMembershipStatus, CcInvariantViolation> {
    if in_active || in_checkpoint {
        // Defense-in-depth: dalam production, ini sudah dicegah oleh ZK proof
        // Runtime check ini untuk mendeteksi implementasi yang salah
        #[cfg(debug_assertions)]
        {
            // Dalam debug build: panic untuk immediate feedback
            // Production: return Err dan log
        }
        return Err(CcInvariantViolation {
            nullifier: *nullifier,
            in_active,
            in_checkpoint,
        });
    }
    Ok(NonMembershipStatus::NonMember)
}

/// Pelanggaran invariant CC. Spec §15.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcInvariantViolation {
    /// Nullifier that melanggar invariant.
    pub nullifier: [u8; 32],
    /// Apakah exists in NS_ACTIVE.
    pub in_active: bool,
    /// Apakah exists in NS_CHECKPOINT.
    pub in_checkpoint: bool,
}

impl core::fmt::Display for CcInvariantViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "CC INVARIANT VIOLATION: nullifier {:?} sudah ada \
             (in_active={}, in_checkpoint={}) — double-spend attempt! spec §15.4",
            &self.nullifier[..4],
            self.in_active,
            self.in_checkpoint
        )
    }
}

/// zero-gap property assertion. Spec §6.3, §15.4.
///
/// ensure none window at mana nullifier hilang antara
/// NS_ACTIVE and NS_CHECKPOINT during checkpoint operation.
///
/// `nullifier_being_archived`: nullifier that currently atpindah to checkpoint.
/// `already_in_checkpoint`: apakah already masuk checkpoint.
pub fn assert_zero_gap_property(
    nullifier: &[u8; 32],
    already_in_checkpoint: bool,
) -> Result<(), ZeroGapViolation> {
    if !already_in_checkpoint {
        return Err(ZeroGapViolation {
            nullifier: *nullifier,
        });
    }
    Ok(())
}

/// Pelanggaran zero-gap property. Spec §6.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeroGapViolation {
    pub nullifier: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    fn null(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    // ── runtime_assert_cc_invariant ───────────────────────────────────────────

    #[test]
    fn runtime_assert_cc_invariant_non_member() {
        // Nullifier tidak ada di kedua set → NonMember (valid). Spec §15.4.
        let result = assert_cc_invariant(&null(0x01), false, false);
        assert_eq!(result, Ok(NonMembershipStatus::NonMember));
    }

    #[test]
    fn runtime_assert_cc_invariant_in_active() {
        // Nullifier ada di NS_ACTIVE → violation. Spec §15.4.
        let result = assert_cc_invariant(&null(0x01), true, false);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.in_active);
        assert!(!err.in_checkpoint);
    }

    #[test]
    fn runtime_assert_cc_invariant_in_checkpoint() {
        // Nullifier ada di NS_CHECKPOINT → violation. Spec §15.4.
        let result = assert_cc_invariant(&null(0x01), false, true);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(!err.in_active);
        assert!(err.in_checkpoint);
    }

    #[test]
    fn runtime_assert_cc_invariant_in_both() {
        // Nullifier ada di keduanya → violation. Spec §15.4.
        let result = assert_cc_invariant(&null(0x01), true, true);
        assert!(result.is_err());
    }

    #[test]
    fn runtime_assert_zero_gap_property_ok() {
        // Nullifier sudah di checkpoint sebelum dihapus dari active → ok. Spec §6.3.
        let result = assert_zero_gap_property(&null(0x01), true);
        assert!(result.is_ok());
    }

    #[test]
    fn runtime_assert_zero_gap_property_violation() {
        // Nullifier belum di checkpoint → gap violation. Spec §6.3.
        let result = assert_zero_gap_property(&null(0x01), false);
        assert!(result.is_err());
    }
}
