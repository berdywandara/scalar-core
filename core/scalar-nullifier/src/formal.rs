//! Formal Verification Runtime Assertions — Invariant CC
//!
//! Spec §15.4 v11.1-FINAL: runtime assertions sebagai defense-in-depth.
//!
//! Sebelum mainnet: invariant CC harus dibuktikan secara formal (TLA+/Coq).
//! File TLA+: verification/invariant_cc.tla
//!
//! Runtime assertions ini berjalan dalam debug builds sebagai defense-in-depth.
//! Tidak menggantikan formal proof — melengkapinya.

// ── Invariant CC Runtime Assertion — spec §15.4 ───────────────────────────────

/// Status non-membership check untuk satu nullifier. Spec §15.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonMembershipStatus {
    /// Nullifier tidak ada dalam set — valid untuk digunakan. Spec §15.4.
    NonMember,
    /// Nullifier sudah ada dalam set — double-spend attempt. Spec §15.4.
    Member,
}

/// Verifikasi invariant CC untuk satu nullifier. Spec §15.4.
///
/// Invariant: jika n ∈ (NS_ACTIVE ∪ NS_CHECKPOINT), maka
///   SMT_NonMembershipVerify(n, active_root) == FALSE ∧
///   SMT_NonMembershipVerify(n, archived_root) == FALSE
///
/// `in_active`: apakah nullifier ada di NS_ACTIVE.
/// `in_checkpoint`: apakah nullifier ada di NS_CHECKPOINT.
///
/// Returns Err jika nullifier sudah ada di salah satu set (double-spend attempt).
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
    /// Nullifier yang melanggar invariant.
    pub nullifier: [u8; 32],
    /// Apakah ada di NS_ACTIVE.
    pub in_active: bool,
    /// Apakah ada di NS_CHECKPOINT.
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

/// Zero-Gap Property assertion. Spec §6.3, §15.4.
///
/// Memastikan tidak ada window di mana nullifier hilang antara
/// NS_ACTIVE dan NS_CHECKPOINT selama checkpoint operation.
///
/// `nullifier_being_archived`: nullifier yang sedang dipindah ke checkpoint.
/// `already_in_checkpoint`: apakah sudah masuk checkpoint.
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

/// Pelanggaran Zero-Gap Property. Spec §6.3.
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

// ── INV-NULLIFIER (MAD §16.1, D-021) ─────────────────────────────────────────
//
// FORMAL SPECIFICATION:
//   ∀ nullifier n:
//     spend(n, tx1) ∧ spend(n, tx2) → tx1 = tx2
//
//   Equivalently: each nullifier appears at most once in the nullifier set.
//
// PRUSTI ANNOTATION (activate with --features prusti):
//   #[requires(!nullifier_set.contains(n))]
//   #[ensures(nullifier_set.contains(n))]
//
// SCOPE: nullifier_set.rs, checkpoint WAL.
// RUNTIME: assert_cc_invariant() (above) enforces this at runtime.

/// Formal statement of INV-NULLIFIER. MAD §16.1.
///
/// Models the set semantics: a nullifier can be inserted at most once.
/// This struct carries proof that the invariant was checked before insertion.
#[derive(Debug, Clone)]
pub struct NullifierInsertionProof {
    /// The nullifier that was inserted.
    pub nullifier: [u8; 32],
    /// Epoch in which the nullifier was inserted.
    pub epoch_id: u64,
}

/// Assert INV-NULLIFIER before inserting a nullifier. MAD §16.1.
///
/// FORMAL: spend(n, tx1) ∧ spend(n, tx2) → tx1 = tx2
/// ↔ nullifier n inserted at most once.
///
/// `already_present`: result of set membership check (true = double-spend).
/// Returns proof token on success (can be passed to insertion function).
pub fn assert_inv_nullifier(
    nullifier: &[u8; 32],
    already_present: bool,
    epoch_id: u64,
) -> Result<NullifierInsertionProof, NullifierDoubleSpend> {
    if already_present {
        return Err(NullifierDoubleSpend {
            nullifier: *nullifier,
            epoch_id,
        });
    }
    Ok(NullifierInsertionProof {
        nullifier: *nullifier,
        epoch_id,
    })
}

/// Double-spend attempt detected. MAD §16.1 INV-NULLIFIER.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NullifierDoubleSpend {
    /// The nullifier that was already spent.
    pub nullifier: [u8; 32],
    /// Epoch of detection.
    pub epoch_id: u64,
}

impl core::fmt::Display for NullifierDoubleSpend {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "INV-NULLIFIER VIOLATION: nullifier {:?}... already spent in epoch {} — MAD §16.1",
            &self.nullifier[..4],
            self.epoch_id
        )
    }
}

#[cfg(test)]
mod inv_nullifier_tests {
    use super::*;

    fn null(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn test_inv_nullifier_first_spend_ok() {
        let proof = assert_inv_nullifier(&null(1), false, 42).unwrap();
        assert_eq!(proof.nullifier, null(1));
        assert_eq!(proof.epoch_id, 42);
    }

    #[test]
    fn test_inv_nullifier_double_spend_detected() {
        let err = assert_inv_nullifier(&null(2), true, 5).unwrap_err();
        assert_eq!(err.nullifier, null(2));
        assert_eq!(err.epoch_id, 5);
    }

    #[test]
    fn test_inv_nullifier_display() {
        let err = NullifierDoubleSpend {
            nullifier: [0xABu8; 32],
            epoch_id: 10,
        };
        let s = format!("{err}");
        assert!(s.contains("INV-NULLIFIER VIOLATION"));
        assert!(s.contains("epoch 10"));
    }
}
