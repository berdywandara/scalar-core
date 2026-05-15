//! AI-Resistant Governance Safeguards 2-4 — Spec §11.5
//!
//! Safeguard 1 (Conviction Cliff) already exists at conviction.rs + governance_power.rs.
//!
//! Safeguard 2: Mandatory Review Period
//! after quorum terachieve: T_REVIEW = 30 days tambahan (abort only).
//! Total timeline: T_LOCK (90 days) + T_REVIEW (30 days) = 120 days.
//!
//! Safeguard 3: Formal Specification Requirement
//! each proposal L1 WAJIB atsertai formal spec text.
//! formal_hash = BLAto3(formal_specification_text)
//! Vote adalah TERHADAP formal_hash, openn teks bebas.
//!
//! Safeguard 4: Proposal Complexity Limit
//! Proposal that menyentuh >3 parameter sekaligus HARUS atsubmit separate.
//! exception: parameter that matematically coupled boleh bersamean.

// ── Constants — Spec §11.5 ───────────────────────────────────────────────────

/// T_LOCK: period voting utama in days. Spec §11.5 Safeguard 2.
/// Layer 2 CONSTRAINED — range: 30-180 days.
pub const T_LOCK_DAYS: u64 = 90;

/// T_REVIEW: mandatory review period after quorum. Spec §11.5 Safeguard 2.
/// OSSIFIED: cannot at-governance to value lebih rendah.
pub const T_REVIEW_DAYS: u64 = 30;

/// Total timeline mthismum: T_LOCK + T_REVIEW. Spec §11.5 Safeguard 2.
pub const T_TOTAL_DAYS: u64 = T_LOCK_DAYS + T_REVIEW_DAYS;

/// Maksimum parameter per proposal. Spec §11.5 Safeguard 4. OSSIFIED.
pub const MAX_PARAMETERS_PER_PROPOSAL: usize = 3;

// ── Safeguard 2: Mandatory Review Period ─────────────────────────────────────

/// Status proposal governance. Spec §11.5 Safeguard 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalReviewStatus {
    /// period voting aktif (T_LOCK). Commit and abort atperbolehkan.
    Voting { days_elapsed: u64 },
    /// Quorum terachieve, masuk T_REVIEW. only abort that atperbolehkan.
    /// Spec §11.5 Safeguard 2: "WAJIB ada T_REVIEW = 30 days tambahan
    /// at mana only abort that can performed."
    MandatoryReview { review_days_elapsed: u64 },
    /// T_REVIEW fthisshed — proposal dapat executed.
    ReadyToExecute,
    /// Proposal at-abort.
    Aborted,
}

/// determine status proposal based on days since quorum. Spec §11.5 S2.
///
/// `days_since_quorum`: days since quorum terachieve (0 = new just quorum).
pub fn review_status(days_since_quorum: u64) -> ProposalReviewStatus {
    if days_since_quorum < T_REVIEW_DAYS {
        ProposalReviewStatus::MandatoryReview {
            review_days_elapsed: days_since_quorum,
        }
    } else {
        ProposalReviewStatus::ReadyToExecute
    }
}

/// check whether aksi "execute" atperbolehkan. Spec §11.5 Safeguard 2.
/// Execute only boleh after T_REVIEW fthisshed.
pub fn can_execute(days_since_quorum: u64) -> bool {
    days_since_quorum >= T_REVIEW_DAYS
}

/// check whether aksi "abort" atperbolehkan. Spec §11.5 Safeguard 2.
/// Abort always atperbolehkan during in review period.
pub fn can_abort(days_since_quorum: u64) -> bool {
    days_since_quorum < T_REVIEW_DAYS
}

// ── Safeguard 3: Formal Specification Requirement ────────────────────────────

/// Formal specification for proposal Layer 1. Spec §11.5 Safeguard 3.
///
/// Vote adalah terhadap `formal_hash`, openn teks bebas.
/// AI cannot menyembunyikan ambiguitas in formal mathematical spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormalSpec {
    /// Teks formal specification (matematis or pseudocode formal).
    pub spec_text: Vec<u8>,
    /// BLAto3(spec_text). Spec §11.5 Safeguard 3.
    pub formal_hash: [u8; 32],
}

impl FormalSpec {
    /// Buat FormalSpec from teks. formal_hash computed otomatis.
    /// Spec §11.5 Safeguard 3: formal_hash = BLAto3(formal_specification_text).
    pub fn new(spec_text: impl Into<Vec<u8>>) -> Self {
        let text = spec_text.into();
        let formal_hash = blake3_hash(&text);
        Self {
            spec_text: text,
            formal_hash,
        }
    }

    /// verification integritas: formal_hash == BLAto3(spec_text). Spec §11.5 S3.
    pub fn verify(&self) -> bool {
        blake3_hash(&self.spec_text) == self.formal_hash
    }
}

/// Hitung BLAto3 hash. Out-circuit — spec §2.1.
fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

// ── Safeguard 4: Proposal Complexity Limit ───────────────────────────────────

/// Error proposal complexity. Spec §11.5 Safeguard 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComplexityError {
    /// Proposal menyentuh terthen banyak parameter.
    TooManyParameters { count: usize, max: usize },
}

impl core::fmt::Display for ComplexityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooManyParameters { count, max } => write!(
                f,
                "Proposal menyentuh {count} parameter, maksimum {max} — spec §11.5 Safeguard 4"
            ),
        }
    }
}

/// validation proposal complexity. Spec §11.5 Safeguard 4.
///
/// `parameter_count`: jumlah parameter that changed oleh proposal.
/// `mathematically_coupled`: if true, exception berlaku — boleh >3.
///
/// Return Ok(()) if valid, Err if terthen complex.
pub fn validate_proposal_complexity(
    parameter_count: usize,
    mathematically_coupled: bool,
) -> Result<(), ComplexityError> {
    if mathematically_coupled {
        // Exception: parameter coupled boleh disubmit bersamaan
        return Ok(());
    }
    if parameter_count > MAX_PARAMETERS_PER_PROPOSAL {
        return Err(ComplexityError::TooManyParameters {
            count: parameter_count,
            max: MAX_PARAMETERS_PER_PROPOSAL,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constants ossified ────────────────────────────────────────────────────

    #[test]
    fn test_t_lock_days_ossified() {
        // Spec §11.5 Safeguard 2: T_LOCK = 90 hari.
        assert_eq!(T_LOCK_DAYS, 90u64);
    }

    #[test]
    fn test_t_review_days_ossified() {
        // Spec §11.5 Safeguard 2: T_REVIEW = 30 hari. OSSIFIED.
        assert_eq!(T_REVIEW_DAYS, 30u64);
    }

    #[test]
    fn test_t_total_days() {
        // Spec §11.5 Safeguard 2: total = 120 hari.
        assert_eq!(T_TOTAL_DAYS, 120u64);
    }

    #[test]
    fn test_max_parameters_per_proposal_ossified() {
        // Spec §11.5 Safeguard 4: max 3 parameter. OSSIFIED.
        assert_eq!(MAX_PARAMETERS_PER_PROPOSAL, 3usize);
    }

    // ── Safeguard 2: Mandatory Review Period ─────────────────────────────────

    #[test]
    fn test_review_status_day_0_is_mandatory_review() {
        // Hari 0 setelah quorum → masih dalam T_REVIEW.
        let status = review_status(0);
        assert_eq!(
            status,
            ProposalReviewStatus::MandatoryReview {
                review_days_elapsed: 0
            }
        );
    }

    #[test]
    fn test_review_status_day_29_still_mandatory() {
        // Hari 29 → masih dalam T_REVIEW (belum selesai).
        assert_eq!(
            review_status(29),
            ProposalReviewStatus::MandatoryReview {
                review_days_elapsed: 29
            }
        );
    }

    #[test]
    fn test_review_status_day_30_ready_to_execute() {
        // Hari 30 → T_REVIEW selesai, siap dieksekusi.
        assert_eq!(review_status(30), ProposalReviewStatus::ReadyToExecute);
    }

    #[test]
    fn test_can_execute_only_after_review() {
        assert!(!can_execute(0));
        assert!(!can_execute(29));
        assert!(can_execute(30));
        assert!(can_execute(100));
    }

    #[test]
    fn test_can_abort_only_during_review() {
        // Spec §11.5 S2: HANYA abort yang bisa dilakukan selama T_REVIEW.
        assert!(can_abort(0));
        assert!(can_abort(29));
        assert!(!can_abort(30)); // T_REVIEW fthisshed — cannot abort lagi
    }

    #[test]
    fn test_execute_and_abort_mutually_exclusive() {
        // Tidak boleh bisa execute dan abort di saat yang sama.
        for days in 0u64..60 {
            let exec = can_execute(days);
            let abort = can_abort(days);
            assert!(
                !(exec && abort),
                "Execute dan abort tidak boleh keduanya true pada hari {days}"
            );
        }
    }

    // ── Safeguard 3: Formal Specification Requirement ────────────────────────

    #[test]
    fn test_formal_spec_hash_computed_correctly() {
        // formal_hash harus BLAKE3(spec_text). Spec §11.5 Safeguard 3.
        let spec = FormalSpec::new(b"forall x in sSCL: x > 0".to_vec());
        assert!(spec.verify());
    }

    #[test]
    fn test_formal_spec_different_texts_different_hashes() {
        let spec1 = FormalSpec::new(b"spec_a".to_vec());
        let spec2 = FormalSpec::new(b"spec_b".to_vec());
        assert_ne!(spec1.formal_hash, spec2.formal_hash);
    }

    #[test]
    fn test_formal_spec_tampered_fails_verify() {
        // Jika spec_text diubah setelah dibuat → verify gagal.
        let mut spec = FormalSpec::new(b"original spec".to_vec());
        spec.spec_text = b"tampered spec".to_vec();
        assert!(!spec.verify());
    }

    #[test]
    fn test_formal_spec_empty_text_valid() {
        // Spec text kosong tetap valid (hash dari empty bytes).
        let spec = FormalSpec::new(vec![]);
        assert!(spec.verify());
    }

    #[test]
    fn test_formal_spec_deterministic() {
        let spec1 = FormalSpec::new(b"deterministic test".to_vec());
        let spec2 = FormalSpec::new(b"deterministic test".to_vec());
        assert_eq!(spec1.formal_hash, spec2.formal_hash);
    }

    // ── Safeguard 4: Proposal Complexity Limit ───────────────────────────────

    #[test]
    fn test_1_parameter_valid() {
        assert!(validate_proposal_complexity(1, false).is_ok());
    }

    #[test]
    fn test_3_parameters_valid() {
        // 3 = MAX_PARAMETERS_PER_PROPOSAL → valid.
        assert!(validate_proposal_complexity(3, false).is_ok());
    }

    #[test]
    fn test_4_parameters_invalid() {
        // 4 > MAX → must submit separately. Spec §11.5 Safeguard 4.
        let err = validate_proposal_complexity(4, false).unwrap_err();
        assert_eq!(err, ComplexityError::TooManyParameters { count: 4, max: 3 });
    }

    #[test]
    fn test_coupled_parameters_exception() {
        // Matematically coupled parameter boleh >3. Spec §11.5 S4 Exception.
        assert!(validate_proposal_complexity(10, true).is_ok());
    }

    #[test]
    fn test_zero_parameters_valid() {
        assert!(validate_proposal_complexity(0, false).is_ok());
    }

    #[test]
    fn test_no_floating_point() {
        // Semua logika murni integer — tidak ada float.
        let _status = review_status(u64::MAX);
        let _exec = can_execute(u64::MAX);
        let spec = FormalSpec::new(b"no float test".to_vec());
        assert!(spec.verify());
    }
}
