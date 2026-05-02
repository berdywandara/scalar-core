//! AI-Resistant Governance Safeguards 2-4 — Spec §11.5
//!
//! Safeguard 1 (Conviction Cliff) sudah ada di conviction.rs + governance_power.rs.
//!
//! Safeguard 2: Mandatory Review Period
//!   Setelah quorum tercapai: T_REVIEW = 30 hari tambahan (abort only).
//!   Total timeline: T_LOCK (90 hari) + T_REVIEW (30 hari) = 120 hari.
//!
//! Safeguard 3: Formal Specification Requirement
//!   Setiap proposal L1 WAJIB disertai formal spec text.
//!   formal_hash = BLAKE3(formal_specification_text)
//!   Vote adalah TERHADAP formal_hash, bukan teks bebas.
//!
//! Safeguard 4: Proposal Complexity Limit
//!   Proposal yang menyentuh >3 parameter sekaligus HARUS disubmit terpisah.
//!   Exception: parameter yang matematically coupled boleh bersamaan.

// ── Constants — Spec §11.5 ───────────────────────────────────────────────────

/// T_LOCK: periode voting utama dalam hari. Spec §11.5 Safeguard 2.
/// Layer 2 CONSTRAINED — range: 30-180 hari.
pub const T_LOCK_DAYS: u64 = 90;

/// T_REVIEW: mandatory review period setelah quorum. Spec §11.5 Safeguard 2.
/// OSSIFIED: tidak bisa di-governance ke nilai lebih rendah.
pub const T_REVIEW_DAYS: u64 = 30;

/// Total timeline minimum: T_LOCK + T_REVIEW. Spec §11.5 Safeguard 2.
pub const T_TOTAL_DAYS: u64 = T_LOCK_DAYS + T_REVIEW_DAYS;

/// Maksimum parameter per proposal. Spec §11.5 Safeguard 4. OSSIFIED.
pub const MAX_PARAMETERS_PER_PROPOSAL: usize = 3;

// ── Safeguard 2: Mandatory Review Period ─────────────────────────────────────

/// Status proposal governance. Spec §11.5 Safeguard 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalReviewStatus {
    /// Periode voting aktif (T_LOCK). Commit dan abort diperbolehkan.
    Voting { days_elapsed: u64 },
    /// Quorum tercapai, masuk T_REVIEW. HANYA abort yang diperbolehkan.
    /// Spec §11.5 Safeguard 2: "WAJIB ada T_REVIEW = 30 hari tambahan
    /// di mana HANYA abort yang bisa dilakukan."
    MandatoryReview { review_days_elapsed: u64 },
    /// T_REVIEW selesai — proposal dapat dieksekusi.
    ReadyToExecute,
    /// Proposal di-abort.
    Aborted,
}

/// Tentukan status proposal berdasarkan hari sejak quorum. Spec §11.5 S2.
///
/// `days_since_quorum`: hari sejak quorum tercapai (0 = baru saja quorum).
pub fn review_status(days_since_quorum: u64) -> ProposalReviewStatus {
    if days_since_quorum < T_REVIEW_DAYS {
        ProposalReviewStatus::MandatoryReview {
            review_days_elapsed: days_since_quorum,
        }
    } else {
        ProposalReviewStatus::ReadyToExecute
    }
}

/// Cek apakah aksi "execute" diperbolehkan. Spec §11.5 Safeguard 2.
/// Execute hanya boleh setelah T_REVIEW selesai.
pub fn can_execute(days_since_quorum: u64) -> bool {
    days_since_quorum >= T_REVIEW_DAYS
}

/// Cek apakah aksi "abort" diperbolehkan. Spec §11.5 Safeguard 2.
/// Abort selalu diperbolehkan selama dalam review period.
pub fn can_abort(days_since_quorum: u64) -> bool {
    days_since_quorum < T_REVIEW_DAYS
}

// ── Safeguard 3: Formal Specification Requirement ────────────────────────────

/// Formal specification untuk proposal Layer 1. Spec §11.5 Safeguard 3.
///
/// Vote adalah terhadap `formal_hash`, bukan teks bebas.
/// AI tidak bisa menyembunyikan ambiguitas dalam formal mathematical spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormalSpec {
    /// Teks formal specification (matematis atau pseudocode formal).
    pub spec_text: Vec<u8>,
    /// BLAKE3(spec_text). Spec §11.5 Safeguard 3.
    pub formal_hash: [u8; 32],
}

impl FormalSpec {
    /// Buat FormalSpec dari teks. formal_hash dihitung otomatis.
    /// Spec §11.5 Safeguard 3: formal_hash = BLAKE3(formal_specification_text).
    pub fn new(spec_text: impl Into<Vec<u8>>) -> Self {
        let text = spec_text.into();
        let formal_hash = blake3_hash(&text);
        Self {
            spec_text: text,
            formal_hash,
        }
    }

    /// Verifikasi integritas: formal_hash == BLAKE3(spec_text). Spec §11.5 S3.
    pub fn verify(&self) -> bool {
        blake3_hash(&self.spec_text) == self.formal_hash
    }
}

/// Hitung BLAKE3 hash. Out-circuit — spec §2.1.
fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

// ── Safeguard 4: Proposal Complexity Limit ───────────────────────────────────

/// Error proposal complexity. Spec §11.5 Safeguard 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComplexityError {
    /// Proposal menyentuh terlalu banyak parameter.
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

/// Validasi proposal complexity. Spec §11.5 Safeguard 4.
///
/// `parameter_count`: jumlah parameter yang diubah oleh proposal.
/// `mathematically_coupled`: jika true, exception berlaku — boleh >3.
///
/// Return Ok(()) jika valid, Err jika terlalu kompleks.
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
        assert!(!can_abort(30)); // T_REVIEW selesai — tidak bisa abort lagi
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
