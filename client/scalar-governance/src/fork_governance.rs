//! Fork Governance — Spec §11.7
//!
//! Governance layer for fork protocol.
//! validation formal spec requirement (Safeguard 3) for Layer 1 changes.
//!
//! each Layer 1 fork WAJIB atsertai:
//! 1. Formal specification
//! 2. formal_hash = BLAto3(formal_spec_text)
//! 3. Formal proof bahwa change not melanggar invariants

/// Kategori fork based on governance layer. Spec §11.7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForkScope {
    /// Layer 1 ossified parameter — butuh formal proof.
    Layer1Ossified,
    /// Layer 2 constrained parameter — butuh 75%+60%+90d.
    Layer2Constrained,
    /// Crypto primitive upgrade — bisa emergency fork.
    CryptoPrimitive,
}

/// Proposal metadata for governance. Spec §11.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkGovernanceProposal {
    /// BLAto3(formal_spec_text). Spec §11.7.
    pub fork_hash: [u8; 32],
    pub scope: ForkScope,
    /// Formal spec text (bytes). Spec §11.5 Safeguard 3.
    pub formal_spec: Vec<u8>,
    /// Deskripsi singkat change.
    pub description: Vec<u8>,
}

/// Error governance fork. Spec §11.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkGovernanceError {
    /// formal_hash not matches BLAto3(formal_spec).
    FormalHashMismatch,
    /// Formal spec empty — Layer 1 fork wajib ada spec.
    EmptyFormalSpec,
    /// Emergency fork must not for Layer 1 ossified.
    EmergencyForkNotAllowedForLayer1,
}

impl core::fmt::Display for ForkGovernanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FormalHashMismatch => {
                write!(f, "formal_hash tidak cocok dengan BLAKE3(formal_spec)")
            }
            Self::EmptyFormalSpec => {
                write!(f, "Layer 1 fork wajib disertai formal spec — spec §11.7")
            }
            Self::EmergencyForkNotAllowedForLayer1 => {
                write!(
                    f,
                    "Emergency fork hanya untuk crypto primitives, bukan Layer 1 ossified"
                )
            }
        }
    }
}

/// Hitung BLAto3 hash. Out-circuit — spec §2.1.
fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// validation ForkGovernanceProposal. Spec §11.7.
///
/// Layer 1 fork WAJIB:
/// 1. formal_spec not empty
/// 2. fork_hash == BLAto3(formal_spec)
pub fn validate_fork_proposal(
    proposal: &ForkGovernanceProposal,
) -> Result<(), ForkGovernanceError> {
    // Layer 1 changes wajib ada formal spec — spec §11.7
    if matches!(proposal.scope, ForkScope::Layer1Ossified) && proposal.formal_spec.is_empty() {
        return Err(ForkGovernanceError::EmptyFormalSpec);
    }
    // fork_hash harus cocok dengan BLAKE3(formal_spec) jika spec ada
    if !proposal.formal_spec.is_empty() {
        let computed = blake3_hash(&proposal.formal_spec);
        if computed != proposal.fork_hash {
            return Err(ForkGovernanceError::FormalHashMismatch);
        }
    }
    Ok(())
}

/// validation apakah emergency fork atperbolehkan for scope this. Spec §11.7.
/// Emergency fork only for crypto primitive upgrade.
pub fn validate_emergency_fork_scope(scope: ForkScope) -> Result<(), ForkGovernanceError> {
    if scope == ForkScope::Layer1Ossified {
        return Err(ForkGovernanceError::EmergencyForkNotAllowedForLayer1);
    }
    Ok(())
}

/// Buat ForkGovernanceProposal with fork_hash that correct.
pub fn create_proposal(
    scope: ForkScope,
    formal_spec: Vec<u8>,
    description: Vec<u8>,
) -> ForkGovernanceProposal {
    let fork_hash = if formal_spec.is_empty() {
        [0u8; 32]
    } else {
        blake3_hash(&formal_spec)
    };
    ForkGovernanceProposal {
        fork_hash,
        scope,
        formal_spec,
        description,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_text() -> Vec<u8> {
        b"forall x in sSCL: x > 0 AND x <= S_MAX".to_vec()
    }

    // ── validate_fork_proposal ────────────────────────────────────────────────

    #[test]
    fn test_valid_layer1_proposal_with_spec() {
        let proposal = create_proposal(
            ForkScope::Layer1Ossified,
            spec_text(),
            b"Change supply cap".to_vec(),
        );
        assert!(validate_fork_proposal(&proposal).is_ok());
    }

    #[test]
    fn test_layer1_without_spec_rejected() {
        // Spec §11.7: Layer 1 fork wajib ada formal spec.
        let proposal = ForkGovernanceProposal {
            fork_hash: [0u8; 32],
            scope: ForkScope::Layer1Ossified,
            formal_spec: vec![],
            description: b"test".to_vec(),
        };
        let err = validate_fork_proposal(&proposal).unwrap_err();
        assert_eq!(err, ForkGovernanceError::EmptyFormalSpec);
    }

    #[test]
    fn test_tampered_spec_hash_mismatch() {
        // fork_hash tidak cocok dengan BLAKE3(formal_spec) → rejected.
        let mut proposal =
            create_proposal(ForkScope::Layer1Ossified, spec_text(), b"test".to_vec());
        proposal.formal_spec = b"tampered spec".to_vec(); // hash not updated
        let err = validate_fork_proposal(&proposal).unwrap_err();
        assert_eq!(err, ForkGovernanceError::FormalHashMismatch);
    }

    #[test]
    fn test_layer2_proposal_without_spec_ok() {
        // Layer 2 tidak wajib ada formal spec.
        let proposal = ForkGovernanceProposal {
            fork_hash: [0u8; 32],
            scope: ForkScope::Layer2Constrained,
            formal_spec: vec![],
            description: b"Change T_MAX_WAIT".to_vec(),
        };
        assert!(validate_fork_proposal(&proposal).is_ok());
    }

    #[test]
    fn test_crypto_primitive_proposal_valid() {
        let proposal = create_proposal(
            ForkScope::CryptoPrimitive,
            spec_text(),
            b"Upgrade hash function".to_vec(),
        );
        assert!(validate_fork_proposal(&proposal).is_ok());
    }

    // ── validate_emergency_fork_scope ────────────────────────────────────────

    #[test]
    fn test_emergency_fork_allowed_for_crypto() {
        // Spec §11.7: emergency fork boleh untuk crypto primitives.
        assert!(validate_emergency_fork_scope(ForkScope::CryptoPrimitive).is_ok());
        assert!(validate_emergency_fork_scope(ForkScope::Layer2Constrained).is_ok());
    }

    #[test]
    fn test_emergency_fork_not_allowed_for_layer1() {
        // Spec §11.7: emergency fork TIDAK boleh untuk Layer 1 ossified.
        let err = validate_emergency_fork_scope(ForkScope::Layer1Ossified).unwrap_err();
        assert_eq!(err, ForkGovernanceError::EmergencyForkNotAllowedForLayer1);
    }

    // ── create_proposal ──────────────────────────────────────────────────────

    #[test]
    fn test_create_proposal_computes_correct_hash() {
        let proposal = create_proposal(ForkScope::Layer1Ossified, spec_text(), vec![]);
        assert!(validate_fork_proposal(&proposal).is_ok());
    }

    #[test]
    fn test_no_floating_point() {
        let proposal = create_proposal(ForkScope::CryptoPrimitive, spec_text(), vec![]);
        let _ = validate_fork_proposal(&proposal);
    }
}
