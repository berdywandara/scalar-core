//! scalar-sdk — Boundary Crate antara Protocol Layer dan Client-Utility Layer
//!
//! Spec §21.2 v7.0
//!
//! PRINSIP ISOLASI (spec §21.6):
//!   - Client code WAJIB import dari scalar-sdk, BUKAN dari protocol crates langsung
//!   - scalar-sdk tidak mengekspos internal protocol
//!   - Protocol layer tidak tahu tentang scalar-sdk (dependency satu arah)
//!   - scalar-sdk TIDAK di-ossify — bisa breaking change tanpa fork
//!
//! DEPENDENCY (spec §21.2):
//!   scalar-sdk → scalar-crypto, scalar-nullifier, scalar-emission,
//!                scalar-stark, scalar-fees
//!
//! API PUBLIK (spec §21.3):
//!   query::*  — F1, F2, F3, F4, F7, F11 — read-only, zero onchain cost
//!   proof::*  — F5, F6, F10, F12 — local ZK proof, zero onchain cost
//!   record::* — F8, F9 — write-once, biaya 1× fee = 40 sSCL

pub mod proof;
pub mod query;
pub mod record;
pub mod types;

// Re-export tipe utama untuk convenience — spec §21.2
pub use types::{
    CredentialProof, DeadManSwitchRecord, IndelibleRecord, MpasReport, NcpProof, NhiReport,
    NrsReport, PaymentProof, ScarcityProof, SdkError, SlaReport, ThresholdProof, TimestampRecord,
};

// Re-export konstanta kritis — spec §21.2
pub use record::RECORD_FEE_MIN_SSCL;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{proof, query, record};
    use scalar_emission::liveness::MaturityStore;

    // ── F1 Scarcity Proof ─────────────────────────────────────────────────────

    #[test]
    fn test_query_scarcity_proof_valid() {
        // M_E < S_E → valid. Spec §21.3 F1.
        let proof = query::query_scarcity_proof(1_000_000_000, 1);
        assert!(proof.is_valid);
        assert_eq!(
            proof.supply_cap_sscl,
            scalar_emission::accumulator::S_E_SSCL
        );
    }

    #[test]
    fn test_query_scarcity_proof_at_cap_valid() {
        // M_E = S_E → valid (tepat di cap).
        let proof = query::query_scarcity_proof(scalar_emission::accumulator::S_E_SSCL, 10);
        assert!(proof.is_valid);
    }

    #[test]
    fn test_query_scarcity_proof_exceeded_invalid() {
        // M_E > S_E → tidak valid.
        let proof = query::query_scarcity_proof(scalar_emission::accumulator::S_E_SSCL + 1, 10);
        assert!(!proof.is_valid);
    }

    // ── F2 MPAS ───────────────────────────────────────────────────────────────

    #[test]
    fn test_query_mpas_zero_deviation_at_e0() {
        // Jika actual = E0, deviasi = 0. Spec §21.3 F2.
        let report = query::query_monetary_policy_score(scalar_emission::accumulator::E0_SSCL, 1);
        assert_eq!(report.deviation_fp, 0);
    }

    #[test]
    fn test_query_mpas_nonzero_deviation() {
        let report = query::query_monetary_policy_score(0, 1);
        assert_eq!(report.deviation_fp, 1_000_000); // 100% deviasi
    }

    // ── F3 NHI ────────────────────────────────────────────────────────────────

    #[test]
    fn test_query_network_health_healthy() {
        // Spec §21.3 F3.
        let report = query::query_network_health(950_000, 0, 0, 5);
        assert_eq!(report.avg_uptime_fp, 950_000);
        assert_eq!(report.epoch_deferred_count, 0);
        assert_eq!(report.slashing_count, 0);
    }

    // ── F4 NRS ────────────────────────────────────────────────────────────────

    #[test]
    fn test_query_node_reputation_empty_store() {
        // Node baru — maturity 0, gov_weight 0. Spec §21.3 F4.
        let store = MaturityStore::new();
        let mut node_id = [0u8; 32];
        node_id[0] = 1;
        let report = query::query_node_reputation(node_id, &store, 10).unwrap();
        assert_eq!(report.gov_weight_fp, 0);
        assert_eq!(report.maturity_raw, 0);
    }

    #[test]
    fn test_query_node_reputation_zero_id_rejected() {
        let store = MaturityStore::new();
        let err = query::query_node_reputation([0u8; 32], &store, 10).unwrap_err();
        assert_eq!(err, SdkError::InvalidNodeId);
    }

    // ── F7 Payment Proof ──────────────────────────────────────────────────────

    #[test]
    fn test_build_payment_proof_deterministic() {
        // Spec §21.3 F7: deterministik.
        let commitment = [0x01u8; 32];
        let p1 = query::build_payment_proof(commitment, 5, 1_000_000);
        let p2 = query::build_payment_proof(commitment, 5, 1_000_000);
        assert_eq!(p1.proof_hash, p2.proof_hash);
    }

    #[test]
    fn test_build_payment_proof_different_amount_different_hash() {
        let commitment = [0x01u8; 32];
        let p1 = query::build_payment_proof(commitment, 5, 1_000_000);
        let p2 = query::build_payment_proof(commitment, 5, 2_000_000);
        assert_ne!(p1.proof_hash, p2.proof_hash);
    }

    // ── F5 Threshold Proof ────────────────────────────────────────────────────

    #[test]
    fn test_build_threshold_proof_met() {
        // Saldo ≥ threshold → result true. Spec §21.3 F5.
        let tp = proof::build_threshold_proof(1_000_000, 500_000, [0u8; 32]).unwrap();
        assert!(tp.result);
    }

    #[test]
    fn test_build_threshold_proof_not_met() {
        let tp = proof::build_threshold_proof(100_000, 500_000, [0u8; 32]).unwrap();
        assert!(!tp.result);
    }

    #[test]
    fn test_build_threshold_proof_exact() {
        // Tepat sama = met.
        let tp = proof::build_threshold_proof(500_000, 500_000, [0u8; 32]).unwrap();
        assert!(tp.result);
    }

    // ── F6 NCP ────────────────────────────────────────────────────────────────

    #[test]
    fn test_build_ncp_compliant() {
        // Coin nullifier tidak ada dalam exclusion set → compliant.
        let nullifier = [0x01u8; 32];
        let excluded = [[0x02u8; 32], [0x03u8; 32]];
        let ncp = proof::build_negative_compliance_proof(nullifier, &excluded, [0u8; 32]).unwrap();
        assert!(ncp.is_compliant);
    }

    #[test]
    fn test_build_ncp_not_compliant() {
        // Coin nullifier ADA dalam exclusion set → tidak compliant.
        let nullifier = [0x02u8; 32];
        let excluded = [[0x02u8; 32], [0x03u8; 32]];
        let ncp = proof::build_negative_compliance_proof(nullifier, &excluded, [0u8; 32]).unwrap();
        assert!(!ncp.is_compliant);
    }

    #[test]
    fn test_build_ncp_empty_excluded_rejected() {
        let nullifier = [0x01u8; 32];
        let err = proof::build_negative_compliance_proof(nullifier, &[], [0u8; 32]).unwrap_err();
        assert!(matches!(err, SdkError::InvalidInput(_)));
    }

    // ── F8 Timestamp Record ───────────────────────────────────────────────────

    #[test]
    fn test_build_timestamp_record_deterministic() {
        // Spec §21.3 F8: deterministik.
        let doc = [0xABu8; 32];
        let r1 = record::build_timestamp_record(doc, 5).unwrap();
        let r2 = record::build_timestamp_record(doc, 5).unwrap();
        assert_eq!(r1.commitment, r2.commitment);
    }

    #[test]
    fn test_build_timestamp_record_zero_hash_rejected() {
        let err = record::build_timestamp_record([0u8; 32], 1).unwrap_err();
        assert!(matches!(err, SdkError::InvalidInput(_)));
    }

    // ── F9 Indelible Record ───────────────────────────────────────────────────

    #[test]
    fn test_build_indelible_record_non_zero_commitment() {
        // Spec §21.3 F9: commitment harus non-zero.
        let data = [0xCDu8; 32];
        let r = record::build_indelible_record(data, 3).unwrap();
        assert_ne!(r.nullifier_commitment, [0u8; 32]);
    }

    #[test]
    fn test_build_indelible_record_zero_data_rejected() {
        let err = record::build_indelible_record([0u8; 32], 1).unwrap_err();
        assert!(matches!(err, SdkError::InvalidInput(_)));
    }

    // ── F12 Dead Man Switch ───────────────────────────────────────────────────

    #[test]
    fn test_build_dead_man_switch_valid() {
        // Spec §21.3 F12.
        let primary = [0x01u8; 32];
        let backup = [0x02u8; 32];
        let dms = proof::build_dead_man_switch(primary, backup, 10).unwrap();
        assert_ne!(dms.succession_commitment, [0u8; 32]);
        assert_eq!(dms.backup_node_id, backup);
    }

    #[test]
    fn test_build_dead_man_switch_zero_backup_rejected() {
        let primary = [0x01u8; 32];
        let err = proof::build_dead_man_switch(primary, [0u8; 32], 10).unwrap_err();
        assert_eq!(err, SdkError::InvalidNodeId);
    }

    // ── Record fee constant ───────────────────────────────────────────────────

    #[test]
    fn test_record_fee_min_ossified() {
        // Spec §9: FLOOR_MIN_ABSOLUTE = 40 sSCL. OSSIFIED.
        assert_eq!(RECORD_FEE_MIN_SSCL, 40u64);
    }
}
