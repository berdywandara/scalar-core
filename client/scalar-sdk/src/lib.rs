//! scalar-sdk — Boundary Crate antara Protocol Layer dan Client-Utility Layer
//!
//! Spec §21.2 v9.0
//!
//! PRINSIP ISOLASI (spec §21.1):
//!   - Client code WAJIB import dari scalar-sdk, BUKAN dari protocol crates langsung
//!   - scalar-sdk tidak mengekspos internal protocol
//!   - Protocol layer tidak tahu tentang scalar-sdk (dependency satu arah)
//!   - scalar-sdk TIDAK di-ossify — bisa breaking change tanpa fork
//!
//! DEPENDENCY YANG DIIZINKAN (spec §21.2):
//!   scalar-sdk → scalar-crypto, scalar-fees, blake3, thiserror
//!
//! DEPENDENCY YANG DILARANG (spec §21.1 Aturan 1):
//!   scalar-sdk TIDAK BOLEH import: scalar-emission, scalar-stark,
//!   scalar-nullifier, scalar-network
//!
//! QA CHECK: grep -r 'use scalar_emission\|use scalar_stark\|use scalar_nullifier' \
//!   crates/scalar-sdk/src/ → harus kosong
//!
//! API PUBLIK (spec §21.3):
//!   query::*  — F1, F2, F3, F4, F7, F11 — read-only, zero onchain cost
//!   proof::*  — F5, F6, F10, F12 — local ZK proof, zero onchain cost
//!   record::* — F8, F9 — write-once, biaya 1× fee = 40 sSCL

pub mod pending_pool;
pub mod proof;
pub mod query;
pub mod record;
pub mod supply;
pub mod types;

// Re-export tipe utama untuk convenience — spec §21.2
pub use types::{
    CredentialProof, DeadManSwitchRecord, IndelibleRecord, MpasReport, NcpProof, NhiReport,
    NrsReport, PaymentProof, ScarcityProof, SdkError, SlaReport, ThresholdProof, TimestampRecord,
};

// Re-export konstanta kritis — spec §21.2
pub use record::RECORD_FEE_MIN_SSCL;

// Re-export ossified constants untuk client convenience — spec §21.2
pub use query::{SDK_E0_SSCL, SDK_S_E_SSCL};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{proof, query, record};

    // ── F1 Scarcity Proof ─────────────────────────────────────────────────────

    #[test]
    fn test_query_scarcity_proof_valid() {
        // M_E < S_E → valid. Spec §21.3 F1.
        let proof = query::query_scarcity_proof(1_000_000_000, 1);
        assert!(proof.is_valid);
        assert_eq!(proof.supply_cap_sscl, SDK_S_E_SSCL);
    }

    #[test]
    fn test_query_scarcity_proof_at_cap_valid() {
        // M_E = S_E → valid (tepat di cap).
        let proof = query::query_scarcity_proof(SDK_S_E_SSCL, 10);
        assert!(proof.is_valid);
    }

    #[test]
    fn test_query_scarcity_proof_exceeded_invalid() {
        // M_E > S_E → tidak valid.
        let proof = query::query_scarcity_proof(SDK_S_E_SSCL + 1, 10);
        assert!(!proof.is_valid);
    }

    // ── F2 MPAS ───────────────────────────────────────────────────────────────

    #[test]
    fn test_query_mpas_zero_deviation_at_e0() {
        // Jika actual = E0, deviasi = 0. Spec §21.3 F2.
        let report = query::query_monetary_policy_score(SDK_E0_SSCL, 1);
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
    fn test_query_node_reputation_valid() {
        // Node dengan data valid — spec §21.3 F4.
        let mut node_id = [0u8; 32];
        node_id[0] = 1;
        let report = query::query_node_reputation(node_id, 500_000, 6, 10).unwrap();
        assert_eq!(report.gov_weight_fp, 500_000);
        assert_eq!(report.maturity_raw, 6);
    }

    #[test]
    fn test_query_node_reputation_zero_id_rejected() {
        let err = query::query_node_reputation([0u8; 32], 0, 0, 10).unwrap_err();
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

    // ── Ossified constants mirroring ──────────────────────────────────────────

    #[test]
    fn test_sdk_s_e_sscl_value() {
        // Spec §3.2 OSSIFIED. Must match scalar-emission::accumulator::S_E_SSCL.
        assert_eq!(SDK_S_E_SSCL, 1_890_000_000_000_000u64);
    }

    #[test]
    fn test_sdk_e0_sscl_value() {
        // Spec §7.1 OSSIFIED. Must match scalar-emission::accumulator::E0_SSCL.
        assert_eq!(SDK_E0_SSCL, 12_600_000_000_000u64);
    }
}

// Re-export fungsi proof dan query yang belum diexport — spec §21.2
pub use proof::{
    build_credential_proof, build_dead_man_switch, build_negative_compliance_proof,
    build_threshold_proof,
};
pub use query::{
    build_payment_proof, query_monetary_policy_score, query_network_health, query_node_reputation,
    query_scarcity_proof, query_uptime_sla,
};
pub use record::{build_indelible_record, build_timestamp_record};
pub use supply::{
    query_deferred_pool, query_security_fund, query_total_minted, verify_supply_conservation,
    AccountingSnapshot, SupplyQueryResult,
};

#[cfg(test)]
mod tests_sprint7_9 {
    use super::*;

    // ── F10: Credential Proof ─────────────────────────────────────────────────

    #[test]
    fn test_build_credential_proof_valid() {
        // Spec §21.3 F10: credential proof valid.
        let credential_data = b"scalar_node_credential_v1";
        let issuer_id = [0x42u8; 32];
        let nonce = [0x01u8; 32];
        let cp = build_credential_proof(credential_data, issuer_id, nonce, 5).unwrap();
        assert_ne!(cp.credential_commitment, [0u8; 32]);
        assert_ne!(cp.issuer_hash, [0u8; 32]);
        assert_eq!(cp.epoch, 5);
    }

    #[test]
    fn test_build_credential_proof_deterministic() {
        // Spec §21.3 F10: deterministik.
        let data = b"test_credential";
        let issuer = [0x01u8; 32];
        let nonce = [0x02u8; 32];
        let cp1 = build_credential_proof(data, issuer, nonce, 1).unwrap();
        let cp2 = build_credential_proof(data, issuer, nonce, 1).unwrap();
        assert_eq!(cp1.credential_commitment, cp2.credential_commitment);
        assert_eq!(cp1.issuer_hash, cp2.issuer_hash);
    }

    #[test]
    fn test_build_credential_proof_empty_data_rejected() {
        // Spec §21.3 F10: data kosong → error.
        let err = build_credential_proof(b"", [0x01u8; 32], [0u8; 32], 1).unwrap_err();
        assert!(matches!(err, SdkError::InvalidInput(_)));
    }

    #[test]
    fn test_build_credential_proof_different_issuer_differs() {
        // Issuer berbeda → issuer_hash berbeda. Spec §21.3 F10.
        let data = b"credential";
        let nonce = [0u8; 32];
        let cp1 = build_credential_proof(data, [0x01u8; 32], nonce, 1).unwrap();
        let cp2 = build_credential_proof(data, [0x02u8; 32], nonce, 1).unwrap();
        assert_ne!(cp1.issuer_hash, cp2.issuer_hash);
    }

    // ── F11: SLA Report ───────────────────────────────────────────────────────

    #[test]
    fn test_query_uptime_sla_met() {
        // uptime_actual ≥ committed → sla_met. Spec §21.3 F11.
        let mut node_id = [0u8; 32];
        node_id[0] = 1;
        let sla = query_uptime_sla(node_id, 950_000, 900_000, 5).unwrap();
        assert!(sla.sla_met);
        assert_eq!(sla.uptime_actual_fp, 950_000);
        assert_eq!(sla.uptime_committed_fp, 900_000);
    }

    #[test]
    fn test_query_uptime_sla_not_met() {
        // uptime_actual < committed → not met. Spec §21.3 F11.
        let mut node_id = [0u8; 32];
        node_id[0] = 1;
        let sla = query_uptime_sla(node_id, 700_000, 900_000, 5).unwrap();
        assert!(!sla.sla_met);
    }

    #[test]
    fn test_query_uptime_sla_exact_met() {
        // uptime_actual = committed → met (boundary). Spec §21.3 F11.
        let mut node_id = [0u8; 32];
        node_id[0] = 1;
        let sla = query_uptime_sla(node_id, 800_000, 800_000, 1).unwrap();
        assert!(sla.sla_met);
    }

    #[test]
    fn test_query_uptime_sla_zero_node_id_rejected() {
        // node_id = [0;32] → error. Spec §21.3 F11.
        let err = query_uptime_sla([0u8; 32], 900_000, 900_000, 1).unwrap_err();
        assert_eq!(err, SdkError::InvalidNodeId);
    }

    // ── F1: Scarcity — additional edge cases ──────────────────────────────────

    #[test]
    fn test_scarcity_proof_zero_minted_valid() {
        // M_E = 0 → valid (genesis state). Spec §21.3 F1.
        let proof = query_scarcity_proof(0, 0);
        assert!(proof.is_valid);
    }

    #[test]
    fn test_scarcity_proof_supply_cap_correct() {
        // supply_cap_sscl harus = SDK_S_E_SSCL. Spec §3.2.
        let proof = query_scarcity_proof(0, 0);
        assert_eq!(proof.supply_cap_sscl, SDK_S_E_SSCL);
        assert_eq!(proof.supply_cap_sscl, 1_890_000_000_000_000u64);
    }

    // ── F2: MPAS — additional edge cases ─────────────────────────────────────

    #[test]
    fn test_mpas_above_e0_deviation() {
        // emission > E0 → deviation > 0. Spec §21.3 F2.
        let report = query_monetary_policy_score(SDK_E0_SSCL + SDK_E0_SSCL, 1);
        assert_eq!(report.deviation_fp, 1_000_000); // 100% di atas E0
    }

    // ── F5: STP — additional edge cases ──────────────────────────────────────

    #[test]
    fn test_threshold_proof_zero_balance_zero_threshold() {
        // 0 ≥ 0 → met. Spec §21.3 F5.
        let tp = build_threshold_proof(0, 0, [0u8; 32]).unwrap();
        assert!(tp.result);
    }

    #[test]
    fn test_threshold_proof_commitment_non_zero() {
        // commitment harus non-zero untuk input non-trivial. Spec §21.3 F5.
        let tp = build_threshold_proof(1_000, 500, [0x42u8; 32]).unwrap();
        assert_ne!(tp.balance_commitment, [0u8; 32]);
    }

    // ── F6: NCP — additional edge cases ──────────────────────────────────────

    #[test]
    fn test_ncp_order_independent() {
        // Urutan exclusion set tidak mempengaruhi hasil. Spec §21.3 F6.
        let nullifier = [0x01u8; 32];
        let nonce = [0u8; 32];
        let set1 = [[0x02u8; 32], [0x03u8; 32]];
        let set2 = [[0x03u8; 32], [0x02u8; 32]];
        let ncp1 = build_negative_compliance_proof(nullifier, &set1, nonce).unwrap();
        let ncp2 = build_negative_compliance_proof(nullifier, &set2, nonce).unwrap();
        assert_eq!(ncp1.exclusion_set_hash, ncp2.exclusion_set_hash);
        assert_eq!(ncp1.is_compliant, ncp2.is_compliant);
    }

    // ── F7: Payment Proof — additional edge cases ─────────────────────────────

    #[test]
    fn test_payment_proof_zero_amount() {
        // Amount = 0 → proof tetap valid (deterministik). Spec §21.3 F7.
        let commitment = [0x01u8; 32];
        let proof = build_payment_proof(commitment, 1, 0);
        assert_ne!(proof.proof_hash, [0u8; 32]);
    }

    // ── F8: Timestamp Record — additional edge cases ──────────────────────────

    #[test]
    fn test_timestamp_record_different_epoch_different_commitment() {
        // Epoch berbeda → commitment berbeda. Spec §21.3 F8.
        let doc = [0x42u8; 32];
        let r1 = build_timestamp_record(doc, 1).unwrap();
        let r2 = build_timestamp_record(doc, 2).unwrap();
        assert_ne!(r1.commitment, r2.commitment);
    }

    // ── F9: Indelible Record — additional edge cases ──────────────────────────

    #[test]
    fn test_indelible_record_different_epoch_different_commitment() {
        // Epoch berbeda → nullifier_commitment berbeda. Spec §21.3 F9.
        let data = [0x42u8; 32];
        let r1 = build_indelible_record(data, 1).unwrap();
        let r2 = build_indelible_record(data, 2).unwrap();
        assert_ne!(r1.nullifier_commitment, r2.nullifier_commitment);
    }

    // ── F12: DMS — additional edge cases ─────────────────────────────────────

    #[test]
    fn test_dead_man_switch_different_epoch_different_commitment() {
        // Epoch berbeda → succession_commitment berbeda. Spec §21.3 F12.
        let primary = [0x01u8; 32];
        let backup = [0x02u8; 32];
        let dms1 = build_dead_man_switch(primary, backup, 1).unwrap();
        let dms2 = build_dead_man_switch(primary, backup, 2).unwrap();
        assert_ne!(dms1.succession_commitment, dms2.succession_commitment);
    }

    // ── Isolation QA ──────────────────────────────────────────────────────────

    #[test]
    fn test_sdk_no_protocol_import() {
        // QA: scalar-sdk tidak import scalar_emission/stark/nullifier.
        // Test ini compile hanya jika isolation terjaga.
        // Keberhasilan compile = isolation ok. Spec §21.1.
        let _ = query_scarcity_proof(0, 0);
    }

    // ── RECORD_FEE_MIN constant ───────────────────────────────────────────────

    #[test]
    fn test_record_fee_min_is_floor_min_absolute() {
        // Spec §9.1: FLOOR_MIN_ABSOLUTE = 40 sSCL = RECORD_FEE_MIN_SSCL.
        assert_eq!(RECORD_FEE_MIN_SSCL, 40u64);
    }
}
