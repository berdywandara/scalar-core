//! Read-only state queries — spec §21.3 F1, F2, F3, F4, F7, F11
//!
//! Semua fungsi di modul ini bersifat read-only: zero onchain cost.
//! Tidak ada state baru yang dibuat di protocol layer — spec §21.6 Aturan 3.
//!
//! ISOLASI: modul ini TIDAK import dari protocol crates — spec §21.1 Aturan 1.
//! Konstanta ossified di-copy secara eksplisit dengan referensi spec.

use crate::types::{
    MpasReport, NhiReport, NrsReport, PaymentProof, ScarcityProof, SdkError, SlaReport,
};

// ── Ossified constants (mirrored from protocol layer) — spec §21.2 ─────────
// Nilai-nilai ini adalah L1 OSSIFIED. Jika berbeda dari scalar-emission,
// itu adalah bug di salah satu sisi — keduanya harus identik.

/// S_E = 18,900,000 SCL = 1,890,000,000,000,000 sSCL. Spec §3.2. OSSIFIED.
pub const SDK_S_E_SSCL: u64 = 1_890_000_000_000_000;

/// E₀ = 126,000 SCL/epoch = 12,600,000,000,000 sSCL. Spec §7.1. OSSIFIED.
pub const SDK_E0_SSCL: u64 = 12_600_000_000_000;

// ── F1 ───────────────────────────────────────────────────────────────────────

/// F1: Query scarcity proof — bukti matematis M_E(k) ≤ S_E. Spec §21.3.
///
/// Tidak memerlukan akses ke node penuh — cukup total minted dari caller.
pub fn query_scarcity_proof(total_minted_sscl: u64, epoch: u64) -> ScarcityProof {
    // Spec §21.3 F1: is_valid = M_E(k) ≤ S_E. OSSIFIED.
    let is_valid = total_minted_sscl <= SDK_S_E_SSCL;
    ScarcityProof {
        total_minted_sscl,
        supply_cap_sscl: SDK_S_E_SSCL,
        epoch,
        is_valid,
    }
}

// ── F2 ───────────────────────────────────────────────────────────────────────

/// F2: Query monetary policy audit score. Spec §21.3.
///
/// Hitung deviasi E(k) aktual vs E₀ proyeksi awal.
/// Deviasi 0 = kebijakan berjalan persis sesuai formula.
pub fn query_monetary_policy_score(emission_actual_sscl: u64, epoch: u64) -> MpasReport {
    // Deviasi = |actual - E0| / E0 dalam fp basis 1_000_000 — spec §21.3 F2
    let deviation_fp = if emission_actual_sscl >= SDK_E0_SSCL {
        ((emission_actual_sscl - SDK_E0_SSCL) as u128)
            .saturating_mul(1_000_000)
            .checked_div(SDK_E0_SSCL as u128)
            .unwrap_or(1_000_000) as u64
    } else {
        ((SDK_E0_SSCL - emission_actual_sscl) as u128)
            .saturating_mul(1_000_000)
            .checked_div(SDK_E0_SSCL as u128)
            .unwrap_or(1_000_000) as u64
    };

    MpasReport {
        emission_actual_sscl,
        emission_projected_sscl: SDK_E0_SSCL,
        deviation_fp,
        epoch,
    }
}

// ── F3 ───────────────────────────────────────────────────────────────────────

/// F3: Query network health index. Spec §21.3.
///
/// Komposit dari uptime, deferred epochs, dan slashing events.
pub fn query_network_health(
    avg_uptime_fp: u64,
    epoch_deferred_count: u32,
    slashing_count: u32,
    epoch: u64,
) -> NhiReport {
    NhiReport {
        avg_uptime_fp,
        epoch_deferred_count,
        slashing_count,
        epoch,
    }
}

// ── F4 ───────────────────────────────────────────────────────────────────────

/// F4: Query node reputation score. Spec §21.3.
///
/// Menerima gov_weight_fp dan maturity_raw sebagai raw values dari caller.
/// Caller bertanggung jawab query MaturityStore — sdk tidak tahu internal protocol.
/// Spec §21.1 Aturan 1: sdk tidak import scalar_emission.
pub fn query_node_reputation(
    node_id: [u8; 32],
    gov_weight_fp: u64,
    maturity_raw: u64,
    epoch: u64,
) -> Result<NrsReport, SdkError> {
    if node_id == [0u8; 32] {
        return Err(SdkError::InvalidNodeId);
    }
    Ok(NrsReport {
        node_id,
        gov_weight_fp,
        maturity_raw,
        epoch,
    })
}

// ── F7 ───────────────────────────────────────────────────────────────────────

/// F7: Build payment proof dari tx record. Spec §21.3.
///
/// BLAKE3(tx_commitment || epoch_bytes || amount_bytes) — out-circuit.
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn build_payment_proof(
    tx_commitment: [u8; 32],
    tx_epoch: u64,
    amount_sscl: u64,
) -> PaymentProof {
    // BLAKE3 out-circuit — spec §21.3 F7, hash discipline §2.1.3
    let mut hasher = blake3::Hasher::new();
    hasher.update(&tx_commitment);
    hasher.update(&tx_epoch.to_le_bytes());
    hasher.update(&amount_sscl.to_le_bytes());
    let proof_hash = *hasher.finalize().as_bytes();

    PaymentProof {
        proof_hash,
        tx_epoch,
        amount_sscl,
    }
}

// ── F11 ──────────────────────────────────────────────────────────────────────

/// F11: Query uptime SLA report. Spec §21.3.
///
/// Menerima uptime_actual_fp dari caller — sdk tidak query MaturityStore langsung.
/// Spec §21.1 Aturan 1: sdk tidak import scalar_emission.
pub fn query_uptime_sla(
    node_id: [u8; 32],
    uptime_actual_fp: u64,
    uptime_committed_fp: u64,
    epoch: u64,
) -> Result<SlaReport, SdkError> {
    if node_id == [0u8; 32] {
        return Err(SdkError::InvalidNodeId);
    }
    let sla_met = uptime_actual_fp >= uptime_committed_fp;
    Ok(SlaReport {
        node_id,
        uptime_actual_fp,
        uptime_committed_fp,
        sla_met,
        epoch,
    })
}
