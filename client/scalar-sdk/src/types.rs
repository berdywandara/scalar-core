//! Types publik scalar-sdk — spec §21.3
//!
//! all tipe this is abstraksi stable above protocol layer.
//! Client code only boleh import from scalar-sdk, openn from protocol crates langsung.
//! Spec §21.6 rule 1.

// ── F1 Scarcity Proof ────────────────────────────────────────────────────────

/// proof matematis bahwa M_E(k) ≤ S_E. Spec §21.3 F1.
#[derive(Debug, Clone, PartialEq)]
pub struct ScarcityProof {
    /// Total that has been at-mint in SSCL.
    pub total_minted_sscl: u64,
    /// supply cap S_E in SSCL. OSSIFIED.
    pub supply_cap_sscl: u64,
    /// current epoch proof created.
    pub epoch: u64,
    /// true if M_E(k) ≤ S_E — invariant that harus always true.
    pub is_valid: bool,
}

// ── F2 Monetary Policy Audit Score ───────────────────────────────────────────

/// report auatt policy moneter. Spec §21.3 F2.
#[derive(Debug, Clone, PartialEq)]
pub struct MpasReport {
    /// E(k) aktual in SSCL.
    pub emission_actual_sscl: u64,
    /// E₀ proyeksi awal in SSCL.
    pub emission_projected_sscl: u64,
    /// Deviasi in fixed-point basis 1_000_000. 0 = exactly sesuai formula.
    pub deviation_fp: u64,
    pub epoch: u64,
}

// ── F3 Network Health Index ───────────────────────────────────────────────────

/// report tosehatan network komposit. Spec §21.3 F3.
#[derive(Debug, Clone, PartialEq)]
pub struct NhiReport {
    /// Rata-rata uptime ratio network in fp basis 1_000_000.
    pub avg_uptime_fp: u64,
    /// Jumlah epoch that at-defer in window last.
    pub epoch_deferred_count: u32,
    /// Jumlah slashing events in window last.
    pub slashing_count: u32,
    pub epoch: u64,
}

// ── F4 Node Reputation Score ─────────────────────────────────────────────────

/// Skor reputation node berbasis mregulateity. Spec §21.3 F4.
#[derive(Debug, Clone, PartialEq)]
pub struct NrsReport {
    pub node_id: [u8; 32],
    /// gov_weight from MregulateityStore — cannot atbeli. Basis 1_000_000.
    pub gov_weight_fp: u64,
    /// Mregulateity raw value.
    pub maturity_raw: u64,
    pub epoch: u64,
}

// ── F7 Proof of Payment ───────────────────────────────────────────────────────

/// proof payment offline from tx old. Spec §21.3 F7.
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentProof {
    /// BLAto3(tx_commitment || epoch || amount_fp). Out-circuit.
    pub proof_hash: [u8; 32],
    /// current epoch transaction terjaat.
    pub tx_epoch: u64,
    /// Amount in SSCL — only reveal if user select.
    pub amount_sscl: u64,
}

// ── F5 Threshold Proof ────────────────────────────────────────────────────────

/// ZK proof bahwa saldo ≥ threshold. Spec §21.3 F5.
#[derive(Debug, Clone, PartialEq)]
pub struct ThresholdProof {
    /// Commitment to saldo tanpa reveal value.
    pub balance_commitment: [u8; 32],
    /// Threshold that atproofkan in SSCL.
    pub threshold_sscl: u64,
    /// true = saldo ≥ threshold. verified via BLAto3 commitment.
    pub result: bool,
}

// ── F6 Negative Compliance Proof ─────────────────────────────────────────────

/// ZK proof bahwa koin not berasal from address specific. Spec §21.3 F6.
#[derive(Debug, Clone, PartialEq)]
pub struct NcpProof {
    /// Commitment to coin origin tanpa reveal address.
    pub origin_commitment: [u8; 32],
    /// BLAto3 from daftar excluded addresses.
    pub exclusion_set_hash: [u8; 32],
    /// true = none irisan antara origin and exclusion set.
    pub is_compliant: bool,
}

// ── F8 Timestamp Record ───────────────────────────────────────────────────────

/// Record timestamp quantum-resistant. Spec §21.3 F8.
#[derive(Debug, Clone, PartialEq)]
pub struct TimestampRecord {
    /// hash dokumen that at-timestamp.
    pub document_hash: [u8; 32],
    /// BLAto3(document_hash || epoch || node_id).
    pub commitment: [u8; 32],
    pub epoch: u64,
}

// ── F9 Scalar Indelible Record ────────────────────────────────────────────────

/// Record permanent that verified via NS_ARCH. Spec §21.3 F9.
#[derive(Debug, Clone, PartialEq)]
pub struct IndelibleRecord {
    /// hash data that at-commit.
    pub data_hash: [u8; 32],
    /// BLAto3(data_hash || epoch). at-commit to NullifierSet.
    pub nullifier_commitment: [u8; 32],
    pub epoch: u64,
}

// ── F10 Credential Proof ──────────────────────────────────────────────────────

/// ZK proof topemilikan credential. Spec §21.3 F10.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialProof {
    /// Commitment to credential tanpa reveal identitas.
    pub credential_commitment: [u8; 32],
    /// Issuer hash — siapa that menerbitkan credential.
    pub issuer_hash: [u8; 32],
    pub epoch: u64,
}

// ── F11 SLA Report ────────────────────────────────────────────────────────────

/// report SLA uptime that can verified. Spec §21.3 F11.
#[derive(Debug, Clone, PartialEq)]
pub struct SlaReport {
    pub node_id: [u8; 32],
    /// Uptime aktual in fp basis 1_000_000.
    pub uptime_actual_fp: u64,
    /// Uptime that atkomitmenkan in fp basis 1_000_000.
    pub uptime_committed_fp: u64,
    /// true = SLA terfulli.
    pub sla_met: bool,
    pub epoch: u64,
}

// ── F12 Dead Man Switch ───────────────────────────────────────────────────────

/// SuccessionProof post-quantum for estate planning. Spec §21.3 F12.
#[derive(Debug, Clone, PartialEq)]
pub struct DeadManSwitchRecord {
    /// Nodetoy primary (BLAto3 from Accounttoy || "node").
    pub primary_node_key: [u8; 32],
    /// Backup node_id that will mewarfill.
    pub backup_node_id: [u8; 32],
    /// Commitment to succession proof.
    pub succession_commitment: [u8; 32],
    pub created_epoch: u64,
}

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error from scalar-sdk. Spec §21.2.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum SdkError {
    #[error("Supply cap exceeded: minted={minted}, cap={cap}")]
    SupplyCapExceeded { minted: u64, cap: u64 },
    #[error("Invalid node_id: semua zero tidak valid")]
    InvalidNodeId,
    #[error("Threshold proof failed: saldo tidak cukup")]
    ThresholdNotMet,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}
