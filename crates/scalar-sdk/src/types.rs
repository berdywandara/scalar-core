//! Types publik scalar-sdk — spec §21.3
//!
//! Semua tipe ini adalah abstraksi stabil di atas protocol layer.
//! Client code HANYA boleh import dari scalar-sdk, bukan dari protocol crates langsung.
//! Spec §21.6 Aturan 1.

// ── F1 Scarcity Proof ────────────────────────────────────────────────────────

/// Bukti matematis bahwa M_E(k) ≤ S_E. Spec §21.3 F1.
#[derive(Debug, Clone, PartialEq)]
pub struct ScarcityProof {
    /// Total yang sudah di-mint dalam sSCL.
    pub total_minted_sscl: u64,
    /// Supply cap S_E dalam sSCL. OSSIFIED.
    pub supply_cap_sscl: u64,
    /// Epoch saat proof dibuat.
    pub epoch: u64,
    /// true jika M_E(k) ≤ S_E — invariant yang harus selalu true.
    pub is_valid: bool,
}

// ── F2 Monetary Policy Audit Score ───────────────────────────────────────────

/// Laporan audit kebijakan moneter. Spec §21.3 F2.
#[derive(Debug, Clone, PartialEq)]
pub struct MpasReport {
    /// E(k) aktual dalam sSCL.
    pub emission_actual_sscl: u64,
    /// E₀ proyeksi awal dalam sSCL.
    pub emission_projected_sscl: u64,
    /// Deviasi dalam fixed-point basis 1_000_000. 0 = persis sesuai formula.
    pub deviation_fp: u64,
    pub epoch: u64,
}

// ── F3 Network Health Index ───────────────────────────────────────────────────

/// Laporan kesehatan jaringan komposit. Spec §21.3 F3.
#[derive(Debug, Clone, PartialEq)]
pub struct NhiReport {
    /// Rata-rata uptime ratio jaringan dalam fp basis 1_000_000.
    pub avg_uptime_fp: u64,
    /// Jumlah epoch yang di-defer dalam window terakhir.
    pub epoch_deferred_count: u32,
    /// Jumlah slashing events dalam window terakhir.
    pub slashing_count: u32,
    pub epoch: u64,
}

// ── F4 Node Reputation Score ─────────────────────────────────────────────────

/// Skor reputasi node berbasis maturity. Spec §21.3 F4.
#[derive(Debug, Clone, PartialEq)]
pub struct NrsReport {
    pub node_id: [u8; 32],
    /// gov_weight dari MaturityStore — tidak bisa dibeli. Basis 1_000_000.
    pub gov_weight_fp: u64,
    /// Maturity raw value.
    pub maturity_raw: u64,
    pub epoch: u64,
}

// ── F7 Proof of Payment ───────────────────────────────────────────────────────

/// Bukti pembayaran offline dari tx lama. Spec §21.3 F7.
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentProof {
    /// BLAKE3(tx_commitment || epoch || amount_fp). Out-circuit.
    pub proof_hash: [u8; 32],
    /// Epoch saat transaksi terjadi.
    pub tx_epoch: u64,
    /// Amount dalam sSCL — hanya reveal jika user memilih.
    pub amount_sscl: u64,
}

// ── F5 Threshold Proof ────────────────────────────────────────────────────────

/// ZK proof bahwa saldo ≥ threshold. Spec §21.3 F5.
#[derive(Debug, Clone, PartialEq)]
pub struct ThresholdProof {
    /// Commitment ke saldo tanpa reveal nilai.
    pub balance_commitment: [u8; 32],
    /// Threshold yang dibuktikan dalam sSCL.
    pub threshold_sscl: u64,
    /// true = saldo ≥ threshold. Diverifikasi via BLAKE3 commitment.
    pub result: bool,
}

// ── F6 Negative Compliance Proof ─────────────────────────────────────────────

/// ZK proof bahwa koin tidak berasal dari address tertentu. Spec §21.3 F6.
#[derive(Debug, Clone, PartialEq)]
pub struct NcpProof {
    /// Commitment ke coin origin tanpa reveal address.
    pub origin_commitment: [u8; 32],
    /// BLAKE3 dari daftar excluded addresses.
    pub exclusion_set_hash: [u8; 32],
    /// true = tidak ada irisan antara origin dan exclusion set.
    pub is_compliant: bool,
}

// ── F8 Timestamp Record ───────────────────────────────────────────────────────

/// Record timestamp quantum-resistant. Spec §21.3 F8.
#[derive(Debug, Clone, PartialEq)]
pub struct TimestampRecord {
    /// Hash dokumen yang di-timestamp.
    pub document_hash: [u8; 32],
    /// BLAKE3(document_hash || epoch || node_id).
    pub commitment: [u8; 32],
    pub epoch: u64,
}

// ── F9 Scalar Indelible Record ────────────────────────────────────────────────

/// Record permanen yang diverifikasi via NS_ARCH. Spec §21.3 F9.
#[derive(Debug, Clone, PartialEq)]
pub struct IndelibleRecord {
    /// Hash data yang di-commit.
    pub data_hash: [u8; 32],
    /// BLAKE3(data_hash || epoch). Di-commit ke NullifierSet.
    pub nullifier_commitment: [u8; 32],
    pub epoch: u64,
}

// ── F10 Credential Proof ──────────────────────────────────────────────────────

/// ZK proof kepemilikan credential. Spec §21.3 F10.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialProof {
    /// Commitment ke credential tanpa reveal identitas.
    pub credential_commitment: [u8; 32],
    /// Issuer hash — siapa yang menerbitkan credential.
    pub issuer_hash: [u8; 32],
    pub epoch: u64,
}

// ── F11 SLA Report ────────────────────────────────────────────────────────────

/// Laporan SLA uptime yang bisa diverifikasi. Spec §21.3 F11.
#[derive(Debug, Clone, PartialEq)]
pub struct SlaReport {
    pub node_id: [u8; 32],
    /// Uptime aktual dalam fp basis 1_000_000.
    pub uptime_actual_fp: u64,
    /// Uptime yang dikomitmenkan dalam fp basis 1_000_000.
    pub uptime_committed_fp: u64,
    /// true = SLA terpenuhi.
    pub sla_met: bool,
    pub epoch: u64,
}

// ── F12 Dead Man Switch ───────────────────────────────────────────────────────

/// SuccessionProof post-quantum untuk estate planning. Spec §21.3 F12.
#[derive(Debug, Clone, PartialEq)]
pub struct DeadManSwitchRecord {
    /// NodeKey primary (BLAKE3 dari AccountKey || "node").
    pub primary_node_key: [u8; 32],
    /// Backup node_id yang akan mewarisi.
    pub backup_node_id: [u8; 32],
    /// Commitment ke succession proof.
    pub succession_commitment: [u8; 32],
    pub created_epoch: u64,
}

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error dari scalar-sdk. Spec §21.2.
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
