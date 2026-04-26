//! scalar-emission — State objects baru untuk PoU Emission (Bagian B)
//!
//! Spesifikasi: Scalar_Master_Technical_Spec.docx §B.3
//!
//! Crate ini mengandung lima state object baru yang diperlukan
//! untuk sistem Proof-of-Uptime (PoU):
//!
//! - [`liveness::LivenessSMT`]            — SMT heartbeat node per epoch
//! - [`mint_nullifier::MintNullifierSet`] — anti double-claim per epoch
//! - [`accumulator::EmissionAccumulator`] — counter total PoU minted
//! - [`accumulator::FeeAccumulator`]      — counter fee per epoch
//! - [`manifest::EpochRewardManifest`]    — struktur manifest reward

pub mod liveness;
pub mod mint_nullifier;
pub mod accumulator;
pub mod manifest;
pub mod epoch;
pub mod consensus;

/// Error type untuk seluruh crate scalar-emission
#[derive(Debug, thiserror::Error)]
pub enum EmissionError {
    #[error("Supply cap S_E terlampaui: minted={minted}, reward={reward}, cap={cap}")]
    SupplyCapExceeded { minted: u64, reward: u64, cap: u64 },

    #[error("Mint nullifier sudah ada — double-claim terdeteksi untuk epoch {epoch_id}")]
    AlreadyClaimed { epoch_id: u64 },

    #[error("Overflow aritmetik pada operasi emission")]
    Overflow,

    #[error("Uptime weight nol — tidak ada node aktif pada epoch ini")]
    ZeroTotalWeight,

    #[error("Node tidak memenuhi threshold uptime minimum (30%)")]
    BelowUptimeThreshold,
}
