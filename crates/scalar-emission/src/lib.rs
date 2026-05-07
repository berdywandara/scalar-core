// File: crates/scalar-emission/src/lib.rs

pub mod accumulator;
pub mod consensus;
pub mod epoch;
pub mod equity;
pub mod institutional;
pub mod liveness;
pub mod longevity;
pub mod manifest;
pub mod pou;
pub mod resumption;
pub mod root_alignment;
pub mod slashing;
pub mod succession;

// ── EmissionError — digunakan oleh accumulator dan modul lain ────────────────

/// Error dari emission subsystem. Spec §B.2.2 MC3.
#[derive(Debug, Clone, PartialEq)]
pub enum EmissionError {
    /// Integer overflow dalam kalkulasi emission.
    Overflow,
    /// Supply cap S_E terlampaui. Spec §B.2.2 MC3.
    SupplyCapExceeded { minted: u64, reward: u64, cap: u64 },
    /// Total weight W(k) = 0 — tidak ada node aktif.
    ZeroTotalWeight,
    /// Node di bawah uptime threshold minimum.
    BelowUptimeThreshold,
}

impl core::fmt::Display for EmissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Overflow => write!(f, "Emission arithmetic overflow"),
            Self::SupplyCapExceeded {
                minted,
                reward,
                cap,
            } => write!(
                f,
                "Supply cap exceeded: minted={minted}, reward={reward}, cap={cap}"
            ),
            Self::ZeroTotalWeight => write!(f, "Total weight W(k) = 0"),
            Self::BelowUptimeThreshold => write!(f, "Node below uptime threshold"),
        }
    }
}
