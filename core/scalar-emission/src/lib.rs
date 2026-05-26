// File: crates/scalar-emission/src/lib.rs

pub mod accounting;
pub mod accumulator;
pub mod consensus;
pub mod dmm;
pub mod epoch;
pub mod equity;
pub mod formal;
pub mod genesis_ceremony;
pub mod institutional;
pub mod liveness;
pub mod longevity;
pub mod mint_nullifier;
pub mod ordering;
pub mod pou;
pub mod resumption;
pub mod root_alignment;
pub mod slashing;
pub mod succession;
pub mod types;
pub mod utxo_set_smt;
pub use utxo_set_smt::{UtxoSetAccumulator, UtxoSetState, DOMAIN_UTXO_SMT, GENESIS_EPOCH_ID};
// Backward-compat alias — remove after all callers updated.
pub use utxo_set_smt::UtxoSetAccumulator as UtxoSetSMT;

// ── EmissionError — digunakan oleh accumulator dan modul lain ────────────────

/// Error dari emission subsystem. Spec §B.2.2 MC3.
#[derive(Debug, Clone, PartialEq)]
pub enum EmissionError {
    /// Integer overflow in emission calculation.
    Overflow,
    /// Supply cap S_E exceeded. Spec §B.2.2 MC3.
    SupplyCapExceeded { minted: u64, reward: u64, cap: u64 },
    /// Total weight W(k) = 0 — no active nodes.
    ZeroTotalWeight,
    /// Node below minimum uptime threshold.
    BelowUptimeThreshold,
    /// Node already claimed reward for this epoch. Spec §5.2 MC2.
    AlreadyClaimed { epoch_id: u64 },
    /// MC5 node authorization failed — invalid SLH-DSA signature. Spec §5.2 MC5.
    NodeAuthorizationFailed,
    /// Reward not found in manifest reward_root. Spec §5.2 MC1.
    RewardNotInManifest,
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
            Self::AlreadyClaimed { epoch_id } => {
                write!(f, "Reward already claimed for epoch {epoch_id}")
            }
            Self::NodeAuthorizationFailed => {
                write!(
                    f,
                    "MC5 node authorization failed: invalid SLH-DSA signature"
                )
            }
            Self::RewardNotInManifest => {
                write!(f, "Reward not found in manifest reward_root")
            }
        }
    }
}

#[cfg(test)]
mod empirical_2_canonical;
