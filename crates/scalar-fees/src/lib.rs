//! scalar-fees — Fee model baru Scalar Network (Bagian B.4)
//!
//! Spesifikasi: Scalar_Master_Technical_Spec.docx §B.4
//!
//! Menggantikan sepenuhnya model lama (50% burn / 30% relay / 15% agg / 5% reserve).
//!
//! Komponen:
//! - [`floor`]   — FLOOR computation (ossified §B.6)
//! - [`batch`]   — Batch Protocol: score, tie-breaking, fairness slot
//! - [`padding`] — Fee padding PADDING_random (§B.4.5)

pub mod batch;
pub mod floor;
pub mod padding;

#[derive(Debug, thiserror::Error)]
pub enum FeeError {
    #[error("fee_total {fee_total} lebih kecil dari FLOOR {floor} yang diwajibkan")]
    BelowFloor { fee_total: u64, floor: u64 },

    #[error("num_inputs {inputs} atau num_outputs {outputs} melebihi batas maksimum 10")]
    ExceedsMaxIO { inputs: u32, outputs: u32 },

    #[error("PREMIUM negatif tidak valid")]
    NegativePremium,

    #[error("Overflow aritmetik pada fee computation")]
    Overflow,
}
