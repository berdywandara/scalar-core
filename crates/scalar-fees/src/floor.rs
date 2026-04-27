//! FLOOR computation — §B.4.1
//!
//! fee_total(tx) = FLOOR + PREMIUM
//!
//! FLOOR = max(FLOOR_MIN_ABSOLUTE, COMPLEXITY_FLOOR)
//! FLOOR_MIN_ABSOLUTE = 40 sSCL  [Layer 1 OSSIFIED]
//! COMPLEXITY_FLOOR   = num_inputs × 10 + num_outputs × 10  [sSCL]
//!
//! Genesis FLOOR value: 100 sSCL [Layer 2 adjustable: 40–500 sSCL]
//!
//! Catatan: fee_total adalah PUBLIK — diperlukan verifikasi C5.

use crate::FeeError;

// ── Konstanta ossified (§B.6 Layer 1) ───────────────────────────────

/// Batas bawah absolut FLOOR. OSSIFIED — tidak bisa diubah tanpa fork.
pub const FLOOR_MIN_ABSOLUTE: u64 = 40;

/// Batas atas absolut FLOOR. OSSIFIED.
pub const FLOOR_MAX_ABSOLUTE: u64 = 10_000;

/// Bobot complexity per input/output dalam sSCL. Layer 2 CONSTRAINED.
/// Default: 10 sSCL, range: 5–50 sSCL.
pub const COMPLEXITY_WEIGHT_DEFAULT: u64 = 10;

/// Nilai FLOOR genesis (Layer 2 default). Bukan ossified.
pub const FLOOR_GENESIS_VALUE: u64 = 100;

/// Maksimum inputs/outputs per transaksi. OSSIFIED (Transfer Circuit C8).
pub const MAX_IO: u32 = 10;

// ── FLOOR computation ────────────────────────────────────────────────

/// Hitung FLOOR untuk transaksi dengan num_inputs dan num_outputs.
///
/// FLOOR = max(FLOOR_MIN_ABSOLUTE, num_inputs × cw + num_outputs × cw)
///
/// `complexity_weight`: nilai dari Layer 2 governance (default: 10 sSCL).
/// Gunakan `COMPLEXITY_WEIGHT_DEFAULT` jika tidak ada override.
///
/// Sesuai §B.4.1.
pub fn compute_floor(
    num_inputs: u32,
    num_outputs: u32,
    complexity_weight: u64,
) -> Result<u64, FeeError> {
    if num_inputs > MAX_IO || num_outputs > MAX_IO {
        return Err(FeeError::ExceedsMaxIO {
            inputs: num_inputs,
            outputs: num_outputs,
        });
    }

    let complexity_floor = ((num_inputs + num_outputs) as u64)
        .checked_mul(complexity_weight)
        .ok_or(FeeError::Overflow)?;

    Ok(FLOOR_MIN_ABSOLUTE.max(complexity_floor))
}

/// Verifikasi bahwa fee_total memenuhi FLOOR minimum.
pub fn verify_fee_above_floor(
    fee_total: u64,
    num_inputs: u32,
    num_outputs: u32,
    complexity_weight: u64,
) -> Result<(), FeeError> {
    let floor = compute_floor(num_inputs, num_outputs, complexity_weight)?;
    if fee_total < floor {
        return Err(FeeError::BelowFloor { fee_total, floor });
    }
    Ok(())
}

/// Ekstrak PREMIUM dari fee_total.
/// PREMIUM = fee_total - FLOOR
/// (termasuk PADDING_random yang tidak bisa dipisahkan)
pub fn extract_premium(
    fee_total: u64,
    num_inputs: u32,
    num_outputs: u32,
    complexity_weight: u64,
) -> Result<u64, FeeError> {
    let floor = compute_floor(num_inputs, num_outputs, complexity_weight)?;
    if fee_total < floor {
        return Err(FeeError::BelowFloor { fee_total, floor });
    }
    Ok(fee_total - floor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_floor_2in_2out_standard() {
        // Standard 2-in/2-out: max(40, 4×10) = max(40, 40) = 40 sSCL
        let floor = compute_floor(2, 2, COMPLEXITY_WEIGHT_DEFAULT).unwrap();
        assert_eq!(floor, 40);
    }

    #[test]
    fn test_floor_min_absolute_dominates() {
        // 1-in/1-out: max(40, 20) = 40 (FLOOR_MIN_ABSOLUTE dominates)
        let floor = compute_floor(1, 1, COMPLEXITY_WEIGHT_DEFAULT).unwrap();
        assert_eq!(floor, 40);
    }

    #[test]
    fn test_floor_large_tx() {
        // 10-in/10-out: max(40, 200) = 200
        let floor = compute_floor(10, 10, COMPLEXITY_WEIGHT_DEFAULT).unwrap();
        assert_eq!(floor, 200);
    }

    #[test]
    fn test_floor_exceeds_max_io() {
        assert!(compute_floor(11, 1, COMPLEXITY_WEIGHT_DEFAULT).is_err());
        assert!(compute_floor(1, 11, COMPLEXITY_WEIGHT_DEFAULT).is_err());
    }

    #[test]
    fn test_verify_fee_above_floor_ok() {
        assert!(verify_fee_above_floor(100, 2, 2, COMPLEXITY_WEIGHT_DEFAULT).is_ok());
    }

    #[test]
    fn test_verify_fee_below_floor_err() {
        // fee_total=39 < floor=40
        assert!(verify_fee_above_floor(39, 2, 2, COMPLEXITY_WEIGHT_DEFAULT).is_err());
    }

    #[test]
    fn test_extract_premium() {
        // fee_total=140, floor=40 → PREMIUM=100
        let premium = extract_premium(140, 2, 2, COMPLEXITY_WEIGHT_DEFAULT).unwrap();
        assert_eq!(premium, 100);
    }

    #[test]
    fn test_extract_premium_zero() {
        // fee_total=floor → PREMIUM=0 (valid, user tidak bid premium)
        let floor = compute_floor(2, 2, COMPLEXITY_WEIGHT_DEFAULT).unwrap();
        let premium = extract_premium(floor, 2, 2, COMPLEXITY_WEIGHT_DEFAULT).unwrap();
        assert_eq!(premium, 0);
    }

    #[test]
    fn test_floor_genesis_value() {
        // Genesis FLOOR value = 100 sSCL (Layer 2 default)
        assert_eq!(FLOOR_GENESIS_VALUE, 100);
        // Genesis value harus ≥ FLOOR_MIN_ABSOLUTE
        const { assert!(FLOOR_GENESIS_VALUE >= FLOOR_MIN_ABSOLUTE);}
    }
}
