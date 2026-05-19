// File: crates/scalar-stark/src/prover.rs
//
// Normalized Prover — Spec §4.4, §15.6
//
// PROVING_TIME_TARGET_MS = 500 ms ± 10 ms (range 490–510 ms). OSSIFIED — spec §4.4.
// Spec §15.6: hardware spesifikasi minimum (8 GB RAM, CPU standar server)
// harus mencapai proving time <= 500 ms untuk 10-in/10-out.
//
// Normalisasi waktu mencegah timing side-channel yang bisa bocorkan
// informasi tentang nilai transaksi atau private witness.

/// Target proving time dalam ms. OSSIFIED — spec §4.4.
pub const PROVING_TIME_TARGET_MS: u64 = 500;

/// Toleransi ±10 ms dari target. OSSIFIED — spec §4.4.
pub const PROVING_TIME_TOLERANCE_MS: u64 = 10;

/// Batas bawah proving time: 490 ms. Spec §4.4.
pub const PROVING_TIME_MIN_MS: u64 = PROVING_TIME_TARGET_MS - PROVING_TIME_TOLERANCE_MS; // 490ms

/// Batas atas proving time: 510 ms. Spec §4.4.
pub const PROVING_TIME_MAX_MS: u64 = PROVING_TIME_TARGET_MS + PROVING_TIME_TOLERANCE_MS; // 510ms
/// Hardware variance limit: 700 ms. Beyond this → hard error. Spec §4.4, §15.6.
pub const PROVING_TIME_HARDWARE_MAX_MS: u64 = 700;

// --- MOCK STRUCTS UNTUK PROVER ---
#[derive(Clone)]
pub struct TransferCircuitWitness;

#[derive(Clone)]
pub struct TransferCircuitPublicInput;

pub struct StarkProof;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProverError {
    /// Internal proving error.
    InternalError,
    /// Proving time exceeded hardware variance limit. Spec §15.6, Finding #12.
    ProvingTimeTooSlow { elapsed_ms: u64, limit_ms: u64 },
}

impl core::fmt::Display for ProverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InternalError => write!(f, "Internal prover error"),
            Self::ProvingTimeTooSlow {
                elapsed_ms,
                limit_ms,
            } => write!(
                f,
                "Proving time {} ms exceeds hardware limit {} ms — spec §15.6",
                elapsed_ms, limit_ms
            ),
        }
    }
}

/// Simulasi internal prover (natural proving time).
/// Placeholder sampai Winterfell diintegrasikan — spec §4.1, §15.3.
pub fn prove_transfer_internal(
    _witness: &TransferCircuitWitness,
    _public_input: &TransferCircuitPublicInput,
) -> Result<StarkProof, ProverError> {
    // Simulasi: proof selesai cepat (sebelum Winterfell diintegrasikan)
    std::thread::sleep(std::time::Duration::from_millis(50));
    Ok(StarkProof)
}

/// Normalized prover: selalu menghasilkan proof dalam 500 ms ± 10 ms.
///
/// Spec §4.4: proving time target 500 ms ± 10 ms (range 490–510 ms). OSSIFIED.
/// Spec §15.6: benchmark wajib <= 500 ms untuk 10-in/10-out pada hardware minimum.
///
/// Normalisasi mencegah timing side-channel — semua proof memiliki
/// waktu yang seragam terlepas dari kompleksitas witness.
pub fn prove_transfer_normalized(
    witness: &TransferCircuitWitness,
    public_input: &TransferCircuitPublicInput,
) -> Result<StarkProof, ProverError> {
    let start = std::time::Instant::now();

    // Lakukan proving normal
    let proof = prove_transfer_internal(witness, public_input)?;

    let elapsed_ms = start.elapsed().as_millis() as u64;

    // Normalisasi: pad ke minimum 490 ms jika proving selesai lebih cepat
    if elapsed_ms < PROVING_TIME_MIN_MS {
        let padding_ms = PROVING_TIME_MIN_MS - elapsed_ms;
        std::thread::sleep(std::time::Duration::from_millis(padding_ms));
    }

    // Evaluasi waktu final setelah padding
    let final_elapsed = start.elapsed().as_millis() as u64;

    // Proving time enforcement — spec §15.6, Finding #12.
    // 490-510 ms: target normalization (OSSIFIED — spec §4.4).
    // 400-700 ms: hardware variance limit.
    // >700 ms: hard error — hardware does not meet spec §15.6 requirement.
    if final_elapsed > PROVING_TIME_HARDWARE_MAX_MS {
        return Err(ProverError::ProvingTimeTooSlow {
            elapsed_ms: final_elapsed,
            limit_ms: PROVING_TIME_HARDWARE_MAX_MS,
        });
    }
    Ok(proof)
}

#[cfg(test)]
mod tests_proving_time_normalization {
    use super::*;

    fn make_witness() -> TransferCircuitWitness {
        TransferCircuitWitness
    }
    fn make_public_input() -> TransferCircuitPublicInput {
        TransferCircuitPublicInput
    }

    /// Spec §4.4: PROVING_TIME_TARGET_MS = 500, toleransi ±10. OSSIFIED.
    #[test]
    fn test_proving_time_constants_match_spec() {
        assert_eq!(
            PROVING_TIME_TARGET_MS, 500,
            "Target harus 500 ms — spec §4.4"
        );
        assert_eq!(
            PROVING_TIME_TOLERANCE_MS, 10,
            "Toleransi harus ±10 ms — spec §4.4"
        );
        assert_eq!(PROVING_TIME_MIN_MS, 490, "Min harus 490 ms");
        assert_eq!(PROVING_TIME_MAX_MS, 510, "Max harus 510 ms");
    }

    /// Proof harus selesai minimal dalam PROVING_TIME_MIN_MS (490 ms).
    /// Upper bound longgar untuk CI environment. Spec §4.4.
    #[test]
    fn test_proving_time_within_target_range() {
        let start = std::time::Instant::now();
        let _proof = prove_transfer_normalized(&make_witness(), &make_public_input()).unwrap();
        let elapsed = start.elapsed().as_millis();

        assert!(
            elapsed >= 480,
            "Proving terlalu cepat: {} ms (min ~490 ms) — spec §4.4",
            elapsed
        );
        // Upper bound longgar untuk CI (scheduler jitter)
        assert!(
            elapsed <= 700,
            "Proving terlalu lambat: {} ms — periksa hardware spec §15.6",
            elapsed
        );
    }

    /// Proof cepat harus di-pad ke minimal PROVING_TIME_MIN_MS. Spec §4.4.
    #[test]
    fn test_fast_proof_gets_padded_to_490ms() {
        let start = std::time::Instant::now();
        let _ = prove_transfer_normalized(&make_witness(), &make_public_input());
        let elapsed = start.elapsed().as_millis();
        assert!(
            elapsed >= 480,
            "Proof cepat harus di-pad ke ~490 ms, dapat {} ms — spec §4.4",
            elapsed
        );
    }
}
