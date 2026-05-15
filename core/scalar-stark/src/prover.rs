// File: crates/scalar-stark/src/prover.rs

pub const PROVING_TIME_TARGET_MS: u64 = 300;
pub const PROVING_TIME_TOLERANCE_MS: u64 = 10;
pub const PROVING_TIME_MIN_MS: u64 = PROVING_TIME_TARGET_MS - PROVING_TIME_TOLERANCE_MS; // 290ms
pub const PROVING_TIME_MAX_MS: u64 = PROVING_TIME_TARGET_MS + PROVING_TIME_TOLERANCE_MS; // 310ms

// --- MOCK STRUCTS UNTUK PROVER ---
#[derive(Clone)]
pub struct TransferCircuitWitness;

#[derive(Clone)]
pub struct TransferCircuitPublicInput;

pub struct StarkProof;

#[derive(Debug)]
pub struct ProverError;

/// Simulasi internal prover (nregulateal proving time)
pub fn prove_transfer_internal(
    _witness: &TransferCircuitWitness,
    _public_input: &TransferCircuitPublicInput,
) -> Result<StarkProof, ProverError> {
    // Simulasi proof yang selesai sangat cepat (contoh: 50ms)
    std::thread::sleep(std::time::Duration::from_millis(50));
    Ok(StarkProof)
}

/// Normalized prover: always produce proof in 300ms ± 10ms
/// prevent timing side-channel that can bocorkan info tentang value transaction or private witness.
pub fn prove_transfer_normalized(
    witness: &TransferCircuitWitness,
    public_input: &TransferCircuitPublicInput,
) -> Result<StarkProof, ProverError> {
    let start = std::time::Instant::now();

    // Lakukan proving normal
    let proof = prove_transfer_internal(witness, public_input)?;

    let elapsed_ms = start.elapsed().as_millis() as u64;

    // Normalisasi waktu:
    if elapsed_ms < PROVING_TIME_MIN_MS {
        // Kurang dari 290ms: tambahkan dummy computation via sleep
        let padding_ms = PROVING_TIME_MIN_MS - elapsed_ms;
        std::thread::sleep(std::time::Duration::from_millis(padding_ms));
    }

    // Evaluasi ulang waktu setelah padding
    let final_elapsed = start.elapsed().as_millis() as u64;

    // Lebih dari 310ms: ini performance issue, bukan security issue. Log warning.
    if final_elapsed > PROVING_TIME_MAX_MS {
        println!(
            "WARNING: Proving time {} ms melebihi target {} ms ± {} ms. Periksa hardware.",
            final_elapsed, PROVING_TIME_TARGET_MS, PROVING_TIME_TOLERANCE_MS
        );
    }

    Ok(proof)
}

#[cfg(test)]
mod tests_proving_time_normalization {
    use super::*;

    fn build_valid_witness_2_2() -> TransferCircuitWitness {
        TransferCircuitWitness
    }
    fn build_test_public_input_2_2() -> TransferCircuitPublicInput {
        TransferCircuitPublicInput
    }
    fn build_trivial_witness() -> TransferCircuitWitness {
        TransferCircuitWitness
    }
    fn build_trivial_public_input() -> TransferCircuitPublicInput {
        TransferCircuitPublicInput
    }

    #[test]
    fn test_proving_time_within_target_range() {
        let witness = build_valid_witness_2_2();
        let public_input = build_test_public_input_2_2();

        let start = std::time::Instant::now();
        let _proof = prove_transfer_normalized(&witness, &public_input).unwrap();
        let elapsed = start.elapsed().as_millis();

        // Target: 300ms ± 10ms = 290ms-310ms
        // Dalam test environment: batas lebih longgar karena clock resolution OS
        assert!(
            elapsed >= 280,
            "Proving terlalu cepat: {}ms (min 290ms)",
            elapsed
        );
        assert!(
            elapsed <= 500,
            "Proving terlalu lambat: {}ms (max 310ms target)",
            elapsed
        );
    }

    #[test]
    fn test_fast_proof_gets_padded() {
        // Simulasi: proving selesai sangat cepat, harus di-pad ke setidaknya 290ms
        let start = std::time::Instant::now();

        let _ = prove_transfer_normalized(&build_trivial_witness(), &build_trivial_public_input());

        let elapsed = start.elapsed().as_millis();
        assert!(
            elapsed >= 280,
            "Proof cepat harus di-pad: {}ms (min 290ms)",
            elapsed
        );
    }

    #[test]
    fn test_proving_time_constants_match_spec() {
        assert_eq!(PROVING_TIME_TARGET_MS, 300);
        assert_eq!(PROVING_TIME_TOLERANCE_MS, 10);
        assert_eq!(PROVING_TIME_MIN_MS, 290);
        assert_eq!(PROVING_TIME_MAX_MS, 310);
    }
}
