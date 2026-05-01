use crate::air::TransferCircuitPublicInput;
use std::time::Instant;

pub const PROVING_TIME_TARGET_MS: u64 = 300;
pub const PROVING_TIME_TOLERANCE_MS: u64 = 10;
pub const PROVING_TIME_MIN_MS: u64 = PROVING_TIME_TARGET_MS - PROVING_TIME_TOLERANCE_MS; // 290ms
pub const PROVING_TIME_MAX_MS: u64 = PROVING_TIME_TARGET_MS + PROVING_TIME_TOLERANCE_MS; // 310ms

/// Normalized prover: selalu menghasilkan proof dalam 300ms ± 10ms
pub fn prove_transfer_normalized(
    _witness: &(),
    _public_input: &TransferCircuitPublicInput,
) -> Result<Vec<u8>, &'static str> {
    let start = Instant::now();

    // Lakukan proving normal (mocked)
    let proof = vec![1, 2, 3];

    let elapsed_ms = start.elapsed().as_millis() as u64;

    // Normalisasi waktu (Anti timing side-channel)
    if elapsed_ms < PROVING_TIME_MIN_MS {
        let padding_ms = PROVING_TIME_MIN_MS - elapsed_ms;
        std::thread::sleep(std::time::Duration::from_millis(padding_ms));
    }

    Ok(proof)
}
