//! Write-once records — spec §21.3 F8, F9
//!
//! Records ini dicommit ke NullifierSet via fee tx minimum 40 sSCL.
//! Hash: BLAKE3 out-circuit — spec §2.1.3.
//! FLOOR_MIN_ABSOLUTE = 40 sSCL — spec §9. OSSIFIED.

use crate::types::{IndelibleRecord, SdkError, TimestampRecord};

/// Fee minimum untuk write-once record dalam sSCL. Spec §9. OSSIFIED.
pub const RECORD_FEE_MIN_SSCL: u64 = 40;

/// F8 (QR Timestamp): Build timestamp record. Spec §21.3.
///
/// document_hash masuk sebagai output_commitment dalam tx.
/// commitment = BLAKE3(document_hash || epoch_bytes).
pub fn build_timestamp_record(
    document_hash: [u8; 32],
    epoch: u64,
) -> Result<TimestampRecord, SdkError> {
    if document_hash == [0u8; 32] {
        return Err(SdkError::InvalidInput(
            "document_hash tidak boleh zero".to_string(),
        ));
    }

    // BLAKE3 out-circuit — spec §2.1.3
    let mut hasher = blake3::Hasher::new();
    hasher.update(&document_hash);
    hasher.update(&epoch.to_le_bytes());
    let commitment = *hasher.finalize().as_bytes();

    Ok(TimestampRecord {
        document_hash,
        commitment,
        epoch,
    })
}

/// F9 (SIR): Build scalar indelible record. Spec §21.3.
///
/// data_hash di-commit ke NullifierSet.
/// NS_ARCH membuktikan validity selamanya — bahkan setelah 100 tahun.
/// nullifier_commitment = BLAKE3(data_hash || epoch_bytes).
pub fn build_indelible_record(
    data_hash: [u8; 32],
    epoch: u64,
) -> Result<IndelibleRecord, SdkError> {
    if data_hash == [0u8; 32] {
        return Err(SdkError::InvalidInput(
            "data_hash tidak boleh zero".to_string(),
        ));
    }

    // BLAKE3 out-circuit — spec §2.1.3
    let mut hasher = blake3::Hasher::new();
    hasher.update(&data_hash);
    hasher.update(&epoch.to_le_bytes());
    let nullifier_commitment = *hasher.finalize().as_bytes();

    Ok(IndelibleRecord {
        data_hash,
        nullifier_commitment,
        epoch,
    })
}
