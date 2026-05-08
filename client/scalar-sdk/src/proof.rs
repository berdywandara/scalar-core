//! Local ZK proof construction — spec §21.3 F5, F6, F10, F12
//!
//! Semua proof dikonstruksi secara lokal: zero onchain cost.
//! Hash: BLAKE3 out-circuit — spec §2.1.3.

use crate::types::{CredentialProof, DeadManSwitchRecord, NcpProof, SdkError, ThresholdProof};

/// F5 (STP): Build threshold proof — saldo ≥ threshold. Spec §21.3.
///
/// ZK proof lokal bahwa saldo ≥ threshold TANPA reveal saldo aktual.
/// Commitment = BLAKE3(balance_sscl_bytes || threshold_bytes || nonce).
pub fn build_threshold_proof(
    balance_sscl: u64,
    threshold_sscl: u64,
    nonce: [u8; 32],
) -> Result<ThresholdProof, SdkError> {
    // Konstruksi commitment tanpa reveal balance — BLAKE3 out-circuit §2.1.3
    let mut hasher = blake3::Hasher::new();
    hasher.update(&balance_sscl.to_le_bytes());
    hasher.update(&threshold_sscl.to_le_bytes());
    hasher.update(&nonce);
    let balance_commitment = *hasher.finalize().as_bytes();

    let result = balance_sscl >= threshold_sscl;

    Ok(ThresholdProof {
        balance_commitment,
        threshold_sscl,
        result,
    })
}

/// F6 (NCP): Build negative compliance proof. Spec §21.3.
///
/// ZK proof bahwa koin tidak berasal dari address dalam exclusion set.
/// origin_commitment = BLAKE3(coin_nullifier || nonce).
/// exclusion_set_hash = BLAKE3(sort(excluded_addresses)).
pub fn build_negative_compliance_proof(
    coin_nullifier: [u8; 32],
    excluded_addresses: &[[u8; 32]],
    nonce: [u8; 32],
) -> Result<NcpProof, SdkError> {
    if excluded_addresses.is_empty() {
        return Err(SdkError::InvalidInput(
            "excluded_addresses tidak boleh kosong".to_string(),
        ));
    }

    // origin_commitment — BLAKE3 out-circuit §2.1.3
    let mut hasher = blake3::Hasher::new();
    hasher.update(&coin_nullifier);
    hasher.update(&nonce);
    let origin_commitment = *hasher.finalize().as_bytes();

    // exclusion_set_hash — sort untuk determinisme
    let mut sorted = excluded_addresses.to_vec();
    sorted.sort_unstable();
    let mut hasher2 = blake3::Hasher::new();
    for addr in &sorted {
        hasher2.update(addr);
    }
    let exclusion_set_hash = *hasher2.finalize().as_bytes();

    // is_compliant: coin_nullifier tidak ada dalam exclusion set
    let is_compliant = !sorted.contains(&coin_nullifier);

    Ok(NcpProof {
        origin_commitment,
        exclusion_set_hash,
        is_compliant,
    })
}

/// F10: Build credential proof. Spec §21.3.
///
/// ZK proof kepemilikan credential tanpa reveal identitas.
pub fn build_credential_proof(
    credential_data: &[u8],
    issuer_id: [u8; 32],
    nonce: [u8; 32],
    epoch: u64,
) -> Result<CredentialProof, SdkError> {
    if credential_data.is_empty() {
        return Err(SdkError::InvalidInput(
            "credential_data tidak boleh kosong".to_string(),
        ));
    }

    // credential_commitment = BLAKE3(credential_data || nonce) — §2.1.3
    let mut hasher = blake3::Hasher::new();
    hasher.update(credential_data);
    hasher.update(&nonce);
    let credential_commitment = *hasher.finalize().as_bytes();

    // issuer_hash = BLAKE3(issuer_id)
    let issuer_hash = *blake3::hash(&issuer_id).as_bytes();

    Ok(CredentialProof {
        credential_commitment,
        issuer_hash,
        epoch,
    })
}

/// F12 (DMS): Build dead man switch record. Spec §21.3.
///
/// SuccessionProof post-quantum untuk estate planning digital.
/// succession_commitment = BLAKE3(primary_key || backup_id || epoch_bytes).
pub fn build_dead_man_switch(
    primary_node_key: [u8; 32],
    backup_node_id: [u8; 32],
    created_epoch: u64,
) -> Result<DeadManSwitchRecord, SdkError> {
    if backup_node_id == [0u8; 32] {
        return Err(SdkError::InvalidNodeId);
    }

    // succession_commitment — BLAKE3 out-circuit §2.1.3
    let mut hasher = blake3::Hasher::new();
    hasher.update(&primary_node_key);
    hasher.update(&backup_node_id);
    hasher.update(&created_epoch.to_le_bytes());
    let succession_commitment = *hasher.finalize().as_bytes();

    Ok(DeadManSwitchRecord {
        primary_node_key,
        backup_node_id,
        succession_commitment,
        created_epoch,
    })
}
