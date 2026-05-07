//! EMPIRICAL-2: Fuzzer Canonical Serialization
//! Spec §22.5, §8.2 — Pre-Mainnet Mandatory
//!
//! Kriteria: 10^9 variasi input → canonical_bytes selalu identik untuk data yang sama.
//! Property yang diuji:
//!   P1: canonical_bytes deterministik
//!   P2: panjang selalu 177 bytes (S4 — no optional fields)
//!   P3: manifest_hash = BLAKE3(canonical_bytes)
//!   P4: slashed_nodes tidak masuk canonical
//!   P5: status tidak masuk canonical
//!   P6: manifest_hash field tidak masuk canonical (no circular hash)
//!   P7: epoch_id little-endian di bytes[0..8] (S3)

#![no_main]

use libfuzzer_sys::fuzz_target;
use scalar_emission::manifest::{
    compute_manifest_canonical_bytes, compute_manifest_hash,
    EpochRewardManifest, EpochStatus, SPEC_VERSION_MANIFEST,
};

fn build_manifest(data: &[u8]) -> EpochRewardManifest {
    let epoch_id = if data.len() >= 8 {
        u64::from_le_bytes(data[0..8].try_into().unwrap_or([0u8; 8]))
    } else { 0 };

    let seed_k: [u8; 32] = if data.len() >= 40 {
        data[8..40].try_into().unwrap_or([0u8; 32])
    } else { [0u8; 32] };

    let accepted_liveness_root: [u8; 32] = if data.len() >= 72 {
        data[40..72].try_into().unwrap_or([0u8; 32])
    } else { [0u8; 32] };

    let emission = if data.len() >= 80 {
        u64::from_le_bytes(data[72..80].try_into().unwrap_or([0u8; 8]))
    } else { 0 };

    EpochRewardManifest {
        epoch_id,
        spec_version: SPEC_VERSION_MANIFEST,
        accepted_liveness_root,
        sync_health_summary: [0u8; 32],
        seed_k,
        manifest_hash: [0u8; 32],
        total_uptime_weight: emission.min(25_920_000_000),
        emission_amount: emission.min(12_600_000_000_000),
        equity_gini: 0,
        fee_total: 0,
        slashed_nodes: vec![],
        reward_root: [0u8; 32],
        previous_emission_total: 0,
        status: EpochStatus::Finalized,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 { return; }

    let manifest = build_manifest(data);

    // P1: Deterministik
    let bytes1 = compute_manifest_canonical_bytes(&manifest);
    let bytes2 = compute_manifest_canonical_bytes(&manifest);
    assert_eq!(bytes1, bytes2, "P1 FAILED: tidak deterministik");

    // P2: Fixed length 177 bytes
    assert_eq!(bytes1.len(), 177, "P2 FAILED: panjang {} bukan 177", bytes1.len());

    // P3: Hash consistency
    let hash = compute_manifest_hash(&manifest);
    let expected = *blake3::hash(&bytes1).as_bytes();
    assert_eq!(hash, expected, "P3 FAILED: manifest_hash != BLAKE3(canonical_bytes)");

    // P4: slashed_nodes tidak masuk canonical
    let mut m2 = manifest.clone();
    m2.slashed_nodes = vec![[0xFFu8; 32], [0xAAu8; 32]];
    let bytes_slashed = compute_manifest_canonical_bytes(&m2);
    assert_eq!(bytes1, bytes_slashed, "P4 FAILED: slashed_nodes masuk canonical");

    // P5: status tidak masuk canonical
    let mut m3 = manifest.clone();
    m3.status = EpochStatus::Open;
    let bytes_open = compute_manifest_canonical_bytes(&m3);
    assert_eq!(bytes1, bytes_open, "P5 FAILED: status masuk canonical");

    // P6: manifest_hash field tidak masuk canonical
    let mut m4 = manifest.clone();
    m4.manifest_hash = [0xBBu8; 32];
    let bytes_hash = compute_manifest_canonical_bytes(&m4);
    assert_eq!(bytes1, bytes_hash, "P6 FAILED: manifest_hash field masuk canonical");

    // P7: epoch_id little-endian di bytes[0..8]
    let epoch_le = manifest.epoch_id.to_le_bytes();
    assert_eq!(&bytes1[0..8], &epoch_le, "P7 FAILED: epoch_id bukan little-endian");
});
