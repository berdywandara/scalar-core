//! Fuzz: Canonical Serialization — Spec §8.2, §8.3, TV EMPIRICAL-2
//!
//! Properties tested:
//!   P1: compute_manifest_hash is deterministic
//!   P2: manifest_hash field is excluded from hash (non-circular)
//!   P3: tx_set_root affects hash (Temuan 2)
//!   P4: hash is never zero
#![no_main]
use libfuzzer_sys::fuzz_target;
use scalar_emission::dmm::{
    compute_manifest_hash, EpochRewardManifest, EpochStatus, SPEC_VERSION_MANIFEST,
};

fn build_manifest(data: &[u8]) -> EpochRewardManifest {
    let epoch_id = if data.len() >= 8 {
        u64::from_le_bytes(data[0..8].try_into().unwrap_or([0u8; 8]))
    } else {
        0
    };

    let seed_k: [u8; 32] = if data.len() >= 40 {
        data[8..40].try_into().unwrap_or([0u8; 32])
    } else {
        [0u8; 32]
    };

    let reward_root: [u8; 32] = if data.len() >= 72 {
        data[40..72].try_into().unwrap_or([0u8; 32])
    } else {
        [0u8; 32]
    };

    let total_emission = if data.len() >= 80 {
        u64::from_le_bytes(data[72..80].try_into().unwrap_or([0u8; 8]))
            .min(12_600_000_000_000)
    } else {
        0
    };

    EpochRewardManifest {
        epoch_id,
        spec_version: SPEC_VERSION_MANIFEST,
        total_emission_sscl: total_emission,
        deferred: (epoch_id % 2) == 0,
        seed_k,
        manifest_hash: [0u8; 32],
        reward_root,
        network_health_digest: [0u8; 32],
        tx_set_root: [0xAAu8; 32],
        node_list: vec![],
        status: EpochStatus::Open,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    let manifest = build_manifest(data);

    // P1: deterministic — same input same hash
    let h1 = compute_manifest_hash(&manifest);
    let h2 = compute_manifest_hash(&manifest);
    assert_eq!(h1, h2, "P1 FAILED: not deterministic");

    // P2: manifest_hash field excluded from hash (non-circular)
    let mut m2 = manifest.clone();
    m2.manifest_hash = [0xFFu8; 32];
    let h3 = compute_manifest_hash(&m2);
    assert_eq!(h1, h3, "P2 FAILED: manifest_hash field is circular");

    // P3: tx_set_root affects hash
    let mut m3 = manifest.clone();
    m3.tx_set_root = [0xBBu8; 32];
    if manifest.tx_set_root != [0xBBu8; 32] {
        let h4 = compute_manifest_hash(&m3);
        assert_ne!(h1, h4, "P3 FAILED: tx_set_root does not affect hash");
    }

    // P4: hash is never zero
    assert_ne!(h1, [0u8; 32], "P4 FAILED: hash is zero");
});
