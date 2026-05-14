#[cfg(test)]
mod empirical_2_canonical_fuzz {
    use crate::dmm::{
        compute_manifest_hash_v12, EpochRewardManifestV12, SPEC_VERSION_MANIFEST_V12,
    };

    fn build_manifest(seed: u64) -> EpochRewardManifestV12 {
        let epoch_id = seed ^ 0xDEADBEEF_CAFEBABE;
        let mut seed_k = [0u8; 32];
        let mut reward_root = [0u8; 32];
        let mut network_health_digest = [0u8; 32];
        let mut tx_set_root = [0u8; 32];
        for i in 0..8 {
            let b = ((seed >> (i * 8)) & 0xFF) as u8;
            seed_k[i] = b;
            seed_k[i + 8] = b.wrapping_add(0x11);
            seed_k[i + 16] = b.wrapping_mul(0x37);
            seed_k[i + 24] = b.wrapping_add(0xAA);
            reward_root[i] = b.wrapping_add(0x42);
            reward_root[i + 8] = b.wrapping_mul(0x13);
            reward_root[i + 16] = b.wrapping_add(0x99);
            reward_root[i + 24] = b ^ 0xF0;
            network_health_digest[i] = b.wrapping_add(0xCC);
            network_health_digest[i + 8] = b ^ 0x77;
            network_health_digest[i + 16] = b.wrapping_mul(0x55);
            network_health_digest[i + 24] = b.wrapping_add(0x33);
            tx_set_root[i] = b.wrapping_add(0x88);
            tx_set_root[i + 8] = b.wrapping_mul(0x7);
            tx_set_root[i + 16] = b ^ 0xAA;
            tx_set_root[i + 24] = b.wrapping_add(0x44);
        }
        let total_emission = (seed % 12_600_000_000_000).min(12_600_000_000_000);
        EpochRewardManifestV12 {
            epoch_id,
            spec_version: SPEC_VERSION_MANIFEST_V12,
            total_emission_sscl: total_emission,
            deferred: seed % 2 == 0,
            seed_k,
            manifest_hash: [0u8; 32],
            reward_root,
            network_health_digest,
            tx_set_root,
            node_list: vec![],
        }
    }

    /// EMPIRICAL-2: 1_000_000 variasi input → manifest_hash deterministik untuk data sama.
    #[test]
    fn empirical_2_canonical_serialization_1m_variations() {
        const N_ITERATIONS: u64 = 1_000_000;

        for seed in 0..N_ITERATIONS {
            let manifest = build_manifest(seed);

            // P1: Deterministik
            let h1 = compute_manifest_hash_v12(&manifest);
            let h2 = compute_manifest_hash_v12(&manifest);
            assert_eq!(h1, h2, "P1 FAILED seed={}: tidak deterministik", seed);

            // P2: manifest_hash field tidak mempengaruhi hash (non-circular)
            let mut m2 = manifest.clone();
            m2.manifest_hash = [0xFFu8; 32];
            let h3 = compute_manifest_hash_v12(&m2);
            assert_eq!(h1, h3, "P2 FAILED seed={}: manifest_hash circular", seed);

            // P3: tx_set_root mempengaruhi hash (Temuan 2)
            let mut m4 = manifest.clone();
            m4.tx_set_root = [0xBBu8; 32];
            let h4 = compute_manifest_hash_v12(&m4);
            if manifest.tx_set_root != [0xBBu8; 32] {
                assert_ne!(
                    h1, h4,
                    "P3 FAILED seed={}: tx_set_root tidak mempengaruhi hash",
                    seed
                );
            }

            // P4: Hash bukan zero
            assert_ne!(h1, [0u8; 32], "P4 FAILED seed={}: hash zero", seed);
        }

        println!(
            "EMPIRICAL-2 PASSED: {} variasi input → manifest_hash selalu deterministik. \
             P1-P4 semua verified. Spec v11.1-FINAL compliant.",
            N_ITERATIONS
        );
    }
}
