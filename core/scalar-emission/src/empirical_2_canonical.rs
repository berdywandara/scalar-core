#[cfg(test)]
mod empirical_2_canonical_fuzz {
    use crate::manifest::{
        compute_manifest_canonical_bytes, compute_manifest_hash, EpochRewardManifest, EpochStatus,
        SPEC_VERSION_MANIFEST,
    };

    fn build_manifest(seed: u64) -> EpochRewardManifest {
        // Derive varied fields dari seed — simulasi fuzz input
        let epoch_id = seed ^ 0xDEADBEEF_CAFEBABE;
        let mut seed_k = [0u8; 32];
        let mut liveness_root = [0u8; 32];
        for i in 0..8 {
            let b = ((seed >> (i * 8)) & 0xFF) as u8;
            seed_k[i] = b;
            seed_k[i + 8] = b.wrapping_add(0x11);
            seed_k[i + 16] = b.wrapping_mul(0x37);
            seed_k[i + 24] = b.wrapping_add(0xAA);
            liveness_root[i] = b.wrapping_add(0x42);
            liveness_root[i + 8] = b.wrapping_mul(0x13);
            liveness_root[i + 16] = b.wrapping_add(0x99);
            liveness_root[i + 24] = b ^ 0xF0;
        }
        let emission = (seed % 12_600_000_000_000).min(12_600_000_000_000);
        EpochRewardManifest {
            epoch_id,
            spec_version: SPEC_VERSION_MANIFEST,
            accepted_liveness_root: liveness_root,
            sync_health_summary: seed_k,
            seed_k,
            manifest_hash: [0u8; 32],
            total_uptime_weight: (seed % 25_920_000_000).min(25_920_000_000),
            emission_amount: emission,
            equity_gini: seed % 1_000_000,
            fee_total: seed % 1_000_000_000,
            slashed_nodes: vec![],
            reward_root: liveness_root,
            previous_emission_total: seed % 1_890_000_000_000_000,
            status: EpochStatus::Finalized,
        }
    }

    /// EMPIRICAL-2: 1_000_000 variasi input → canonical_bytes identik untuk data sama.
    /// Spec §22.5, §8.2. Memverifikasi S1-S4 canonical serialization rules.
    #[test]
    fn empirical_2_canonical_serialization_1m_variations() {
        const N_ITERATIONS: u64 = 1_000_000;
        let violations = 0u64;

        for seed in 0..N_ITERATIONS {
            let manifest = build_manifest(seed);

            // P1: Deterministik
            let b1 = compute_manifest_canonical_bytes(&manifest);
            let b2 = compute_manifest_canonical_bytes(&manifest);
            assert_eq!(b1, b2, "P1 FAILED seed={}: tidak deterministik", seed);

            // P2: Fixed length 177 bytes (S4)
            assert_eq!(
                b1.len(),
                177,
                "P2 FAILED seed={}: panjang {} bukan 177",
                seed,
                b1.len()
            );

            // P3: manifest_hash = BLAKE3(canonical_bytes)
            let hash = compute_manifest_hash(&manifest);
            let expected = *blake3::hash(&b1).as_bytes();
            assert_eq!(hash, expected, "P3 FAILED seed={}: hash mismatch", seed);

            // P4: slashed_nodes tidak masuk canonical
            let mut m_slashed = manifest.clone();
            m_slashed.slashed_nodes = vec![[0xFFu8; 32]];
            let b_slashed = compute_manifest_canonical_bytes(&m_slashed);
            assert_eq!(
                b1, b_slashed,
                "P4 FAILED seed={}: slashed_nodes masuk canonical",
                seed
            );

            // P5: status tidak masuk canonical
            let mut m_open = manifest.clone();
            m_open.status = EpochStatus::Open;
            let b_open = compute_manifest_canonical_bytes(&m_open);
            assert_eq!(
                b1, b_open,
                "P5 FAILED seed={}: status masuk canonical",
                seed
            );

            // P6: manifest_hash field tidak masuk canonical
            let mut m_hash = manifest.clone();
            m_hash.manifest_hash = [0xBBu8; 32];
            let b_hash = compute_manifest_canonical_bytes(&m_hash);
            assert_eq!(
                b1, b_hash,
                "P6 FAILED seed={}: manifest_hash field masuk canonical",
                seed
            );

            // P7: epoch_id little-endian di bytes[0..8] (S3)
            let epoch_le = manifest.epoch_id.to_le_bytes();
            assert_eq!(
                &b1[0..8],
                &epoch_le,
                "P7 FAILED seed={}: epoch_id bukan little-endian",
                seed
            );

            if violations > 0 {
                break;
            }
        }

        assert_eq!(
            violations, 0,
            "EMPIRICAL-2 FAILED: {} violations dari {} iterasi",
            violations, N_ITERATIONS
        );

        println!(
            "EMPIRICAL-2 PASSED: {} variasi input → canonical_bytes selalu identik. \
             P1-P7 semua verified. Spec §22.5 §8.2 compliant.",
            N_ITERATIONS
        );
    }
}
