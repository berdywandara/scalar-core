//! State Inspector — Read-only State Inspection — Spec §16.4 v11.1-FINAL
//!
//! API publik untuk inspeksi state tanpa akses ke kunci privat.
//!
//! Spec §16.4: "Hanya operasi read-only dan ZK verification."

use blake3::Hasher;
use scalar_emission::dmm::{
    compute_manifest_hash, EpochRewardManifest, SPEC_VERSION_MANIFEST,
};

// ── NullifierStatus — spec §16.4 ─────────────────────────────────────────────

/// Status nullifier berdasarkan inspeksi state. Spec §16.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NullifierStatus {
    /// Nullifier belum pernah digunakan — coin masih valid. Spec §16.4.
    Unspent,
    /// Nullifier sudah digunakan — coin sudah dibelanjakan. Spec §16.4.
    Spent { epoch_detected: u64 },
    /// Status tidak diketahui — data tidak mencukupi. Spec §16.4.
    Unknown,
}

// ── ManifestAuditResult — spec §16.4 ─────────────────────────────────────────

/// Hasil audit manifest. Spec §16.4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestAuditResult {
    /// Manifest valid — hash cocok dan spec_version benar. Spec §16.4.
    Valid {
        node_count: usize,
        total_emission_sscl: u64,
    },
    /// Manifest hash tidak cocok — data corrupt atau dimanipulasi. Spec §16.4.
    HashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// spec_version tidak valid. Spec §16.4.
    InvalidSpecVersion { version: u8, expected: u8 },
    /// Manifest kosong (tidak ada node). Spec §16.4.
    EmptyManifest,
}

impl ManifestAuditResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid { .. })
    }
}

// ── inspect_nullifier_state — spec §16.4 ─────────────────────────────────────

/// Inspeksi status nullifier dari snapshot state. Spec §16.4.
///
/// `nullifier`: 32-byte nullifier yang di-inspeksi.
/// `spent_nullifiers`: slice nullifier yang sudah digunakan (dari state snapshot).
///
/// Returns NullifierStatus — read-only, tidak mengubah state.
/// Tidak ada akses ke private key atau internal nullifier store. Spec §16.4.
pub fn inspect_nullifier_state(
    nullifier: &[u8; 32],
    spent_nullifiers: &[[u8; 32]],
) -> NullifierStatus {
    // Linear search — production menggunakan SMT lookup
    for (i, spent) in spent_nullifiers.iter().enumerate() {
        if spent == nullifier {
            return NullifierStatus::Spent {
                epoch_detected: i as u64, // simplified: index sebagai epoch proxy
            };
        }
    }
    NullifierStatus::Unspent
}

// ── verify_manifest_hash — spec §16.4 ────────────────────────────────────────

/// Verifikasi manifest_hash dari EpochRewardManifest. Spec §16.4.
///
/// Menghitung ulang hash dan membandingkan dengan manifest.manifest_hash.
/// Returns ManifestAuditResult — read-only. Spec §16.4.
pub fn verify_manifest_hash(manifest: &EpochRewardManifest) -> ManifestAuditResult {
    // Cek spec_version
    if manifest.spec_version != SPEC_VERSION_MANIFEST {
        return ManifestAuditResult::InvalidSpecVersion {
            version: manifest.spec_version,
            expected: SPEC_VERSION_MANIFEST,
        };
    }

    // Cek node list tidak kosong
    if manifest.node_list.is_empty() && manifest.total_emission_sscl > 0 {
        return ManifestAuditResult::EmptyManifest;
    }

    // Hitung ulang hash dan bandingkan
    let computed_hash = compute_manifest_hash(manifest);
    if computed_hash != manifest.manifest_hash {
        return ManifestAuditResult::HashMismatch {
            expected: manifest.manifest_hash,
            actual: computed_hash,
        };
    }

    ManifestAuditResult::Valid {
        node_count: manifest.node_list.len(),
        total_emission_sscl: manifest.total_emission_sscl,
    }
}

/// Hitung BLAKE3 hash dari data untuk audit. Spec §16.4.
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn audit_blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use scalar_emission::dmm::{
        compute_network_health_digest, compute_reward_root, compute_seed_k,
        EpochRewardManifest, NodeRewardEntry,
    };

    fn make_valid_manifest() -> EpochRewardManifest {
        let node_list = vec![NodeRewardEntry {
            node_id_full: [0x01u8; 32],
            reward_sscl: 1_000_000,
            uptime_weight_fp: 800_000,
        }];
        let reward_root = compute_reward_root(&node_list);
        let network_health_digest = compute_network_health_digest(1, 1, 800_000);
        let seed_k = compute_seed_k(&[0x42u8; 32]);

        let mut manifest = EpochRewardManifest {
            epoch_id: 1,
            node_list,
            spec_version: SPEC_VERSION_MANIFEST,
            total_emission_sscl: 1_000_000,
            deferred: false,
            seed_k,
            manifest_hash: [0u8; 32],
            reward_root,
            network_health_digest,
            tx_set_root: [0u8; 32],
        };
        // Compute dan set hash yang benar
        let hash = compute_manifest_hash(&manifest);
        manifest.manifest_hash = hash;
        manifest
    }

    // ── test_inspect_nullifier_state ─────────────────────────────────────────

    #[test]
    fn test_inspect_nullifier_state_unspent() {
        // Nullifier tidak ada dalam set → Unspent. Spec §16.4.
        let nullifier = [0x01u8; 32];
        let spent = [[0x02u8; 32], [0x03u8; 32]];
        let result = inspect_nullifier_state(&nullifier, &spent);
        assert_eq!(result, NullifierStatus::Unspent);
    }

    #[test]
    fn test_inspect_nullifier_state_spent() {
        // Nullifier ada dalam set → Spent. Spec §16.4.
        let nullifier = [0x02u8; 32];
        let spent = [[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];
        let result = inspect_nullifier_state(&nullifier, &spent);
        assert!(matches!(result, NullifierStatus::Spent { .. }));
    }

    #[test]
    fn test_inspect_nullifier_empty_set_unspent() {
        // Set kosong → selalu Unspent. Spec §16.4.
        let result = inspect_nullifier_state(&[0x01u8; 32], &[]);
        assert_eq!(result, NullifierStatus::Unspent);
    }

    // ── test_verify_manifest_hash_valid ──────────────────────────────────────

    #[test]
    fn test_verify_manifest_hash_valid() {
        // Manifest dengan hash benar → Valid. Spec §16.4.
        let manifest = make_valid_manifest();
        let result = verify_manifest_hash(&manifest);
        assert!(
            result.is_valid(),
            "Manifest valid harus pass verify: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_manifest_hash_tampered() {
        // Manifest dengan hash salah → HashMismatch. Spec §16.4.
        let mut manifest = make_valid_manifest();
        manifest.manifest_hash = [0xFFu8; 32]; // tamper
        let result = verify_manifest_hash(&manifest);
        assert!(
            matches!(result, ManifestAuditResult::HashMismatch { .. }),
            "Tampered manifest harus HashMismatch"
        );
    }

    #[test]
    fn test_verify_manifest_invalid_spec_version() {
        // spec_version != 0x06 → InvalidSpecVersion. Spec §16.4.
        let mut manifest = make_valid_manifest();
        manifest.spec_version = 0x02; // v9.0 version
        let result = verify_manifest_hash(&manifest);
        assert!(matches!(
            result,
            ManifestAuditResult::InvalidSpecVersion { .. }
        ));
    }

    // ── test_audit_no_private_key_access ─────────────────────────────────────

    #[test]
    fn test_audit_isolation() {
        // Fungsi audit tidak membutuhkan private key. Spec §16.4.
        // Test compile → tidak ada parameter private key.
        let nullifier = [0x01u8; 32];
        let _ = inspect_nullifier_state(&nullifier, &[]);
        let manifest = make_valid_manifest();
        let _ = verify_manifest_hash(&manifest);
    }

    #[test]
    fn test_audit_blake3_hash_deterministic() {
        // audit_blake3_hash deterministik. Spec §16.4.
        let data = b"scalar audit test data";
        let h1 = audit_blake3_hash(data);
        let h2 = audit_blake3_hash(data);
        assert_eq!(h1, h2);
    }
}
