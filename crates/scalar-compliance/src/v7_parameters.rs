
// ── SCL-SPEC-SEED-001 §8.1 — Argon2id Seed KDF OSSIFIED Constants ────────────

/// Memory Argon2id seed derivation dalam KiB (64 MB). OSSIFIED — SCL-SPEC-SEED-001 §8.1.
pub const ARGON2ID_SEED_MEMORY_KIB: u32 = 65536;

/// Iterasi Argon2id seed derivation. OSSIFIED — SCL-SPEC-SEED-001 §8.1.
pub const ARGON2ID_SEED_ITER: u32 = 3;

/// Parallelism Argon2id seed derivation. OSSIFIED — SCL-SPEC-SEED-001 §8.1.
pub const ARGON2ID_SEED_PARALLEL: u32 = 1;

/// Output length Argon2id seed derivation dalam bytes. OSSIFIED — SCL-SPEC-SEED-001 §8.1.
pub const ARGON2ID_SEED_OUTPUT_LEN: usize = 64;

/// Salt prefix versi v2. OSSIFIED — SCL-SPEC-SEED-001 §8.1.
pub const COMPLIANCE_SEED_SALT_PREFIX_V2: &[u8] = b"scalar_v2";

/// Versi seed derivation. OSSIFIED — SCL-SPEC-SEED-001 §8.1.
pub const COMPLIANCE_SEED_VERSION: u8 = 0x02;

/// Salt total length: 9 prefix + 32 genesis_hash. OSSIFIED — SCL-SPEC-SEED-001 §3.3.
pub const ARGON2ID_SEED_SALT_TOTAL_LEN: usize = 41;

#[cfg(test)]
mod seed_compliance_tests {
    use super::*;

    #[test]
    fn test_compliance_argon2id_seed_memory_kib() {
        // SCL-SPEC-SEED-001 §8.1: memory = 65536 KiB. OSSIFIED.
        assert_eq!(ARGON2ID_SEED_MEMORY_KIB, 65536u32);
    }

    #[test]
    fn test_compliance_argon2id_seed_iter() {
        // SCL-SPEC-SEED-001 §8.1: iterations = 3. OSSIFIED.
        assert_eq!(ARGON2ID_SEED_ITER, 3u32);
    }

    #[test]
    fn test_compliance_argon2id_seed_parallel() {
        // SCL-SPEC-SEED-001 §8.1: parallelism = 1. OSSIFIED.
        assert_eq!(ARGON2ID_SEED_PARALLEL, 1u32);
    }

    #[test]
    fn test_compliance_argon2id_seed_output_len() {
        // SCL-SPEC-SEED-001 §8.1: output = 64 bytes. OSSIFIED.
        assert_eq!(ARGON2ID_SEED_OUTPUT_LEN, 64usize);
    }

    #[test]
    fn test_compliance_seed_salt_prefix_v2() {
        // SCL-SPEC-SEED-001 §8.1: prefix = b"scalar_v2". OSSIFIED.
        assert_eq!(COMPLIANCE_SEED_SALT_PREFIX_V2, b"scalar_v2");
        assert_eq!(COMPLIANCE_SEED_SALT_PREFIX_V2.len(), 9);
    }

    #[test]
    fn test_compliance_seed_version() {
        // SCL-SPEC-SEED-001 §8.1: SEED_VERSION = 0x02. OSSIFIED.
        assert_eq!(COMPLIANCE_SEED_VERSION, 0x02u8);
    }

    #[test]
    fn test_compliance_seed_salt_total_len() {
        // SCL-SPEC-SEED-001 §3.3: salt = 9 + 32 = 41 bytes.
        assert_eq!(ARGON2ID_SEED_SALT_TOTAL_LEN, 41usize);
        assert_eq!(COMPLIANCE_SEED_SALT_PREFIX_V2.len() + 32, ARGON2ID_SEED_SALT_TOTAL_LEN);
    }

    #[test]
    fn test_compliance_memory_at_minimum() {
        // SCL-SPEC-SEED-001 §8.2: minimum absolut tidak boleh diturunkan.
        assert!(ARGON2ID_SEED_MEMORY_KIB >= 65536u32);
    }

    #[test]
    fn test_compliance_iter_at_minimum() {
        // SCL-SPEC-SEED-001 §8.2: minimum absolut tidak boleh diturunkan.
        assert!(ARGON2ID_SEED_ITER >= 3u32);
    }
}
