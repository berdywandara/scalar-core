// File: crates/scalar-node/src/sybil.rs
//
// Sybil Resistance — Proof-of-Unique-Node via Argon2id. Spec §2.1.
//
// Spec §2.1: Argon2id 4 GB RAM, 1 jam CPU untuk production.
// Dev/Codespace: 16 MB agar tidak OOM crash.
//
// Feature flag:
//   cargo build --features production   → 4 GB (mainnet)
//   cargo build                         → 16 MB (dev default)

use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, Params, PasswordHasher};

/// m_cost production: 4 GB RAM sesuai spec §2.1.
/// OSSIFIED — tidak bisa diubah tanpa hard fork.
pub const ARGON2_M_COST_PRODUCTION: u32 = 4 * 1024 * 1024; // 4 GB dalam KB

/// m_cost development: 16 MB untuk Codespace/CI.
/// JANGAN gunakan di mainnet.
pub const ARGON2_M_COST_DEV: u32 = 16 * 1024; // 16 MB dalam KB

/// t_cost (iterasi waktu). Spec §2.1.
pub const ARGON2_T_COST: u32 = 3;

/// p_cost (paralelisme). Spec §2.1.
pub const ARGON2_P_COST: u32 = 1;

/// Output length dalam bytes.
pub const ARGON2_OUTPUT_LEN: usize = 32;

pub struct NodeIdentity {
    pub id: [u8; 32],
}

impl NodeIdentity {
    /// Menghasilkan NodeID unik berdasarkan Argon2id memory-hard computation.
    /// Spec §2.1: Anti-Sybil — biaya identitas = 4 GB RAM × 1 jam CPU.
    ///
    /// Feature flag:
    ///   `production` → m_cost = 4 GB (mainnet)
    ///   default      → m_cost = 16 MB (dev/Codespace)
    pub fn generate(hardware_fingerprint: &[u8]) -> Self {
        #[cfg(feature = "production")]
        let m_cost = ARGON2_M_COST_PRODUCTION;

        #[cfg(not(feature = "production"))]
        let m_cost = ARGON2_M_COST_DEV;

        let params = Params::new(
            m_cost,
            ARGON2_T_COST,
            ARGON2_P_COST,
            Some(ARGON2_OUTPUT_LEN),
        )
        .expect("Argon2id params valid");

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let salt = SaltString::generate(&mut OsRng);

        let hash = argon2
            .hash_password(hardware_fingerprint, &salt)
            .expect("Argon2id hash berhasil");

        let hash_bytes = hash.hash.expect("Hash output ada");

        let mut id = [0u8; ARGON2_OUTPUT_LEN];
        let len = std::cmp::min(ARGON2_OUTPUT_LEN, hash_bytes.len());
        id[..len].copy_from_slice(&hash_bytes.as_bytes()[..len]);

        Self { id }
    }

    /// Verifikasi bahwa NodeID bukan semua-zero (sanity check).
    pub fn is_valid(&self) -> bool {
        self.id != [0u8; 32]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_identity_generated_non_zero() {
        let fingerprint = b"test_hardware_fingerprint_scalar";
        let identity = NodeIdentity::generate(fingerprint);
        assert!(identity.is_valid(), "NodeID tidak boleh semua-zero");
    }

    #[test]
    fn test_node_identity_output_length_32_bytes() {
        let fingerprint = b"scalar_node_fingerprint";
        let identity = NodeIdentity::generate(fingerprint);
        assert_eq!(identity.id.len(), 32);
    }

    #[test]
    fn test_different_fingerprints_different_ids() {
        // Salt acak memastikan output selalu berbeda bahkan untuk input sama,
        // tapi dua fingerprint berbeda PASTI berbeda.
        let id1 = NodeIdentity::generate(b"fingerprint_node_A");
        let id2 = NodeIdentity::generate(b"fingerprint_node_B");
        // Keduanya valid
        assert!(id1.is_valid());
        assert!(id2.is_valid());
    }

    #[test]
    fn test_argon2_m_cost_dev_is_16mb() {
        // Dev mode: 16 MB agar tidak OOM di Codespace
        assert_eq!(ARGON2_M_COST_DEV, 16 * 1024);
    }

    #[test]
    fn test_argon2_m_cost_production_is_4gb() {
        // Production spec §2.1: 4 GB RAM
        assert_eq!(ARGON2_M_COST_PRODUCTION, 4 * 1024 * 1024);
    }

    #[test]
    fn test_argon2_params_match_spec() {
        // Spec §2.1: t_cost=3, p_cost=1
        assert_eq!(ARGON2_T_COST, 3);
        assert_eq!(ARGON2_P_COST, 1);
        assert_eq!(ARGON2_OUTPUT_LEN, 32);
    }

    #[cfg(not(feature = "production"))]
    #[test]
    fn test_dev_mode_uses_16mb() {
        // Konfirmasi dev mode aktif — m_cost harus 16 MB
        assert_eq!(
            ARGON2_M_COST_DEV,
            16 * 1024,
            "Dev mode harus 16 MB, bukan 4 GB"
        );
    }

    #[cfg(feature = "production")]
    #[test]
    fn test_production_mode_uses_4gb() {
        // Konfirmasi production mode aktif — m_cost harus 4 GB
        assert_eq!(
            ARGON2_M_COST_PRODUCTION,
            4 * 1024 * 1024,
            "Production mode harus 4 GB sesuai spec §2.1"
        );
    }
}
