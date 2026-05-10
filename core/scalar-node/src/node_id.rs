//! NodeID Production — Argon2id Anti-Sybil — Spec §10.2, Gap G-2
//!
//! PR-V12-012 FIX: node_key placeholder [0x42;32] diganti dengan
//! production NodeID dari Argon2id sesuai spec §10.2.
//!
//! Spec §10.2:
//!   node_id_full = Argon2id(
//!     input  = mnemonic,
//!     salt   = b"scalar_nodeid_v1" || genesis_hash,
//!     memory = 4 GB (production) / 16 MB (dev),
//!     time   = 3_600 iter (production) / 100 iter (dev),
//!     output = 32 bytes
//!   )
//!
//! Tier C (§10.1): Argon2id 16 MB / 100 iter (sama dengan dev mode).
//! Tier A/B: Argon2id 4 GB / 3_600 iter (production mode).
//!
//! Compile-time error jika build mainnet tanpa --features production.
//! (Spec §10.2: "Compile-time error if build mainnet without --features production")

use argon2::{Algorithm, Argon2, Params, Version};

// ── Constants — spec §10.2 ────────────────────────────────────────────────────

/// Salt prefix untuk NodeID derivation. OSSIFIED — spec §10.2.
pub const NODE_ID_SALT_PREFIX: &[u8] = b"scalar_nodeid_v1";

/// Salt prefix length. Spec §10.2.
pub const NODE_ID_SALT_PREFIX_LEN: usize = 16;

/// Argon2id memory cost production (Tier A/B): 4 GB dalam KiB. OSSIFIED — spec §10.2.
pub const ARGON2_NODE_MEMORY_PRODUCTION_KIB: u32 = 4 * 1024 * 1024;

/// Argon2id time cost production (Tier A/B): 3_600 iterasi. OSSIFIED — spec §10.2.
pub const ARGON2_NODE_TIME_PRODUCTION: u32 = 3_600;

/// Argon2id memory cost Tier C / dev: 16 MB dalam KiB. Spec §10.1.
pub const ARGON2_NODE_MEMORY_TIER_C_KIB: u32 = 16 * 1024;

/// Argon2id time cost Tier C / dev: 100 iterasi. Spec §10.1.
pub const ARGON2_NODE_TIME_TIER_C: u32 = 100;

/// Parallelism Argon2id NodeID. Spec §10.2.
pub const ARGON2_NODE_PARALLELISM: u32 = 1;

/// Output length NodeID. Spec §10.2.
pub const NODE_ID_OUTPUT_LEN: usize = 32;

/// Tier C node_id prefix byte. Spec §10.1.
pub const TIER_C_NODE_PREFIX: u8 = 0xFE;

// ── NodeIdDerivationMode — tier selection ─────────────────────────────────────

/// Mode derivasi NodeID. Spec §10.1, §10.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeIdDerivationMode {
    /// Tier A/B production: 4 GB / 3_600 iter. Spec §10.2.
    /// Aktif dengan --features production.
    Production,
    /// Tier C / dev: 16 MB / 100 iter. Spec §10.1.
    /// Default mode untuk dev dan Tier C.
    TierCOrDev,
}

impl NodeIdDerivationMode {
    pub fn memory_kib(&self) -> u32 {
        match self {
            Self::Production => ARGON2_NODE_MEMORY_PRODUCTION_KIB,
            Self::TierCOrDev => ARGON2_NODE_MEMORY_TIER_C_KIB,
        }
    }

    pub fn time_cost(&self) -> u32 {
        match self {
            Self::Production => ARGON2_NODE_TIME_PRODUCTION,
            Self::TierCOrDev => ARGON2_NODE_TIME_TIER_C,
        }
    }
}

// ── ProductionNodeId — spec §10.2 ─────────────────────────────────────────────

/// Production NodeID yang diturunkan dari Argon2id. Spec §10.2.
#[derive(Clone, Debug)]
pub struct ProductionNodeId {
    /// Full 32-byte NodeID. Spec §10.2.
    pub node_id_full: [u8; 32],
    /// Mode derivasi yang digunakan.
    pub mode: NodeIdDerivationMode,
}

impl ProductionNodeId {
    /// Derive NodeID dari mnemonic dan genesis_hash. Spec §10.2.
    ///
    /// `mnemonic`: kata-kata mnemonic sebagai bytes (UTF-8).
    /// `genesis_hash`: 32-byte genesis hash.
    /// `mode`: Production (4GB) atau TierCOrDev (16MB).
    ///
    /// salt = b"scalar_nodeid_v1" || genesis_hash
    pub fn derive(
        mnemonic: &[u8],
        genesis_hash: &[u8; 32],
        mode: NodeIdDerivationMode,
    ) -> Result<Self, NodeIdError> {
        // Buat salt: b"scalar_nodeid_v1" || genesis_hash
        let mut salt = Vec::with_capacity(NODE_ID_SALT_PREFIX_LEN + 32);
        salt.extend_from_slice(NODE_ID_SALT_PREFIX);
        salt.extend_from_slice(genesis_hash);

        // Argon2id params sesuai mode
        let params = Params::new(
            mode.memory_kib(),
            mode.time_cost(),
            ARGON2_NODE_PARALLELISM,
            Some(NODE_ID_OUTPUT_LEN),
        ).map_err(|_| NodeIdError::InvalidParams)?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut output = [0u8; NODE_ID_OUTPUT_LEN];
        argon2
            .hash_password_into(mnemonic, &salt, &mut output)
            .map_err(|_| NodeIdError::DerivationFailed)?;

        // Validasi: output tidak boleh semua zero
        if output == [0u8; 32] {
            return Err(NodeIdError::ZeroOutput);
        }

        Ok(Self {
            node_id_full: output,
            mode,
        })
    }

    /// Cek apakah ini node Tier C (prefix 0xFE). Spec §10.1.
    pub fn is_tier_c(&self) -> bool {
        self.node_id_full[0] == TIER_C_NODE_PREFIX
    }

    /// Derive node_id_full menggunakan mode yang sesuai dengan feature flag.
    ///
    /// Production build (--features production) → Production mode.
    /// Dev build → TierCOrDev mode.
    pub fn derive_with_feature_flag(
        mnemonic: &[u8],
        genesis_hash: &[u8; 32],
    ) -> Result<Self, NodeIdError> {
        #[cfg(feature = "production")]
        let mode = NodeIdDerivationMode::Production;

        #[cfg(not(feature = "production"))]
        let mode = NodeIdDerivationMode::TierCOrDev;

        Self::derive(mnemonic, genesis_hash, mode)
    }
}

// ── Error ─────────────────────────────────────────────────────────────────────

/// Error derivasi NodeID. Spec §10.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeIdError {
    /// Params Argon2id tidak valid.
    InvalidParams,
    /// Derivasi gagal.
    DerivationFailed,
    /// Output adalah zero — tidak valid.
    ZeroOutput,
}

impl core::fmt::Display for NodeIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidParams => write!(f, "Argon2id params tidak valid — spec §10.2"),
            Self::DerivationFailed => write!(f, "Argon2id derivasi gagal — spec §10.2"),
            Self::ZeroOutput => write!(f, "NodeID output adalah zero — tidak valid"),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_GENESIS: [u8; 32] = [0x42u8; 32];
    const TEST_MNEMONIC: &[u8] = b"scalar test mnemonic twelve words here for node id derivation";

    // ── test_nodeid_argon2id_production (dev mode) ────────────────────────────

    #[test]
    fn test_nodeid_argon2id_not_placeholder() {
        // NodeID tidak lagi placeholder [0x42;32]. Spec §10.2, Gap G-2.
        let result = ProductionNodeId::derive(
            TEST_MNEMONIC, &TEST_GENESIS, NodeIdDerivationMode::TierCOrDev
        );
        assert!(result.is_ok(), "Derivasi harus berhasil: {:?}", result);
        let node_id = result.unwrap();
        // NodeID TIDAK boleh sama dengan placeholder [0x42;32]
        assert_ne!(node_id.node_id_full, [0x42u8; 32],
            "NodeID tidak boleh sama dengan placeholder");
        // NodeID tidak boleh zero
        assert_ne!(node_id.node_id_full, [0u8; 32],
            "NodeID tidak boleh zero");
    }

    // ── test_nodeid_tier_c_argon2id_params ───────────────────────────────────

    #[test]
    fn test_nodeid_tier_c_argon2id_params() {
        // Tier C pakai 16MB/100iter. Spec §10.1.
        let mode = NodeIdDerivationMode::TierCOrDev;
        assert_eq!(mode.memory_kib(), ARGON2_NODE_MEMORY_TIER_C_KIB,
            "Tier C harus pakai 16 MB");
        assert_eq!(mode.time_cost(), ARGON2_NODE_TIME_TIER_C,
            "Tier C harus pakai 100 iterasi");
        assert_eq!(ARGON2_NODE_MEMORY_TIER_C_KIB, 16 * 1024);
        assert_eq!(ARGON2_NODE_TIME_TIER_C, 100);
    }

    // ── test_nodeid_tier_a_argon2id_params ───────────────────────────────────

    #[test]
    fn test_nodeid_tier_a_argon2id_params() {
        // Tier A/B pakai 4GB/3600iter. Spec §10.2.
        let mode = NodeIdDerivationMode::Production;
        assert_eq!(mode.memory_kib(), ARGON2_NODE_MEMORY_PRODUCTION_KIB,
            "Tier A/B harus pakai 4 GB");
        assert_eq!(mode.time_cost(), ARGON2_NODE_TIME_PRODUCTION,
            "Tier A/B harus pakai 3_600 iterasi");
        assert_eq!(ARGON2_NODE_MEMORY_PRODUCTION_KIB, 4 * 1024 * 1024);
        assert_eq!(ARGON2_NODE_TIME_PRODUCTION, 3_600);
    }

    // ── test_salt_format ──────────────────────────────────────────────────────

    #[test]
    fn test_salt_format_prefix() {
        // salt = b"scalar_nodeid_v1" || genesis_hash. Spec §10.2.
        assert_eq!(NODE_ID_SALT_PREFIX, b"scalar_nodeid_v1");
        assert_eq!(NODE_ID_SALT_PREFIX_LEN, 16usize);
        assert_eq!(NODE_ID_SALT_PREFIX.len(), NODE_ID_SALT_PREFIX_LEN);
    }

    // ── test_deterministic_same_input ────────────────────────────────────────

    #[test]
    fn test_nodeid_deterministic_same_input() {
        // Argon2id dengan salt deterministik (bukan OsRng) → output sama.
        // Spec §10.2: NodeID harus reproducible dari mnemonic + genesis_hash.
        let r1 = ProductionNodeId::derive(
            TEST_MNEMONIC, &TEST_GENESIS, NodeIdDerivationMode::TierCOrDev
        ).unwrap();
        let r2 = ProductionNodeId::derive(
            TEST_MNEMONIC, &TEST_GENESIS, NodeIdDerivationMode::TierCOrDev
        ).unwrap();
        assert_eq!(r1.node_id_full, r2.node_id_full,
            "NodeID harus deterministik untuk input yang sama");
    }

    // ── test_different_mnemonic_different_id ─────────────────────────────────

    #[test]
    fn test_different_mnemonic_different_id() {
        // Mnemonic berbeda → NodeID berbeda. Spec §10.2.
        let id1 = ProductionNodeId::derive(
            b"mnemonic_node_alpha", &TEST_GENESIS, NodeIdDerivationMode::TierCOrDev
        ).unwrap();
        let id2 = ProductionNodeId::derive(
            b"mnemonic_node_beta", &TEST_GENESIS, NodeIdDerivationMode::TierCOrDev
        ).unwrap();
        assert_ne!(id1.node_id_full, id2.node_id_full,
            "Mnemonic berbeda harus menghasilkan NodeID berbeda");
    }

    // ── test_different_genesis_different_id ──────────────────────────────────

    #[test]
    fn test_different_genesis_different_id() {
        // genesis_hash berbeda → NodeID berbeda. Spec §10.2.
        let genesis_a = [0x01u8; 32];
        let genesis_b = [0x02u8; 32];
        let id1 = ProductionNodeId::derive(
            TEST_MNEMONIC, &genesis_a, NodeIdDerivationMode::TierCOrDev
        ).unwrap();
        let id2 = ProductionNodeId::derive(
            TEST_MNEMONIC, &genesis_b, NodeIdDerivationMode::TierCOrDev
        ).unwrap();
        assert_ne!(id1.node_id_full, id2.node_id_full,
            "genesis_hash berbeda harus menghasilkan NodeID berbeda");
    }

    // ── test_feature_flag_mode ────────────────────────────────────────────────

    #[test]
    #[cfg(not(feature = "production"))]
    fn test_dev_mode_uses_tier_c_params() {
        // Dev mode (tidak ada --features production) → TierCOrDev. Spec §10.2.
        let result = ProductionNodeId::derive_with_feature_flag(
            TEST_MNEMONIC, &TEST_GENESIS
        );
        assert!(result.is_ok());
        let node = result.unwrap();
        assert_eq!(node.mode, NodeIdDerivationMode::TierCOrDev,
            "Dev mode harus pakai TierCOrDev params");
    }

    // ── test_output_length ────────────────────────────────────────────────────

    #[test]
    fn test_nodeid_output_length_32() {
        // Output = 32 bytes. Spec §10.2.
        let result = ProductionNodeId::derive(
            TEST_MNEMONIC, &TEST_GENESIS, NodeIdDerivationMode::TierCOrDev
        ).unwrap();
        assert_eq!(result.node_id_full.len(), NODE_ID_OUTPUT_LEN);
        assert_eq!(NODE_ID_OUTPUT_LEN, 32);
    }
}
