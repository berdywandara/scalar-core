//! NodeID Derivation — BLAKE3 — SCALAR-PROTOCOL §3.1, SCALAR-TECHNICAL §10.5
//!
//! node_id_full = BLAKE3(b"scalar_nodeid" || mnemonic || genesis_hash)
//!
//! Domain separator b"scalar_nodeid" (13 bytes) is OSSIFIED — SCALAR-PROTOCOL §2.3.
//! Identical derivation for all nodes. No tier distinction.
//! Derivation time: < 1 ms on any hardware.
//!
//! Argon2id is retained ONLY in keystore.rs for:
//!   Passphrase KDF : Argon2id(passphrase, salt, 64 MB, 3 iter) — keystore file protection
//!   Wallet seed KDF: Argon2id(mnemonic, DOMAIN_SEED_KDF||genesis, 64 MB, 3 iter) — §11.1

use scalar_crypto::domain::DOMAIN_NODEID;

// ── Constants — SCALAR-PROTOCOL §2.3, §3.1 ───────────────────────────────────

/// NodeID domain separator. OSSIFIED — SCALAR-PROTOCOL §2.3.
/// b"scalar_nodeid" — identical for all nodes, no per-tier variant.
pub use scalar_crypto::domain::DOMAIN_NODEID as NODE_ID_SALT_PREFIX;

/// Length of NODE_ID_SALT_PREFIX in bytes. Spec §2.3.
pub const NODE_ID_SALT_PREFIX_LEN: usize = 13; // b"scalar_nodeid"

/// NodeID output length in bytes. SCALAR-PROTOCOL §3.1.
pub const NODE_ID_OUTPUT_LEN: usize = 32;

// ── derive_node_id — SCALAR-PROTOCOL §3.1 ────────────────────────────────────

/// Derive NodeID from mnemonic and genesis_hash using BLAKE3.
///
/// SCALAR-PROTOCOL §3.1, SCALAR-TECHNICAL §10.5:
///   node_id_full = BLAKE3(b"scalar_nodeid" || mnemonic || genesis_hash)
///
/// Properties:
///   - Domain separator b"scalar_nodeid" is OSSIFIED — SCALAR-PROTOCOL §2.3
///   - Identical derivation for all nodes (no tier distinction)
///   - Deterministic: same inputs always produce the same output
///   - Derivation time: < 1 ms on any hardware
pub fn derive_node_id(mnemonic: &str, genesis_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_NODEID);
    hasher.update(mnemonic.as_bytes());
    hasher.update(genesis_hash);
    hasher.finalize().into()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_GENESIS_ZERO: [u8; 32] = [0x00u8; 32];
    const TEST_GENESIS_PATTERN: [u8; 32] = [0x42u8; 32];

    // 24-word mnemonic: "scalar" + 23 BIP-39 words — spec §3.1.
    const TEST_MNEMONIC_24: &str = "scalar abandon ability able about above absent \
        absorb abstract absurd abuse access accident account accuse achieve acid \
        acoustic acquire across act action actor actual";

    // ── test_domain_separator_ossified ───────────────────────────────────────

    #[test]
    fn test_domain_separator_ossified() {
        // b"scalar_nodeid" is OSSIFIED — SCALAR-PROTOCOL §2.3.
        assert_eq!(DOMAIN_NODEID, b"scalar_nodeid");
        assert_eq!(NODE_ID_SALT_PREFIX, b"scalar_nodeid");
        assert_eq!(NODE_ID_SALT_PREFIX_LEN, 13usize);
        assert_eq!(DOMAIN_NODEID.len(), NODE_ID_SALT_PREFIX_LEN);
    }

    // ── test_derive_node_id_not_zero ─────────────────────────────────────────

    #[test]
    fn test_derive_node_id_not_zero() {
        // Output must not be all-zero. SCALAR-PROTOCOL §3.1.
        let id = derive_node_id(TEST_MNEMONIC_24, &TEST_GENESIS_PATTERN);
        assert_ne!(id, [0u8; 32], "NodeID must not be zero");
    }

    // ── test_derive_node_id_output_length ────────────────────────────────────

    #[test]
    fn test_derive_node_id_output_length() {
        // Output must be exactly 32 bytes. SCALAR-PROTOCOL §3.1.
        let id = derive_node_id(TEST_MNEMONIC_24, &TEST_GENESIS_PATTERN);
        assert_eq!(id.len(), NODE_ID_OUTPUT_LEN);
        assert_eq!(NODE_ID_OUTPUT_LEN, 32);
    }

    // ── test_derive_node_id_deterministic ────────────────────────────────────

    #[test]
    fn test_derive_node_id_deterministic() {
        // Same inputs → identical output. SCALAR-PROTOCOL §3.1.
        let id1 = derive_node_id(TEST_MNEMONIC_24, &TEST_GENESIS_PATTERN);
        let id2 = derive_node_id(TEST_MNEMONIC_24, &TEST_GENESIS_PATTERN);
        assert_eq!(
            id1, id2,
            "NodeID must be deterministic for identical inputs"
        );
    }

    // ── test_derive_node_id_different_mnemonic ───────────────────────────────

    #[test]
    fn test_derive_node_id_different_mnemonic() {
        // Different mnemonic → different NodeID. SCALAR-PROTOCOL §3.1.
        let mnemonic_b = "scalar zoo zebra yellow xray wolf vote usual trust sure \
            sugar strong storm stick state space speak solve sleep skill \
            sister simple since silver";
        let id1 = derive_node_id(TEST_MNEMONIC_24, &TEST_GENESIS_PATTERN);
        let id2 = derive_node_id(mnemonic_b, &TEST_GENESIS_PATTERN);
        assert_ne!(id1, id2, "Different mnemonics must yield different NodeIDs");
    }

    // ── test_derive_node_id_different_genesis ────────────────────────────────

    #[test]
    fn test_derive_node_id_different_genesis() {
        // Different genesis_hash → different NodeID. SCALAR-PROTOCOL §3.1.
        let id1 = derive_node_id(TEST_MNEMONIC_24, &[0x01u8; 32]);
        let id2 = derive_node_id(TEST_MNEMONIC_24, &[0x02u8; 32]);
        assert_ne!(
            id1, id2,
            "Different genesis_hash must yield different NodeIDs"
        );
    }

    // ── test_derive_node_id_test_vector ──────────────────────────────────────

    #[test]
    fn test_derive_node_id_test_vector() {
        // TEST VECTOR 1 (spec change doc §8):
        //   mnemonic     = TEST_MNEMONIC_24
        //   genesis_hash = [0x00; 32]
        //   expected     = BLAKE3(b"scalar_nodeid" || mnemonic_utf8 || [0x00; 32])
        // Reference computed inline for cross-platform verification.
        let id = derive_node_id(TEST_MNEMONIC_24, &TEST_GENESIS_ZERO);
        let mut h = blake3::Hasher::new();
        h.update(b"scalar_nodeid");
        h.update(TEST_MNEMONIC_24.as_bytes());
        h.update(&TEST_GENESIS_ZERO);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(id, expected, "BLAKE3 NodeID test vector mismatch");
        assert_ne!(
            id, TEST_GENESIS_ZERO,
            "NodeID must differ from genesis bytes"
        );
    }
}
