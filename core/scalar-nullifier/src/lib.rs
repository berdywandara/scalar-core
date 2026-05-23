//! scalar-nullifier — NullifierSet 2-Layer
//!
//! Spec §6.1–6.3: implementasi genesis NullifierSet.
//!
//! Layer 1 – NS_ACTIVE: SMT depth-32, 3 epoch terakhir (smt.rs, nullifier_set.rs)
//! Layer 2 – NS_CHECKPOINT: Recursive STARK proof (nullifier_set.rs)
//!
//! Modul publik:
//! - nullifier_set  — NullifierSet, CheckpointProof, WalEntry (§6.1–6.3)
//! - smt            — SparseMerkleTree depth-32 (§6.1)
//! - formal         — Runtime assertions invariant CC (§15.4)

pub mod formal;
pub mod nullifier_set;
pub mod smt;
pub mod smt_quaternary;

// Re-export tipe utama untuk kemudahan akses
pub use nullifier_set::{
    CheckpointError, CheckpointProof, NullifierSet, WalEntry, WalStatus,
    CHECKPOINT_INTERVAL_EPOCHS, CHECKPOINT_TIMEOUT_S, NS_ACTIVE_WINDOW_EPOCHS,
};
pub use smt::{SparseMerkleTree, MAX_NULLIFIERS_PER_CHECKPOINT, SMT_DEPTH};
