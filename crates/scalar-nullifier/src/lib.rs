//! Core Nullifier & SMT Management for Scalar Network

pub mod smt;
pub mod delta_sync;
pub mod nullifier_set;

#[derive(Debug, PartialEq)]
pub enum NullifierError {
    AlreadyExists,
    InvalidProof,
    NotFound,
}

pub use smt::{ScalarSMT, NodeHash};
pub use nullifier_set::NullifierSet;
pub use delta_sync::DeltaSyncMessage;
