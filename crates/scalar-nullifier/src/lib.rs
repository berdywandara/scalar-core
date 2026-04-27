//! Core Nullifier & SMT Management for Scalar Network

pub mod delta_sync;
pub mod nullifier_set;
pub mod smt;

#[derive(Debug, PartialEq)]
pub enum NullifierError {
    AlreadyExists,
    InvalidProof,
    NotFound,
}

pub use delta_sync::DeltaSyncMessage;
pub use nullifier_set::NullifierSet;
pub use smt::{NodeHash, ScalarSMT};
