pub mod smt;
pub mod nullifier_set;
pub mod delta_sync;

#[derive(thiserror::Error, Debug)]
pub enum NullifierError {
    #[error("Nullifier already exists (Double Spend Detected)")]
    AlreadySpent,
    #[error("Invalid Merkle proof for the given root")]
    InvalidProof,
}
