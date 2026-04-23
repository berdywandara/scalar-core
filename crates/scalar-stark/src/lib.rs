pub mod air;
pub mod prover;
pub mod verifier;
pub mod constraints;

#[derive(thiserror::Error, Debug)]
pub enum StarkError {
    #[error("Proof generation failed")]
    ProverError,
    #[error("Proof verification failed")]
    VerifierError,
}
