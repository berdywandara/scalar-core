pub mod air;
pub mod constraints;
pub mod prover;
pub mod verifier;

#[derive(thiserror::Error, Debug)]
pub enum StarkError {
    #[error("Proof generation failed")]
    ProverError,
    #[error("Proof verification failed")]
    VerifierError,
}
