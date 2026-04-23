pub mod coin_selection;
pub mod key_management;
pub mod transaction;

#[derive(thiserror::Error, Debug)]
pub enum WalletError {
    #[error("Insufficient funds")]
    InsufficientFunds,
    #[error("Proof generation timeout")]
    ProvingTimeout,
}
