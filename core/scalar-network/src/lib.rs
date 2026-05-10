// File: crates/scalar-network/src/lib.rs

pub mod adaptive_mux;
pub mod dandelion;
pub mod eclipse;
pub mod fork;
pub mod gossip;
pub mod gss;
pub mod heartbeat_verifier;
pub mod node_score;
pub mod nmt;
pub mod reconciliation;
pub mod relay;
pub mod state_beacon;
pub mod sync;
pub mod time_security;

// EMPIRICAL TEST SUITE — Spec §22.5 Pre-Mainnet Mandatory
#[cfg(test)]
mod empirical_tests;
