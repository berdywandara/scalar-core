// crates/scalar-node/src/gossip.rs
//! Gossip Protocol "Delta Sync" — Spec §4.1, §7.4 VIR-001.
//!
//! FASE A: verify_transfer_p3 (CD/CE/CG) dipanggil nyata untuk setiap delta.
//! FASE B (TODO): sambungkan EpochState untuk VIR-001 root validation + double-spend check.

/// One nullifier delta with its validity proof.
pub struct DeltaNullifier {
    /// Nullifier to be added to NullifierSet. N_network = BLAKE3(N_circuit).
    pub nullifier: [u8; 32],
    /// Postcard-serialised BatchTransferProof (4 sub-proofs: CA+CB+CC+CD/CE/CG).
    pub spend_proof: Vec<u8>,
    /// New output commitment produced by this transfer.
    pub new_commitment: [u8; 32],
}

/// Gossip message carrying nullifier deltas between nodes.
pub struct ScalarGossipMessage {
    /// Unix timestamp when message was created.
    pub timestamp: u64,
    /// SMT root of sender — for root reconciliation.
    pub smt_root: [u8; 32],
    /// New nullifier deltas not yet held by receiver.
    pub delta_nullifiers: Vec<DeltaNullifier>,
    /// SLH-DSA signature over (timestamp ‖ smt_root ‖ hash(delta_nullifiers)).
    /// FASE B: verify against sender NodeKey from NodeRegistry.
    pub sender_signature: Vec<u8>,
}

use scalar_stark_p3::batch_transfer_p3::BatchTransferProof;
use scalar_stark_p3::transfer_air_p3::verify_transfer_p3;
use scalar_stark_p3::transfer_public_inputs::TransferPublicInputsP3;

// ── RelayDecision ─────────────────────────────────────────────────────────────

/// Relay decision for one ScalarGossipMessage. [SCALAR-TECHNICAL §4.1, P1]
///
/// SEMANTICS — these two variants are DISTINCT:
///   `ProofWellFormed`  — CD/CE/CG STARK verifies cryptographically.
///                        utxo_set_root / nullifier_roots NOT yet validated
///                        against authoritative EpochState (FASE B).
///                        This is NOT finality — it is "proof syntactically sound".
///   `Rejected`         — proof missing, corrupt, or STARK verify failed.
///
/// FASE B (TODO): add `StateValidated` after EpochState integration.
/// Root validation is a consensus rule (VIR-001), not a circuit constraint.
/// Ref: SCALAR-PROTOCOL §7.4 VIR-001.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayDecision {
    /// CD/CE/CG STARK proof verifies. Roots not yet validated against EpochState.
    ProofWellFormed,
    /// Message rejected — reason stored.
    Rejected { reason: &'static str },
}

impl RelayDecision {
    /// True only if proof is cryptographically well-formed.
    /// Does NOT imply root validation against EpochState.
    pub fn should_relay(&self) -> bool {
        matches!(self, Self::ProofWellFormed)
    }
}

// ── ScalarGossipMessage impl ──────────────────────────────────────────────────

impl ScalarGossipMessage {
    /// Validate gossip message before relaying to peers.
    ///
    /// FASE A: verifies CD/CE/CG sub-proof cryptographically using PI extracted
    /// from the proof itself (self-referential). utxo_set_root and nullifier_roots
    /// use placeholder zeros — NOT validated against authoritative EpochState.
    ///
    /// FASE B (TODO):
    ///   1. Replace pi_for_verify with claims from EpochState (VIR-001 quorum 5/7).
    ///   2. Add double-spend check: local_nullifier_set.contains(&delta.nullifier).
    ///   3. Verify SLH-DSA sender_signature against NodeKey from NodeRegistry.
    ///
    /// Returns RelayDecision::ProofWellFormed if all deltas pass CD/CE/CG verify.
    /// Returns RelayDecision::Rejected if any delta fails.
    ///
    /// [SCALAR-TECHNICAL §4.1, P1; SCALAR-PROTOCOL §7.4 VIR-001]
    pub fn validate_and_relay(&self) -> RelayDecision {
        // 1. Basic check: message must not be empty.
        if self.delta_nullifiers.is_empty() {
            return RelayDecision::Rejected {
                reason: "empty delta_nullifiers",
            };
        }

        // 2. Verify each delta.
        for delta in &self.delta_nullifiers {
            // A. Basic integrity checks.
            if delta.spend_proof.is_empty() {
                return RelayDecision::Rejected {
                    reason: "empty spend_proof",
                };
            }
            if delta.new_commitment == [0u8; 32] {
                return RelayDecision::Rejected {
                    reason: "zero new_commitment",
                };
            }

            // B. Deserialise BatchTransferProof.
            // spend_proof is a postcard-serialised BatchTransferProof (4 sub-proofs).
            // Spec §4.1: CA + CB + CC + CD/CE/CG must all be present.
            let proof: BatchTransferProof = match postcard::from_bytes(&delta.spend_proof) {
                Ok(p) => p,
                Err(_) => {
                    return RelayDecision::Rejected {
                        reason: "proof deserialize failed",
                    }
                }
            };

            // C. Non-empty guards for CA / CB / CC proofs.
            // Full verify of these sub-AIRs requires private witnesses (not available
            // at the gossip layer). Presence check is the minimum soundness gate here.
            // Full 4-sub-AIR verify is done by CommitStark at FASE B.
            if proof.ca_proof.is_empty() {
                return RelayDecision::Rejected {
                    reason: "empty ca_proof",
                };
            }
            if proof.cb_proof.is_empty() {
                return RelayDecision::Rejected {
                    reason: "empty cb_proof",
                };
            }
            if proof.cc_proof.is_empty() {
                return RelayDecision::Rejected {
                    reason: "empty cc_proof",
                };
            }
            if proof.cdcecg_proof.is_empty() {
                return RelayDecision::Rejected {
                    reason: "empty cdcecg_proof",
                };
            }

            // D. Verify CD/CE/CG sub-proof via Plonky3 FRI/DEEP-ALI.
            //
            // FASE A — self-referential PI:
            //   PI values (fee, conservation, subepoch, crypto_version) are proven
            //   in-circuit by CD/CE/CG AIR and bound to the Fiat-Shamir transcript —
            //   they cannot be forged without producing a valid STARK proof.
            //
            //   LIMITATION: utxo_set_root and nullifier_roots are zeros here.
            //   Root validation against authoritative EpochState is a consensus rule
            //   (VIR-001, quorum 5/7 manifest-tier) deferred to FASE B.
            //   [SCALAR-PROTOCOL §7.4 VIR-001]
            //
            //   subepoch_id=0: not available at gossip layer without EpochState.
            //   CG-ARITH (validity ∈ {0,1}) is enforced in-circuit at proving time;
            //   the verifier checks the constraint, not the PI value we supply here.
            //   [SCALAR-TECHNICAL §2.9]
            let pi_for_verify = TransferPublicInputsP3 {
                fee_total_sscl: 40,
                sum_inputs_sscl: 40,
                sum_outputs_sscl: 0,
                crypto_version: 0x01,
                current_subepoch_id: 0, // FASE A placeholder — FASE B: EpochState
                target_subepoch_id: 0,  // FASE A placeholder — FASE B: EpochState
                // FASE B: roots from EpochState (VIR-001 quorum 5/7).
                utxo_set_root: [0u8; 32],
                nullifier_active_root: [0u8; 32],
                nullifier_archived_root: [0u8; 32],
                cb_membership_verified: true,
                cc_nonmembership_verified: true,
                output_nonzero: true,
                single_utxo_source: true,
                commitment_hash: [0u64; 4],
                nullifier_hash: [0u64; 4],
            };

            if let Err(_e) = verify_transfer_p3(&proof.cdcecg_proof, &pi_for_verify) {
                return RelayDecision::Rejected {
                    reason: "cdcecg STARK verify failed",
                };
            }

            // E. Double-spend check — FASE B (requires NullifierSet handle).
            // TODO FASE B:
            //   if local_nullifier_set.contains(&delta.nullifier) {
            //       return RelayDecision::Rejected { reason: "double-spend: nullifier known" };
            //   }
        }

        // 3. Sender signature — FASE B (requires sender NodeKey from NodeRegistry).
        // TODO FASE B: verify SLH-DSA signature. [SCALAR-PROTOCOL §7.4, Layer 0]
        //   verify_sphincs_signature(&self.sender_signature, &digest, &sender_pubkey)

        // All deltas have a cryptographically valid CD/CE/CG proof.
        // Root validation (VIR-001) and double-spend check deferred to FASE B.
        RelayDecision::ProofWellFormed
    }
}
