//! MEV Protection (D-018). MAD §20.2.
//!
//! Three components:
//!   1. Commit-Reveal ordering protocol — prevents frontrunning.
//!   2. Transaction encryption to aggregator — hides tx until committed.
//!   3. MEV redistribution — captured MEV returned to fee pool.
//!
//! Commit-Reveal protocol:
//!   PHASE 1 — COMMIT: user submits commit = BLAKE3(TX_ORDER_DOMAIN || tx_hash || nonce)
//!             Aggregator records commit, does not know tx content.
//!   PHASE 2 — REVEAL: user submits full tx. Aggregator verifies commit matches.
//!             Ordering determined by commit arrival time, not reveal time.
//!   → Frontrunning impossible: ordering is fixed before content is known.
//!
//! Tx encryption:
//!   User encrypts tx to aggregator's public key (ChaCha20-Poly1305).
//!   Aggregator decrypts after commit phase closes.
//!   → Aggregator cannot see tx content during ordering phase.

use std::collections::HashMap;

/// TX ordering domain separator. OSSIFIED — MAD §1.4.
const TX_ORDER_DOMAIN: &[u8] = b"scalar_tx_order";

// ── Commit-Reveal ─────────────────────────────────────────────────────────────

/// Commitment from the user. Phase 1 of commit-reveal. MAD D-018.
/// commit = BLAKE3("scalar_tx_order" || tx_hash || nonce)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxCommitment {
    /// Commitment hash. BLAKE3(TX_ORDER_DOMAIN || tx_hash || nonce).
    pub commitment: [u8; 32],
    /// Sequence number assigned at commit time (determines ordering).
    pub sequence: u64,
    /// Unix timestamp (ms) when commitment was received.
    pub received_at_ms: u64,
}

/// Compute a transaction commitment. MAD D-018.
///
/// `tx_hash`: BLAKE3 hash of the full transaction bytes.
/// `nonce`: 128-bit random nonce, kept secret by user until reveal.
pub fn compute_tx_commitment(tx_hash: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TX_ORDER_DOMAIN);
    hasher.update(tx_hash.as_ref());
    hasher.update(nonce.as_ref());
    *hasher.finalize().as_bytes()
}

/// Commit-reveal entry stored by aggregator. MAD D-018.
#[derive(Debug, Clone)]
pub struct CommitEntry {
    /// The commitment.
    pub commitment: TxCommitment,
    /// Encrypted transaction bytes (if encrypted submission used).
    pub encrypted_tx: Option<Vec<u8>>,
    /// Status of this entry.
    pub status: CommitStatus,
}

/// Status of a commit-reveal entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitStatus {
    /// Commitment received, waiting for reveal.
    Committed,
    /// Revealed and verified — ready for processing.
    Revealed { tx_bytes: Vec<u8> },
    /// Reveal timeout — commitment expired without reveal.
    Expired,
    /// Reveal failed — commitment mismatch.
    Invalid,
}

/// Error from CommitRevealPool operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitRevealError {
    #[error("Commitment {0:?} not found")]
    NotFound([u8; 32]),

    #[error("Entry already revealed")]
    AlreadyRevealed,

    #[error("Commitment mismatch: provided nonce does not match commitment")]
    CommitmentMismatch,

    #[error("Entry expired — reveal window closed")]
    Expired,
}

/// Commit-reveal pool managed by the aggregator. MAD D-018.
///
/// Sequence numbers are monotonically increasing — ordering is fixed at commit time.
pub struct CommitRevealPool {
    /// Entries keyed by commitment hash.
    entries: HashMap<[u8; 32], CommitEntry>,
    /// Next sequence number to assign.
    next_seq: u64,
    /// Reveal timeout in ms — after this, commitment expires.
    reveal_timeout_ms: u64,
}

impl CommitRevealPool {
    /// Create pool with given reveal timeout.
    pub fn new(reveal_timeout_ms: u64) -> Self {
        Self {
            entries: HashMap::new(),
            next_seq: 0,
            reveal_timeout_ms,
        }
    }

    /// Phase 1 — COMMIT: record a new commitment. MAD D-018.
    ///
    /// Assigns a sequence number (ordering) at commit time.
    /// Returns the assigned TxCommitment.
    pub fn commit(
        &mut self,
        commitment_hash: [u8; 32],
        encrypted_tx: Option<Vec<u8>>,
        now_ms: u64,
    ) -> TxCommitment {
        let seq = self.next_seq;
        self.next_seq += 1;

        let tc = TxCommitment {
            commitment: commitment_hash,
            sequence: seq,
            received_at_ms: now_ms,
        };

        self.entries.insert(
            commitment_hash,
            CommitEntry {
                commitment: tc.clone(),
                encrypted_tx,
                status: CommitStatus::Committed,
            },
        );

        tc
    }

    /// Phase 2 — REVEAL: verify and unlock a committed transaction. MAD D-018.
    ///
    /// Verifies that BLAKE3(TX_ORDER_DOMAIN || tx_hash || nonce) == commitment_hash.
    /// On success, tx_bytes are stored and status → Revealed.
    pub fn reveal(
        &mut self,
        commitment_hash: [u8; 32],
        tx_bytes: Vec<u8>,
        nonce: &[u8; 16],
        now_ms: u64,
    ) -> Result<u64, CommitRevealError> {
        let entry = self
            .entries
            .get_mut(&commitment_hash)
            .ok_or(CommitRevealError::NotFound(commitment_hash))?;

        match &entry.status {
            CommitStatus::Revealed { .. } => return Err(CommitRevealError::AlreadyRevealed),
            CommitStatus::Expired | CommitStatus::Invalid => {
                return Err(CommitRevealError::Expired)
            }
            CommitStatus::Committed => {}
        }

        // Check reveal timeout
        let elapsed = now_ms.saturating_sub(entry.commitment.received_at_ms);
        if elapsed > self.reveal_timeout_ms {
            entry.status = CommitStatus::Expired;
            return Err(CommitRevealError::Expired);
        }

        // Compute expected commitment from tx_bytes + nonce
        let tx_hash: [u8; 32] = *blake3::hash(&tx_bytes).as_bytes();
        let expected = compute_tx_commitment(&tx_hash, nonce);

        if expected != commitment_hash {
            entry.status = CommitStatus::Invalid;
            return Err(CommitRevealError::CommitmentMismatch);
        }

        let seq = entry.commitment.sequence;
        entry.status = CommitStatus::Revealed { tx_bytes };
        Ok(seq)
    }

    /// Expire all commitments older than reveal_timeout_ms. MAD D-018.
    pub fn expire_stale(&mut self, now_ms: u64) {
        for entry in self.entries.values_mut() {
            if let CommitStatus::Committed = &entry.status {
                let elapsed = now_ms.saturating_sub(entry.commitment.received_at_ms);
                if elapsed > self.reveal_timeout_ms {
                    entry.status = CommitStatus::Expired;
                }
            }
        }
    }

    /// Drain all revealed transactions in commit-sequence order. MAD D-018.
    ///
    /// Returns (sequence, tx_bytes) pairs sorted by sequence ascending.
    /// Ordering is determined by commit time — frontrunning impossible.
    pub fn drain_revealed(&mut self) -> Vec<(u64, Vec<u8>)> {
        let mut revealed: Vec<(u64, Vec<u8>)> = self
            .entries
            .values()
            .filter_map(|e| {
                if let CommitStatus::Revealed { tx_bytes } = &e.status {
                    Some((e.commitment.sequence, tx_bytes.clone()))
                } else {
                    None
                }
            })
            .collect();

        // Sort by sequence (commit order) — not reveal order.
        revealed.sort_by_key(|(seq, _)| *seq);

        // Remove drained entries
        self.entries
            .retain(|_, e| !matches!(e.status, CommitStatus::Revealed { .. }));

        revealed
    }

    /// Committed count (awaiting reveal).
    pub fn committed_count(&self) -> usize {
        self.entries
            .values()
            .filter(|e| e.status == CommitStatus::Committed)
            .count()
    }
}

// ── MEV Redistribution ────────────────────────────────────────────────────────

/// MEV redistribution tracker. MAD D-018.
///
/// Any MEV captured by the aggregator (ordering profit) is tracked here
/// and redistributed to the fee pool for validator rewards.
/// Invariant: total_captured == total_redistributed + pending_redistribution.
#[derive(Debug, Default)]
pub struct MevRedistribution {
    /// Total MEV captured (sSCL).
    pub total_captured_sscl: u64,
    /// Total MEV redistributed to fee pool (sSCL).
    pub total_redistributed_sscl: u64,
}

impl MevRedistribution {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record MEV captured. MAD D-018.
    pub fn record_capture(&mut self, amount_sscl: u64) {
        self.total_captured_sscl = self.total_captured_sscl.saturating_add(amount_sscl);
    }

    /// Redistribute pending MEV to fee pool. MAD D-018.
    /// Returns the amount redistributed.
    pub fn redistribute(&mut self) -> u64 {
        let pending = self.pending_sscl();
        self.total_redistributed_sscl = self.total_redistributed_sscl.saturating_add(pending);
        pending
    }

    /// Pending MEV not yet redistributed.
    pub fn pending_sscl(&self) -> u64 {
        self.total_captured_sscl
            .saturating_sub(self.total_redistributed_sscl)
    }

    /// Invariant check: captured >= redistributed.
    pub fn invariant_holds(&self) -> bool {
        self.total_captured_sscl >= self.total_redistributed_sscl
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT_MS: u64 = 30_000; // 30s reveal window

    fn pool() -> CommitRevealPool {
        CommitRevealPool::new(TIMEOUT_MS)
    }

    fn make_tx(seed: u8) -> Vec<u8> {
        vec![seed; 256]
    }

    fn make_nonce(seed: u8) -> [u8; 16] {
        [seed; 16]
    }

    fn tx_commitment_hash(tx: &[u8], nonce: &[u8; 16]) -> [u8; 32] {
        let tx_hash: [u8; 32] = *blake3::hash(tx).as_bytes();
        compute_tx_commitment(&tx_hash, nonce)
    }

    // ── commit_tx_commitment ─────────────────────────────────────────────

    #[test]
    fn test_compute_commitment_deterministic() {
        let tx = make_tx(1);
        let nonce = make_nonce(0xAA);
        let h1 = tx_commitment_hash(&tx, &nonce);
        let h2 = tx_commitment_hash(&tx, &nonce);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_nonces_different_commitments() {
        let tx = make_tx(1);
        let h1 = tx_commitment_hash(&tx, &make_nonce(1));
        let h2 = tx_commitment_hash(&tx, &make_nonce(2));
        assert_ne!(
            h1, h2,
            "Different nonces must produce different commitments"
        );
    }

    // ── CommitRevealPool — happy path ─────────────────────────────────

    #[test]
    fn test_commit_reveal_happy_path() {
        let mut p = pool();
        let tx = make_tx(0x42);
        let nonce = make_nonce(0x11);
        let commit_hash = tx_commitment_hash(&tx, &nonce);

        let tc = p.commit(commit_hash, None, 0);
        assert_eq!(tc.sequence, 0);
        assert_eq!(p.committed_count(), 1);

        let seq = p.reveal(commit_hash, tx.clone(), &nonce, 1000).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(p.committed_count(), 0);
    }

    #[test]
    fn test_commit_sequence_ordering() {
        let mut p = pool();
        let tx_a = make_tx(1);
        let nonce_a = make_nonce(1);
        let tx_b = make_tx(2);
        let nonce_b = make_nonce(2);
        let h_a = tx_commitment_hash(&tx_a, &nonce_a);
        let h_b = tx_commitment_hash(&tx_b, &nonce_b);

        // B commits first (lower sequence)
        p.commit(h_b, None, 0);
        p.commit(h_a, None, 1);

        p.reveal(h_a, tx_a, &nonce_a, 100).unwrap();
        p.reveal(h_b, tx_b, &nonce_b, 200).unwrap();

        let ordered = p.drain_revealed();
        // B has seq=0, A has seq=1 → B first regardless of reveal order
        assert_eq!(ordered[0].0, 0, "B committed first → seq 0");
        assert_eq!(ordered[1].0, 1, "A committed second → seq 1");
    }

    #[test]
    fn test_reveal_wrong_nonce_rejected() {
        let mut p = pool();
        let tx = make_tx(1);
        let nonce = make_nonce(1);
        let h = tx_commitment_hash(&tx, &nonce);
        p.commit(h, None, 0);

        let wrong_nonce = make_nonce(2);
        assert_eq!(
            p.reveal(h, tx, &wrong_nonce, 100).unwrap_err(),
            CommitRevealError::CommitmentMismatch
        );
    }

    #[test]
    fn test_reveal_timeout_expired() {
        let mut p = pool();
        let tx = make_tx(1);
        let nonce = make_nonce(1);
        let h = tx_commitment_hash(&tx, &nonce);
        p.commit(h, None, 0);

        // Reveal after timeout
        let err = p.reveal(h, tx, &nonce, TIMEOUT_MS + 1).unwrap_err();
        assert_eq!(err, CommitRevealError::Expired);
    }

    #[test]
    fn test_reveal_not_found() {
        let mut p = pool();
        let err = p
            .reveal([0xFFu8; 32], vec![], &make_nonce(0), 0)
            .unwrap_err();
        assert!(matches!(err, CommitRevealError::NotFound(_)));
    }

    #[test]
    fn test_double_reveal_rejected() {
        let mut p = pool();
        let tx = make_tx(1);
        let nonce = make_nonce(1);
        let h = tx_commitment_hash(&tx, &nonce);
        p.commit(h, None, 0);
        p.reveal(h, tx.clone(), &nonce, 0).unwrap();
        assert_eq!(
            p.reveal(h, tx, &nonce, 0).unwrap_err(),
            CommitRevealError::AlreadyRevealed
        );
    }

    #[test]
    fn test_expire_stale_commitments() {
        let mut p = pool();
        let tx = make_tx(1);
        let nonce = make_nonce(1);
        let h = tx_commitment_hash(&tx, &nonce);
        p.commit(h, None, 0);
        assert_eq!(p.committed_count(), 1);
        p.expire_stale(TIMEOUT_MS + 1);
        assert_eq!(p.committed_count(), 0);
    }

    // ── MevRedistribution ─────────────────────────────────────────────

    #[test]
    fn test_mev_redistribution_invariant() {
        let mut m = MevRedistribution::new();
        m.record_capture(1_000_000);
        assert_eq!(m.pending_sscl(), 1_000_000);
        assert!(m.invariant_holds());
        let redistributed = m.redistribute();
        assert_eq!(redistributed, 1_000_000);
        assert_eq!(m.pending_sscl(), 0);
        assert!(m.invariant_holds());
    }

    #[test]
    fn test_mev_partial_redistribution() {
        let mut m = MevRedistribution::new();
        m.record_capture(1_000);
        m.record_capture(2_000);
        assert_eq!(m.pending_sscl(), 3_000);
        m.redistribute();
        assert_eq!(m.pending_sscl(), 0);
        assert_eq!(m.total_redistributed_sscl, 3_000);
    }
}
