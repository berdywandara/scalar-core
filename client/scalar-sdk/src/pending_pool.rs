//! Pending transaction pool — wallet SDK. PraGenesis §3.1.6, §3.1.10.5.
//!
//! Manages transactions whose referenced SubEpochCommitment has not (yet)
//! reached quorum (EXPIRED_SUBEPOCH_REF), plus epoch-boundary drop.
//!
//! Boundary discipline (§19.1): this module imports ONLY scalar-crypto types
//! (VerificationResult, TransactionSubEpochRef). It performs NO quorum
//! verification itself — the network/node layer supplies a VerificationResult;
//! the pool only manages lifecycle (retry counting, dropping).
//!
//! Funds are never lost: a dropped tx never spent its inputs (its nullifier
//! never entered the NullifierSet), so the input UTXOs remain available.

use scalar_crypto::imt::{TransactionSubEpochRef, VerificationResult};

/// Max retry attempts per tx within the current epoch. PraGenesis §3.1.6.
pub const MAX_RETRY_COUNT: u32 = 3;
/// Max pending epochs before a tx is dropped. PraGenesis §3.1.6.
pub const MAX_PENDING_EPOCHS: u64 = 1;

/// Outcome of feeding a VerificationResult to a pending tx.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingOutcome {
    /// Tx accepted (source verified) — remove from pool, broadcast.
    Accepted,
    /// Still pending (quorum not yet reached); retry_count incremented.
    Retained { retry_count: u32 },
    /// Dropped after exceeding MAX_RETRY_COUNT. Input UTXOs remain valid.
    DroppedMaxRetry,
    /// Dropped for a hard mismatch (frontier/count/epoch/hash). New proof needed.
    DroppedInvalid,
}

/// A transaction waiting on its referenced sub-epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTx {
    pub txid: [u8; 32],
    pub subepoch_ref: TransactionSubEpochRef,
    pub retry_count: u32,
}

impl PendingTx {
    pub fn new(txid: [u8; 32], subepoch_ref: TransactionSubEpochRef) -> Self {
        Self {
            txid,
            subepoch_ref,
            retry_count: 0,
        }
    }
}

/// Wallet-side pending pool. PraGenesis §3.1.10.5.
#[derive(Debug, Default, Clone)]
pub struct PendingPool {
    txs: Vec<PendingTx>,
}

impl PendingPool {
    pub fn new() -> Self {
        Self { txs: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn add(&mut self, tx: PendingTx) {
        self.txs.push(tx);
    }

    pub fn contains(&self, txid: &[u8; 32]) -> bool {
        self.txs.iter().any(|t| &t.txid == txid)
    }

    /// Apply a VerificationResult to one tx (looked up by txid). §3.1.6.
    ///
    /// - Valid                          → Accepted (removed).
    /// - SubEpochQuorumFailed/NotFound  → retry; drop after MAX_RETRY_COUNT.
    /// - Frontier/Count/Epoch/Hash      → DroppedInvalid (must regenerate proof).
    pub fn apply_result(&mut self, txid: &[u8; 32], result: &VerificationResult) -> PendingOutcome {
        let Some(pos) = self.txs.iter().position(|t| &t.txid == txid) else {
            return PendingOutcome::DroppedInvalid;
        };
        match result {
            VerificationResult::Valid => {
                self.txs.remove(pos);
                PendingOutcome::Accepted
            }
            VerificationResult::SubEpochNotFound
            | VerificationResult::SubEpochQuorumFailed { .. } => {
                self.txs[pos].retry_count += 1;
                if self.txs[pos].retry_count > MAX_RETRY_COUNT {
                    self.txs.remove(pos);
                    PendingOutcome::DroppedMaxRetry
                } else {
                    PendingOutcome::Retained {
                        retry_count: self.txs[pos].retry_count,
                    }
                }
            }
            // Hard, cryptographically-bound mismatches: proof cannot be reused.
            VerificationResult::SubEpochHashMismatch
            | VerificationResult::IMTFrontierMismatch
            | VerificationResult::IMTCountMismatch
            | VerificationResult::EpochMismatch { .. } => {
                self.txs.remove(pos);
                PendingOutcome::DroppedInvalid
            }
        }
    }

    /// Epoch-Boundary Drop. PraGenesis §3.1.10.5.
    ///
    /// Any pending tx whose subepoch_ref.epoch_id < current_epoch_id is dropped:
    /// its IMT frontier is from a reset epoch and can never re-verify. Input UTXOs
    /// stay available (must re-spend via EpochSMT in the new epoch). Returns the
    /// dropped txids (for user notification).
    pub fn detect_epoch_boundary_drop(&mut self, current_epoch_id: u64) -> Vec<[u8; 32]> {
        let mut dropped = Vec::new();
        self.txs.retain(|t| {
            if t.subepoch_ref.epoch_id < current_epoch_id {
                dropped.push(t.txid);
                false
            } else {
                true
            }
        });
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mkref(epoch_id: u64) -> TransactionSubEpochRef {
        TransactionSubEpochRef {
            epoch_id,
            subepoch_id: 0,
            subepoch_hash: [0u8; 32],
        }
    }

    // ── TV 5.5 — EXPIRED_SUBEPOCH_REF retry + drop (§3.1.6) ───────────────────
    #[test]
    fn tv_5_5_expired_subepoch_ref_retry_then_drop() {
        let mut pool = PendingPool::new();
        let txid = [0x01u8; 32];
        pool.add(PendingTx::new(txid, mkref(1)));

        let qf = VerificationResult::SubEpochQuorumFailed { subepoch_id: 0 };
        // retries 1,2,3 → retained
        for expected in 1..=MAX_RETRY_COUNT {
            assert_eq!(
                pool.apply_result(&txid, &qf),
                PendingOutcome::Retained {
                    retry_count: expected
                }
            );
            assert!(
                pool.contains(&txid),
                "tx must remain pending during retries"
            );
        }
        // 4th attempt exceeds MAX_RETRY_COUNT → dropped
        assert_eq!(
            pool.apply_result(&txid, &qf),
            PendingOutcome::DroppedMaxRetry
        );
        assert!(!pool.contains(&txid), "tx dropped after MAX_RETRY_COUNT");
        // Input UTXOs remain valid: pool simply no longer tracks it (no spend occurred).
        assert!(pool.is_empty());
    }

    #[test]
    fn tv_5_5_valid_accepts_and_removes() {
        let mut pool = PendingPool::new();
        let txid = [0x02u8; 32];
        pool.add(PendingTx::new(txid, mkref(1)));
        assert_eq!(
            pool.apply_result(&txid, &VerificationResult::Valid),
            PendingOutcome::Accepted
        );
        assert!(!pool.contains(&txid));
    }

    #[test]
    fn hard_mismatch_drops_invalid() {
        let mut pool = PendingPool::new();
        let txid = [0x03u8; 32];
        pool.add(PendingTx::new(txid, mkref(1)));
        assert_eq!(
            pool.apply_result(&txid, &VerificationResult::IMTFrontierMismatch),
            PendingOutcome::DroppedInvalid
        );
        assert!(!pool.contains(&txid));
    }

    // ── TV 5.13 — Epoch-Boundary Drop (§3.1.10.5) ─────────────────────────────
    #[test]
    fn tv_5_13_epoch_boundary_drop() {
        let mut pool = PendingPool::new();
        let old_tx = [0xAAu8; 32];
        let cur_tx = [0xBBu8; 32];
        pool.add(PendingTx::new(old_tx, mkref(1))); // epoch 1
        pool.add(PendingTx::new(cur_tx, mkref(2))); // epoch 2 (current)

        // Epoch advances to 2: tx referencing epoch 1 must be dropped.
        let dropped = pool.detect_epoch_boundary_drop(2);
        assert_eq!(dropped, vec![old_tx]);
        assert!(!pool.contains(&old_tx), "stale-epoch tx dropped");
        assert!(pool.contains(&cur_tx), "current-epoch tx retained");
        // Dropped tx never spent inputs → UTXOs available (pool no longer tracks it).
    }
}
