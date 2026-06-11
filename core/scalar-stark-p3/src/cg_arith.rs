//! CG-ARITH — Sequential temporal validity over sub-epoch sequence numbers.
//!
//! Spec (OSSIFIED): SCALAR-TECHNICAL §2.9 (CG-ARITH); SCALAR-PROTOCOL §503/§510 (C4).
//! Wall-clock is amputated from validity (P1, P2). A transfer carries a user-signed
//! `target_subepoch_id` (witness); `current_subepoch_id` is a consensus-bound public
//! input the prover cannot choose. Validity is decided purely by the integer relation:
//!
//!   order guard : current_subepoch_id >= target_subepoch_id   (prevents Goldilocks underflow)
//!   validity    = current_subepoch_id - target_subepoch_id
//!   assert        validity <= CG_MAX_VALIDITY (= 1)
//!
//! validity = 0 : intra-sub-epoch commit.
//! validity = 1 : boundary-spillover. Its legitimacy (quorumed MicroCommitment + CommitStark
//!                finalization) is CG-WINDOW-TRIGGER, enforced downstream by G-12 — NOT here.
//!
//! This module is the off-circuit reference + witness computation. The in-circuit
//! enforcement lives in `TransferAirP3` (wired in a later G-07 sub-step) and mirrors
//! exactly the relation proven here.

/// OSSIFIED: sub-epochs per epoch. `current_subepoch_id = epoch_id * 24 + local_index`.
/// SCALAR-TECHNICAL §2.9.
pub const SUBEPOCHS_PER_EPOCH: u64 = 24;

/// OSSIFIED: maximum CG validity tolerance (sequential equivalent of the old TTL).
/// Only validity ∈ {0, 1} is admissible. SCALAR-TECHNICAL §2.9 CG-ARITH.
pub const CG_MAX_VALIDITY: u64 = 1;

/// Compose a GLOBAL sub-epoch sequence number from epoch and local index. OSSIFIED (×24).
pub fn subepoch_id(epoch_id: u64, local_index: u64) -> u64 {
    epoch_id * SUBEPOCHS_PER_EPOCH + local_index
}

/// Derive epoch from a GLOBAL sub-epoch sequence number (integer division). OSSIFIED.
pub fn epoch_of(subepoch_id: u64) -> u64 {
    subepoch_id / SUBEPOCHS_PER_EPOCH
}

/// Local sub-epoch index within its epoch. OSSIFIED.
pub fn local_index_of(subepoch_id: u64) -> u64 {
    subepoch_id % SUBEPOCHS_PER_EPOCH
}

/// CG-ARITH validity (off-circuit reference / witness computation). Returns the validity
/// distance if the transaction is temporally admissible, else `None` (reject).
///
///   Some(0) — intra-sub-epoch (current == target)
///   Some(1) — boundary-spillover (current == target + 1); legitimacy gated by CG-WINDOW (G-12)
///   None    — order-guard violation (current < target) OR stale (validity > 1)
pub fn cg_validity(current_subepoch_id: u64, target_subepoch_id: u64) -> Option<u64> {
    // Order guard: current >= target. In-circuit this is a bit-decomposition underflow guard
    // (prevents Goldilocks field wrap when computing current - target).
    if current_subepoch_id < target_subepoch_id {
        return None;
    }
    let validity = current_subepoch_id - target_subepoch_id;
    if validity > CG_MAX_VALIDITY {
        return None;
    }
    Some(validity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subepochs_per_epoch_ossified() {
        assert_eq!(SUBEPOCHS_PER_EPOCH, 24);
    }

    #[test]
    fn test_cg_max_validity_ossified() {
        assert_eq!(CG_MAX_VALIDITY, 1);
    }

    #[test]
    fn test_subepoch_id_compose_decompose() {
        let id = subepoch_id(100, 7);
        assert_eq!(id, 100 * 24 + 7);
        assert_eq!(epoch_of(id), 100);
        assert_eq!(local_index_of(id), 7);
    }

    #[test]
    fn test_subepoch_id_boundary_local_23() {
        let id = subepoch_id(5, 23);
        assert_eq!(epoch_of(id), 5);
        assert_eq!(local_index_of(id), 23);
        // next sub-epoch rolls into the following epoch
        assert_eq!(epoch_of(id + 1), 6);
        assert_eq!(local_index_of(id + 1), 0);
    }

    #[test]
    fn test_cg_validity_intra_subepoch() {
        assert_eq!(cg_validity(1000, 1000), Some(0));
    }

    #[test]
    fn test_cg_validity_boundary_spillover() {
        assert_eq!(cg_validity(1001, 1000), Some(1));
    }

    #[test]
    fn test_cg_validity_rejects_stale() {
        assert_eq!(cg_validity(1002, 1000), None);
        assert_eq!(cg_validity(2000, 1000), None);
    }

    #[test]
    fn test_cg_validity_rejects_order_guard() {
        // current < target → would underflow the field; rejected.
        assert_eq!(cg_validity(999, 1000), None);
        assert_eq!(cg_validity(0, 1), None);
    }
}
