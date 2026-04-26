//! EpochRewardManifest — Struktur manifest reward per epoch
//!
//! Spesifikasi: Scalar_Master_Technical_Spec.docx §B.3.1 + §B.5
//!
//! Deterministik dari accepted_liveness_root — semua node jujur
//! menghasilkan reward_root identik (§B.3.1).
//! Sorting key: node_id ascending (OSSIFIED §B.6).

use scalar_crypto::poseidon2::hash_2_to_1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochStatus {
    /// Manifest final — mint claim gate terbuka.
    Finalized,
    /// Konsensus gagal — no-makeup policy (§B.5.2).
    Deferred,
}

/// Reward satu node dalam manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeReward {
    pub node_id:       [u8; 32],
    pub reward_amount: u64,
}

/// EpochRewardManifest — sesuai §B.3.1 field-by-field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochRewardManifest {
    pub epoch_id:               u64,
    pub accepted_liveness_root: [u8; 32],
    pub total_uptime_weight:    u64,
    pub emission_amount:        u64,
    pub fee_total:              u64,
    pub reward_root:            [u8; 32],
    pub previous_emission_total: u64,
    pub status:                 EpochStatus,
}

impl EpochRewardManifest {
    /// Buat manifest DEFERRED. M_E tidak berubah (§B.5.2).
    pub fn deferred(epoch_id: u64, previous_emission_total: u64) -> Self {
        Self {
            epoch_id,
            accepted_liveness_root:  [0u8; 32],
            total_uptime_weight:     0,
            emission_amount:         0,
            fee_total:               0,
            reward_root:             [0u8; 32],
            previous_emission_total,
            status:                  EpochStatus::Deferred,
        }
    }

    /// Hitung reward_root dari slice NodeReward.
    ///
    /// WAJIB: rewards harus sudah di-sort ascending by node_id
    /// sebelum dipanggil — menjamin determinisme (§B.3.1).
    ///
    /// Leaf   = Poseidon2(node_id_lo, reward_amount)
    /// Parent = Poseidon2(left, right)
    pub fn compute_reward_root(rewards: &[NodeReward]) -> [u8; 32] {
        if rewards.is_empty() {
            return [0u8; 32];
        }
        let mut hashes: Vec<u64> = rewards.iter().map(|r| {
            let lo = u64::from_le_bytes(r.node_id[0..8].try_into().unwrap());
            hash_2_to_1(lo, r.reward_amount)
        }).collect();

        while hashes.len() > 1 {
            let mut next = Vec::new();
            let mut i = 0;
            while i < hashes.len() {
                let left  = hashes[i];
                let right = if i + 1 < hashes.len() { hashes[i + 1] } else { hashes[i] };
                next.push(hash_2_to_1(left, right));
                i += 2;
            }
            hashes = next;
        }

        let mut root = [0u8; 32];
        root[0..8].copy_from_slice(&hashes[0].to_le_bytes());
        root
    }

    /// Verifikasi invariant aritmetik (tanpa akses LivenessSMT).
    /// Verifikasi penuh dilakukan di §B.5.1 Step 5.
    pub fn verify_arithmetic_invariants(&self) -> bool {
        if self.status == EpochStatus::Deferred {
            return self.emission_amount == 0
                && self.total_uptime_weight == 0
                && self.reward_root == [0u8; 32];
        }
        self.previous_emission_total
            .checked_add(self.emission_amount)
            .map(|t| t <= crate::accumulator::S_E_SSCL)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nr(b: u8, amount: u64) -> NodeReward {
        let mut node_id = [0u8; 32]; node_id[0] = b;
        NodeReward { node_id, reward_amount: amount }
    }

    #[test]
    fn test_reward_root_deterministic() {
        let r = vec![nr(1, 1000), nr(2, 800), nr(3, 600)];
        assert_eq!(
            EpochRewardManifest::compute_reward_root(&r),
            EpochRewardManifest::compute_reward_root(&r)
        );
    }

    #[test]
    fn test_reward_root_order_sensitive() {
        let asc  = vec![nr(1, 1000), nr(2, 800)];
        let desc = vec![nr(2,  800), nr(1, 1000)];
        assert_ne!(
            EpochRewardManifest::compute_reward_root(&asc),
            EpochRewardManifest::compute_reward_root(&desc)
        );
    }

    #[test]
    fn test_reward_root_empty() {
        assert_eq!(EpochRewardManifest::compute_reward_root(&[]), [0u8; 32]);
    }

    #[test]
    fn test_reward_root_single_nonzero() {
        assert_ne!(
            EpochRewardManifest::compute_reward_root(&[nr(42, 99_999)]),
            [0u8; 32]
        );
    }

    #[test]
    fn test_deferred_invariants() {
        let m = EpochRewardManifest::deferred(5, 1_000_000);
        assert_eq!(m.status, EpochStatus::Deferred);
        assert!(m.verify_arithmetic_invariants());
    }

    #[test]
    fn test_finalized_invariant_ok() {
        let root = EpochRewardManifest::compute_reward_root(&[nr(1, 500_000_000)]);
        let m = EpochRewardManifest {
            epoch_id: 0,
            accepted_liveness_root:  [1u8; 32],
            total_uptime_weight:     1_000_000,
            emission_amount:         500_000_000,
            fee_total:               0,
            reward_root:             root,
            previous_emission_total: 0,
            status:                  EpochStatus::Finalized,
        };
        assert!(m.verify_arithmetic_invariants());
    }

    #[test]
    fn test_finalized_invariant_cap_exceeded() {
        let m = EpochRewardManifest {
            epoch_id: 0,
            accepted_liveness_root:  [1u8; 32],
            total_uptime_weight:     1_000_000,
            emission_amount:         1,
            fee_total:               0,
            reward_root:             [1u8; 32],
            previous_emission_total: crate::accumulator::S_E_SSCL,
            status:                  EpochStatus::Finalized,
        };
        assert!(!m.verify_arithmetic_invariants());
    }
}
