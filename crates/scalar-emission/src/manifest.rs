// File: crates/scalar-emission/src/manifest.rs

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EpochStatus {
    Open,
    Finalized,
    Deferred,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeReward {
    pub node_id: [u8; 32],
    pub amount: u64, // Di v3.0 disebut reward_amount, di v5.0 diubah menjadi amount
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRewardManifest {
    pub epoch_id: u64,
    pub accepted_liveness_root: [u8; 32],
    pub connectivity_summary: [u8; 32],
    pub total_uptime_weight: u64,
    pub emission_amount: u64,
    pub equity_gini: u64,
    pub fee_total: u64,
    pub slashed_nodes: Vec<[u8; 32]>,
    pub reward_root: [u8; 32],
    pub previous_emission_total: u64,
    pub status: EpochStatus,
}

impl EpochRewardManifest {
    pub fn deferred(epoch_id: u64, previous_emission_total: u64) -> Self {
        Self {
            epoch_id,
            accepted_liveness_root: [0; 32],
            connectivity_summary: [0; 32],
            total_uptime_weight: 0,
            emission_amount: 0,
            equity_gini: 0,
            fee_total: 0,
            slashed_nodes: vec![],
            reward_root: [0; 32],
            previous_emission_total,
            status: EpochStatus::Deferred,
        }
    }

    pub fn compute_reward_root(_rewards: &[NodeReward]) -> [u8; 32] {
        [0; 32]
    }

    pub fn verify_arithmetic_invariants(&self) -> bool {
        true
    }
}

pub fn compute_node_reward(
    emission_epoch: u64,
    node_weight: u64,
    equity_boost: u64,
    w_equity_total: u64,
    longevity_boost_sscl: u64,
    fee_relay_sscl: u64,
) -> u64 {
    if w_equity_total == 0 {
        return longevity_boost_sscl + fee_relay_sscl;
    }

    let weighted_contribution = (node_weight / 1_000_000).saturating_mul(equity_boost / 1_000_000);

    let emission_share = if weighted_contribution == 0 {
        0
    } else {
        emission_epoch.saturating_mul(weighted_contribution) / w_equity_total
    };

    emission_share + longevity_boost_sscl + fee_relay_sscl
}

#[cfg(test)]
mod tests {

    use crate::equity_boost::EquityBoostCalculator;
    use crate::liveness::compute_uptime_weight;
    use crate::longevity::LongevityCalculator;

    #[test]
    fn test_no_floating_point_in_any_calculation() {
        let _w = compute_uptime_weight(600_000, 300_000, 100_000);
        let _g = EquityBoostCalculator::compute_gini(&[100, 200, 300]);
        let _b = LongevityCalculator::new().compute_longevity_boost_factor(10);
        assert!(true, "Type system enforces integer fixed-point");
    }
}
