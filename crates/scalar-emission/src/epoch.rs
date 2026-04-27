//! EpochProcessor — Orkestrasi komputasi reward per epoch
//!
//! Spesifikasi: Scalar_Master_Technical_Spec.docx §B.1 + §B.5.1 Step 4
//!
//! Modul ini mengintegrasikan semua state objects dari FASE 1:
//! LivenessSMT → uptime weights → EmissionAccumulator → EpochRewardManifest
//!
//! Flow Step 4 §B.5.1 (deterministik dari accepted_liveness_root):
//!   W(k) = Σ uptime_weight(node_i)
//!   E(k) = E₀ × (1 − M_E_prev/S_E)²
//!   ∀ node_i: reward_i = E(k) × w_i/W(k) + fee_share_i
//!   reward_root = MerkleRoot(sorted_by_node_id({node_id_i, reward_i}))

use crate::{
    accumulator::{EmissionAccumulator, FeeAccumulator},
    liveness::LivenessSMT,
    manifest::{EpochRewardManifest, EpochStatus, NodeReward},
    EmissionError,
};

/// Input untuk komputasi epoch — semua data yang dibutuhkan Step 4.
pub struct EpochInput<'a> {
    pub epoch_id: u64,
    /// accepted_liveness_root dari konsensus 67% (Step 3 §B.5.1)
    pub accepted_liveness_root: [u8; 32],
    /// Daftar node_id yang aktif epoch ini (dari LivenessSMT)
    pub active_node_ids: &'a [[u8; 32]],
    /// LivenessSMT yang sudah di-freeze pada epoch_end_timestamp
    pub liveness_smt: &'a LivenessSMT,
    /// EmissionAccumulator saat ini (M_E sebelum epoch ini)
    pub emission_acc: &'a EmissionAccumulator,
    /// FeeAccumulator epoch ini
    pub fee_acc: &'a FeeAccumulator,
}

/// Output komputasi epoch.
pub struct EpochOutput {
    pub manifest: EpochRewardManifest,
    /// E(k) yang dihitung — untuk di-commit ke EmissionAccumulator
    pub emission_amount: u64,
    /// Per-node rewards (sorted ascending by node_id) — untuk verifikasi
    pub node_rewards: Vec<NodeReward>,
}

/// Hitung manifest reward epoch k secara deterministik.
///
/// Semua node jujur yang memanggil fungsi ini dengan input identik
/// akan menghasilkan `reward_root` yang identik — properti kritis
/// untuk konsensus manifest (§B.5.1 Step 5).
///
/// CATATAN: Fungsi ini hanya komputasi (pure) — tidak mengubah state.
/// Pemanggil bertanggung jawab untuk:
///   1. Memanggil `EmissionAccumulator::commit_epoch(emission_amount)`
///   2. Mereset `FeeAccumulator` untuk epoch berikutnya
/// Kedua langkah ini hanya dilakukan setelah gate ≥67% terpenuhi (Step 6).
pub fn compute_epoch_rewards(input: &EpochInput) -> Result<EpochOutput, EmissionError> {
    // ── Step 4a: Hitung E(k) dari M_E sebelumnya ─────────────────────
    let e_k = input.emission_acc.emission_this_epoch();

    // ── Step 4b: Hitung uptime weight setiap node ────────────────────
    // w_i dalam fixed-point basis 1_000_000
    let weights: Vec<(usize, u64)> = input
        .active_node_ids
        .iter()
        .enumerate()
        .map(|(i, node_id)| {
            let w = input
                .liveness_smt
                .compute_uptime_weight_fp(node_id, input.epoch_id);
            (i, w)
        })
        .collect();

    // ── Step 4c: W(k) = Σ w_i (hanya node yang eligible, w_i > 0) ───
    let total_weight_fp: u64 = weights.iter().map(|(_, w)| w).sum();

    // ── Step 4d: Fee share per node (70% relay pool, proporsional) ───
    // Untuk FASE 2: fee share relay didistribusikan proporsional uptime.
    // Aggregator reward (25%) dan security fund (5%) ditangani terpisah
    // di Fase 5 (Batch Protocol). Di sini hanya relay share.
    let (relay_pool, _aggregator_pool, _security_fund) = input.fee_acc.distribution();

    // ── Step 4e: R_i(k) = E(k) × w_i/W(k) + fee_relay_i ───────────
    let mut node_rewards: Vec<NodeReward> = Vec::new();

    for (i, w_i) in &weights {
        if *w_i == 0 {
            // Di bawah threshold 30% — tidak eligible (§B.1.4)
            continue;
        }

        // PoU emission reward
        let pou_reward =
            EmissionAccumulator::reward_for_node(e_k, *w_i, total_weight_fp).unwrap_or(0);

        // Fee relay reward proporsional uptime
        let fee_relay_reward = if total_weight_fp > 0 {
            ((relay_pool as u128)
                .saturating_mul(*w_i as u128)
                .checked_div(total_weight_fp as u128)
                .unwrap_or(0)) as u64
        } else {
            0
        };

        let total_reward = pou_reward.saturating_add(fee_relay_reward);

        if total_reward > 0 {
            node_rewards.push(NodeReward {
                node_id: input.active_node_ids[*i],
                reward_amount: total_reward,
            });
        }
    }

    // ── Step 4f: Sort ascending by node_id — WAJIB untuk determinisme ─
    // §B.3.1: "Sorting key: sorted ascending by node_id"
    node_rewards.sort_unstable_by_key(|r| r.node_id);

    // ── Step 4g: reward_root = MerkleRoot(sorted rewards) ────────────
    let reward_root = EpochRewardManifest::compute_reward_root(&node_rewards);

    // ── Step 4h: Bangun manifest ──────────────────────────────────────
    let manifest = EpochRewardManifest {
        epoch_id: input.epoch_id,
        accepted_liveness_root: input.accepted_liveness_root,
        total_uptime_weight: total_weight_fp,
        emission_amount: e_k,
        fee_total: input.fee_acc.total_fee,
        reward_root,
        previous_emission_total: input.emission_acc.total_minted,
        status: EpochStatus::Finalized,
    };

    // Verifikasi invariant aritmetik sebelum return
    if !manifest.verify_arithmetic_invariants() {
        return Err(EmissionError::SupplyCapExceeded {
            minted: input.emission_acc.total_minted,
            reward: e_k,
            cap: crate::accumulator::S_E_SSCL,
        });
    }

    Ok(EpochOutput {
        manifest,
        emission_amount: e_k,
        node_rewards,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::liveness::NodeHeartbeat;

    /// Helper: buat node_id dari satu byte
    fn node(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    /// Helper: isi LivenessSMT dengan n heartbeat untuk node tertentu di epoch 0
    fn fill_heartbeats(smt: &mut LivenessSMT, node_id: [u8; 32], count: u64) {
        for i in 0..count {
            smt.insert_heartbeat(&NodeHeartbeat {
                node_id,
                timestamp: i * 600,
                smt_root: [0u8; 32],
                epoch_id: 0,
                signature: vec![],
            });
        }
    }

    #[test]
    fn test_compute_epoch_no_nodes() {
        let smt = LivenessSMT::new();
        let acc = EmissionAccumulator::new();
        let fee_acc = FeeAccumulator::new();

        let input = EpochInput {
            epoch_id: 0,
            accepted_liveness_root: [1u8; 32],
            active_node_ids: &[],
            liveness_smt: &smt,
            emission_acc: &acc,
            fee_acc: &fee_acc,
        };

        let output = compute_epoch_rewards(&input).unwrap();
        // Tidak ada node → tidak ada reward
        assert!(output.node_rewards.is_empty());
        assert_eq!(output.manifest.status, EpochStatus::Finalized);
        assert_eq!(output.manifest.reward_root, [0u8; 32]);
    }

    #[test]
    fn test_compute_epoch_below_threshold_excluded() {
        let mut smt = LivenessSMT::new();
        let n1 = node(1);
        // Hanya 1 heartbeat dari 4320 — jauh di bawah 30%
        fill_heartbeats(&mut smt, n1, 1);

        let acc = EmissionAccumulator::new();
        let fee_acc = FeeAccumulator::new();

        let input = EpochInput {
            epoch_id: 0,
            accepted_liveness_root: [1u8; 32],
            active_node_ids: &[n1],
            liveness_smt: &smt,
            emission_acc: &acc,
            fee_acc: &fee_acc,
        };

        let output = compute_epoch_rewards(&input).unwrap();
        // Node di bawah threshold → tidak dapat reward
        assert!(output.node_rewards.is_empty());
    }

    #[test]
    fn test_compute_epoch_single_node_full_uptime() {
        use crate::accumulator::E0_SSCL;
        use crate::liveness::EXPECTED_HEARTBEATS_PER_EPOCH;

        let mut smt = LivenessSMT::new();
        let n1 = node(1);
        fill_heartbeats(&mut smt, n1, EXPECTED_HEARTBEATS_PER_EPOCH);

        let acc = EmissionAccumulator::new(); // M_E = 0, E(0) = E₀
        let fee_acc = FeeAccumulator::new(); // fee = 0

        let input = EpochInput {
            epoch_id: 0,
            accepted_liveness_root: [1u8; 32],
            active_node_ids: &[n1],
            liveness_smt: &smt,
            emission_acc: &acc,
            fee_acc: &fee_acc,
        };

        let output = compute_epoch_rewards(&input).unwrap();

        assert_eq!(output.node_rewards.len(), 1);
        // Satu node, 100% uptime, W = 1_000_000, w_i = 1_000_000
        // R = E₀ × 1_000_000 / 1_000_000 = E₀
        assert_eq!(output.node_rewards[0].reward_amount, E0_SSCL);
        assert_eq!(output.emission_amount, E0_SSCL);
    }

    #[test]
    fn test_compute_epoch_two_nodes_proportional() {
        use crate::liveness::EXPECTED_HEARTBEATS_PER_EPOCH;

        let mut smt = LivenessSMT::new();
        let n1 = node(1);
        let n2 = node(2);

        // Node 1: 100% uptime, Node 2: 50% uptime
        fill_heartbeats(&mut smt, n1, EXPECTED_HEARTBEATS_PER_EPOCH);
        fill_heartbeats(&mut smt, n2, EXPECTED_HEARTBEATS_PER_EPOCH / 2);

        let acc = EmissionAccumulator::new();
        let fee_acc = FeeAccumulator::new();

        let input = EpochInput {
            epoch_id: 0,
            accepted_liveness_root: [1u8; 32],
            active_node_ids: &[n1, n2],
            liveness_smt: &smt,
            emission_acc: &acc,
            fee_acc: &fee_acc,
        };

        let output = compute_epoch_rewards(&input).unwrap();

        assert_eq!(output.node_rewards.len(), 2);

        // Sort sudah ascending by node_id
        let r1 = output.node_rewards[0].reward_amount; // node 1
        let r2 = output.node_rewards[1].reward_amount; // node 2

        // Node 1 (100%) harus dapat ~2× node 2 (50%)
        assert!(r1 > r2, "Node 100% uptime harus dapat lebih dari 50%");
        // Total tidak boleh melebihi E(k)
        assert!(r1 + r2 <= output.emission_amount);
    }

    #[test]
    fn test_reward_root_deterministic_same_input() {
        use crate::liveness::EXPECTED_HEARTBEATS_PER_EPOCH;

        let mut smt = LivenessSMT::new();
        let n1 = node(5);
        fill_heartbeats(&mut smt, n1, EXPECTED_HEARTBEATS_PER_EPOCH);

        let acc = EmissionAccumulator::new();
        let fee_acc = FeeAccumulator::new();
        let nodes = [n1];

        let input1 = EpochInput {
            epoch_id: 0,
            accepted_liveness_root: [9u8; 32],
            active_node_ids: &nodes,
            liveness_smt: &smt,
            emission_acc: &acc,
            fee_acc: &fee_acc,
        };
        let out1 = compute_epoch_rewards(&input1).unwrap();

        let input2 = EpochInput {
            epoch_id: 0,
            accepted_liveness_root: [9u8; 32],
            active_node_ids: &nodes,
            liveness_smt: &smt,
            emission_acc: &acc,
            fee_acc: &fee_acc,
        };
        let out2 = compute_epoch_rewards(&input2).unwrap();

        assert_eq!(
            out1.manifest.reward_root, out2.manifest.reward_root,
            "reward_root harus deterministik untuk input yang sama"
        );
    }

    #[test]
    fn test_node_rewards_sorted_ascending() {
        use crate::liveness::EXPECTED_HEARTBEATS_PER_EPOCH;

        let mut smt = LivenessSMT::new();
        // Masukkan dalam urutan terbalik (node 3, 2, 1)
        let n3 = node(3);
        let n2 = node(2);
        let n1 = node(1);
        fill_heartbeats(&mut smt, n3, EXPECTED_HEARTBEATS_PER_EPOCH);
        fill_heartbeats(&mut smt, n2, EXPECTED_HEARTBEATS_PER_EPOCH);
        fill_heartbeats(&mut smt, n1, EXPECTED_HEARTBEATS_PER_EPOCH);

        let acc = EmissionAccumulator::new();
        let fee_acc = FeeAccumulator::new();

        // active_node_ids dalam urutan acak
        let nodes = [n3, n1, n2];
        let input = EpochInput {
            epoch_id: 0,
            accepted_liveness_root: [1u8; 32],
            active_node_ids: &nodes,
            liveness_smt: &smt,
            emission_acc: &acc,
            fee_acc: &fee_acc,
        };

        let output = compute_epoch_rewards(&input).unwrap();

        // Verifikasi output selalu ascending by node_id
        for i in 1..output.node_rewards.len() {
            assert!(
                output.node_rewards[i - 1].node_id <= output.node_rewards[i].node_id,
                "NodeRewards harus sorted ascending by node_id"
            );
        }
    }

    #[test]
    fn test_emission_decreases_over_epochs() {
        use crate::accumulator::E0_SSCL;
        use crate::liveness::EXPECTED_HEARTBEATS_PER_EPOCH;

        let mut smt = LivenessSMT::new();
        let n1 = node(1);
        fill_heartbeats(&mut smt, n1, EXPECTED_HEARTBEATS_PER_EPOCH);

        // Epoch 0: M_E = 0
        let mut acc = EmissionAccumulator::new();
        let fee_acc = FeeAccumulator::new();

        let input0 = EpochInput {
            epoch_id: 0,
            accepted_liveness_root: [1u8; 32],
            active_node_ids: &[n1],
            liveness_smt: &smt,
            emission_acc: &acc,
            fee_acc: &fee_acc,
        };
        let out0 = compute_epoch_rewards(&input0).unwrap();
        assert_eq!(out0.emission_amount, E0_SSCL); // Epoch 0 = E₀

        // Commit epoch 0
        acc.commit_epoch(out0.emission_amount).unwrap();

        // Epoch 1: M_E > 0 → E(1) < E₀
        let input1 = EpochInput {
            epoch_id: 1,
            accepted_liveness_root: [2u8; 32],
            active_node_ids: &[n1],
            liveness_smt: &smt,
            emission_acc: &acc,
            fee_acc: &fee_acc,
        };
        let out1 = compute_epoch_rewards(&input1).unwrap();
        assert!(
            out1.emission_amount < out0.emission_amount,
            "Emisi harus berkurang setiap epoch"
        );
    }

    #[test]
    fn test_fee_included_in_relay_reward() {
        use crate::liveness::EXPECTED_HEARTBEATS_PER_EPOCH;

        let mut smt = LivenessSMT::new();
        let n1 = node(1);
        fill_heartbeats(&mut smt, n1, EXPECTED_HEARTBEATS_PER_EPOCH);

        let acc = EmissionAccumulator::new();
        let mut fee_acc = FeeAccumulator::new();
        fee_acc.add_fee(10_000_000).unwrap(); // 0.1 SCL fee

        let input = EpochInput {
            epoch_id: 0,
            accepted_liveness_root: [1u8; 32],
            active_node_ids: &[n1],
            liveness_smt: &smt,
            emission_acc: &acc,
            fee_acc: &fee_acc,
        };

        let output_with_fee = compute_epoch_rewards(&input).unwrap();

        // Reward dengan fee harus > reward tanpa fee
        let fee_acc_empty = FeeAccumulator::new();
        let input_no_fee = EpochInput {
            epoch_id: 0,
            accepted_liveness_root: [1u8; 32],
            active_node_ids: &[n1],
            liveness_smt: &smt,
            emission_acc: &acc,
            fee_acc: &fee_acc_empty,
        };
        let output_no_fee = compute_epoch_rewards(&input_no_fee).unwrap();

        assert!(
            output_with_fee.node_rewards[0].reward_amount
                > output_no_fee.node_rewards[0].reward_amount,
            "Fee harus meningkatkan reward node"
        );
    }
}
