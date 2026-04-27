//! EpochRewardManifest Consensus Protocol — Protokol 6-langkah
//!
//! Spesifikasi: Scalar_Master_Technical_Spec.docx §B.5
//!
//! Step 1: Epoch Close — freeze LivenessSMT pada epoch_end_timestamp
//! Step 2: Broadcast LivenessRootAnnouncement ke semua peers
//! Step 3: Root Consensus — hitung mode, threshold 67% (OSSIFIED)
//! Step 4: Manifest Computation — deterministik dari accepted_liveness_root
//! Step 5: Manifest Verification — recompute dan bandingkan
//! Step 6: Mint Claim Gate — buka hanya jika ≥67% accepted
//!
//! Parameter ossified (§B.5.3 + §B.6):
//! - LIVENESS_CONSENSUS_THRESHOLD = 67%
//! - T_collect = 10 menit (Layer 2, default)
//! - T_extend  = 30 menit (Layer 2, default)
//! - Epoch boundary: tegas, no grace window
//! - DEFERRED → no makeup policy

use crate::{
    accumulator::{EmissionAccumulator, FeeAccumulator},
    epoch::{compute_epoch_rewards, EpochInput},
    liveness::LivenessSMT,
    manifest::{EpochRewardManifest, EpochStatus},
};
use std::collections::HashMap;

// ── Konstanta ossified (§B.5.3 + §B.6) ─────────────────────────────

/// Threshold konsensus liveness root (67%). OSSIFIED.
/// Identik dengan finality threshold transaksi biasa.
pub const LIVENESS_CONSENSUS_THRESHOLD_NUM: u64 = 67;
pub const LIVENESS_CONSENSUS_THRESHOLD_DEN: u64 = 100;

/// T_collect default: 10 menit dalam detik. Layer 2 CONSTRAINED.
pub const T_COLLECT_SECS_DEFAULT: u64 = 10 * 60;

/// T_extend default: 30 menit dalam detik. Layer 2 CONSTRAINED.
pub const T_EXTEND_SECS_DEFAULT: u64 = 30 * 60;

// ── Structs ──────────────────────────────────────────────────────────

/// LivenessRootAnnouncement — broadcast Step 2 §B.5.1
///
/// Setiap node mem-broadcast ini setelah epoch close.
/// Signature SPHINCS+ diverifikasi oleh penerima sebelum
/// announcement dimasukkan ke pool.
#[derive(Debug, Clone)]
pub struct LivenessRootAnnouncement {
    pub epoch_id: u64,
    pub liveness_root: [u8; 32],
    pub node_id: [u8; 32],
    pub timestamp: u64,
    /// SPHINCS+ signature atas (epoch_id ∥ liveness_root ∥ node_id ∥ timestamp)
    /// Verifikasi dilakukan di luar struct ini (publik, seperti C8).
    pub node_signature: Vec<u8>,
}

/// Hasil Step 3 — Root Consensus
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusResult {
    /// ≥67% sepakat pada satu root — lanjut ke Step 4
    Accepted {
        accepted_liveness_root: [u8; 32],
        /// Fraksi yang setuju (dalam basis 100)
        fraction_pct: u64,
    },
    /// Tidak ada root yang mencapai 67% setelah T_extend
    /// → EPOCH_REWARD_DEFERRED (§B.5.2)
    Deferred,
}

/// Status mint claim gate (Step 6)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintClaimGate {
    /// Gate terbuka — MINT_CLAIM_CIRCUIT boleh dijalankan
    Open { manifest: EpochRewardManifest },
    /// Gate tertutup — epoch DEFERRED, tidak ada claim selamanya
    Closed { reason: &'static str },
}

// ── Step 1: Epoch Close ──────────────────────────────────────────────

/// Step 1: Ambil snapshot liveness_root pada epoch_end_timestamp.
///
/// Batas tegas: heartbeat setelah timestamp ini masuk epoch berikutnya.
/// Tidak ada grace window (OSSIFIED §B.5.3).
///
/// Dalam implementasi produksi, `current_timestamp` dibandingkan
/// dengan `epoch_end_timestamp` yang ditetapkan saat genesis.
/// Di sini fungsi ini menerima LivenessSMT yang sudah di-freeze.
pub fn step1_epoch_close(liveness_smt: &LivenessSMT) -> [u8; 32] {
    liveness_smt.root()
}

// ── Step 3: Root Consensus ───────────────────────────────────────────

/// Step 3: Hitung mode dari announcements yang terkumpul.
///
/// winner_frac = root_counts[winner_root] / total_announcements
/// Jika winner_frac ≥ 67% → Accepted
/// Jika tidak → Deferred (setelah T_extend juga gagal)
///
/// OSSIFIED: threshold 67% tidak bisa diubah tanpa fork (§B.5.3).
pub fn step3_compute_consensus(announcements: &[LivenessRootAnnouncement]) -> ConsensusResult {
    if announcements.is_empty() {
        return ConsensusResult::Deferred;
    }

    // Hitung frekuensi setiap root
    let mut counts: HashMap<[u8; 32], u64> = HashMap::new();
    for ann in announcements {
        *counts.entry(ann.liveness_root).or_insert(0) += 1;
    }

    let total = announcements.len() as u64;

    // Cari root dengan count tertinggi
    let (winner_root, winner_count) = counts
        .iter()
        .max_by_key(|(_, &c)| c)
        .map(|(&r, &c)| (r, c))
        .unwrap();

    // Threshold: winner_count / total ≥ 67/100
    // Integer arithmetic: winner_count * 100 ≥ total * 67
    if winner_count * LIVENESS_CONSENSUS_THRESHOLD_DEN >= total * LIVENESS_CONSENSUS_THRESHOLD_NUM {
        let fraction_pct = (winner_count * 100) / total;
        ConsensusResult::Accepted {
            accepted_liveness_root: winner_root,
            fraction_pct,
        }
    } else {
        ConsensusResult::Deferred
    }
}

// ── Step 5: Manifest Verification ───────────────────────────────────

/// Step 5: Verifikasi manifest yang diterima dari peer.
///
/// Recompute manifest dari accepted_liveness_root dan bandingkan
/// reward_root. Jika tidak sama → REJECT (§B.5.1 Step 5).
///
/// Return Ok(()) jika manifest valid, Err jika mismatch.
pub fn step5_verify_manifest(
    received_manifest: &EpochRewardManifest,
    accepted_liveness_root: [u8; 32],
    active_node_ids: &[[u8; 32]],
    liveness_smt: &LivenessSMT,
    emission_acc: &EmissionAccumulator,
    fee_acc: &FeeAccumulator,
) -> Result<(), &'static str> {
    // Manifest DEFERRED: reward_root harus NULL ([0u8; 32])
    if received_manifest.status == EpochStatus::Deferred {
        if received_manifest.reward_root != [0u8; 32] {
            return Err("Step5: manifest DEFERRED tapi reward_root bukan NULL");
        }
        return Ok(());
    }

    // Recompute manifest dari accepted_liveness_root
    let input = EpochInput {
        epoch_id: received_manifest.epoch_id,
        accepted_liveness_root,
        active_node_ids,
        liveness_smt,
        emission_acc,
        fee_acc,
    };

    let recomputed =
        compute_epoch_rewards(&input).map_err(|_| "Step5: gagal recompute manifest")?;

    // Bandingkan reward_root — harus identik (deterministik)
    if recomputed.manifest.reward_root != received_manifest.reward_root {
        return Err("Step5: reward_root mismatch — manifest ditolak");
    }

    // Bandingkan emission_amount
    if recomputed.manifest.emission_amount != received_manifest.emission_amount {
        return Err("Step5: emission_amount mismatch — manifest ditolak");
    }

    Ok(())
}

// ── Step 6: Mint Claim Gate ──────────────────────────────────────────

/// Step 6: Buka atau tutup mint claim gate.
///
/// Gate terbuka hanya jika:
///   1. ConsensusResult::Accepted (≥67%)
///   2. EmissionAccumulator berhasil di-commit dengan E(k)
///
/// Jika gate terbuka: EmissionAccumulator.commit_epoch() dipanggil
/// SEBELUM gate dibuka (§B.5.1 Step 6: "UPDATE EmissionAccumulator += E_k
/// sebelum gate mint claim dibuka").
///
/// Jika DEFERRED: EmissionAccumulator TIDAK berubah (§B.5.2).
pub fn step6_mint_claim_gate(
    consensus: ConsensusResult,
    epoch_id: u64,
    active_node_ids: &[[u8; 32]],
    liveness_smt: &LivenessSMT,
    emission_acc: &mut EmissionAccumulator,
    fee_acc: &FeeAccumulator,
) -> MintClaimGate {
    match consensus {
        ConsensusResult::Deferred => {
            // DEFERRED: EmissionAccumulator tidak berubah (§B.5.2)
            // reward_root = NULL, tidak ada claim selamanya
            MintClaimGate::Closed {
                reason: "EPOCH_REWARD_DEFERRED: konsensus gagal setelah T_extend",
            }
        }

        ConsensusResult::Accepted {
            accepted_liveness_root,
            ..
        } => {
            // Step 4: Compute manifest
            let input = EpochInput {
                epoch_id,
                accepted_liveness_root,
                active_node_ids,
                liveness_smt,
                emission_acc: &*emission_acc,
                fee_acc,
            };

            let output = match compute_epoch_rewards(&input) {
                Ok(o) => o,
                Err(_) => {
                    return MintClaimGate::Closed {
                        reason: "Step4: gagal compute epoch rewards",
                    }
                }
            };

            // Step 6: Update EmissionAccumulator SEBELUM gate dibuka
            if let Err(_) = emission_acc.commit_epoch(output.emission_amount) {
                return MintClaimGate::Closed {
                    reason: "Step6: supply cap terlampaui saat commit emission",
                };
            }

            MintClaimGate::Open {
                manifest: output.manifest,
            }
        }
    }
}

// ── Full Protocol (untuk testing) ───────────────────────────────────

/// Jalankan protokol 6-langkah secara sinkron (untuk testing/simulasi).
///
/// Dalam produksi, Step 2 dan 3 bersifat async dengan timeout T_collect
/// dan T_extend. Di sini semua announcements sudah tersedia.
pub fn run_epoch_consensus_protocol(
    epoch_id: u64,
    liveness_smt: &LivenessSMT,
    announcements: &[LivenessRootAnnouncement],
    active_node_ids: &[[u8; 32]],
    emission_acc: &mut EmissionAccumulator,
    fee_acc: &FeeAccumulator,
) -> MintClaimGate {
    // Step 1
    let _my_root = step1_epoch_close(liveness_smt);

    // Step 3 (Step 2 = broadcast, sudah dilakukan oleh layer network)
    let consensus = step3_compute_consensus(announcements);

    // Step 6 (Step 4 dan 5 di dalam step6)
    step6_mint_claim_gate(
        consensus,
        epoch_id,
        active_node_ids,
        liveness_smt,
        emission_acc,
        fee_acc,
    )
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::liveness::{LivenessSMT, NodeHeartbeat, EXPECTED_HEARTBEATS_PER_EPOCH};

    fn node(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    fn announcement(epoch_id: u64, node_id: [u8; 32], root: [u8; 32]) -> LivenessRootAnnouncement {
        LivenessRootAnnouncement {
            epoch_id,
            liveness_root: root,
            node_id,
            timestamp: 12345,
            node_signature: vec![],
        }
    }

    fn fill_smt(smt: &mut LivenessSMT, node_id: [u8; 32], count: u64, epoch_id: u64) {
        for i in 0..count {
            smt.insert_heartbeat(&NodeHeartbeat {
                node_id,
                timestamp: i * 600,
                smt_root: [0u8; 32],
                epoch_id,
                signature: vec![],
            });
        }
    }

    // ── Step 3: Consensus ─────────────────────────────────────────────

    #[test]
    fn test_consensus_threshold_exact_67() {
        // 67 dari 100 node setuju → harus Accepted
        let root_a = [1u8; 32];
        let root_b = [2u8; 32];
        let mut anns = Vec::new();
        for i in 0..67u8 {
            anns.push(announcement(0, node(i), root_a));
        }
        for i in 67..100u8 {
            anns.push(announcement(0, node(i), root_b));
        }
        let result = step3_compute_consensus(&anns);
        assert!(matches!(result, ConsensusResult::Accepted { .. }));
        if let ConsensusResult::Accepted {
            accepted_liveness_root,
            fraction_pct,
        } = result
        {
            assert_eq!(accepted_liveness_root, root_a);
            assert_eq!(fraction_pct, 67);
        }
    }

    #[test]
    fn test_consensus_below_threshold_deferred() {
        // 66 dari 100 → DEFERRED (< 67%)
        let root_a = [1u8; 32];
        let root_b = [2u8; 32];
        let mut anns = Vec::new();
        for i in 0..66u8 {
            anns.push(announcement(0, node(i), root_a));
        }
        for i in 66..100u8 {
            anns.push(announcement(0, node(i), root_b));
        }
        assert_eq!(step3_compute_consensus(&anns), ConsensusResult::Deferred);
    }

    #[test]
    fn test_consensus_100_percent_agreement() {
        let root = [9u8; 32];
        let anns: Vec<_> = (0..50u8).map(|i| announcement(0, node(i), root)).collect();
        let result = step3_compute_consensus(&anns);
        assert!(matches!(
            result,
            ConsensusResult::Accepted {
                fraction_pct: 100,
                ..
            }
        ));
    }

    #[test]
    fn test_consensus_empty_announcements() {
        assert_eq!(step3_compute_consensus(&[]), ConsensusResult::Deferred);
    }

    #[test]
    fn test_consensus_single_announcement() {
        // 1 dari 1 = 100% → Accepted
        let anns = vec![announcement(0, node(1), [5u8; 32])];
        assert!(matches!(
            step3_compute_consensus(&anns),
            ConsensusResult::Accepted { .. }
        ));
    }

    // ── Step 5: Manifest Verification ────────────────────────────────

    #[test]
    fn test_step5_deferred_manifest_valid() {
        let deferred = EpochRewardManifest::deferred(0, 0);
        let smt = LivenessSMT::new();
        let acc = EmissionAccumulator::new();
        let fee_acc = FeeAccumulator::new();

        let result = step5_verify_manifest(&deferred, [0u8; 32], &[], &smt, &acc, &fee_acc);
        assert!(result.is_ok());
    }

    #[test]
    fn test_step5_deferred_manifest_nonzero_root_rejected() {
        let mut deferred = EpochRewardManifest::deferred(0, 0);
        // Manipulasi: set reward_root non-zero pada manifest DEFERRED
        deferred.reward_root = [1u8; 32];

        let smt = LivenessSMT::new();
        let acc = EmissionAccumulator::new();
        let fee_acc = FeeAccumulator::new();

        let result = step5_verify_manifest(&deferred, [0u8; 32], &[], &smt, &acc, &fee_acc);
        assert!(result.is_err());
    }

    // ── Step 6: Mint Claim Gate ───────────────────────────────────────

    #[test]
    fn test_step6_deferred_closes_gate() {
        let smt = LivenessSMT::new();
        let mut acc = EmissionAccumulator::new();
        let fee_acc = FeeAccumulator::new();

        let gate =
            step6_mint_claim_gate(ConsensusResult::Deferred, 0, &[], &smt, &mut acc, &fee_acc);

        assert!(matches!(gate, MintClaimGate::Closed { .. }));
        // EmissionAccumulator tidak berubah (no-makeup policy)
        assert_eq!(acc.total_minted, 0);
    }

    #[test]
    fn test_step6_accepted_opens_gate_and_commits_emission() {
        let mut smt = LivenessSMT::new();
        let n1 = node(1);
        fill_smt(&mut smt, n1, EXPECTED_HEARTBEATS_PER_EPOCH, 0);

        let liveness_root = smt.root();
        let mut acc = EmissionAccumulator::new();
        let fee_acc = FeeAccumulator::new();
        let nodes = [n1];

        let gate = step6_mint_claim_gate(
            ConsensusResult::Accepted {
                accepted_liveness_root: liveness_root,
                fraction_pct: 100,
            },
            0,
            &nodes,
            &smt,
            &mut acc,
            &fee_acc,
        );

        // Gate harus terbuka
        assert!(matches!(gate, MintClaimGate::Open { .. }));

        // EmissionAccumulator harus sudah di-commit dengan E(0) = E₀
        use crate::accumulator::E0_SSCL;
        assert_eq!(
            acc.total_minted, E0_SSCL,
            "EmissionAccumulator harus di-commit sebelum gate dibuka"
        );
    }

    // ── Full Protocol ─────────────────────────────────────────────────

    #[test]
    fn test_full_protocol_happy_path() {
        let mut smt = LivenessSMT::new();
        let n1 = node(1);
        let n2 = node(2);
        fill_smt(&mut smt, n1, EXPECTED_HEARTBEATS_PER_EPOCH, 0);
        fill_smt(&mut smt, n2, EXPECTED_HEARTBEATS_PER_EPOCH, 0);

        let liveness_root = smt.root();
        let mut acc = EmissionAccumulator::new();
        let fee_acc = FeeAccumulator::new();
        let nodes = [n1, n2];

        // 80% setuju pada root yang sama (>67%) → Accepted
        let mut anns = Vec::new();
        for i in 0..80u8 {
            anns.push(announcement(0, node(i + 10), liveness_root));
        }
        for i in 0..20u8 {
            anns.push(announcement(0, node(i + 90), [0xABu8; 32]));
        }

        let gate = run_epoch_consensus_protocol(0, &smt, &anns, &nodes, &mut acc, &fee_acc);

        assert!(
            matches!(gate, MintClaimGate::Open { .. }),
            "Happy path harus menghasilkan gate Open"
        );

        // Emission sudah di-commit
        assert!(
            acc.total_minted > 0,
            "EmissionAccumulator harus di-update setelah gate dibuka"
        );
    }

    #[test]
    fn test_full_protocol_no_consensus_deferred() {
        let smt = LivenessSMT::new();
        let mut acc = EmissionAccumulator::new();
        let fee_acc = FeeAccumulator::new();

        // Split 50/50 — tidak ada yang mencapai 67%
        let mut anns = Vec::new();
        for i in 0..50u8 {
            anns.push(announcement(0, node(i), [1u8; 32]));
        }
        for i in 50..100u8 {
            anns.push(announcement(0, node(i), [2u8; 32]));
        }

        let gate = run_epoch_consensus_protocol(0, &smt, &anns, &[], &mut acc, &fee_acc);

        assert!(
            matches!(gate, MintClaimGate::Closed { .. }),
            "Split 50/50 harus menghasilkan DEFERRED"
        );

        // EmissionAccumulator tidak berubah
        assert_eq!(
            acc.total_minted, 0,
            "DEFERRED: EmissionAccumulator tidak boleh berubah"
        );
    }

    #[test]
    fn test_deferred_no_makeup_next_epoch() {
        // Epoch 0: DEFERRED → M_E = 0
        // Epoch 1: E(1) dihitung dari M_E(0) = 0 → sama dengan E(0) = E₀
        // (no-makeup: bukan kompensasi, hanya formula normal dari M_E yang tidak berubah)
        use crate::accumulator::E0_SSCL;

        let acc_after_deferred = EmissionAccumulator::new(); // M_E = 0 (tidak berubah)
                                                             // E(1) = E₀ × (1 - 0)² = E₀ — normal, bukan kompensasi
        assert_eq!(
            acc_after_deferred.emission_this_epoch(),
            E0_SSCL,
            "Epoch setelah DEFERRED harus hitung normal dari M_E yang tidak berubah"
        );
    }
}
