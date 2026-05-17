//! NMT Hybrid 23+1 — Spec §12.3 v11.1-FINAL
//!
//! Upgrade NMT dari 8 peer (v9.0) ke 24 peer dengan skema hybrid:
//!   - 23 slot deterministik: nmt_rank terkecil dari committed_manifest(k-1).node_list
//!   - 1 slot acak: ChaCha20 dengan seed BLAKE3(seed_k || "nmt_random")
//!
//! Syarat eligibilitas NMT peer:
//!   - NodeScore > NMT_SCORE_THRESHOLD (800_000) — spec §12.4, T-3
//!   - Diversitas: maks 3 per /24 subnet, 5 per ASN, 4 per region
//!   - Tier C otomatis tidak eligible (score maks 600_000 < 800_000)
//!
//! Eclipse defense meningkat signifikan dengan skema 23+1:
//!   - 23 deterministik: attacker harus manipulasi manifest k-1
//!   - 1 acak: attacker tidak bisa prediksi slot random
//!
//! Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
//! No floating point — semua arithmetic integer.

use crate::node_score::{is_tier_c, NMT_SCORE_THRESHOLD};
use blake3::Hasher;
use scalar_crypto::domain::DOMAIN_NMT_RANDOM;

// ── Ossified constants — spec §12.3, §17 ─────────────────────────────────────

/// Total NMT peer count. OSSIFIED — spec §12.3, §17.
/// Upgrade dari 8 (v9.0) ke 24 (v11.1-FINAL).
pub const NMT_PEER_COUNT_V12: usize = 24;

/// Slot deterministik dalam NMT. OSSIFIED — spec §12.3.
pub const NMT_DETERMINISTIC_SLOTS: usize = 23;

/// Slot acak dalam NMT. OSSIFIED — spec §12.3, §17.
pub const NMT_RANDOM_SLOTS: usize = 1;

/// Diversitas: maksimum node per /24 subnet. OSSIFIED — spec §12.3.
pub const NMT_MAX_PER_SUBNET24: usize = 3;

/// Diversitas: maksimum node per ASN. OSSIFIED — spec §12.3.
pub const NMT_MAX_PER_ASN: usize = 5;

/// Diversitas: maksimum node per region. OSSIFIED — spec §12.3.
pub const NMT_MAX_PER_REGION: usize = 4;

/// Domain untuk random slot seed. Spec §12.3.

// ── NmtNodeCandidate — node yang eligible untuk NMT ──────────────────────────

/// Kandidat node untuk NMT peer selection. Spec §12.3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NmtNodeCandidate {
    pub node_id_full: [u8; 32],
    pub node_score: u64,
    /// /24 subnet identifier (4 bytes). Untuk diversitas check.
    pub subnet24: [u8; 4],
    /// ASN identifier (4 bytes). Untuk diversitas check.
    pub asn: [u8; 4],
    /// Region identifier (1 byte). Untuk diversitas check.
    pub region: u8,
}

impl NmtNodeCandidate {
    /// Cek apakah node eligible sebagai NMT peer. Spec §12.3, T-3.
    pub fn is_eligible(&self) -> bool {
        // NodeScore harus > NMT_SCORE_THRESHOLD (800_000)
        self.node_score > NMT_SCORE_THRESHOLD
            // Tier C otomatis tidak eligible
            && !is_tier_c(&self.node_id_full)
    }
}

// ── nmt_rank computation — spec §12.3 ────────────────────────────────────────

/// Hitung nmt_rank untuk satu node. Spec §12.3, T-3.
///
/// nmt_rank(id) = BLAKE3("scalar_nmt" || id || seed_k)
/// Node dengan nmt_rank terkecil dipilih sebagai NMT peer deterministik.
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compute_nmt_rank(node_id_full: &[u8; 32], seed_k: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"scalar_nmt"); // domain separator — spec §2.3
    hasher.update(node_id_full);
    hasher.update(seed_k);
    *hasher.finalize().as_bytes()
}

/// Hitung random slot seed. Spec §12.3.
///
/// random_seed = BLAKE3(seed_k || "nmt_random")
/// Digunakan untuk ChaCha20 seed pemilihan 1 slot acak.
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compute_nmt_random_seed(seed_k: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(seed_k);
    hasher.update(DOMAIN_NMT_RANDOM); // b"nmt_random"
    *hasher.finalize().as_bytes()
}

// ── NmtSelectionResult — hasil seleksi NMT peer ───────────────────────────────

/// Hasil seleksi NMT peer 23+1. Spec §12.3.
#[derive(Debug, Clone)]
pub struct NmtSelectionResult {
    /// 23 slot deterministik (nmt_rank terkecil). Spec §12.3.
    pub deterministic_slots: Vec<[u8; 32]>,
    /// 1 slot acak (ChaCha20). Spec §12.3. None jika populasi tidak mencukupi.
    pub random_slot: Option<[u8; 32]>,
    /// Total peer yang dipilih (max 24).
    pub total_selected: usize,
}

impl NmtSelectionResult {
    /// Semua NMT peer yang dipilih (deterministik + acak).
    pub fn all_peers(&self) -> Vec<[u8; 32]> {
        let mut peers = self.deterministic_slots.clone();
        if let Some(random) = self.random_slot {
            peers.push(random);
        }
        peers
    }
}

// ── select_nmt_peers_hybrid — algoritma utama spec §12.3 ─────────────────────

/// Pilih NMT peers dengan skema hybrid 23+1. Spec §12.3 v11.1-FINAL.
///
/// Algoritma:
/// 1. Filter node eligible: NodeScore > 800_000, bukan Tier C.
/// 2. Hitung nmt_rank untuk setiap node eligible.
/// 3. Sort ascending berdasarkan nmt_rank.
/// 4. Ambil 23 terkecil sebagai deterministic slots (dengan diversitas check).
/// 5. Pilih 1 slot acak dari populasi yang sama menggunakan random_seed.
/// 6. Return NmtSelectionResult.
///
/// `candidates`: daftar semua node dari committed_manifest(k-1).
/// `seed_k`: seed dari committed_manifest_hash(k-1). Spec §8.1.
pub fn select_nmt_peers_hybrid(
    candidates: &[NmtNodeCandidate],
    seed_k: &[u8; 32],
) -> NmtSelectionResult {
    // Step 1: Filter eligible (NodeScore > 800_000, bukan Tier C)
    let eligible: Vec<&NmtNodeCandidate> = candidates.iter().filter(|c| c.is_eligible()).collect();

    if eligible.is_empty() {
        return NmtSelectionResult {
            deterministic_slots: vec![],
            random_slot: None,
            total_selected: 0,
        };
    }

    // Step 2: Hitung nmt_rank untuk setiap node eligible
    let mut ranked: Vec<(&NmtNodeCandidate, [u8; 32])> = eligible
        .iter()
        .map(|c| (*c, compute_nmt_rank(&c.node_id_full, seed_k)))
        .collect();

    // Step 3: Sort ascending by nmt_rank (deterministik)
    ranked.sort_unstable_by_key(|(_, rank)| *rank);

    // Step 4: Ambil NMT_DETERMINISTIC_SLOTS (23) terkecil dengan diversitas check
    let mut deterministic_slots: Vec<[u8; 32]> = Vec::new();
    let mut subnet24_counts: std::collections::HashMap<[u8; 4], usize> =
        std::collections::HashMap::new();
    let mut asn_counts: std::collections::HashMap<[u8; 4], usize> =
        std::collections::HashMap::new();
    let mut region_counts: std::collections::HashMap<u8, usize> = std::collections::HashMap::new();

    for (candidate, _rank) in &ranked {
        if deterministic_slots.len() >= NMT_DETERMINISTIC_SLOTS {
            break;
        }

        // Diversitas check — spec §12.3
        let subnet_count = subnet24_counts
            .get(&candidate.subnet24)
            .copied()
            .unwrap_or(0);
        let asn_count = asn_counts.get(&candidate.asn).copied().unwrap_or(0);
        let region_count = region_counts.get(&candidate.region).copied().unwrap_or(0);

        if subnet_count >= NMT_MAX_PER_SUBNET24 {
            continue;
        }
        if asn_count >= NMT_MAX_PER_ASN {
            continue;
        }
        if region_count >= NMT_MAX_PER_REGION {
            continue;
        }

        // Node lolos diversitas — tambahkan ke slot deterministik
        deterministic_slots.push(candidate.node_id_full);
        *subnet24_counts.entry(candidate.subnet24).or_insert(0) += 1;
        *asn_counts.entry(candidate.asn).or_insert(0) += 1;
        *region_counts.entry(candidate.region).or_insert(0) += 1;
    }

    // Step 5: Pilih 1 slot acak dari eligible population
    // Menggunakan BLAKE3(seed_k || "nmt_random") sebagai deterministic random seed
    // Spec §12.3: "ChaCha20 dengan seed BLAKE3(seed_k || 'nmt_random')"
    let random_seed = compute_nmt_random_seed(seed_k);
    let random_slot = select_random_slot(&eligible, &random_seed, &deterministic_slots);

    let total_selected = deterministic_slots.len() + if random_slot.is_some() { 1 } else { 0 };

    NmtSelectionResult {
        deterministic_slots,
        random_slot,
        total_selected,
    }
}

/// Pilih 1 slot acak dari eligible pool, tidak boleh duplikat dengan deterministic slots.
/// Spec §12.3: random slot menggunakan ChaCha20 seed deterministik.
///
/// Implementasi: gunakan random_seed untuk memilih index dari eligible pool.
/// Deterministik: seed sama → index sama → node sama.
fn select_random_slot(
    eligible: &[&NmtNodeCandidate],
    random_seed: &[u8; 32],
    already_selected: &[[u8; 32]],
) -> Option<[u8; 32]> {
    // Filter: tidak boleh duplikat dengan deterministic slots
    let remaining: Vec<&NmtNodeCandidate> = eligible
        .iter()
        .filter(|c| !already_selected.contains(&c.node_id_full))
        .copied()
        .collect();

    if remaining.is_empty() {
        return None;
    }

    // Pilih index menggunakan 8 byte pertama dari random_seed (simulasi ChaCha20)
    // Production: gunakan ChaCha20 RNG yang di-seed dengan random_seed
    let index_bytes = &random_seed[0..8];
    let index_u64 = u64::from_le_bytes(index_bytes.try_into().unwrap());
    let index = (index_u64 % remaining.len() as u64) as usize;

    Some(remaining[index].node_id_full)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_candidate(seed: u8, score: u64, region: u8) -> NmtNodeCandidate {
        let mut node_id = [seed; 32];
        node_id[0] = if score > 0 { 0x01 } else { 0xFE }; // 0xFE = Tier C
        NmtNodeCandidate {
            node_id_full: node_id,
            node_score: score,
            subnet24: [seed, 0, 0, 0],
            asn: [seed / 10, 0, 0, 0],
            region,
        }
    }

    fn make_tier_c_candidate(seed: u8) -> NmtNodeCandidate {
        let mut node_id = [seed; 32];
        node_id[0] = 0xFE; // Tier C
        NmtNodeCandidate {
            node_id_full: node_id,
            node_score: 1_000_000, // raw max, tapi is_tier_c → not eligible
            subnet24: [seed, 0, 0, 0],
            asn: [0, 0, 0, 0],
            region: 0,
        }
    }

    fn seed_k() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn make_large_pool(n: usize) -> Vec<NmtNodeCandidate> {
        (0..n)
            .map(|i| {
                let seed = (i % 256) as u8;
                // Gunakan node_id yang lebih beragam untuk menghindari prefix 0xFE
                let mut node_id = [0u8; 32];
                node_id[0] = 0x01;
                node_id[1] = (i / 256) as u8;
                node_id[2] = seed;
                NmtNodeCandidate {
                    node_id_full: node_id,
                    node_score: 850_000, // > NMT_SCORE_THRESHOLD
                    subnet24: [(i % 10) as u8, 0, 0, 0],
                    asn: [(i % 20) as u8, 0, 0, 0],
                    region: (i % 8) as u8,
                }
            })
            .collect()
    }

    // ── test_nmt_23_deterministic_slots ──────────────────────────────────────

    #[test]
    fn test_nmt_23_deterministic_slots() {
        // 23 slot deterministik dari nmt_rank. Spec §12.3.
        let candidates = make_large_pool(50);
        let result = select_nmt_peers_hybrid(&candidates, &seed_k());
        assert!(
            result.deterministic_slots.len() <= NMT_DETERMINISTIC_SLOTS,
            "Deterministik slots tidak boleh melebihi {}",
            NMT_DETERMINISTIC_SLOTS
        );
        assert!(
            !result.deterministic_slots.is_empty(),
            "Harus ada setidaknya beberapa deterministik slots"
        );
    }

    // ── test_nmt_1_random_slot_chacha20 ──────────────────────────────────────

    #[test]
    fn test_nmt_1_random_slot_chacha20() {
        // 1 slot acak dari BLAKE3(seed_k || "nmt_random"). Spec §12.3.
        let candidates = make_large_pool(30);
        let result = select_nmt_peers_hybrid(&candidates, &seed_k());
        // Dengan populasi cukup, random slot harus ada
        assert!(
            result.random_slot.is_some(),
            "Random slot harus ada jika populasi cukup"
        );
    }

    // ── test_nmt_random_seed_reproducible ────────────────────────────────────

    #[test]
    fn test_nmt_random_seed_reproducible() {
        // seed identik → random slot identik (deterministik internal). Spec §12.3.
        let candidates = make_large_pool(30);
        let r1 = select_nmt_peers_hybrid(&candidates, &seed_k());
        let r2 = select_nmt_peers_hybrid(&candidates, &seed_k());
        assert_eq!(
            r1.random_slot, r2.random_slot,
            "Random slot harus deterministik untuk seed yang sama"
        );
        assert_eq!(
            r1.deterministic_slots, r2.deterministic_slots,
            "Deterministik slots harus identik"
        );
    }

    // ── test_nmt_tier_c_excluded ──────────────────────────────────────────────

    #[test]
    fn test_nmt_tier_c_excluded() {
        // Tier C tidak muncul di 24 slot. Spec §12.3, §10.1.
        let mut candidates = make_large_pool(30);
        // Tambahkan beberapa Tier C nodes
        candidates.push(make_tier_c_candidate(0xA1));
        candidates.push(make_tier_c_candidate(0xA2));

        let result = select_nmt_peers_hybrid(&candidates, &seed_k());
        let all_peers = result.all_peers();

        for peer_id in &all_peers {
            assert!(
                !is_tier_c(peer_id),
                "Tier C tidak boleh ada dalam NMT peer list — spec §12.3"
            );
        }
    }

    // ── test_nmt_insufficient_population ─────────────────────────────────────

    #[test]
    fn test_nmt_insufficient_population() {
        // Populasi < 24 → slot kosong, tidak error. Spec §12.3.
        let candidates = vec![
            make_candidate(0x01, 900_000, 0),
            make_candidate(0x02, 850_000, 1),
        ];
        let result = select_nmt_peers_hybrid(&candidates, &seed_k());
        // Tidak error, cukup ambil yang tersedia
        assert!(result.total_selected <= candidates.len() + 1);
    }

    // ── test_nmt_peer_count_constants ────────────────────────────────────────

    #[test]
    fn test_nmt_peer_count_constant() {
        // NMT_PEER_COUNT_V12 = 24. Spec §12.3, §17.
        assert_eq!(NMT_PEER_COUNT_V12, 24usize);
    }

    #[test]
    fn test_nmt_random_slots_constant() {
        // NMT_RANDOM_SLOTS = 1. Spec §12.3, §17.
        assert_eq!(NMT_RANDOM_SLOTS, 1usize);
    }

    #[test]
    fn test_nmt_deterministic_slots_constant() {
        // NMT_DETERMINISTIC_SLOTS = 23. Spec §12.3.
        assert_eq!(NMT_DETERMINISTIC_SLOTS, 23usize);
    }

    #[test]
    fn test_nmt_total_equals_23_plus_1() {
        // 23 + 1 = 24. Spec §12.3.
        assert_eq!(
            NMT_DETERMINISTIC_SLOTS + NMT_RANDOM_SLOTS,
            NMT_PEER_COUNT_V12
        );
    }

    // ── test_nmt_rank_deterministic ───────────────────────────────────────────

    #[test]
    fn test_nmt_rank_deterministic() {
        // nmt_rank deterministik untuk input yang sama. Spec §12.3.
        let node_id = [0x42u8; 32];
        let sk = seed_k();
        let r1 = compute_nmt_rank(&node_id, &sk);
        let r2 = compute_nmt_rank(&node_id, &sk);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_nmt_rank_different_nodes_differ() {
        // Node berbeda → rank berbeda. Spec §12.3.
        let sk = seed_k();
        let r1 = compute_nmt_rank(&[0x01u8; 32], &sk);
        let r2 = compute_nmt_rank(&[0x02u8; 32], &sk);
        assert_ne!(r1, r2);
    }

    // ── test_random_slot_not_duplicate ───────────────────────────────────────

    #[test]
    fn test_random_slot_not_in_deterministic() {
        // Random slot tidak duplikat dengan deterministik slots. Spec §12.3.
        let candidates = make_large_pool(30);
        let result = select_nmt_peers_hybrid(&candidates, &seed_k());

        if let Some(random) = result.random_slot {
            assert!(
                !result.deterministic_slots.contains(&random),
                "Random slot tidak boleh duplikat dengan deterministik slots"
            );
        }
    }

    // ── test_nmt_domain_separator ─────────────────────────────────────────────

    #[test]
    fn test_nmt_random_domain() {
        // DOMAIN_NMT_RANDOM = b"nmt_random". Spec §12.3.
        assert_eq!(DOMAIN_NMT_RANDOM, b"nmt_random");
    }

    // ── test_nmt_random_seed_computation ─────────────────────────────────────

    #[test]
    fn test_nmt_random_seed_different_for_different_seed_k() {
        // Seed_k berbeda → random_seed berbeda. Spec §12.3.
        let rs1 = compute_nmt_random_seed(&[0x01u8; 32]);
        let rs2 = compute_nmt_random_seed(&[0x02u8; 32]);
        assert_ne!(rs1, rs2);
    }
}
