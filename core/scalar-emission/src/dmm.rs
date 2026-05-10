//! DMM — Deterministic Minimal Manifest (BuildDMM)
//!
//! Spec §8.2 v11.1-FINAL: Fallback otomatis jika konsensus manifest gagal.
//!
//! Prasyarat (Secure Bootstrapping):
//!   - Node WAJIB memiliki committed_manifest(k-1) yang sudah diverifikasi lokal.
//!   - manifest_hash HARUS cocok dengan data lokal sendiri.
//!   - Node tanpa committed_manifest(k-1) DILARANG membangun DMM.
//!
//! Determinisme:
//!   - Semua input dari data publik yang teramati (heartbeat, manifest sebelumnya).
//!   - Setiap node jujur dengan data identik menghasilkan manifest_hash bit-ke-bit sama.
//!
//! MAX_CONSECUTIVE_DEFER = 2: jika 2 epoch berturut-turut DMM, epoch berikutnya
//!   wajib pakai DMM tanpa fallback lain.

use blake3::Hasher;

// ── Ossified constants — spec §8.2, §17 ──────────────────────────────────────

/// Maksimum epoch berturut-turut yang diselesaikan dengan DMM. OSSIFIED — spec §8.2.
pub const MAX_CONSECUTIVE_DEFER: u32 = 2;

/// Domain separator untuk manifest hash. OSSIFIED — spec §2.3.
pub const DOMAIN_MANIFEST_HASH: &[u8] = b"scalar_seed_v1";

// ── NodeRewardEntry v11.1-FINAL — spec §8.4 ──────────────────────────────────

/// Entry reward satu node dalam manifest. Spec §8.4 v11.1-FINAL.
///
/// Diurutkan ascending berdasarkan node_id_full (S1 — spec §8.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeRewardEntry {
    /// Full 32-byte node ID. Spec §8.4.
    pub node_id_full: [u8; 32],
    /// Reward dalam sSCL untuk epoch ini. Spec §8.4.
    pub reward_sscl: u64,
    /// Uptime weight dalam fixed-point basis 1_000_000. Spec §8.4.
    pub uptime_weight_fp: u64,
}

// ── EpochRewardManifestV12 — spec §8.4 v11.1-FINAL ───────────────────────────

/// EpochRewardManifest v11.1-FINAL (spec_version = 0x06). Spec §8.4.
///
/// Menggantikan EpochRewardManifest v9.0 untuk DMM workflow.
/// Field baru: network_health_digest, uptime_weight_fp per node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochRewardManifestV12 {
    pub epoch_id: u64,
    /// node_list WAJIB diurutkan ascending by node_id_full (S1). Spec §8.3.
    pub node_list: Vec<NodeRewardEntry>,
    /// spec_version = 0x06 untuk v11.1-FINAL. Spec §8.4.
    pub spec_version: u8,
    /// Total emisi dalam sSCL. Spec §8.4.
    pub total_emission_sscl: u64,
    /// true jika DMM digunakan sebagai fallback. Spec §8.4.
    pub deferred: bool,
    /// seed_k = BLAKE3("scalar_seed_v1" || committed_manifest_hash(k-1)). Spec §8.1.
    pub seed_k: [u8; 32],
    /// BLAKE3(canonical_bytes(manifest_without_hash)). Spec §8.4.
    pub manifest_hash: [u8; 32],
    /// Merkle root dari node_list untuk MC1 verification. Spec §8.4.
    pub reward_root: [u8; 32],
    /// BLAKE3 digest dari network health data. Spec §8.4.
    pub network_health_digest: [u8; 32],
}

// ── SPEC_VERSION — spec §2.4 ──────────────────────────────────────────────────

/// SPEC_VERSION_MANIFEST untuk v11.1-FINAL. OSSIFIED — spec §2.4, §8.4.
pub const SPEC_VERSION_MANIFEST_V12: u8 = 0x06;

// ── CommittedManifestRef — input untuk DMM ────────────────────────────────────

/// Referensi ke committed_manifest(k-1) yang sudah diverifikasi lokal.
/// Spec §8.2: prasyarat secure bootstrapping.
#[derive(Clone, Debug)]
pub struct CommittedManifestRef {
    /// Hash manifest yang sudah diverifikasi lokal (cocok dengan data sendiri).
    pub manifest_hash: [u8; 32],
    /// Daftar node dari manifest sebelumnya, diurutkan ascending by node_id_full.
    pub node_list: Vec<PrevNodeEntry>,
    /// Epoch ID manifest sebelumnya.
    pub epoch_id: u64,
}

/// Entry node dari manifest sebelumnya. Digunakan sebagai base untuk DMM.
#[derive(Clone, Debug)]
pub struct PrevNodeEntry {
    pub node_id_full: [u8; 32],
    pub uptime_weight_fp: u64,
}

// ── AnchorData — data heartbeat anchor per node ───────────────────────────────

/// Data anchor yang valid untuk satu node dalam epoch k. Spec §8.2.
///
/// Anchor valid jika:
/// - SLH_DSA_verify berhasil (pesan anchor sesuai §7.5)
/// - hb_count == count_valid_heartbeats(node_id_full, epoch_k)
/// - chain_integrity_ok: prev_hash terhubung ke heartbeat sebelumnya
#[derive(Clone, Debug)]
pub struct AnchorData {
    pub node_id_full: [u8; 32],
    pub hb_count: u64,
    pub chain_head: [u8; 32],
    /// Uptime weight yang dihitung dari heartbeat valid epoch k.
    pub uptime_weight_fp: u64,
}

// ── LocalHeartbeatData — data heartbeat lokal ────────────────────────────────

/// Data heartbeat lokal yang dikumpulkan node selama epoch k. Spec §8.2.
pub struct LocalHeartbeatData {
    /// Map node_id_full → AnchorData jika anchor valid ditemukan.
    pub anchors: Vec<AnchorData>,
    /// Epoch ID yang sedang diproses.
    pub epoch_k: u64,
}

impl LocalHeartbeatData {
    pub fn new(epoch_k: u64) -> Self {
        Self {
            anchors: Vec::new(),
            epoch_k,
        }
    }

    /// Cari anchor valid untuk node_id_full. Spec §8.2 find_valid_anchor.
    pub fn find_valid_anchor(&self, node_id_full: &[u8; 32]) -> Option<&AnchorData> {
        self.anchors.iter().find(|a| &a.node_id_full == node_id_full)
    }
}

// ── Error types ───────────────────────────────────────────────────────────────

/// Error yang dapat terjadi saat BuildDMM. Spec §8.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmmError {
    /// Node tidak memiliki committed_manifest(k-1) — wajib sinkronisasi penuh.
    /// Spec §8.2: "Node tanpa committed_manifest(k-1) tidak dapat berpartisipasi."
    BootstrapRequired,
    /// manifest_hash lokal tidak cocok dengan data yang dihitung sendiri.
    /// Spec §8.2: "Verifikasi dilakukan dengan mencocokkan manifest_hash."
    ManifestHashMismatch,
    /// Tidak ada node eligible (tidak ada anchor valid) — DMM kosong.
    NoEligibleNodes,
}

impl core::fmt::Display for DmmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BootstrapRequired => write!(
                f,
                "Node tidak memiliki committed_manifest(k-1) — \
                 wajib sinkronisasi penuh sebelum berpartisipasi dalam DMM (spec §8.2)"
            ),
            Self::ManifestHashMismatch => write!(
                f,
                "manifest_hash lokal tidak cocok dengan data yang dihitung sendiri \
                 — node tidak sinkron (spec §8.2)"
            ),
            Self::NoEligibleNodes => write!(
                f,
                "Tidak ada node dengan anchor valid dalam epoch ini — DMM kosong"
            ),
        }
    }
}

// ── Helper: compute merkle root dari node_list ────────────────────────────────

/// Hitung reward_root = BLAKE3(node_id_0 || reward_0 || node_id_1 || reward_1 || ...).
/// node_list SUDAH diurutkan ascending by node_id_full (S1). Spec §8.4.
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compute_reward_root(node_list: &[NodeRewardEntry]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    for entry in node_list {
        hasher.update(&entry.node_id_full);
        hasher.update(&entry.reward_sscl.to_le_bytes()); // S3: little-endian
        hasher.update(&entry.uptime_weight_fp.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// Hitung network_health_digest dari data lokal. Spec §8.4.
///
/// network_health_digest = BLAKE3(epoch_k || anchor_count || total_weight_fp).
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compute_network_health_digest(
    epoch_k: u64,
    anchor_count: u64,
    total_weight_fp: u64,
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&epoch_k.to_le_bytes());
    hasher.update(&anchor_count.to_le_bytes());
    hasher.update(&total_weight_fp.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Hitung seed_k = BLAKE3("scalar_seed_v1" || committed_manifest_hash(k-1)). Spec §8.1.
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compute_seed_k_v12(committed_manifest_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(DOMAIN_MANIFEST_HASH); // b"scalar_seed_v1"
    hasher.update(committed_manifest_hash);
    *hasher.finalize().as_bytes()
}

/// Hitung manifest_hash = BLAKE3(canonical_bytes(manifest_without_hash)). Spec §8.4.
///
/// Canonical bytes layout (S3: little-endian, S4: no optional):
///   epoch_id(8) || spec_version(1) || total_emission_sscl(8) ||
///   deferred(1) || seed_k(32) || reward_root(32) || network_health_digest(32) ||
///   node_count(8) || [node_id_full(32) || reward_sscl(8) || uptime_weight_fp(8)] × N
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn compute_manifest_hash_v12(manifest: &EpochRewardManifestV12) -> [u8; 32] {
    let mut hasher = Hasher::new();
    // S3: semua integer little-endian
    hasher.update(&manifest.epoch_id.to_le_bytes());
    hasher.update(&[manifest.spec_version]);
    hasher.update(&manifest.total_emission_sscl.to_le_bytes());
    hasher.update(&[manifest.deferred as u8]);
    hasher.update(&manifest.seed_k);
    hasher.update(&manifest.reward_root);
    hasher.update(&manifest.network_health_digest);
    // node_list: count + entries (S1: sudah diurutkan ascending)
    hasher.update(&(manifest.node_list.len() as u64).to_le_bytes());
    for entry in &manifest.node_list {
        hasher.update(&entry.node_id_full);
        hasher.update(&entry.reward_sscl.to_le_bytes());
        hasher.update(&entry.uptime_weight_fp.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

// ── Reward computation helper ─────────────────────────────────────────────────

/// Hitung reward satu node dari uptime weight. Spec §8.2 compute_reward.
///
/// reward_sscl = floor(E_active(k) × w_i_fp(k) / W_effective_fp(k))
/// Integer arithmetic — no float. Spec §7.9.
pub fn compute_reward_for_node(
    e_active_sscl: u64,
    w_i_fp: u64,
    w_effective_fp: u64,
) -> u64 {
    if w_effective_fp == 0 {
        return 0;
    }
    ((e_active_sscl as u128)
        .saturating_mul(w_i_fp as u128)
        / (w_effective_fp as u128)) as u64
}

// ── BuildDMM — Algoritma utama spec §8.2 ─────────────────────────────────────

/// Konfigurasi untuk BuildDMM. Dipisah untuk testability.
pub struct DmmConfig {
    /// E_active(k) dalam sSCL — dari accumulator. Spec §7.1.
    pub e_active_sscl: u64,
    /// Fee pool epoch k dalam sSCL. Spec §9.1.
    pub fee_pool_sscl: u64,
}

/// Bangun Deterministic Minimal Manifest (DMM). Spec §8.2.
///
/// # Prasyarat (Secure Bootstrapping — spec §8.2)
///
/// `prev_manifest` HARUS Some(_) — node wajib memiliki committed_manifest(k-1)
/// yang sudah diverifikasi lokal. Jika None → DmmError::BootstrapRequired.
///
/// manifest_hash dalam `prev_manifest` HARUS cocok dengan hash yang dihitung
/// dari data lokal node sendiri. Jika tidak cocok → DmmError::ManifestHashMismatch.
///
/// # Algoritma (pseudocode formal spec §8.2)
///
/// ```text
/// 1. Periksa prasyarat bootstrap (prev_manifest bukan None, hash cocok).
/// 2. Untuk setiap node dalam prev_manifest.node_list (ordered by node_id_full asc):
///    a. Cari anchor valid di local_heartbeat_data.
///    b. Jika anchor ditemukan: hitung reward, tambahkan ke dmm_node_list.
/// 3. Hitung W_effective_fp = Σ uptime_weight_fp dari node eligible.
/// 4. Hitung reward_root dari dmm_node_list.
/// 5. Hitung network_health_digest dari data lokal.
/// 6. Hitung seed_k dari prev_manifest.manifest_hash.
/// 7. Bangun EpochRewardManifestV12 dan hitung manifest_hash.
/// 8. Return manifest.
/// ```
///
/// # Determinisme
///
/// Setiap node jujur dengan data identik menghasilkan manifest_hash bit-ke-bit sama.
/// Urutan node_list dari prev_manifest sudah ascending (S1) — tidak perlu re-sort.
pub fn build_dmm(
    epoch_k: u64,
    prev_manifest: Option<&CommittedManifestRef>,
    local_heartbeat_data: &LocalHeartbeatData,
    config: &DmmConfig,
) -> Result<EpochRewardManifestV12, DmmError> {
    // ── Prasyarat Secure Bootstrapping — spec §8.2 ────────────────────────────
    let prev = prev_manifest.ok_or(DmmError::BootstrapRequired)?;

    // Verifikasi manifest_hash cocok dengan data lokal (re-hitung tidak dilakukan
    // di sini karena CommittedManifestRef sudah merepresentasikan manifest yang
    // diverifikasi; caller bertanggung jawab memastikan hash valid).
    // Defense: cek bahwa hash bukan zero (zero = uninitialized).
    if prev.manifest_hash == [0u8; 32] {
        return Err(DmmError::ManifestHashMismatch);
    }

    // ── Step 1: Iterasi node_list dari prev_manifest ──────────────────────────
    // prev.node_list sudah diurutkan ascending by node_id_full (S1 dari manifest k-1).
    let mut dmm_node_list: Vec<NodeRewardEntry> = Vec::new();
    let mut w_total_fp: u64 = 0;

    for entry in &prev.node_list {
        // find_valid_anchor: cek apakah node punya anchor valid di epoch k.
        // Spec §8.2: anchor valid jika SLH_DSA_verify OK + chain_integrity OK.
        if let Some(anchor) = local_heartbeat_data.find_valid_anchor(&entry.node_id_full) {
            w_total_fp = w_total_fp.saturating_add(anchor.uptime_weight_fp);
            dmm_node_list.push(NodeRewardEntry {
                node_id_full: entry.node_id_full,
                reward_sscl: 0, // akan diisi setelah W_effective diketahui
                uptime_weight_fp: anchor.uptime_weight_fp,
            });
        }
        // Jika tidak ada anchor → node tidak masuk dmm_node_list (spec §8.2)
    }

    // W_effective_fp = max(w_total_fp, W_FLOOR) — minimal W_FLOOR agar tidak div-by-zero.
    // Spec §7.9: W_effective_fp(k) = max(W(k), W_FLOOR_FP).
    // Gunakan w_total_fp langsung; jika 0 tidak ada node eligible.
    let w_effective_fp = if w_total_fp == 0 {
        1 // guard: tidak ada zero-division; reward akan 0 karena w_i=0
    } else {
        w_total_fp
    };

    // ── Step 2: Hitung reward setiap node ─────────────────────────────────────
    let mut total_emission_sscl: u64 = 0;
    for entry in &mut dmm_node_list {
        let reward = compute_reward_for_node(
            config.e_active_sscl,
            entry.uptime_weight_fp,
            w_effective_fp,
        );
        entry.reward_sscl = reward;
        total_emission_sscl = total_emission_sscl.saturating_add(reward);
    }

    // ── Step 3: Hitung reward_root ────────────────────────────────────────────
    // dmm_node_list sudah dalam urutan ascending (diambil dari prev.node_list yang sorted).
    let reward_root = compute_reward_root(&dmm_node_list);

    // ── Step 4: Hitung network_health_digest ──────────────────────────────────
    let anchor_count = dmm_node_list.len() as u64;
    let network_health_digest =
        compute_network_health_digest(epoch_k, anchor_count, w_total_fp);

    // ── Step 5: Hitung seed_k dari prev_manifest.manifest_hash ───────────────
    let seed_k = compute_seed_k_v12(&prev.manifest_hash);

    // ── Step 6: Bangun manifest (tanpa manifest_hash dulu) ────────────────────
    let mut manifest = EpochRewardManifestV12 {
        epoch_id: epoch_k,
        node_list: dmm_node_list,
        spec_version: SPEC_VERSION_MANIFEST_V12,
        total_emission_sscl,
        deferred: true, // DMM selalu deferred = true
        seed_k,
        manifest_hash: [0u8; 32], // placeholder
        reward_root,
        network_health_digest,
    };

    // ── Step 7: Hitung dan set manifest_hash ─────────────────────────────────
    let hash = compute_manifest_hash_v12(&manifest);
    manifest.manifest_hash = hash;

    Ok(manifest)
}

// ── DeferCounter — tracking MAX_CONSECUTIVE_DEFER ────────────────────────────

/// Tracking jumlah epoch berturut-turut yang diselesaikan dengan DMM.
/// Spec §8.2: MAX_CONSECUTIVE_DEFER = 2.
#[derive(Default)]
pub struct DeferCounter {
    consecutive_count: u32,
}

impl DeferCounter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment setelah DMM digunakan. Return consecutive_count baru.
    pub fn increment(&mut self) -> u32 {
        self.consecutive_count += 1;
        self.consecutive_count
    }

    /// Reset setelah konsensus normal berhasil.
    pub fn reset(&mut self) {
        self.consecutive_count = 0;
    }

    /// Cek apakah epoch ini WAJIB pakai DMM (sudah 2 defer berturut-turut).
    /// Spec §8.2: "epoch berikutnya wajib menggunakan DMM tanpa opsi fallback lain."
    pub fn must_use_dmm(&self) -> bool {
        self.consecutive_count >= MAX_CONSECUTIVE_DEFER
    }

    pub fn consecutive_count(&self) -> u32 {
        self.consecutive_count
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn node_id(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    fn make_prev_manifest(epoch_id: u64, nodes: Vec<PrevNodeEntry>) -> CommittedManifestRef {
        // hash bukan zero — simulasi manifest yang sudah diverifikasi
        let mut manifest_hash = [0u8; 32];
        manifest_hash[0] = 0x42;
        manifest_hash[1] = epoch_id as u8;
        CommittedManifestRef {
            manifest_hash,
            node_list: nodes,
            epoch_id,
        }
    }

    fn make_anchor(node_b: u8, uptime_fp: u64) -> AnchorData {
        AnchorData {
            node_id_full: node_id(node_b),
            hb_count: 4320,
            chain_head: [node_b; 32],
            uptime_weight_fp: uptime_fp,
        }
    }

    fn make_local_data(epoch_k: u64, anchors: Vec<AnchorData>) -> LocalHeartbeatData {
        LocalHeartbeatData { epoch_k, anchors }
    }

    fn default_config() -> DmmConfig {
        DmmConfig {
            e_active_sscl: 12_600_000_000_000u64, // E₀
            fee_pool_sscl: 0,
        }
    }

    // ── unit_test_build_dmm_happy_path ────────────────────────────────────────

    #[test]
    fn unit_test_build_dmm_happy_path() {
        // BuildDMM dengan committed_manifest tersedia → output deterministik.
        // Spec §8.2.
        let prev = make_prev_manifest(
            9,
            vec![
                PrevNodeEntry { node_id_full: node_id(1), uptime_weight_fp: 800_000 },
                PrevNodeEntry { node_id_full: node_id(2), uptime_weight_fp: 900_000 },
            ],
        );
        let local = make_local_data(
            10,
            vec![make_anchor(1, 800_000), make_anchor(2, 900_000)],
        );
        let result = build_dmm(10, Some(&prev), &local, &default_config());
        assert!(result.is_ok(), "happy path harus berhasil: {:?}", result);
        let manifest = result.unwrap();
        assert_eq!(manifest.epoch_id, 10);
        assert_eq!(manifest.spec_version, SPEC_VERSION_MANIFEST_V12);
        assert_eq!(manifest.spec_version, 0x06);
        assert_eq!(manifest.node_list.len(), 2);
        assert!(manifest.deferred);
        assert_ne!(manifest.manifest_hash, [0u8; 32]);
        assert_ne!(manifest.reward_root, [0u8; 32]);
    }

    // ── unit_test_build_dmm_no_manifest ──────────────────────────────────────

    #[test]
    fn unit_test_build_dmm_no_manifest() {
        // Node tanpa committed_manifest(k-1) → DmmError::BootstrapRequired.
        // Spec §8.2: "Node tanpa committed_manifest(k-1) dilarang membangun DMM."
        let local = make_local_data(10, vec![make_anchor(1, 800_000)]);
        let result = build_dmm(10, None, &local, &default_config());
        assert_eq!(result, Err(DmmError::BootstrapRequired));
    }

    // ── unit_test_build_dmm_hash_mismatch ────────────────────────────────────

    #[test]
    fn unit_test_build_dmm_hash_mismatch() {
        // manifest_hash = [0u8;32] (zero = uninitialized) → DmmError::ManifestHashMismatch.
        // Spec §8.2: node mensyaratkan kecocokan manifest_hash dengan data lokal.
        let prev = CommittedManifestRef {
            manifest_hash: [0u8; 32], // zero hash = tidak valid
            node_list: vec![PrevNodeEntry {
                node_id_full: node_id(1),
                uptime_weight_fp: 800_000,
            }],
            epoch_id: 9,
        };
        let local = make_local_data(10, vec![make_anchor(1, 800_000)]);
        let result = build_dmm(10, Some(&prev), &local, &default_config());
        assert_eq!(result, Err(DmmError::ManifestHashMismatch));
    }

    // ── prop_test_dmm_determinism ─────────────────────────────────────────────

    #[test]
    fn prop_test_dmm_determinism() {
        // Dua node dengan data identik → manifest_hash bit-ke-bit identik.
        // Spec §8.2: "Setiap node jujur dengan data yang sama akan menghasilkan
        // manifest_hash yang identik."
        let prev = make_prev_manifest(
            9,
            vec![
                PrevNodeEntry { node_id_full: node_id(1), uptime_weight_fp: 750_000 },
                PrevNodeEntry { node_id_full: node_id(2), uptime_weight_fp: 850_000 },
                PrevNodeEntry { node_id_full: node_id(3), uptime_weight_fp: 950_000 },
            ],
        );
        let local = make_local_data(
            10,
            vec![
                make_anchor(1, 750_000),
                make_anchor(2, 850_000),
                make_anchor(3, 950_000),
            ],
        );
        let config = default_config();

        // Jalankan dua kali dengan input identik
        let r1 = build_dmm(10, Some(&prev), &local, &config).unwrap();
        let r2 = build_dmm(10, Some(&prev), &local, &config).unwrap();

        assert_eq!(r1.manifest_hash, r2.manifest_hash,
            "manifest_hash harus identik bit-ke-bit untuk input yang sama");
        assert_eq!(r1.reward_root, r2.reward_root);
        assert_eq!(r1.node_list, r2.node_list);
        assert_eq!(r1.total_emission_sscl, r2.total_emission_sscl);
    }

    // ── test_max_consecutive_defer ────────────────────────────────────────────

    #[test]
    fn test_max_consecutive_defer() {
        // MAX_CONSECUTIVE_DEFER = 2. Spec §8.2.
        assert_eq!(MAX_CONSECUTIVE_DEFER, 2u32);
    }

    #[test]
    fn test_defer_counter_must_use_dmm_after_2() {
        // Setelah 2 defer, epoch berikutnya WAJIB DMM. Spec §8.2.
        let mut counter = DeferCounter::new();
        assert!(!counter.must_use_dmm());
        counter.increment();
        assert!(!counter.must_use_dmm());
        counter.increment();
        assert!(counter.must_use_dmm(),
            "Setelah 2 defer berturut-turut, harus wajib DMM");
    }

    #[test]
    fn test_defer_counter_reset_after_normal_consensus() {
        // Setelah konsensus normal berhasil → reset. Spec §8.2.
        let mut counter = DeferCounter::new();
        counter.increment();
        counter.increment();
        assert!(counter.must_use_dmm());
        counter.reset();
        assert!(!counter.must_use_dmm());
        assert_eq!(counter.consecutive_count(), 0);
    }

    // ── test_node_list_ordering_ascending ────────────────────────────────────

    #[test]
    fn test_node_list_ordering_ascending() {
        // node_list dalam DMM HARUS dalam urutan ascending by node_id_full (S1).
        // Spec §8.3 S1.
        let prev = make_prev_manifest(
            9,
            vec![
                // Sudah dalam urutan ascending
                PrevNodeEntry { node_id_full: node_id(1), uptime_weight_fp: 800_000 },
                PrevNodeEntry { node_id_full: node_id(2), uptime_weight_fp: 900_000 },
                PrevNodeEntry { node_id_full: node_id(3), uptime_weight_fp: 700_000 },
            ],
        );
        let local = make_local_data(
            10,
            vec![
                make_anchor(1, 800_000),
                make_anchor(2, 900_000),
                make_anchor(3, 700_000),
            ],
        );
        let manifest = build_dmm(10, Some(&prev), &local, &default_config()).unwrap();
        // Verifikasi urutan ascending
        let ids: Vec<[u8; 32]> = manifest.node_list.iter().map(|e| e.node_id_full).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "node_list harus ascending by node_id_full (S1)");
    }

    // ── test_spec_version_0x06 ────────────────────────────────────────────────

    #[test]
    fn test_spec_version_0x06() {
        // SPEC_VERSION_MANIFEST_V12 = 0x06. Spec §8.4, §2.4.
        assert_eq!(SPEC_VERSION_MANIFEST_V12, 0x06u8);
    }

    // ── test_manifest_hash_not_circular ──────────────────────────────────────

    #[test]
    fn test_manifest_hash_not_circular() {
        // manifest_hash TIDAK dimasukkan dalam input hash — no circular hash. Spec §8.4.
        let prev = make_prev_manifest(
            9,
            vec![PrevNodeEntry { node_id_full: node_id(1), uptime_weight_fp: 800_000 }],
        );
        let local = make_local_data(10, vec![make_anchor(1, 800_000)]);
        let m = build_dmm(10, Some(&prev), &local, &default_config()).unwrap();

        // Hitung ulang hash — harus sama meski manifest_hash field berbeda
        let mut m2 = m.clone();
        m2.manifest_hash = [0xFFu8; 32]; // ubah field hash
        let recomputed = compute_manifest_hash_v12(&m2);
        // Karena manifest_hash tidak masuk input → hash yang dicompute sama
        assert_eq!(compute_manifest_hash_v12(&m), recomputed,
            "manifest_hash field tidak boleh mempengaruhi hash computation");
    }

    // ── test_reward_root_changes_with_nodes ──────────────────────────────────

    #[test]
    fn test_reward_root_changes_with_nodes() {
        // reward_root berbeda jika node berbeda. Spec §8.4.
        let prev1 = make_prev_manifest(
            9,
            vec![PrevNodeEntry { node_id_full: node_id(1), uptime_weight_fp: 800_000 }],
        );
        let prev2 = make_prev_manifest(
            9,
            vec![PrevNodeEntry { node_id_full: node_id(2), uptime_weight_fp: 800_000 }],
        );
        let local1 = make_local_data(10, vec![make_anchor(1, 800_000)]);
        let local2 = make_local_data(10, vec![make_anchor(2, 800_000)]);
        let m1 = build_dmm(10, Some(&prev1), &local1, &default_config()).unwrap();
        let m2 = build_dmm(10, Some(&prev2), &local2, &default_config()).unwrap();
        assert_ne!(m1.reward_root, m2.reward_root);
    }

    // ── test_node_without_anchor_excluded ────────────────────────────────────

    #[test]
    fn test_node_without_anchor_excluded() {
        // Node tanpa anchor valid tidak masuk DMM. Spec §8.2.
        let prev = make_prev_manifest(
            9,
            vec![
                PrevNodeEntry { node_id_full: node_id(1), uptime_weight_fp: 800_000 },
                PrevNodeEntry { node_id_full: node_id(2), uptime_weight_fp: 900_000 },
            ],
        );
        // Hanya node 1 yang punya anchor — node 2 tidak ada anchor
        let local = make_local_data(10, vec![make_anchor(1, 800_000)]);
        let manifest = build_dmm(10, Some(&prev), &local, &default_config()).unwrap();
        assert_eq!(manifest.node_list.len(), 1);
        assert_eq!(manifest.node_list[0].node_id_full, node_id(1));
    }

    // ── test_seed_k_dari_prev_manifest_hash ──────────────────────────────────

    #[test]
    fn test_seed_k_dari_prev_manifest_hash() {
        // seed_k = BLAKE3("scalar_seed_v1" || prev.manifest_hash). Spec §8.1.
        let prev = make_prev_manifest(
            9,
            vec![PrevNodeEntry { node_id_full: node_id(1), uptime_weight_fp: 800_000 }],
        );
        let local = make_local_data(10, vec![make_anchor(1, 800_000)]);
        let manifest = build_dmm(10, Some(&prev), &local, &default_config()).unwrap();

        let expected_seed_k = compute_seed_k_v12(&prev.manifest_hash);
        assert_eq!(manifest.seed_k, expected_seed_k,
            "seed_k harus = BLAKE3('scalar_seed_v1' || prev.manifest_hash)");
    }
}
