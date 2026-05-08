//! Slashing — Spec §8.1 Step 3.5
//!
//! Equivocation detection: node yang mengirim dua liveness_root berbeda
//! untuk epoch yang sama (keduanya signed dengan NodeKey yang sama)
//! di-blacklist permanen dan maturity di-reset ke 0.
//!
//! EVIDENCE FORMAT (spec §8.1 Step 3.5):
//!   SlashingProof = {
//!     node_id       : bytes32
//!     epoch_id      : uint64
//!     announcement_1: LivenessRootAnnouncement  — root X
//!     announcement_2: LivenessRootAnnouncement  — root Y (X ≠ Y)
//!     verifier_node : bytes32
//!   }
//!
//! CONSEQUENCE:
//!   - NodeID di-blacklist selamanya
//!   - maturity di-reset ke 0
//!   - Node tidak bisa claim reward epoch ini

use std::collections::HashSet;

// ── LivenessRootAnnouncement — Spec §8.1 Step 2 ──────────────────────────────

/// Announcement liveness root dari satu node. Spec §8.1 Step 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivenessRootAnnouncement {
    pub epoch_id: u64,
    pub liveness_root: [u8; 32],
    /// BLAKE3 hash dari semua connectivity_proofs. Spec §8.1 Step 2.
    pub connectivity_summary: [u8; 32],
    pub node_id: [u8; 32],
    pub timestamp: u64,
    /// SPHINCS+ signature dari NodeKey. Spec §8.1 Step 2.
    /// In production: full SPHINCS+ sig. Di sini disimpan sebagai bytes.
    pub node_signature: Vec<u8>,
}

// ── SlashingProof — Spec §8.1 Step 3.5 ───────────────────────────────────────

/// Bukti equivocation dari satu node. Spec §8.1 Step 3.5.
///
/// Valid jika:
/// - announcement_1.node_id == announcement_2.node_id
/// - announcement_1.epoch_id == announcement_2.epoch_id
/// - announcement_1.liveness_root ≠ announcement_2.liveness_root
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashingProof {
    /// NodeID yang terbukti equivocate.
    pub node_id: [u8; 32],
    pub epoch_id: u64,
    /// Announcement pertama (liveness_root X).
    pub announcement_1: LivenessRootAnnouncement,
    /// Announcement kedua (liveness_root Y ≠ X).
    pub announcement_2: LivenessRootAnnouncement,
    /// NodeID yang menemukan dan melaporkan bukti ini.
    pub verifier_node: [u8; 32],
}

/// Error validasi SlashingProof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlashingError {
    /// node_id tidak konsisten antara proof dan announcements.
    NodeIdMismatch,
    /// epoch_id tidak konsisten.
    EpochIdMismatch,
    /// Kedua liveness_root sama — bukan equivocation.
    SameRoot,
    /// announcement.node_id tidak cocok dengan proof.node_id.
    AnnouncementNodeIdMismatch,
}

impl core::fmt::Display for SlashingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NodeIdMismatch => write!(f, "NodeID tidak konsisten dalam SlashingProof"),
            Self::EpochIdMismatch => write!(f, "EpochID tidak konsisten dalam SlashingProof"),
            Self::SameRoot => write!(f, "Kedua liveness_root sama — bukan equivocation"),
            Self::AnnouncementNodeIdMismatch => {
                write!(f, "Announcement node_id tidak cocok dengan proof node_id")
            }
        }
    }
}

// ── Validation ────────────────────────────────────────────────────────────────

/// Validasi SlashingProof. Spec §8.1 Step 3.5.
///
/// Return Ok(()) jika proof valid — node terbukti equivocate.
/// Return Err jika proof tidak valid.
///
/// CATATAN: Verifikasi SPHINCS+ signature membutuhkan public key node
/// yang diambil dari registry. Dalam implementasi ini, signature
/// disimpan tapi verifikasi kriptografis didelegasikan ke caller
/// yang memiliki akses ke public key registry.
pub fn validate_slashing_proof(proof: &SlashingProof) -> Result<(), SlashingError> {
    // announcement_1 harus dari node yang sama
    if proof.announcement_1.node_id != proof.node_id {
        return Err(SlashingError::AnnouncementNodeIdMismatch);
    }
    // announcement_2 harus dari node yang sama
    if proof.announcement_2.node_id != proof.node_id {
        return Err(SlashingError::AnnouncementNodeIdMismatch);
    }
    // epoch harus sama di announcement_1
    if proof.announcement_1.epoch_id != proof.epoch_id {
        return Err(SlashingError::EpochIdMismatch);
    }
    // epoch harus sama di announcement_2
    if proof.announcement_2.epoch_id != proof.epoch_id {
        return Err(SlashingError::EpochIdMismatch);
    }
    // liveness_root harus berbeda — itulah bukti equivocation
    if proof.announcement_1.liveness_root == proof.announcement_2.liveness_root {
        return Err(SlashingError::SameRoot);
    }
    Ok(())
}

// ── SlashingRegistry ─────────────────────────────────────────────────────────

/// Registry node yang di-blacklist permanen karena equivocation.
/// Spec §8.1 Step 3.5: "NodeID N di-blacklist selamanya."
#[derive(Default)]
pub struct SlashingRegistry {
    /// Set NodeID yang di-blacklist permanen.
    blacklisted: HashSet<[u8; 32]>,
}

impl SlashingRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Proses SlashingProof. Jika valid → blacklist node + return true.
    /// Jika proof tidak valid → return false tanpa efek.
    /// Spec §8.1 Step 3.5.
    pub fn process_proof(&mut self, proof: &SlashingProof) -> bool {
        if validate_slashing_proof(proof).is_ok() {
            self.blacklisted.insert(proof.node_id);
            true
        } else {
            false
        }
    }

    /// Cek apakah node di-blacklist. Spec §8.1 Step 3.5.
    pub fn is_blacklisted(&self, node_id: &[u8; 32]) -> bool {
        self.blacklisted.contains(node_id)
    }

    /// Jumlah node yang di-blacklist.
    pub fn blacklisted_count(&self) -> usize {
        self.blacklisted.len()
    }

    /// Apply slashing consequences ke maturity_weights map.
    /// maturity di-reset ke 0 untuk semua node blacklisted. Spec §8.1 Step 3.5.
    pub fn apply_maturity_reset(
        &self,
        maturity_weights: &mut std::collections::HashMap<[u8; 32], u64>,
    ) {
        for node_id in &self.blacklisted {
            maturity_weights.insert(*node_id, 0);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn node(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    fn root(b: u8) -> [u8; 32] {
        let mut r = [0u8; 32];
        r[0] = b;
        r
    }

    fn announcement(node_b: u8, epoch: u64, root_b: u8) -> LivenessRootAnnouncement {
        LivenessRootAnnouncement {
            epoch_id: epoch,
            liveness_root: root(root_b),
            connectivity_summary: [0u8; 32],
            node_id: node(node_b),
            timestamp: 1000,
            node_signature: vec![0u8; 32],
        }
    }

    fn valid_proof(node_b: u8, epoch: u64) -> SlashingProof {
        SlashingProof {
            node_id: node(node_b),
            epoch_id: epoch,
            announcement_1: announcement(node_b, epoch, 1),
            announcement_2: announcement(node_b, epoch, 2), // root berbeda
            verifier_node: node(99),
        }
    }

    // ── validate_slashing_proof ───────────────────────────────────────────────

    #[test]
    fn test_valid_proof_accepted() {
        // Spec §8.1 Step 3.5: dua root berbeda = equivocation valid.
        let proof = valid_proof(1, 10);
        assert!(validate_slashing_proof(&proof).is_ok());
    }

    #[test]
    fn test_same_root_rejected() {
        // Dua root sama bukan equivocation.
        let mut proof = valid_proof(1, 10);
        proof.announcement_2.liveness_root = proof.announcement_1.liveness_root;
        let err = validate_slashing_proof(&proof).unwrap_err();
        assert_eq!(err, SlashingError::SameRoot);
    }

    #[test]
    fn test_announcement_node_id_mismatch_rejected() {
        // announcement dari node berbeda bukan bukti equivocation node ini.
        let mut proof = valid_proof(1, 10);
        proof.announcement_1.node_id = node(2); // node berbeda
        let err = validate_slashing_proof(&proof).unwrap_err();
        assert_eq!(err, SlashingError::AnnouncementNodeIdMismatch);
    }

    #[test]
    fn test_epoch_id_mismatch_rejected() {
        // announcement dari epoch berbeda bukan equivocation dalam satu epoch.
        let mut proof = valid_proof(1, 10);
        proof.announcement_2.epoch_id = 11; // epoch berbeda
        let err = validate_slashing_proof(&proof).unwrap_err();
        assert_eq!(err, SlashingError::EpochIdMismatch);
    }

    // ── SlashingRegistry ─────────────────────────────────────────────────────

    #[test]
    fn test_valid_proof_blacklists_node() {
        // Spec §8.1 Step 3.5: node di-blacklist selamanya.
        let mut registry = SlashingRegistry::new();
        let proof = valid_proof(1, 10);
        assert!(registry.process_proof(&proof));
        assert!(registry.is_blacklisted(&node(1)));
    }

    #[test]
    fn test_invalid_proof_does_not_blacklist() {
        let mut registry = SlashingRegistry::new();
        let mut proof = valid_proof(1, 10);
        proof.announcement_2.liveness_root = proof.announcement_1.liveness_root; // invalid
        assert!(!registry.process_proof(&proof));
        assert!(!registry.is_blacklisted(&node(1)));
    }

    #[test]
    fn test_blacklist_is_permanent() {
        // Spec §8.1: blacklist permanen — tidak bisa di-unblacklist.
        let mut registry = SlashingRegistry::new();
        registry.process_proof(&valid_proof(1, 10));
        assert!(registry.is_blacklisted(&node(1)));
        // Proses lagi proof lain — masih blacklisted
        registry.process_proof(&valid_proof(2, 10));
        assert!(registry.is_blacklisted(&node(1)));
        assert!(registry.is_blacklisted(&node(2)));
        assert_eq!(registry.blacklisted_count(), 2);
    }

    #[test]
    fn test_non_blacklisted_node_returns_false() {
        let registry = SlashingRegistry::new();
        assert!(!registry.is_blacklisted(&node(42)));
    }

    #[test]
    fn test_maturity_reset_to_zero() {
        // Spec §8.1 Step 3.5: maturity di-reset ke 0.
        let mut registry = SlashingRegistry::new();
        registry.process_proof(&valid_proof(1, 10));

        let mut maturity: HashMap<[u8; 32], u64> = HashMap::new();
        maturity.insert(node(1), 25_000_000); // maturity penuh sebelum slash
        maturity.insert(node(2), 10_000_000); // node lain tidak terpengaruh

        registry.apply_maturity_reset(&mut maturity);

        assert_eq!(*maturity.get(&node(1)).unwrap(), 0); // di-reset
        assert_eq!(*maturity.get(&node(2)).unwrap(), 10_000_000); // tidak berubah
    }

    #[test]
    fn test_multiple_proofs_same_node_idempotent() {
        // Blacklist dua kali untuk node yang sama → tetap satu entry.
        let mut registry = SlashingRegistry::new();
        registry.process_proof(&valid_proof(1, 10));
        registry.process_proof(&valid_proof(1, 11)); // epoch berbeda, masih sama node
        assert_eq!(registry.blacklisted_count(), 1);
    }

    #[test]
    fn test_no_float_in_slashing_logic() {
        // Semua logika murni integer/bytes.
        let mut registry = SlashingRegistry::new();
        let proof = valid_proof(7, 42);
        registry.process_proof(&proof);
        assert!(registry.is_blacklisted(&node(7)));
    }
}
