//! Attack Matrix — DMM Manipulation & UTXO Ordering Attack Mitigations
//!
//! Spec §14.3 v11.1-FINAL: dua mitigasi red flag baru.
//!
//! (1) DMM Manipulation Attack:
//!   Node jahat tidak bisa mempengaruhi DMM karena DMM hanya dibangun
//!   dari committed_manifest(k-1) yang terverifikasi lokal.
//!   Runtime check: jika DMM dibangun dari data peer yang tidak diverifikasi → error.
//!
//! (2) UTXO Ordering Attack:
//!   Node jahat tidak bisa mengubah utxo_set_root karena tx_ordering_key
//!   deterministik dari BLAKE3. Setiap node yang memproses tx set yang sama
//!   menghasilkan ordering identik.
//!
//! (3) Gossip Rate Limiting:
//!   Mencegah flooding DMM requests via rate limiter di gossip layer.

use blake3::Hasher;

// ── DMM Manipulation Attack Mitigation — spec §14.3 ──────────────────────────

/// Error keamanan DMM. Spec §14.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmmSecurityError {
    /// DMM dibangun dari data peer yang tidak diverifikasi lokal.
    /// Spec §14.3: "DMM hanya dibangun dari committed_manifest yang diverifikasi lokal."
    UnverifiedPeerData { reason: &'static str },
    /// manifest_hash tidak cocok dengan data lokal — node tidak sinkron.
    ManifestHashMismatch,
    /// Node tidak memiliki committed_manifest — wajib sinkronisasi dulu.
    BootstrapRequired,
}

impl core::fmt::Display for DmmSecurityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnverifiedPeerData { reason } => write!(
                f,
                "DMM SECURITY: data dari peer tidak diverifikasi lokal — {reason} \
                 (spec §14.3 DMM manipulation mitigation)"
            ),
            Self::ManifestHashMismatch => write!(
                f,
                "DMM SECURITY: manifest_hash tidak cocok — node tidak sinkron (spec §14.3)"
            ),
            Self::BootstrapRequired => write!(
                f,
                "DMM SECURITY: tidak ada committed_manifest — wajib sinkronisasi penuh (spec §14.3)"
            ),
        }
    }
}

/// Verifikasi bahwa DMM hanya dibangun dari data yang terverifikasi lokal.
/// Spec §14.3: mitigasi DMM Manipulation Attack.
///
/// `manifest_hash_local`: hash yang dihitung node sendiri dari data lokal.
/// `manifest_hash_claimed`: hash yang diklaim (dari peer atau dari store).
///
/// Returns Ok(()) jika hash cocok dan manifest tidak zero.
/// Returns Err jika ada indikasi data tidak terverifikasi.
pub fn verify_dmm_source_integrity(
    manifest_hash_local: &[u8; 32],
    manifest_hash_claimed: &[u8; 32],
) -> Result<(), DmmSecurityError> {
    // Hash zero = uninitialized — tidak boleh digunakan untuk DMM
    if *manifest_hash_claimed == [0u8; 32] {
        return Err(DmmSecurityError::BootstrapRequired);
    }
    if *manifest_hash_local == [0u8; 32] {
        return Err(DmmSecurityError::BootstrapRequired);
    }

    // Hash harus cocok — jika tidak, data dari peer tidak dapat dipercaya
    if manifest_hash_local != manifest_hash_claimed {
        return Err(DmmSecurityError::ManifestHashMismatch);
    }

    Ok(())
}

/// Runtime check: DMM tidak boleh dibangun dari unverified peer data.
/// Spec §14.3: "Tambahkan runtime check: jika DMM dibangun dari data peer
/// yang tidak diverifikasi → panic!"
///
/// Dalam implementasi ini: return Err (production bisa panic! di debug build).
pub fn assert_dmm_from_verified_source(
    is_locally_verified: bool,
    context: &'static str,
) -> Result<(), DmmSecurityError> {
    if !is_locally_verified {
        return Err(DmmSecurityError::UnverifiedPeerData { reason: context });
    }
    Ok(())
}

// ── UTXO Ordering Attack Mitigation — spec §14.3 ─────────────────────────────

/// Error UTXO ordering attack. Spec §14.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtxoOrderingError {
    /// Dua node menghasilkan ordering berbeda untuk tx set yang sama.
    /// Ini menunjukkan salah satu node tidak mengikuti canonical ordering.
    OrderingMismatch,
    /// tx_ordering_key computation menghasilkan nilai yang tidak deterministik.
    NonDeterministicKey,
}

/// Verifikasi bahwa tx_ordering_key deterministik. Spec §14.3.
///
/// tx_ordering_key = BLAKE3(DOMAIN_TX_ORDER || tx_hash || epoch_id)
/// Harus selalu menghasilkan nilai yang sama untuk input yang sama.
///
/// Hash discipline: BLAKE3 out-circuit — spec §2.1.3.
pub fn verify_tx_ordering_key_deterministic(
    tx_hash: &[u8; 32],
    epoch_id: u64,
) -> Result<[u8; 32], UtxoOrderingError> {
    // Hitung dua kali — harus identik
    let key1 = compute_ordering_key(tx_hash, epoch_id);
    let key2 = compute_ordering_key(tx_hash, epoch_id);

    if key1 != key2 {
        return Err(UtxoOrderingError::NonDeterministicKey);
    }

    Ok(key1)
}

/// Hitung tx_ordering_key. Spec §8.5, §14.3.
///
/// BLAKE3(b"scalar_tx_order_v1" || tx_hash || epoch_id_le64)
fn compute_ordering_key(tx_hash: &[u8; 32], epoch_id: u64) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"scalar_tx_order_v1");
    hasher.update(tx_hash);
    hasher.update(&epoch_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Verifikasi bahwa dua node menghasilkan ordering identik untuk tx set yang sama.
/// Spec §14.3: "Tambahkan assertion bahwa setiap node yang memproses tx set
/// yang sama menghasilkan ordering identik."
pub fn verify_ordering_consistency(
    ordering_a: &[[u8; 32]],
    ordering_b: &[[u8; 32]],
) -> Result<(), UtxoOrderingError> {
    if ordering_a == ordering_b {
        Ok(())
    } else {
        Err(UtxoOrderingError::OrderingMismatch)
    }
}

// ── Gossip Rate Limiter — spec §14.3 ─────────────────────────────────────────

/// Rate limiter untuk DMM requests di gossip layer. Spec §14.3.
///
/// Mencegah flooding DMM requests yang bisa mengganggu jaringan.
/// Batas: MAX_DMM_REQUESTS_PER_EPOCH per node per epoch.
pub struct DmmRequestRateLimiter {
    /// Map node_id_short → jumlah request dalam epoch ini.
    request_counts: std::collections::HashMap<[u8; 4], u32>,
    /// Epoch ID saat ini.
    current_epoch: u64,
}

/// Maksimum DMM request per node per epoch. Spec §14.3.
pub const MAX_DMM_REQUESTS_PER_EPOCH: u32 = 10;

impl DmmRequestRateLimiter {
    pub fn new(epoch: u64) -> Self {
        Self {
            request_counts: std::collections::HashMap::new(),
            current_epoch: epoch,
        }
    }

    /// Cek apakah request dari node ini diizinkan. Spec §14.3.
    ///
    /// Returns true jika masih dalam batas rate limit.
    /// Returns false jika node sudah melebihi batas.
    pub fn check_and_record(&mut self, node_id_short: [u8; 4], epoch: u64) -> bool {
        // Reset jika epoch baru
        if epoch != self.current_epoch {
            self.request_counts.clear();
            self.current_epoch = epoch;
        }

        let count = self.request_counts.entry(node_id_short).or_insert(0);
        if *count >= MAX_DMM_REQUESTS_PER_EPOCH {
            return false; // Rate limited
        }
        *count += 1;
        true
    }

    /// Jumlah request dari node ini dalam epoch saat ini.
    pub fn request_count(&self, node_id_short: &[u8; 4]) -> u32 {
        self.request_counts.get(node_id_short).copied().unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_hash(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    // ── test_dmm_manipulation_blocked ────────────────────────────────────────

    #[test]
    fn test_dmm_manipulation_blocked() {
        // DMM dari unverified peer data → error. Spec §14.3.
        let result = assert_dmm_from_verified_source(false, "peer data not verified");
        assert!(result.is_err(), "Unverified peer data harus di-block");
        assert!(matches!(
            result,
            Err(DmmSecurityError::UnverifiedPeerData { .. })
        ));
    }

    #[test]
    fn test_dmm_verified_source_allowed() {
        // DMM dari data terverifikasi lokal → ok. Spec §14.3.
        let result = assert_dmm_from_verified_source(true, "local verified");
        assert!(result.is_ok());
    }

    #[test]
    fn test_dmm_source_integrity_match() {
        // Hash identik → ok. Spec §14.3.
        let hash = valid_hash(0x42);
        let result = verify_dmm_source_integrity(&hash, &hash);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dmm_source_integrity_mismatch() {
        // Hash berbeda → ManifestHashMismatch. Spec §14.3.
        let local = valid_hash(0x42);
        let claimed = valid_hash(0xFF); // berbeda
        let result = verify_dmm_source_integrity(&local, &claimed);
        assert_eq!(result, Err(DmmSecurityError::ManifestHashMismatch));
    }

    #[test]
    fn test_dmm_source_integrity_zero_hash() {
        // Zero hash → BootstrapRequired. Spec §14.3.
        let zero = [0u8; 32];
        let hash = valid_hash(0x42);
        assert_eq!(
            verify_dmm_source_integrity(&hash, &zero),
            Err(DmmSecurityError::BootstrapRequired)
        );
        assert_eq!(
            verify_dmm_source_integrity(&zero, &hash),
            Err(DmmSecurityError::BootstrapRequired)
        );
    }

    // ── test_utxo_ordering_attack_prevention ─────────────────────────────────

    #[test]
    fn test_utxo_ordering_attack_prevention() {
        // Ordering identik meski urutan penerimaan berbeda. Spec §14.3.
        let tx_hashes = vec![[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];
        let epoch = 5u64;

        // Node A: tx diterima dalam urutan 1,2,3
        let mut keys_a: Vec<[u8; 32]> = tx_hashes
            .iter()
            .map(|h| compute_ordering_key(h, epoch))
            .collect();
        keys_a.sort_unstable();

        // Node B: tx diterima dalam urutan 3,1,2
        let reordered = vec![tx_hashes[2], tx_hashes[0], tx_hashes[1]];
        let mut keys_b: Vec<[u8; 32]> = reordered
            .iter()
            .map(|h| compute_ordering_key(h, epoch))
            .collect();
        keys_b.sort_unstable();

        let result = verify_ordering_consistency(&keys_a, &keys_b);
        assert!(
            result.is_ok(),
            "Ordering harus identik meski urutan penerimaan berbeda — spec §14.3"
        );
    }

    #[test]
    fn test_tx_ordering_key_deterministic() {
        // tx_ordering_key deterministik. Spec §14.3.
        let tx_hash = [0x42u8; 32];
        let result = verify_tx_ordering_key_deterministic(&tx_hash, 5);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ordering_mismatch_detected() {
        // Ordering berbeda → mismatch terdeteksi. Spec §14.3.
        let a = vec![[0x01u8; 32], [0x02u8; 32]];
        let b = vec![[0x02u8; 32], [0x01u8; 32]];
        let result = verify_ordering_consistency(&a, &b);
        assert_eq!(result, Err(UtxoOrderingError::OrderingMismatch));
    }

    // ── test_dmm_gossip_rate_limit ────────────────────────────────────────────

    #[test]
    fn test_dmm_gossip_rate_limit() {
        // Flooding DMM request di-rate-limit. Spec §14.3.
        let mut limiter = DmmRequestRateLimiter::new(1);
        let node = [0x01u8; 4];

        // Request dalam batas → allowed
        for _ in 0..MAX_DMM_REQUESTS_PER_EPOCH {
            assert!(
                limiter.check_and_record(node, 1),
                "Request dalam batas harus diizinkan"
            );
        }

        // Request melebihi batas → blocked
        assert!(
            !limiter.check_and_record(node, 1),
            "Request melebihi batas harus di-block (rate limited)"
        );
    }

    #[test]
    fn test_rate_limiter_resets_on_new_epoch() {
        // Rate limiter reset di epoch baru. Spec §14.3.
        let mut limiter = DmmRequestRateLimiter::new(1);
        let node = [0x01u8; 4];

        // Habiskan quota epoch 1
        for _ in 0..MAX_DMM_REQUESTS_PER_EPOCH {
            limiter.check_and_record(node, 1);
        }
        assert!(!limiter.check_and_record(node, 1)); // blocked

        // Epoch 2: quota reset
        assert!(
            limiter.check_and_record(node, 2),
            "Request harus diizinkan di epoch baru setelah reset"
        );
    }

    #[test]
    fn test_rate_limiter_different_nodes_independent() {
        // Rate limit per node independent. Spec §14.3.
        let mut limiter = DmmRequestRateLimiter::new(1);
        let node_a = [0x01u8; 4];
        let node_b = [0x02u8; 4];

        // Habiskan quota node_a
        for _ in 0..MAX_DMM_REQUESTS_PER_EPOCH {
            limiter.check_and_record(node_a, 1);
        }

        // node_b masih punya quota
        assert!(
            limiter.check_and_record(node_b, 1),
            "Node B harus punya quota independen dari Node A"
        );
    }

    #[test]
    fn test_max_dmm_requests_constant() {
        // MAX_DMM_REQUESTS_PER_EPOCH = 10. Spec §14.3.
        assert_eq!(MAX_DMM_REQUESTS_PER_EPOCH, 10u32);
    }
}
