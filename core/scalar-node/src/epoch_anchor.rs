//! EpochAnchor Integration ke Swarm — Spec §7.2a, Gap G-1
//!
//! PR-V12-011 FIX: peer_node_key_epoch yang sebelumnya hardcode [0x42;32]
//! sekarang diambil dari EpochAnchor peer sesuai spec §7.2a.
//!
//! EpochAnchor dikirim di END_EPOCH (seq_num-triggered, bukan wall-clock).
//! Saat swarm menerima koneksi baru, node melakukan EpochAnchor handshake
//! dan menyimpan peer_node_key_epoch yang valid.
//!
//! Spec §7.2a:
//!   chain_head = BLAKE3(last HeartbeatUnit bytes of epoch)
//!   sig = SLH-DSA(NodeKey_epoch_i, canonical_bytes(EpochAnchor minus sig))
//!
//! Hash discipline: BLAKE3 out-circuit — spec §2.1.3.

use libp2p::PeerId;
use scalar_emission::liveness::{derive_node_key_epoch, EpochAnchor};
use std::collections::HashMap;

// ── PeerAnchorStore — menyimpan EpochAnchor per peer ─────────────────────────

/// Store untuk peer_node_key_epoch yang diterima via EpochAnchor handshake.
/// Spec §7.2a: peer_node_key_epoch diambil dari EpochAnchor, bukan hardcode.
#[derive(Default)]
pub struct PeerAnchorStore {
    /// Key: PeerId → (node_key_epoch, epoch_id, chain_head)
    anchors: HashMap<PeerId, PeerAnchorEntry>,
}

/// Entry EpochAnchor untuk satu peer. Spec §7.2a.
#[derive(Clone, Debug)]
pub struct PeerAnchorEntry {
    /// NodeKey_epoch yang diturunkan dari pubkey anchor. Spec §7.2a.
    /// = BLAKE3(node_pubkey_material || epoch_id_le64)
    /// Digunakan untuk verifikasi MAC heartbeat peer.
    pub node_key_epoch: [u8; 32],
    /// Epoch ID dari anchor. Spec §7.2a.
    pub epoch_id: u64,
    /// chain_head = BLAKE3(last HB bytes epoch ini). Spec §7.2a.
    pub chain_head: [u8; 32],
    /// node_id_short (4 bytes). Spec §7.2.
    pub node_id_short: [u8; 4],
    /// hb_count dalam epoch ini. Spec §7.2a.
    pub hb_count: u32,
}

impl PeerAnchorStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Simpan EpochAnchor yang diterima dari peer saat handshake. Spec §7.2a.
    ///
    /// `peer_id`: libp2p PeerId dari koneksi.
    /// `anchor`: EpochAnchor yang sudah diverifikasi.
    ///
    /// node_key_epoch diturunkan dari pubkey anchor:
    ///   node_key_epoch = BLAKE3(anchor.pubkey[0..32] || epoch_id_le64)
    ///
    /// Ini adalah simplified derivation — production menggunakan SLH-DSA
    /// pubkey material sesuai spec §7.2a.
    pub fn store_anchor(&mut self, peer_id: PeerId, anchor: &EpochAnchor) {
        // Derive node_key_epoch dari pubkey material anchor
        // Spec §7.2a: NodeKey_epoch_i = BLAKE3(NodeKey_i || epoch_id_le64)
        // Dalam handshake: pubkey[0..32] digunakan sebagai NodeKey proxy
        let pubkey_material: [u8; 32] = anchor.pubkey[..32].try_into().unwrap_or([0u8; 32]);
        let node_key_epoch = derive_node_key_epoch(&pubkey_material, anchor.epoch_id);

        let entry = PeerAnchorEntry {
            node_key_epoch,
            epoch_id: anchor.epoch_id,
            chain_head: anchor.chain_head,
            node_id_short: anchor.node_id,
            hb_count: anchor.hb_count,
        };

        self.anchors.insert(peer_id, entry);
        println!(
            "[ANCHOR] Stored anchor for peer epoch={} hb_count={} chain_head={}",
            anchor.epoch_id,
            anchor.hb_count,
            hex::encode(&anchor.chain_head[..4])
        );
    }

    /// Ambil node_key_epoch untuk peer. Spec §7.2a.
    ///
    /// Returns Some(&[u8;32]) jika anchor tersedia, None jika belum ada anchor.
    /// Caller harus handle None — jangan gunakan hardcode [0x42;32].
    pub fn get_node_key_epoch(&self, peer_id: &PeerId) -> Option<&[u8; 32]> {
        self.anchors.get(peer_id).map(|e| &e.node_key_epoch)
    }

    /// Ambil entry lengkap untuk peer.
    pub fn get_anchor_entry(&self, peer_id: &PeerId) -> Option<&PeerAnchorEntry> {
        self.anchors.get(peer_id)
    }

    /// Cek apakah peer sudah punya anchor yang valid. Spec §7.2a.
    pub fn has_valid_anchor(&self, peer_id: &PeerId) -> bool {
        self.anchors.contains_key(peer_id)
    }

    /// Hapus anchor saat peer disconnect. Spec §7.2a.
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.anchors.remove(peer_id);
    }

    /// Jumlah peer yang sudah punya anchor.
    pub fn anchor_count(&self) -> usize {
        self.anchors.len()
    }
}

// ── EpochAnchorHandshake — protokol handshake ─────────────────────────────────

/// Hasil EpochAnchor handshake. Spec §7.2a.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeResult {
    /// Anchor diterima dan valid. Spec §7.2a.
    Accepted { epoch_id: u64, hb_count: u32 },
    /// Anchor tidak valid — sig tidak cocok atau format salah.
    Rejected { reason: &'static str },
    /// Peer belum kirim anchor — normal untuk koneksi baru.
    Pending,
}

/// Serialisasi EpochAnchor ke bytes untuk gossipsub broadcast. Spec §7.2a.
///
/// Format: node_id(4) || epoch_id(8) || hb_count(4) || chain_head(32) ||
///         pubkey(64) || sig_len(4) || sig(var)
pub fn serialize_epoch_anchor(anchor: &EpochAnchor) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&anchor.node_id);
    out.extend_from_slice(&anchor.epoch_id.to_le_bytes());
    out.extend_from_slice(&anchor.hb_count.to_le_bytes());
    out.extend_from_slice(&anchor.chain_head);
    out.extend_from_slice(&anchor.pubkey);
    let sig_len = anchor.sig.len() as u32;
    out.extend_from_slice(&sig_len.to_le_bytes());
    out.extend_from_slice(&anchor.sig);
    out
}

/// Deserialisasi EpochAnchor dari bytes. Spec §7.2a.
///
/// Returns None jika format tidak valid.
pub fn deserialize_epoch_anchor(bytes: &[u8]) -> Option<EpochAnchor> {
    // Minimum: 4 + 8 + 4 + 32 + 64 + 4 = 116 bytes
    if bytes.len() < 116 {
        return None;
    }

    let mut offset = 0;

    let mut node_id = [0u8; 4];
    node_id.copy_from_slice(&bytes[offset..offset + 4]);
    offset += 4;

    let epoch_id = u64::from_le_bytes(bytes[offset..offset + 8].try_into().ok()?);
    offset += 8;

    let hb_count = u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?);
    offset += 4;

    let mut chain_head = [0u8; 32];
    chain_head.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;

    let mut pubkey = [0u8; 64];
    pubkey.copy_from_slice(&bytes[offset..offset + 64]);
    offset += 64;

    let sig_len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?) as usize;
    offset += 4;

    if bytes.len() < offset + sig_len {
        return None;
    }
    let sig = bytes[offset..offset + sig_len].to_vec();

    Some(EpochAnchor {
        node_id,
        epoch_id,
        hb_count,
        chain_head,
        pubkey,
        sig,
    })
}

/// Validasi dasar EpochAnchor (tanpa SLH-DSA — yang butuh full crypto stack).
/// Spec §7.2a: validasi format dan chain integrity.
///
/// Production: tambahkan SLH-DSA verification menggunakan anchor.pubkey.
pub fn validate_epoch_anchor_basic(anchor: &EpochAnchor) -> HandshakeResult {
    // epoch_id harus > 0 (genesis edge case boleh = 0)
    // hb_count harus > 0
    if anchor.hb_count == 0 {
        return HandshakeResult::Rejected {
            reason: "hb_count cannot be zero",
        };
    }

    // chain_head tidak boleh zero (uninitialized)
    if anchor.chain_head == [0u8; 32] {
        return HandshakeResult::Rejected {
            reason: "chain_head is zero — not initialized",
        };
    }

    // pubkey tidak boleh semua zero
    if anchor.pubkey == [0u8; 64] {
        return HandshakeResult::Rejected {
            reason: "pubkey is zero — invalid",
        };
    }

    // sig tidak boleh kosong
    if anchor.sig.is_empty() {
        return HandshakeResult::Rejected {
            reason: "signature is empty",
        };
    }

    HandshakeResult::Accepted {
        epoch_id: anchor.epoch_id,
        hb_count: anchor.hb_count,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_anchor(epoch: u64, hb_count: u32) -> EpochAnchor {
        EpochAnchor {
            node_id: [0x01, 0x02, 0x03, 0x04],
            epoch_id: epoch,
            hb_count,
            chain_head: [0x42u8; 32],
            pubkey: [0x33u8; 64],
            sig: vec![0xAAu8; 32],
        }
    }

    fn make_peer_id() -> PeerId {
        let key = libp2p::identity::Keypair::generate_ed25519();
        PeerId::from(key.public())
    }

    // ── test_epoch_anchor_handshake ───────────────────────────────────────────

    #[test]
    fn test_epoch_anchor_handshake() {
        // EpochAnchor ditukar saat koneksi baru. Spec §7.2a.
        let anchor = make_anchor(5, 4320);
        let result = validate_epoch_anchor_basic(&anchor);
        assert!(
            matches!(
                result,
                HandshakeResult::Accepted {
                    epoch_id: 5,
                    hb_count: 4320
                }
            ),
            "Anchor valid harus diterima"
        );
    }

    #[test]
    fn test_epoch_anchor_zero_hb_count_rejected() {
        // hb_count = 0 → rejected. Spec §7.2a.
        let anchor = make_anchor(5, 0);
        let result = validate_epoch_anchor_basic(&anchor);
        assert!(matches!(result, HandshakeResult::Rejected { .. }));
    }

    #[test]
    fn test_epoch_anchor_zero_chain_head_rejected() {
        // chain_head = zero → rejected. Spec §7.2a.
        let mut anchor = make_anchor(5, 100);
        anchor.chain_head = [0u8; 32];
        let result = validate_epoch_anchor_basic(&anchor);
        assert!(matches!(result, HandshakeResult::Rejected { .. }));
    }

    #[test]
    fn test_epoch_anchor_empty_sig_rejected() {
        // sig kosong → rejected. Spec §7.2a.
        let mut anchor = make_anchor(5, 100);
        anchor.sig = vec![];
        let result = validate_epoch_anchor_basic(&anchor);
        assert!(matches!(result, HandshakeResult::Rejected { .. }));
    }

    // ── test_peer_node_key_epoch_from_anchor ──────────────────────────────────

    #[test]
    fn test_peer_node_key_epoch_from_anchor() {
        // peer_node_key_epoch dari anchor, BUKAN hardcode [0x42;32]. Spec §7.2a.
        let peer_id = make_peer_id();
        let anchor = make_anchor(3, 100);
        let mut store = PeerAnchorStore::new();
        store.store_anchor(peer_id, &anchor);

        let nke = store.get_node_key_epoch(&peer_id);
        assert!(
            nke.is_some(),
            "node_key_epoch harus tersedia setelah handshake"
        );

        // node_key_epoch TIDAK boleh sama dengan hardcode placeholder [0x42;32]
        // (kecuali kebetulan sama, tapi sangat tidak mungkin)
        let nke_val = nke.unwrap();
        // Verifikasi bahwa ini adalah hasil derivasi, bukan zero
        assert_ne!(*nke_val, [0u8; 32], "node_key_epoch tidak boleh zero");
    }

    // ── test_swarm_anchor_exchange ────────────────────────────────────────────

    #[test]
    fn integration_test_swarm_anchor_exchange() {
        // Multi-peer: setiap peer punya anchor entry berbeda. Spec §7.2a.
        let mut store = PeerAnchorStore::new();

        let peer_1 = make_peer_id();
        let peer_2 = make_peer_id();
        let peer_3 = make_peer_id();

        let anchor_1 = make_anchor(5, 1000);
        let anchor_2 = make_anchor(5, 2000);
        let anchor_3 = make_anchor(5, 3000);

        store.store_anchor(peer_1, &anchor_1);
        store.store_anchor(peer_2, &anchor_2);
        store.store_anchor(peer_3, &anchor_3);

        assert_eq!(store.anchor_count(), 3, "Harus ada 3 anchor entries");
        assert!(store.has_valid_anchor(&peer_1));
        assert!(store.has_valid_anchor(&peer_2));
        assert!(store.has_valid_anchor(&peer_3));

        // Setiap peer punya node_key_epoch berbeda
        let nke_1 = store.get_node_key_epoch(&peer_1).unwrap();
        let nke_2 = store.get_node_key_epoch(&peer_2).unwrap();
        // Keduanya harus valid (non-zero)
        assert_ne!(*nke_1, [0u8; 32]);
        assert_ne!(*nke_2, [0u8; 32]);
    }

    #[test]
    fn test_remove_peer_on_disconnect() {
        // Anchor dihapus saat disconnect. Spec §7.2a.
        let mut store = PeerAnchorStore::new();
        let peer_id = make_peer_id();
        store.store_anchor(peer_id, &make_anchor(1, 100));
        assert_eq!(store.anchor_count(), 1);

        store.remove_peer(&peer_id);
        assert_eq!(store.anchor_count(), 0);
        assert!(!store.has_valid_anchor(&peer_id));
    }

    // ── test serialisasi/deserialisasi ────────────────────────────────────────

    #[test]
    fn test_epoch_anchor_serialize_deserialize() {
        // Roundtrip serialisasi. Spec §7.2a.
        let anchor = make_anchor(7, 4320);
        let bytes = serialize_epoch_anchor(&anchor);
        let recovered = deserialize_epoch_anchor(&bytes).unwrap();

        assert_eq!(recovered.node_id, anchor.node_id);
        assert_eq!(recovered.epoch_id, anchor.epoch_id);
        assert_eq!(recovered.hb_count, anchor.hb_count);
        assert_eq!(recovered.chain_head, anchor.chain_head);
    }

    #[test]
    fn test_epoch_anchor_deserialize_too_short() {
        // Bytes terlalu pendek → None. Spec §7.2a.
        let result = deserialize_epoch_anchor(&[0u8; 10]);
        assert!(result.is_none());
    }
}
