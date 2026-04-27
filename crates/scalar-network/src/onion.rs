//! GAP B-006: Onion Routing & Padding (Sphinx-like)

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum PaddingSize {
    Small = 1024,    // 1 KB (State messages)
    Medium = 16384,  // 16 KB (Small proofs)
    Large = 65536,   // 64 KB (Full proofs)
    XLarge = 262144, // 256 KB (Aggregated proofs)
}

pub struct OnionRouter;

impl OnionRouter {
    /// 3-hop routing default. Setiap hop mengenkripsi data mundur.
    pub fn build_route(payload: &[u8], _hop_keys: &[[u8; 32]; 3]) -> Vec<u8> {
        // 1. Padding data
        let padded = Self::pad_payload(payload);

        // 2. Layered Encryption (ML-KEM + ChaCha20-Poly1305)
        // Di produksi, iterasi dari hop terakhir ke pertama

        padded
    }

    fn pad_payload(payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let target = if len <= PaddingSize::Small as usize {
            PaddingSize::Small as usize
        } else if len <= PaddingSize::Medium as usize {
            PaddingSize::Medium as usize
        } else if len <= PaddingSize::Large as usize {
            PaddingSize::Large as usize
        } else {
            PaddingSize::XLarge as usize
        };

        let mut out = payload.to_vec();
        out.resize(target, 0);
        out
    }
}
