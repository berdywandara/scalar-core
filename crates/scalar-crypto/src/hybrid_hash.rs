// File: crates/scalar-crypto/src/hybrid_hash.rs

use crate::poseidon2::Poseidon2Hasher;

pub enum HashContext {
    InCircuit,
    OutCircuit,
}

pub struct HybridHasher;

impl HybridHasher {
    pub fn hash(context: HashContext, data: &[u8]) -> Vec<u8> {
        match context {
            HashContext::OutCircuit => {
                // Spesifikasi v5.0: Out-circuit WAJIB BLAKE3
                let mut hasher = blake3::Hasher::new();
                hasher.update(data);
                hasher.finalize().as_bytes().to_vec()
            }
            HashContext::InCircuit => {
                // Spesifikasi v5.0: In-circuit WAJIB Poseidon2
                let fields = Poseidon2Hasher::hash_bytes_to_field(data);
                let mut out = Vec::with_capacity(32);
                for f in fields {
                    out.extend_from_slice(&f.to_le_bytes());
                }
                out
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_routing_context() {
        let data = b"scalar_v5_payload";
        let out_hash = HybridHasher::hash(HashContext::OutCircuit, data);
        let in_hash = HybridHasher::hash(HashContext::InCircuit, data);

        assert_ne!(
            out_hash, in_hash,
            "Hasil rute In-Circuit dan Out-Circuit harus berbeda"
        );
        assert_eq!(out_hash.len(), 32);
        assert_eq!(in_hash.len(), 32);
    }
}
