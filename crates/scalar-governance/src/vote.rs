// File: crates/scalar-governance/src/vote.rs

use zeroize::{Zeroize, ZeroizeOnDrop};

/// WAJIB dihapus dari RAM setelah otorisasi (Mematuhi Aturan Keamanan Memori)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VoteSecret {
    pub(crate) secret_key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CastVote {
    pub proposal_id: u64,
    pub voter_pubkey: [u8; 32],
    pub power: u64,
    pub vote_hash: [u8; 32], // Out-circuit Hash
}

impl VoteSecret {
    pub fn new(secret: [u8; 32]) -> Self {
        Self { secret_key: secret }
    }

    /// Menghasilkan otorisasi vote menggunakan BLAKE3 (Out-circuit hashing rule v5.0)
    pub fn generate_vote_hash(&self, proposal_id: u64, voter_pubkey: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&proposal_id.to_le_bytes());
        hasher.update(voter_pubkey);
        hasher.update(&self.secret_key); // Private info
        *hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vote_hash_deterministic_and_secure() {
        let secret = VoteSecret::new([1; 32]);
        let pubkey = [2; 32];

        let hash1 = secret.generate_vote_hash(42, &pubkey);
        let hash2 = secret.generate_vote_hash(42, &pubkey);

        assert_eq!(hash1, hash2, "BLAKE3 hash harus deterministik");
        // secret dihapus secara otomatis dari memory setelah context selesai (ZeroizeOnDrop)
    }
}
