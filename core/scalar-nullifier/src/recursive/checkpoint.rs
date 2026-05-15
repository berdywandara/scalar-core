// File: crates/scalar-nullifier/src/recursive/checkpoint.rs

use std::collections::HashSet;

/// representation Mock from Recursive STARK Proof.
/// implemented secara full on milestone M5/M6.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecursiveProof {
    pub data: Vec<u8>,
}

/// NS_ARCH: STARK Checkpoint layer (Interface & Stub)
/// store root state from layer COLD that has at-roll-up menjaat STARK proof.
pub struct ArchCheckpoint {
    pub latest_epoch: u64,
    pub latest_root: [u8; 32], // Merepresentationkan Poseidon2 root
    verified_nullifiers: HashSet<[u8; 32]>, // Stub: Fast lookup for item that terproof masuk arch
}

impl ArchCheckpoint {
    pub fn new() -> Self {
        Self {
            latest_epoch: 0,
            latest_root: [0; 32],
            verified_nullifiers: HashSet::new(),
        }
    }

    /// Mengecheck whether sebuah nullifier already validated and masuk to NS_ARCH
    pub fn contains(&self, nullifier: &[u8; 32]) -> bool {
        self.verified_nullifiers.contains(nullifier)
    }

    /// interface verification Recursive STARK Proof.
    /// when this (v5.0 M5) perform mock verification and validate rule sistem.
    pub fn verify_and_apply_checkpoint(
        &mut self,
        epoch: u64,
        new_root: [u8; 32],
        proof: &RecursiveProof,
        archived_items: &[[u8; 32]], // data public input for merekonstruksi state
    ) -> Result<(), &'static str> {
        if epoch <= self.latest_epoch {
            return Err("Epoch harus monotonic (strictly increasing)");
        }

        if proof.data.is_empty() {
            return Err("Invalid Recursive Proof: empty data");
        }

        // MOCK VERIFICATION LOGIC
        // Integrasi dengan STARK verifier akan ditempatkan di sini.

        // Apply state setelah verifikasi dianggap PASS
        self.latest_epoch = epoch;
        self.latest_root = new_root;
        for item in archived_items {
            self.verified_nullifiers.insert(*item);
        }

        Ok(())
    }
}

impl Default for ArchCheckpoint {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests_arch_checkpoint {
    use super::*;

    #[test]
    fn test_checkpoint_accepts_valid_proof() {
        let mut arch = ArchCheckpoint::new();
        let proof = RecursiveProof {
            data: vec![0xFF; 32],
        };
        let new_root = [1u8; 32];
        let items = [[10u8; 32], [20u8; 32]];

        let res = arch.verify_and_apply_checkpoint(1, new_root, &proof, &items);
        assert!(res.is_ok());
        assert_eq!(arch.latest_epoch, 1);
        assert_eq!(arch.latest_root, new_root);
        assert!(arch.contains(&[10u8; 32]));
    }

    #[test]
    fn test_checkpoint_rejects_empty_proof() {
        let mut arch = ArchCheckpoint::new();
        let empty_proof = RecursiveProof { data: vec![] };
        let res = arch.verify_and_apply_checkpoint(1, [1u8; 32], &empty_proof, &[]);
        assert!(res.is_err(), "Harus menolak proof yang kosong");
    }

    #[test]
    fn test_checkpoint_epoch_must_be_monotonic() {
        let mut arch = ArchCheckpoint::new();
        let proof = RecursiveProof { data: vec![0xFF] };

        // Pendaftaran pertama harus berhasil
        assert!(arch
            .verify_and_apply_checkpoint(5, [1u8; 32], &proof, &[])
            .is_ok());

        // Epoch sama atau lebih kecil harus ditolak
        assert!(arch
            .verify_and_apply_checkpoint(5, [2u8; 32], &proof, &[])
            .is_err());
        assert!(arch
            .verify_and_apply_checkpoint(4, [2u8; 32], &proof, &[])
            .is_err());

        // Epoch lebih besar harus diterima
        assert!(arch
            .verify_and_apply_checkpoint(6, [3u8; 32], &proof, &[])
            .is_ok());
    }
}
