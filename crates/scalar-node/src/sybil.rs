//! Modul Ketahanan Sybil (Sybil Resistance)
//! Mengimplementasikan Proof-of-Unique-Node menggunakan Argon2id (Concept 3.5.2)

use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, Params, PasswordHasher};

pub struct NodeIdentity {
    pub id: [u8; 32],
}

impl NodeIdentity {
    /// Menghasilkan Identitas Unik berdasarkan komputasi Memory-Hard
    pub fn generate(hardware_fingerprint: &[u8]) -> Self {
        // CATATAN ARSITEK:
        // Sesuai dokumen Concept 3.5.2, di Mainnet/Production ini akan diset ke 4GB RAM.
        // Untuk environment Development (Codespace) saat ini, kita gunakan 16MB
        // agar server GitHub Anda tidak mengalami Out-Of-Memory (OOM) crash.
        let m_cost = 16 * 1024; // 16 MB untuk Dev (Production: 4 * 1024 * 1024 KB)
        let t_cost = 3; // Iterasi waktu
        let p_cost = 1; // Paralelisme

        let params = Params::new(m_cost, t_cost, p_cost, Some(32)).unwrap();
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        // Menghasilkan salt acak yang aman
        let salt = SaltString::generate(&mut OsRng);

        // Eksekusi komputasi memori berat untuk menghasilkan ID Node
        let hash = argon2.hash_password(hardware_fingerprint, &salt).unwrap();
        let hash_bytes = hash.hash.unwrap();

        let mut id = [0u8; 32];
        let len = std::cmp::min(32, hash_bytes.len());
        id[..len].copy_from_slice(&hash_bytes.as_bytes()[..len]);

        Self { id }
    }
}
