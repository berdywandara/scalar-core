// crates/scalar-wallet-core/src/key_management.rs
//! Hierarchical Key Derivation — sesuai NC5 §5.7 Layer 9
//! 
//! Chain derivasi yang benar (NC5 final):
//!   seed
//!     → MasterKey  = BLAKE3(seed ∥ "scalar_master")
//!     → AccountKey = BLAKE3(MasterKey ∥ "account" ∥ i)
//!     → SpendKey   = BLAKE3(AccountKey ∥ "spend")
//!     → ViewKey    = BLAKE3(AccountKey ∥ "view")
//!     → NodeKey    = BLAKE3(AccountKey ∥ "node")
//!     → DuressKey  = BLAKE3(AccountKey ∥ "duress" ∥ index_le_bytes)
//!
//! Kata pertama mnemonic HARUS "scalar" — divalidasi di layer UI
//! sebelum fungsi ini dipanggil (NC5 GAP-016).
//!
//! `seed` yang diterima derive_from_seed() adalah output dari:
//! PBKDF2-HMAC-SHA3(mnemonic, "scalar_v1", 2048)
//! — pemanggil bertanggung jawab untuk langkah PBKDF2 tersebut.

use scalar_crypto::blake3;

// ── Tipe kunci (tuple structs, identik dengan file original) ─────────

pub struct SpendKey(pub [u8; 32]);
pub struct ViewKey(pub [u8; 32]);
pub struct NodeKey(pub [u8; 32]);
pub struct DuressKey(pub [u8; 32]);

// ── WalletKeys ────────────────────────────────────────────────────────
// Perubahan dari original:
//   - duress_1 / duress_2 (hardcoded) → duress_keys: Vec<DuressKey>
//     agar mendukung indeks yang dinamis sesuai spec NC5.
//   - derive_from_seed menambahkan account_index parameter.

pub struct WalletKeys {
    pub spend_key:   SpendKey,
    pub view_key:    ViewKey,
    pub node_key:    NodeKey,
    pub duress_keys: Vec<DuressKey>,  // index 0 = duress_1, index 1 = duress_2, dst.
}

impl WalletKeys {
    /// Derivasi hierarki kunci dari master seed, untuk account ke-`account_index`.
    ///
    /// Untuk penggunaan wallet standar: account_index = 0.
    /// Multi-account support: panggil dengan account_index berbeda.
    pub fn derive_from_seed(seed: &[u8], account_index: u64) -> Self {
        // ── Step 1: MasterKey = BLAKE3(seed ∥ "scalar_master") ──────
        let master_key = blake3_concat(seed, b"scalar_master");

        // ── Step 2: AccountKey = BLAKE3(MasterKey ∥ "account" ∥ i) ─
        let mut account_input = Vec::with_capacity(32 + 7 + 8);
        account_input.extend_from_slice(&master_key);
        account_input.extend_from_slice(b"account");
        account_input.extend_from_slice(&account_index.to_le_bytes());
        let account_key: [u8; 32] = *blake3::hash(&account_input).as_bytes();

        // ── Step 3: Purpose keys = BLAKE3(AccountKey ∥ domain) ──────
        let spend_key = SpendKey(blake3_concat(&account_key, b"spend"));
        let view_key  = ViewKey(blake3_concat(&account_key, b"view"));
        let node_key  = NodeKey(blake3_concat(&account_key, b"node"));

        // ── Step 4: DuressKey = BLAKE3(AccountKey ∥ "duress" ∥ i) ──
        // Default: 2 level duress (index 0 dan 1), sesuai impl original.
        let duress_keys: Vec<DuressKey> = (0u64..2)
            .map(|i| {
                let mut input = Vec::with_capacity(32 + 6 + 8);
                input.extend_from_slice(&account_key);
                input.extend_from_slice(b"duress");
                input.extend_from_slice(&i.to_le_bytes());
                DuressKey(*blake3::hash(&input).as_bytes())
            })
            .collect();

        Self {
            spend_key,
            view_key,
            node_key,
            duress_keys,
        }
    }

    /// Backward-compat helpers — akses duress key by index.
    pub fn duress_1(&self) -> Option<&DuressKey> {
        self.duress_keys.get(0)
    }

    pub fn duress_2(&self) -> Option<&DuressKey> {
        self.duress_keys.get(1)
    }
}

// ── Helper internal ───────────────────────────────────────────────────

/// BLAKE3(a ∥ b) — helper untuk menghindari repetisi Vec boilerplate.
fn blake3_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(a.len() + b.len());
    input.extend_from_slice(a);
    input.extend_from_slice(b);
    *blake3::hash(&input).as_bytes()
}