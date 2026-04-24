//! GAP C-001 & C-003: Hierarchical Key Derivation & ViewKey
//! Derivasi 4 tipe kunci dari Seed menggunakan BLAKE3 KDF

use scalar_crypto::blake3;

pub struct SpendKey(pub [u8; 32]);
pub struct ViewKey(pub [u8; 32]);
pub struct NodeKey(pub [u8; 32]);
pub struct DuressKey(pub [u8; 32]);

pub struct WalletKeys {
    pub spend_key: SpendKey,
    pub view_key: ViewKey,
    pub node_key: NodeKey,
    pub duress_1: DuressKey,
    pub duress_2: DuressKey,
}

impl WalletKeys {
    /// Menghasilkan hierarki kunci deterministik dari master seed
    /// Kata pertama mnemonic harus divalidasi "scalar" di layer UI
    pub fn derive_from_seed(seed: &[u8]) -> Self {
        // Domain Separators (scalar_v1)
        let spend_seed = blake3::derive_key("scalar_v1_spend", seed);
        let view_seed = blake3::derive_key("scalar_v1_view", seed);
        let node_seed = blake3::derive_key("scalar_v1_node", seed);
        
        // Multi-level Duress (Decoy wallets)
        let duress_1_seed = blake3::derive_key("scalar_v1_duress_1", seed);
        let duress_2_seed = blake3::derive_key("scalar_v1_duress_2", seed);

        Self {
            spend_key: SpendKey(spend_seed),
            view_key: ViewKey(view_seed),     // Read-only balance
            node_key: NodeKey(node_seed),     // Identity P2P node
            duress_1: DuressKey(duress_1_seed), // Fake wallet 1
            duress_2: DuressKey(duress_2_seed), // Fake wallet 2
        }
    }
}
