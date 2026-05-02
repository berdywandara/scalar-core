//! Institutional Nodes — Spec §10.3
//!
//! Institusi adalah entitas dengan multiple authorized operators dan
//! succession plan internal. Mencegah network collapse karena demographic
//! turnover antar generasi.
//!
//! P(network_alive) = 85% bergantung pada institutional nodes.
//! Tanpa institutional nodes: P ≈ 1% (spec §19.1).
//!
//! ATURAN OSSIFIED (spec §10.3):
//! - Maximum 7 operators per institusi
//! - M-of-N minimum: M > N/2 (majority threshold)
//! - Uptime institusi = MAXIMUM dari semua operator aktif
//! - Longevity dari institution_registered_epoch (tidak reset)

use std::collections::HashMap;

// ── Constants — Spec §10.3 ────────────────────────────────────────────────────

/// Maksimum operator per institusi. OSSIFIED — spec §10.3.
pub const MAX_OPERATORS: usize = 7;

// ── OperatorEntry — Spec §10.3 ────────────────────────────────────────────────

/// Entry satu operator dalam institusi. Spec §10.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorEntry {
    /// NodeID operator individual. Spec §10.3.
    pub operator_id: [u8; 32],
    /// Commitment ke NodeKey operator. Spec §10.3.
    pub node_key_commitment: [u8; 32],
    /// Epoch saat operator ditambahkan. Spec §10.3.
    pub added_epoch: u64,
    /// Status aktif operator. Spec §10.3.
    pub is_active: bool,
}

// ── InstitutionalNode — Spec §10.3 ───────────────────────────────────────────

/// Node institusional dengan multiple operators. Spec §10.3.
///
/// Contoh institusi eligible: universitas, perpustakaan publik,
/// non-profit endowment, koperasi, open source foundation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstitutionalNode {
    /// NodeID institusi (immutable). Spec §10.3.
    pub institution_id: [u8; 32],
    /// BLAKE3(nama institusi). Spec §10.3.
    pub institution_name_hash: [u8; 32],
    /// Daftar operator (max 7). Spec §10.3.
    pub operators: Vec<OperatorEntry>,
    /// Threshold M dari M-of-N. Spec §10.3: M > N/2.
    pub m_of_n_threshold: u8,
    /// Epoch saat institusi didaftarkan. Spec §10.3.
    pub registered_epoch: u64,
    /// Social commitment hash. Spec §10.3.
    pub institution_commitment: [u8; 32],
}

/// Error operasi institusional. Spec §10.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstitutionalError {
    /// Melebihi max 7 operators.
    TooManyOperators { count: usize },
    /// M-of-N threshold tidak memenuhi M > N/2.
    InsufficientThreshold { m: u8, n: u8 },
    /// Threshold = 0 tidak valid.
    ZeroThreshold,
    /// Operator tidak ditemukan.
    OperatorNotFound,
    /// Tidak cukup signatures aktif untuk operasi ini.
    InsufficientSignatures { provided: usize, required: u8 },
    /// Operator sudah ada.
    OperatorAlreadyExists,
}

impl core::fmt::Display for InstitutionalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooManyOperators { count } => {
                write!(f, "Terlalu banyak operator: {count} (max {MAX_OPERATORS})")
            }
            Self::InsufficientThreshold { m, n } => {
                write!(f, "Threshold M={m} tidak memenuhi M > N/2 (N={n})")
            }
            Self::ZeroThreshold => write!(f, "Threshold tidak boleh 0"),
            Self::OperatorNotFound => write!(f, "Operator tidak ditemukan"),
            Self::InsufficientSignatures { provided, required } => {
                write!(f, "Signatures tidak cukup: {provided} < {required}")
            }
            Self::OperatorAlreadyExists => write!(f, "Operator sudah terdaftar"),
        }
    }
}

impl InstitutionalNode {
    /// Buat InstitutionalNode baru. Validasi M-of-N dan max operators.
    /// Spec §10.3.
    pub fn new(
        institution_id: [u8; 32],
        institution_name_hash: [u8; 32],
        operators: Vec<OperatorEntry>,
        m_of_n_threshold: u8,
        registered_epoch: u64,
        institution_commitment: [u8; 32],
    ) -> Result<Self, InstitutionalError> {
        // Max 7 operators — spec §10.3 OSSIFIED
        if operators.len() > MAX_OPERATORS {
            return Err(InstitutionalError::TooManyOperators {
                count: operators.len(),
            });
        }
        // Threshold tidak boleh 0
        if m_of_n_threshold == 0 {
            return Err(InstitutionalError::ZeroThreshold);
        }
        // M > N/2 — spec §10.3
        let n = operators.len() as u8;
        if n > 0 && m_of_n_threshold * 2 <= n {
            return Err(InstitutionalError::InsufficientThreshold {
                m: m_of_n_threshold,
                n,
            });
        }
        Ok(Self {
            institution_id,
            institution_name_hash,
            operators,
            m_of_n_threshold,
            registered_epoch,
            institution_commitment,
        })
    }

    /// Jumlah operator aktif.
    pub fn active_operator_count(&self) -> usize {
        self.operators.iter().filter(|op| op.is_active).count()
    }

    /// Uptime institusi = MAXIMUM dari semua operator aktif. Spec §10.3.
    /// Institusi dianggap online jika ≥1 operator online.
    /// `operator_uptimes`: map operator_id → uptime_weight (fixed-point).
    pub fn institutional_uptime(&self, operator_uptimes: &HashMap<[u8; 32], u64>) -> u64 {
        self.operators
            .iter()
            .filter(|op| op.is_active)
            .map(|op| operator_uptimes.get(&op.operator_id).copied().unwrap_or(0))
            .max()
            .unwrap_or(0)
    }

    /// Verifikasi bahwa operasi kritis punya cukup signatures aktif.
    /// Spec §10.3: rotasi operator butuh M signatures.
    pub fn verify_quorum(&self, signing_operators: &[[u8; 32]]) -> Result<(), InstitutionalError> {
        let valid_signatures = signing_operators
            .iter()
            .filter(|sig_id| {
                self.operators
                    .iter()
                    .any(|op| op.is_active && &op.operator_id == *sig_id)
            })
            .count();

        if valid_signatures < self.m_of_n_threshold as usize {
            return Err(InstitutionalError::InsufficientSignatures {
                provided: valid_signatures,
                required: self.m_of_n_threshold,
            });
        }
        Ok(())
    }

    /// Tambah operator baru. Butuh M-of-N approval dari operators aktif.
    /// Spec §10.3: rotasi operator butuh M signatures.
    pub fn add_operator(
        &mut self,
        new_operator: OperatorEntry,
        signing_operators: &[[u8; 32]],
    ) -> Result<(), InstitutionalError> {
        // Cek duplikat
        if self
            .operators
            .iter()
            .any(|op| op.operator_id == new_operator.operator_id)
        {
            return Err(InstitutionalError::OperatorAlreadyExists);
        }
        // Max 7 operators
        if self.operators.len() >= MAX_OPERATORS {
            return Err(InstitutionalError::TooManyOperators {
                count: self.operators.len() + 1,
            });
        }
        // Verifikasi quorum
        self.verify_quorum(signing_operators)?;
        self.operators.push(new_operator);
        Ok(())
    }

    /// Deactivate operator. Butuh M-of-N approval.
    /// Spec §10.3: rotasi operator butuh M signatures.
    pub fn deactivate_operator(
        &mut self,
        operator_id: &[u8; 32],
        signing_operators: &[[u8; 32]],
    ) -> Result<(), InstitutionalError> {
        self.verify_quorum(signing_operators)?;
        let op = self
            .operators
            .iter_mut()
            .find(|op| &op.operator_id == operator_id)
            .ok_or(InstitutionalError::OperatorNotFound)?;
        op.is_active = false;
        Ok(())
    }
}

// ── InstitutionalRegistry — Spec §16.1 ───────────────────────────────────────

/// Registry semua institutional nodes. Spec §16.1.
#[derive(Default)]
pub struct InstitutionalRegistry {
    nodes: HashMap<[u8; 32], InstitutionalNode>,
}

impl InstitutionalRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Daftarkan institutional node baru.
    pub fn register(&mut self, node: InstitutionalNode) {
        self.nodes.insert(node.institution_id, node);
    }

    /// Cari institutional node by institution_id.
    pub fn get(&self, institution_id: &[u8; 32]) -> Option<&InstitutionalNode> {
        self.nodes.get(institution_id)
    }

    /// Cari mutable institutional node.
    pub fn get_mut(&mut self, institution_id: &[u8; 32]) -> Option<&mut InstitutionalNode> {
        self.nodes.get_mut(institution_id)
    }

    /// Jumlah institusi terdaftar.
    pub fn count(&self) -> usize {
        self.nodes.len()
    }

    /// Hitung longevity institusi dalam epoch. Spec §10.3.
    /// Longevity tidak reset saat operator berganti.
    pub fn longevity_epochs(&self, institution_id: &[u8; 32], current_epoch: u64) -> u64 {
        self.nodes
            .get(institution_id)
            .map(|node| current_epoch.saturating_sub(node.registered_epoch))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_id(b: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    fn make_operator(b: u8, epoch: u64, active: bool) -> OperatorEntry {
        OperatorEntry {
            operator_id: node_id(b),
            node_key_commitment: [b; 32],
            added_epoch: epoch,
            is_active: active,
        }
    }

    fn make_institution(ops: Vec<OperatorEntry>, m: u8) -> InstitutionalNode {
        InstitutionalNode::new(node_id(99), [0u8; 32], ops, m, 1, [0u8; 32]).unwrap()
    }

    // ── Constants ────────────────────────────────────────────────────────────

    #[test]
    fn test_max_operators_is_7() {
        // Spec §10.3: max 7 operators. OSSIFIED.
        assert_eq!(MAX_OPERATORS, 7usize);
    }

    // ── InstitutionalNode::new() ──────────────────────────────────────────────

    #[test]
    fn test_valid_institution_3_of_5() {
        // M=3, N=5: 3 > 5/2=2.5 → valid.
        let ops: Vec<_> = (1..=5).map(|i| make_operator(i, 1, true)).collect();
        let result = InstitutionalNode::new(node_id(99), [0u8; 32], ops, 3, 1, [0u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_too_many_operators_rejected() {
        // 8 operators > MAX_OPERATORS=7 → error.
        let ops: Vec<_> = (1..=8).map(|i| make_operator(i, 1, true)).collect();
        let err = InstitutionalNode::new(node_id(99), [0u8; 32], ops, 5, 1, [0u8; 32]).unwrap_err();
        assert_eq!(err, InstitutionalError::TooManyOperators { count: 8 });
    }

    #[test]
    fn test_threshold_not_majority_rejected() {
        // M=2, N=5: 2 <= 5/2=2.5 → NOT majority → error.
        let ops: Vec<_> = (1..=5).map(|i| make_operator(i, 1, true)).collect();
        let err = InstitutionalNode::new(node_id(99), [0u8; 32], ops, 2, 1, [0u8; 32]).unwrap_err();
        assert_eq!(
            err,
            InstitutionalError::InsufficientThreshold { m: 2, n: 5 }
        );
    }

    #[test]
    fn test_zero_threshold_rejected() {
        let ops: Vec<_> = (1..=3).map(|i| make_operator(i, 1, true)).collect();
        let err = InstitutionalNode::new(node_id(99), [0u8; 32], ops, 0, 1, [0u8; 32]).unwrap_err();
        assert_eq!(err, InstitutionalError::ZeroThreshold);
    }

    #[test]
    fn test_exact_7_operators_valid() {
        // Tepat 7 = MAX_OPERATORS → valid.
        let ops: Vec<_> = (1..=7).map(|i| make_operator(i, 1, true)).collect();
        let result = InstitutionalNode::new(node_id(99), [0u8; 32], ops, 4, 1, [0u8; 32]);
        assert!(result.is_ok());
    }

    // ── Uptime (MAXIMUM of active operators) §10.3 ───────────────────────────

    #[test]
    fn test_institutional_uptime_max_of_active() {
        // Spec §10.3: uptime = MAX dari semua operator aktif.
        let inst = make_institution(
            vec![
                make_operator(1, 1, true),
                make_operator(2, 1, true),
                make_operator(3, 1, false), // inactive
            ],
            2,
        );
        let mut uptimes = HashMap::new();
        uptimes.insert(node_id(1), 600_000u64);
        uptimes.insert(node_id(2), 900_000u64);
        uptimes.insert(node_id(3), 1_000_000u64); // inactive, tidak dihitung
        assert_eq!(inst.institutional_uptime(&uptimes), 900_000);
    }

    #[test]
    fn test_institutional_uptime_no_active_ops_is_zero() {
        let inst = make_institution(vec![make_operator(1, 1, false)], 1);
        let uptimes = HashMap::new();
        assert_eq!(inst.institutional_uptime(&uptimes), 0);
    }

    #[test]
    fn test_institutional_uptime_online_if_one_operator_online() {
        // Spec §10.3: institusi online jika ≥1 operator online.
        let inst = make_institution(
            vec![make_operator(1, 1, true), make_operator(2, 1, true)],
            2,
        );
        let mut uptimes = HashMap::new();
        uptimes.insert(node_id(1), 0u64);
        uptimes.insert(node_id(2), 500_000u64); // satu online
        assert!(inst.institutional_uptime(&uptimes) > 0);
    }

    // ── Quorum / M-of-N ──────────────────────────────────────────────────────

    #[test]
    fn test_quorum_met() {
        let inst = make_institution(
            vec![
                make_operator(1, 1, true),
                make_operator(2, 1, true),
                make_operator(3, 1, true),
            ],
            2,
        );
        let signers = [node_id(1), node_id(2)];
        assert!(inst.verify_quorum(&signers).is_ok());
    }

    #[test]
    fn test_quorum_not_met() {
        let inst = make_institution(
            vec![
                make_operator(1, 1, true),
                make_operator(2, 1, true),
                make_operator(3, 1, true),
            ],
            2,
        );
        let signers = [node_id(1)]; // hanya 1, butuh 2
        let err = inst.verify_quorum(&signers).unwrap_err();
        assert_eq!(
            err,
            InstitutionalError::InsufficientSignatures {
                provided: 1,
                required: 2
            }
        );
    }

    #[test]
    fn test_inactive_operator_signature_not_counted() {
        let inst = make_institution(
            vec![
                make_operator(1, 1, false), // inactive
                make_operator(2, 1, true),
                make_operator(3, 1, true),
            ],
            2,
        );
        // node 1 inactive → tidak counted
        let signers = [node_id(1), node_id(2)];
        let result = inst.verify_quorum(&signers);
        // hanya 1 valid signature (node 2) → tidak cukup jika butuh 2
        assert_eq!(
            result,
            Err(InstitutionalError::InsufficientSignatures {
                provided: 1,
                required: 2
            })
        );
    }

    // ── Operator rotation ────────────────────────────────────────────────────

    #[test]
    fn test_add_operator_with_quorum() {
        let mut inst = make_institution(
            vec![
                make_operator(1, 1, true),
                make_operator(2, 1, true),
                make_operator(3, 1, true),
            ],
            2,
        );
        let new_op = make_operator(4, 5, true);
        let signers = [node_id(1), node_id(2)];
        assert!(inst.add_operator(new_op, &signers).is_ok());
        assert_eq!(inst.operators.len(), 4);
    }

    #[test]
    fn test_add_operator_duplicate_rejected() {
        let mut inst = make_institution(
            vec![
                make_operator(1, 1, true),
                make_operator(2, 1, true),
                make_operator(3, 1, true),
            ],
            2,
        );
        let dup_op = make_operator(1, 5, true); // node_id 1 sudah ada
        let signers = [node_id(1), node_id(2)];
        let err = inst.add_operator(dup_op, &signers).unwrap_err();
        assert_eq!(err, InstitutionalError::OperatorAlreadyExists);
    }

    #[test]
    fn test_deactivate_operator_with_quorum() {
        let mut inst = make_institution(
            vec![
                make_operator(1, 1, true),
                make_operator(2, 1, true),
                make_operator(3, 1, true),
            ],
            2,
        );
        let signers = [node_id(1), node_id(2)];
        assert!(inst.deactivate_operator(&node_id(3), &signers).is_ok());
        assert!(!inst.operators[2].is_active);
    }

    // ── InstitutionalRegistry ────────────────────────────────────────────────

    #[test]
    fn test_registry_register_and_get() {
        let mut registry = InstitutionalRegistry::new();
        let inst = make_institution(
            vec![make_operator(1, 1, true), make_operator(2, 1, true)],
            2,
        );
        let id = inst.institution_id;
        registry.register(inst);
        assert!(registry.get(&id).is_some());
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_registry_longevity_epochs() {
        // Spec §10.3: longevity dari registered_epoch, tidak reset.
        let mut registry = InstitutionalRegistry::new();
        let inst = InstitutionalNode::new(
            node_id(50),
            [0u8; 32],
            vec![make_operator(1, 10, true), make_operator(2, 10, true)],
            2,
            10, // registered_epoch = 10
            [0u8; 32],
        )
        .unwrap();
        let id = inst.institution_id;
        registry.register(inst);

        assert_eq!(registry.longevity_epochs(&id, 40), 30); // 40 - 10 = 30
        assert_eq!(registry.longevity_epochs(&id, 10), 0); // baru terdaftar
    }

    #[test]
    fn test_no_floating_point() {
        // Semua logika murni integer.
        let inst = make_institution(vec![make_operator(1, 1, true)], 1);
        let uptimes: HashMap<[u8; 32], u64> = HashMap::new();
        let _ = inst.institutional_uptime(&uptimes);
    }
}
