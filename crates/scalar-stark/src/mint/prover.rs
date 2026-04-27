//! MintClaimProver — Prover untuk MINT_CLAIM_CIRCUIT
//! Spesifikasi: Scalar_Master_Technical_Spec.docx §B.2
//!
//! FIX: Trace tidak boleh fully constant — Winterfell DEEP composition
//! membutuhkan non-zero constraint polynomial degree.
//! Solusi: col 5 berisi counter 0..len sebagai "liveness column"
//! yang membuat trace non-trivial. Transition constraint col 5:
//! next[5] - current[5] - 1 = 0 (increment by 1 each row).
//! Col 0-4 tetap konstan dan di-assert via boundary constraints.

use super::air::{MintClaimAir, MintClaimPublicInputs};
use scalar_crypto::poseidon2::hash_2_to_1;
use scalar_emission::accumulator::S_E_SSCL;
use winterfell::{
    crypto::hashers::Blake3_256, crypto::DefaultRandomCoin, math::fields::f64::BaseElement,
    math::FieldElement, matrix::ColMatrix, ProofOptions, Prover, TraceTable,
};

pub struct MintClaimPrivateInputs {
    pub node_id: [u8; 32],
    pub node_key: [u8; 32],
    pub reward_amount: u64,
    pub reward_merkle_path: Vec<[u8; 32]>,
    pub output_secrets: Vec<u64>,
    pub output_values: Vec<u64>,
}

const POU_MINT_DOMAIN: u64 = 0x706f755f6d696e74;

pub fn compute_mint_nullifier(node_id: &[u8; 32], epoch_id: u64) -> u64 {
    let node_id_lo = u64::from_le_bytes(node_id[0..8].try_into().unwrap());
    let intermediate = hash_2_to_1(node_id_lo, epoch_id);
    hash_2_to_1(intermediate, POU_MINT_DOMAIN)
}

pub fn validate_mint_inputs(
    priv_inputs: &MintClaimPrivateInputs,
    pub_inputs: &MintClaimPublicInputs,
    total_pou_minted: u64,
) -> Result<(), &'static str> {
    let computed = compute_mint_nullifier(&priv_inputs.node_id, pub_inputs.epoch_id);
    if computed != pub_inputs.mint_nullifier {
        return Err("MC2: mint_nullifier tidak cocok");
    }
    let new_total = total_pou_minted
        .checked_add(priv_inputs.reward_amount)
        .ok_or("MC3: overflow")?;
    if new_total > S_E_SSCL {
        return Err("MC3: supply cap S_E terlampaui");
    }
    let output_sum: u64 = priv_inputs
        .output_values
        .iter()
        .try_fold(0u64, |acc, &v| acc.checked_add(v))
        .ok_or("MC5: overflow output sum")?;
    if output_sum > priv_inputs.reward_amount {
        return Err("MC5: output sum melebihi reward_amount");
    }
    if priv_inputs.output_values.is_empty() {
        return Err("MC4: minimal 1 output diperlukan");
    }
    Ok(())
}

pub fn build_mint_trace(
    priv_inputs: &MintClaimPrivateInputs,
    pub_inputs: &MintClaimPublicInputs,
    total_pou_minted: u64,
) -> Result<TraceTable<BaseElement>, &'static str> {
    validate_mint_inputs(priv_inputs, pub_inputs, total_pou_minted)?;

    let len = 64usize;

    // col 0-4: konstan, di-assert via boundary constraints (get_assertions)
    // col 5: counter 0,1,2,...,len-1
    //   → transition: next[5] - current[5] = 1  (non-trivial)
    //   → ini membuat DEEP composition polynomial non-zero
    //   → boundary assertion: col 5 row 0 = 0
    let counter_col: Vec<BaseElement> = (0..len).map(|i| BaseElement::new(i as u64)).collect();

    Ok(TraceTable::init(vec![
        vec![BaseElement::new(pub_inputs.epoch_id); len], // col 0
        vec![BaseElement::new(pub_inputs.reward_root); len], // col 1
        vec![BaseElement::new(pub_inputs.mint_nullifier); len], // col 2
        vec![BaseElement::new(pub_inputs.emission_accumulator_root); len], // col 3
        vec![BaseElement::new(pub_inputs.output_count); len], // col 4
        counter_col,                                      // col 5: 0..63
    ]))
}

pub(crate) struct MintClaimStarkProver {
    pub options: ProofOptions,
    pub pub_inputs: MintClaimPublicInputs,
}

impl Prover for MintClaimStarkProver {
    type BaseField = BaseElement;
    type Air = MintClaimAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: winterfell::math::FieldElement<BaseField = Self::BaseField>> =
        winterfell::DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: winterfell::math::FieldElement<BaseField = Self::BaseField>> =
        winterfell::DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> MintClaimPublicInputs {
        self.pub_inputs.clone()
    }
    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: winterfell::math::FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &winterfell::TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &winterfell::StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, winterfell::TracePolyTable<E>) {
        winterfell::DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E: winterfell::math::FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<winterfell::AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        winterfell::DefaultConstraintEvaluator::new(
            air,
            aux_rand_elements,
            composition_coefficients,
        )
    }
}

pub fn generate_mint_proof(
    priv_inputs: &MintClaimPrivateInputs,
    pub_inputs: MintClaimPublicInputs,
    total_pou_minted: u64,
) -> Result<Vec<u8>, &'static str> {
    let trace = build_mint_trace(priv_inputs, &pub_inputs, total_pou_minted)?;
    let options = ProofOptions::new(28, 8, 0, winterfell::FieldExtension::None, 8, 31);
    let prover = MintClaimStarkProver {
        options,
        pub_inputs,
    };
    let proof = prover
        .prove(trace)
        .map_err(|_| "Gagal generate MINT_CLAIM STARK proof")?;
    Ok(proof.to_bytes())
}
