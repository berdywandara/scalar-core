use crate::air::ScalarAir;
use winterfell::{Prover, TraceTable, ProofOptions};
use winterfell::math::fields::f64::BaseElement;
use winterfell::crypto::hashers::Blake3_256;
use winterfell::crypto::DefaultRandomCoin;
use winterfell::matrix::ColMatrix;

pub struct ScalarStarkProver {
    options: ProofOptions,
}

impl Prover for ScalarStarkProver {
    type BaseField = BaseElement;
    type Air = ScalarAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: winterfell::math::FieldElement<BaseField = Self::BaseField>> = winterfell::DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: winterfell::math::FieldElement<BaseField = Self::BaseField>> = winterfell::DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> () { () }
    fn options(&self) -> &ProofOptions { &self.options }

    fn new_trace_lde<E: winterfell::math::FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &winterfell::TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>, // FIXED: Menggunakan ColMatrix
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
        winterfell::DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

pub struct ScalarProver {
    options: ProofOptions,
}

impl ScalarProver {
    pub fn new() -> Self {
        Self { options: ProofOptions::new(28, 8, 0, winterfell::FieldExtension::None, 8, 31) }
    }

    pub fn build_execution_trace(inputs: &[u64], outputs: &[u64], fee: u64) -> TraceTable<BaseElement> {
        let length = 64; 
        let sum_in: u64 = inputs.iter().sum();
        let sum_out: u64 = outputs.iter().sum();
        
        let col0 = vec![BaseElement::new(sum_in); length];
        let col1 = vec![BaseElement::new(sum_out); length];
        let col2 = vec![BaseElement::new(fee); length];
        
        TraceTable::init(vec![col0, col1, col2])
    }

    pub fn generate_proof(&self, trace: TraceTable<BaseElement>) -> Result<Vec<u8>, &'static str> {
        let prover = ScalarStarkProver {
            options: self.options.clone(),
        };
        
        let proof = prover.prove(trace)
            .map_err(|_| "Gagal menghasilkan STARK proof")?;
            
        Ok(proof.to_bytes())
    }
}
