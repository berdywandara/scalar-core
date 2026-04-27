use crate::air::{ScalarAir, ScalarPublicInputs};
use winterfell::crypto::hashers::Blake3_256;
use winterfell::crypto::DefaultRandomCoin;
use winterfell::math::fields::f64::BaseElement;
use winterfell::matrix::ColMatrix;
use winterfell::{ProofOptions, Prover, TraceTable};

pub struct ScalarStarkProver {
    options: ProofOptions,
    pub_inputs: ScalarPublicInputs,
}

impl Prover for ScalarStarkProver {
    type BaseField = BaseElement;
    type Air = ScalarAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3_256<BaseElement>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: winterfell::math::FieldElement<BaseField = Self::BaseField>> =
        winterfell::DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: winterfell::math::FieldElement<BaseField = Self::BaseField>> =
        winterfell::DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, _trace: &Self::Trace) -> ScalarPublicInputs {
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

pub struct ScalarProver {
    options: ProofOptions,
}

impl ScalarProver {
    pub fn new() -> Self {
        Self {
            options: ProofOptions::new(28, 8, 0, winterfell::FieldExtension::None, 8, 31),
        }
    }

    pub fn build_execution_trace(
        inputs: &[u64],
        outputs: &[u64],
        fee: u64,
    ) -> TraceTable<BaseElement> {
        let length = 64;
        let sum_in: u64 = inputs.iter().sum();
        let sum_out: u64 = outputs.iter().sum();
        TraceTable::init(vec![
            vec![BaseElement::new(sum_in); length],
            vec![BaseElement::new(sum_out); length],
            vec![BaseElement::new(fee); length],
        ])
    }

    pub fn generate_proof(
        &self,
        trace: TraceTable<BaseElement>,
        pub_inputs: ScalarPublicInputs,
    ) -> Result<Vec<u8>, &'static str> {
        let prover = ScalarStarkProver {
            options: self.options.clone(),
            pub_inputs,
        };
        let proof = prover
            .prove(trace)
            .map_err(|_| "Gagal menghasilkan STARK proof")?;
        Ok(proof.to_bytes())
    }
}
