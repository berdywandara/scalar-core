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

// 1. Memperbaiki warning clippy (Menambahkan Default trait)
impl Default for ScalarProver {
    fn default() -> Self {
        Self::new()
    }
}

// 2. Memastikan SEMUA fungsi terkait berada di DALAM blok impl ini
impl ScalarProver {
    pub fn new() -> Self {
        Self {
            options: ProofOptions::new(28, 8, 0, winterfell::FieldExtension::None, 8, 31),
        }
    }

    // Fungsi Trace Builder dikalibrasi untuk C5 Value Conservation
    pub fn build_execution_trace(
        inputs: &[u64],
        outputs: &[u64],
        _fee: u64, // Fee akan dibuktikan via public_inputs, tidak perlu di-inject ke trace awal
    ) -> TraceTable<BaseElement> {
        let length = 64; // Minimum trace length STARK
        let sum_in: u64 = inputs.iter().sum();
        let sum_out: u64 = outputs.iter().sum();

        let mut v_in_col = vec![BaseElement::new(0); length];
        let mut v_out_col = vec![BaseElement::new(0); length];
        let mut balance_col = vec![BaseElement::new(0); length];

        // Step 0: Masukkan nilai input dan output di baris pertama, balance dimulai dari 0
        v_in_col[0] = BaseElement::new(sum_in);
        v_out_col[0] = BaseElement::new(sum_out);
        balance_col[0] = BaseElement::new(0);

        // Step 1 hingga akhir: Akumulasi matematis berjalan
        for i in 0..(length - 1) {
            let current_balance = balance_col[i];
            let current_v_in = v_in_col[i];
            let current_v_out = v_out_col[i];
            
            // Evaluasi constraint transisi C5: B_next = B_current + v_in - v_out
            balance_col[i + 1] = current_balance + current_v_in - current_v_out;
        }

        TraceTable::init(vec![v_in_col, v_out_col, balance_col])
    }

    // Fungsi ini sekarang aman memakai &self karena berada di dalam impl
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
            .map_err(|_| "Gagal menghasilkan STARK proof: Constraint C5 dilanggar!")?;
            
        Ok(proof.to_bytes())
    }
}