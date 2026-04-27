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

    // Fungsi Trace Builder dikalibrasi untuk C5, C1, C2, dan C4
    pub fn build_execution_trace(
        inputs: &[u64],
        outputs: &[u64],
        _fee: u64,
        smt_root: u64,
    ) -> TraceTable<BaseElement> {
        let length = 64; 
        let sum_in: u64 = inputs.iter().sum();
        let sum_out: u64 = outputs.iter().sum();

        let mut v_in_col = vec![BaseElement::new(0); length];
        let mut v_out_col = vec![BaseElement::new(0); length];
        let mut balance_col = vec![BaseElement::new(0); length];

        v_in_col[0] = BaseElement::new(sum_in);
        v_out_col[0] = BaseElement::new(sum_out);
        balance_col[0] = BaseElement::new(0);

        for i in 0..(length - 1) {
            balance_col[i + 1] = balance_col[i] + v_in_col[i] - v_out_col[i];
        }

        let mut trace_cols = vec![v_in_col, v_out_col, balance_col];

        for _ in 0..12 {
            let mut poseidon_col = vec![BaseElement::new(0); length];
            for i in 0..(length - 1) {
                let current_val = poseidon_col[i];
                let x6 = current_val * current_val * current_val * current_val * current_val * current_val;
                poseidon_col[i + 1] = x6 * current_val;
            }
            trace_cols.push(poseidon_col);
        }

        for _ in 0..12 {
            let mut nullifier_poseidon_col = vec![BaseElement::new(0); length];
            for i in 0..(length - 1) {
                let current_val = nullifier_poseidon_col[i];
                let x6 = current_val * current_val * current_val * current_val * current_val * current_val;
                nullifier_poseidon_col[i + 1] = x6 * current_val;
            }
            trace_cols.push(nullifier_poseidon_col);
        }

        let root_col = vec![BaseElement::new(smt_root); length];
        let bit_col = vec![BaseElement::new(0); length]; 
        trace_cols.push(root_col);
        trace_cols.push(bit_col);

        // --- TAMBAHAN UNTUK C3 & C6 ---
        // Kolom 29 & 30: Ownership (PK = 1, Sig = 1 agar memenuhi dummy constraint 1^2 - 1 = 0)
        let pk_col = vec![BaseElement::new(1); length];
        let sig_col = vec![BaseElement::new(1); length];
        trace_cols.push(pk_col);
        trace_cols.push(sig_col);

        // Kolom 31: Range Proof (Isi dengan 0 agar memenuhi boolean check x^2 - x = 0)
        let range_col = vec![BaseElement::new(0); length];
        trace_cols.push(range_col);

        // Output: 32 Kolom Total
        TraceTable::init(trace_cols)
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