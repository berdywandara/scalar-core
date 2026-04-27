use winterfell::math::fields::f64::BaseElement;
use winterfell::math::{FieldElement, ToElements};
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

pub const TRACE_WIDTH: usize = 3;

#[derive(Clone, Debug)]
pub struct ScalarPublicInputs {
    pub genesis_smt_root: u64,
    pub current_nullifier_smt_root: u64,
    pub fee_value: u64,
    pub timestamp: u64,
}

impl ToElements<BaseElement> for ScalarPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            BaseElement::new(self.genesis_smt_root),
            BaseElement::new(self.current_nullifier_smt_root),
            BaseElement::new(self.fee_value),
            BaseElement::new(self.timestamp),
        ]
    }
}

pub struct ScalarAir {
    context: AirContext<BaseElement>,
    pub_inputs: ScalarPublicInputs,
}

impl Air for ScalarAir {
    type BaseField = BaseElement;
    type PublicInputs = ScalarPublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        // PR-CS-04: C5 Value Conservation membutuhkan 1 Transition Constraint dengan derajat (degree) 1
        let degrees = vec![TransitionConstraintDegree::new(1)];
        
        // Kita mendefinisikan 4 Boundary Assertions untuk mengunci awal dan akhir transaksi
        Self {
            context: AirContext::new(trace_info, degrees, 4, options),
            pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        // --- CONSTRAINT C5: VALUE CONSERVATION ---
        // Menjamin tidak ada koin SCL yang diciptakan dari ketiadaan atau lenyap tanpa jejak.
        // Kolom 0: Input Values (v_in)
        // Kolom 1: Output Values (v_out)
        // Kolom 2: Running Balance (B)
        
        let current_v_in = frame.current()[0];
        let current_v_out = frame.current()[1];
        let current_balance = frame.current()[2];
        
        let next_balance = frame.next()[2];

        // Polinomial harus mengevaluasi ke 0 agar STARK Proof valid:
        // B_next = B_current + v_in - v_out
        result[0] = next_balance - (current_balance + current_v_in - current_v_out);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        let fee = BaseElement::new(self.pub_inputs.fee_value);

        vec![
            // 1. Initial State: Saldo akumulasi harus dimulai dari 0
            Assertion::single(0, 2, BaseElement::ZERO),
            
            // 2. Padding Constraint: Step terakhir tidak boleh memiliki input nilai baru
            Assertion::single(last_step, 0, BaseElement::ZERO),
            
            // 3. Padding Constraint: Step terakhir tidak boleh memiliki output nilai baru
            Assertion::single(last_step, 1, BaseElement::ZERO),
            
            // 4. THE ABSOLUTE TRUTH: Total Balance di akhir trace HARUS sama dengan Fee
            Assertion::single(last_step, 2, fee),
        ]
    }
}