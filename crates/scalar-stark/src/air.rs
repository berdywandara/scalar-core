use winterfell::math::fields::f64::BaseElement;
use winterfell::math::{FieldElement, ToElements};
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

// TRACE_WIDTH berevolusi dari 3 menjadi 15
// Kolom 0-2: Value Conservation (C5)
// Kolom 3-14: Poseidon2 Hash State (C1)
pub const TRACE_WIDTH: usize = 15;

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
        // 1 Constraint Derajat 1 untuk C5 (Value Conservation)
        let mut degrees = vec![TransitionConstraintDegree::new(1)];
        
        // 12 Constraint Derajat 7 untuk C1 (Poseidon2 S-Box x^7)
        degrees.resize(13, TransitionConstraintDegree::new(7));
        
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
        let current_v_in = frame.current()[0];
        let current_v_out = frame.current()[1];
        let current_balance = frame.current()[2];
        let next_balance = frame.next()[2];

        // Result[0] adalah constraint C5
        result[0] = next_balance - (current_balance + current_v_in - current_v_out);

        // --- CONSTRAINT C1: COMMITMENT VALIDITY (POSEIDON2) ---
        // S-Box Poseidon2 menggunakan x^7. Kita mengunci 12 kolom state agar mematuhi polinomial ini.
        for i in 0..12 {
            let state_val = frame.current()[3 + i];
            
            // Manual x^7 untuk kepatuhan matematis FieldElement Winterfell
            let x2 = state_val * state_val;
            let x4 = x2 * x2;
            let x6 = x4 * x2;
            let sbox_val = x6 * state_val; // state_val^7
            
            // Result[1..13] adalah constraint C1
            // Di produksi penuh, ini akan diekspansi dengan matriks MDS dan Round Constants
            result[1 + i] = frame.next()[3 + i] - sbox_val;
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        let fee = BaseElement::new(self.pub_inputs.fee_value);

        vec![
            Assertion::single(0, 2, BaseElement::ZERO),
            Assertion::single(last_step, 0, BaseElement::ZERO),
            Assertion::single(last_step, 1, BaseElement::ZERO),
            Assertion::single(last_step, 2, fee),
        ]
    }
}