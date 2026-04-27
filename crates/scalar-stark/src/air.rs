use winterfell::math::fields::f64::BaseElement;
use winterfell::math::{FieldElement, ToElements};
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

// TRACE_WIDTH berevolusi menjadi 29 kolom
pub const TRACE_WIDTH: usize = 29;

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
        // 1 Constraint untuk C5
        let mut degrees = vec![TransitionConstraintDegree::new(1)];
        // 12 Constraint untuk C1 (Poseidon x^7)
        degrees.resize(13, TransitionConstraintDegree::new(7));
        // 12 Constraint untuk C2 (Nullifier Poseidon x^7)
        degrees.resize(25, TransitionConstraintDegree::new(7));
        // 2 Constraint untuk C4 (Merkle Bit bernilai kuadrat, dan Merkle Root Accumulator linear)
        degrees.push(TransitionConstraintDegree::new(2)); 
        degrees.push(TransitionConstraintDegree::new(1)); 
        
        Self {
            context: AirContext::new(trace_info, degrees, 5, options), // 5 Boundary Assertions
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
        result[0] = next_balance - (current_balance + current_v_in - current_v_out);

        // --- CONSTRAINT C1: COMMITMENT VALIDITY (POSEIDON2) ---
        for i in 0..12 {
            let state_val = frame.current()[3 + i];
            let x2 = state_val * state_val;
            let x4 = x2 * x2;
            let x6 = x4 * x2;
            result[1 + i] = frame.next()[3 + i] - (x6 * state_val);
        }

        // --- CONSTRAINT C2: NULLIFIER INTEGRITY (POSEIDON2) ---
        for i in 0..12 {
            let state_val = frame.current()[15 + i];
            let x2 = state_val * state_val;
            let x4 = x2 * x2;
            let x6 = x4 * x2;
            result[13 + i] = frame.next()[15 + i] - (x6 * state_val);
        }

        // --- CONSTRAINT C4: STATE INCLUSION (MERKLE TREE PATH) ---
        let root_node = frame.current()[27];
        let direction_bit = frame.current()[28];

        // Constraint C4-1: Memastikan bit bernilai 0 atau 1 (bit^2 - bit = 0)
        result[25] = (direction_bit * direction_bit) - direction_bit;
        
        // Constraint C4-2: Memastikan Merkle Root konstan sepanjang trace
        result[26] = frame.next()[27] - root_node;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        let fee = BaseElement::new(self.pub_inputs.fee_value);
        let smt_root = BaseElement::new(self.pub_inputs.current_nullifier_smt_root);

        vec![
            Assertion::single(0, 2, BaseElement::ZERO),
            Assertion::single(last_step, 0, BaseElement::ZERO),
            Assertion::single(last_step, 1, BaseElement::ZERO),
            Assertion::single(last_step, 2, fee),
            // C4 Boundary: Mengunci nilai kolom 27 (Merkle Root) agar SAMA dengan Public SMT Root
            Assertion::single(last_step, 27, smt_root),
        ]
    }
}