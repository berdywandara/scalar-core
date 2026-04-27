use winterfell::math::fields::f64::BaseElement;
use winterfell::math::{FieldElement, ToElements};
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

// TRACE_WIDTH berevolusi menjadi 32 kolom untuk mengakomodasi C3 & C6
pub const TRACE_WIDTH: usize = 32;

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
        let mut degrees = vec![TransitionConstraintDegree::new(1)]; // C5
        degrees.resize(13, TransitionConstraintDegree::new(7)); // C1
        degrees.resize(25, TransitionConstraintDegree::new(7)); // C2
        
        degrees.push(TransitionConstraintDegree::new(2)); // C4-1
        degrees.push(TransitionConstraintDegree::new(1)); // C4-2
        
        // Tambahan untuk C3 (Ownership) & C6 (Range Proof)
        degrees.push(TransitionConstraintDegree::new(2)); // C3-1: Signature Check
        degrees.push(TransitionConstraintDegree::new(1)); // C3-2: PK Constant
        degrees.push(TransitionConstraintDegree::new(2)); // C6: Boolean Bit Check
        
        Self {
            context: AirContext::new(trace_info, degrees, 5, options),
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
        // --- CONSTRAINT C5 ---
        let current_v_in = frame.current()[0];
        let current_v_out = frame.current()[1];
        let current_balance = frame.current()[2];
        result[0] = frame.next()[2] - (current_balance + current_v_in - current_v_out);

        // --- CONSTRAINT C1 & C2 ---
        for i in 0..12 {
            // C1
            let state_val_c1 = frame.current()[3 + i];
            let x6_c1 = state_val_c1 * state_val_c1 * state_val_c1 * state_val_c1 * state_val_c1 * state_val_c1;
            result[1 + i] = frame.next()[3 + i] - (x6_c1 * state_val_c1);
            
            // C2
            let state_val_c2 = frame.current()[15 + i];
            let x6_c2 = state_val_c2 * state_val_c2 * state_val_c2 * state_val_c2 * state_val_c2 * state_val_c2;
            result[13 + i] = frame.next()[15 + i] - (x6_c2 * state_val_c2);
        }

        // --- CONSTRAINT C4 ---
        let root_node = frame.current()[27];
        let direction_bit = frame.current()[28];
        result[25] = (direction_bit * direction_bit) - direction_bit;
        result[26] = frame.next()[27] - root_node;

        // --- CONSTRAINT C3: OWNERSHIP VALIDITY ---
        let pk_col = frame.current()[29];
        let sig_col = frame.current()[30];
        // Simulasi validasi signature kuadratik (PK^2 = Sig)
        result[27] = (pk_col * pk_col) - sig_col;
        result[28] = frame.next()[29] - pk_col;

        // --- CONSTRAINT C6: RANGE PROOF ---
        let range_bit = frame.current()[31];
        // Memaksa kolom range decomposition agar murni biner (x^2 - x = 0)
        result[29] = (range_bit * range_bit) - range_bit;
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
            Assertion::single(last_step, 27, smt_root),
        ]
    }
}