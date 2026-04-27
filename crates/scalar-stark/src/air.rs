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
        let degrees = vec![TransitionConstraintDegree::new(1); TRACE_WIDTH];
        Self {
            context: AirContext::new(trace_info, degrees, 2, options),
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
        for i in 0..TRACE_WIDTH {
            result[i] = frame.next()[i] - frame.current()[i];
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![]
    }
}
