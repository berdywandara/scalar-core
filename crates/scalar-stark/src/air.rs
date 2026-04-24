use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use winterfell::math::fields::f64::BaseElement;
use winterfell::math::FieldElement;

pub const TRACE_WIDTH: usize = 3;

pub struct ScalarAir {
    context: AirContext<BaseElement>,
}

impl Air for ScalarAir {
    type BaseField = BaseElement;
    type PublicInputs = ();
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, _pub_inputs: (), options: ProofOptions) -> Self {
        let degrees = vec![TransitionConstraintDegree::new(1); TRACE_WIDTH];
        Self {
            context: AirContext::new(trace_info, degrees, 2, options),
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> { &self.context }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self, frame: &EvaluationFrame<E>, _periodic_values: &[E], result: &mut [E],
    ) {
        for i in 0..TRACE_WIDTH {
            result[i] = frame.next()[i] - frame.current()[i];
        }
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> { vec![] }
}
