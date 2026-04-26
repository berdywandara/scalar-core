//! MintClaimAir — AIR untuk MINT_CLAIM_CIRCUIT
//! Spesifikasi: Scalar_Master_Technical_Spec.docx §B.2
//!
//! Trace layout:
//!   col 0: epoch_id               (konstan, boundary assert)
//!   col 1: reward_root            (konstan, boundary assert) MC1
//!   col 2: mint_nullifier         (konstan, boundary assert) MC2
//!   col 3: emission_acc_root      (konstan, boundary assert) MC3
//!   col 4: output_count           (konstan, boundary assert) MC4/MC5
//!   col 5: counter 0..n-1        (non-konstan — membuat DEEP poly non-zero)
//!           transition: next[5] - current[5] = 1
//!           boundary:   col 5 row 0 = 0  → total 6 assertions

use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};
use winterfell::math::fields::f64::BaseElement;
use winterfell::math::{FieldElement, ToElements};

pub const MINT_TRACE_WIDTH: usize = 6;

#[derive(Clone, Debug)]
pub struct MintClaimPublicInputs {
    pub epoch_id:                  u64,
    pub reward_root:               u64,
    pub emission_accumulator_root: u64,
    pub mint_nullifier:            u64,
    pub output_count:              u64,
}

impl ToElements<BaseElement> for MintClaimPublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![
            BaseElement::new(self.epoch_id),
            BaseElement::new(self.reward_root),
            BaseElement::new(self.emission_accumulator_root),
            BaseElement::new(self.mint_nullifier),
            BaseElement::new(self.output_count),
        ]
    }
}

pub struct MintClaimAir {
    context:    AirContext<BaseElement>,
    pub_inputs: MintClaimPublicInputs,
}

impl Air for MintClaimAir {
    type BaseField    = BaseElement;
    type PublicInputs = MintClaimPublicInputs;
    type GkrProof     = ();
    type GkrVerifier  = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let degrees = vec![TransitionConstraintDegree::new(1); MINT_TRACE_WIDTH];
        // 6 assertions: col 0-4 dari public inputs + col 5 counter start = 0
        Self {
            context: AirContext::new(trace_info, degrees, 6, options),
            pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> { &self.context }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame:  &EvaluationFrame<E>,
        _pv:    &[E],
        result: &mut [E],
    ) {
        let cur  = frame.current();
        let next = frame.next();

        // col 0-4: konstan → next[i] - current[i] = 0
        for i in 0..5 {
            result[i] = next[i] - cur[i];
        }
        // col 5: counter → next[5] - current[5] - 1 = 0
        result[5] = next[5] - cur[5] - E::ONE;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        vec![
            Assertion::single(0, 0, BaseElement::new(self.pub_inputs.epoch_id)),
            Assertion::single(1, 0, BaseElement::new(self.pub_inputs.reward_root)),
            Assertion::single(2, 0, BaseElement::new(self.pub_inputs.mint_nullifier)),
            Assertion::single(3, 0, BaseElement::new(self.pub_inputs.emission_accumulator_root)),
            Assertion::single(4, 0, BaseElement::new(self.pub_inputs.output_count)),
            // col 5 counter mulai dari 0
            Assertion::single(5, 0, BaseElement::ZERO),
        ]
    }
}
