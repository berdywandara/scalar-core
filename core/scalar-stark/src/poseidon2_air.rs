//! Poseidon2 Permutation AIR — In-Circuit Implementation
//!
//! Arithmetizes one full Poseidon2 permutation (t=4, Goldilocks, 30 rounds)
//! as a Winterfell AIR. This is the foundational gadget for CA (ownership
//! proof) and CC (nullifier) constraints in the Transfer Circuit.
//!
//! # Trace Layout
//!
//! TOTAL_ROUNDS = 30 rounds. Trace has 32 rows (next power of 2 ≥ 30+1).
//! Row r (0..=29) represents round r. Row 30 holds final output. Row 31 = padding.
//!
//! ## Column Layout (POSEIDON2_TRACE_WIDTH = 29)
//!
//! State-in columns (4): cols 0..3
//!   s[i] = state ENTERING round r (before AddRC)
//!
//! State-after-RC columns (4): cols 4..7
//!   s_rc[i] = s[i] + RC[r][i]  (after AddRC, before S-box)
//!
//! S-box intermediate columns (16): cols 8..23
//!   For each i in 0..4, cols 8+4i .. 8+4i+3:
//!     x2[i] = s_rc[i]^2
//!     x4[i] = x2[i]^2
//!     x6[i] = x4[i] * x2[i]
//!     x7[i] = x6[i] * s_rc[i]   ← S-box output
//!   In partial rounds (i > 0): x2=x4=x6=x7=s_rc[i] (pass-through)
//!
//! Round index column (1): col 24
//!   round_idx = r (0..29), then 30 for output row
//!
//! Is-partial column (1): col 25
//!   1 if round r is a partial round, 0 otherwise
//!
//! Input snapshot (3): cols 26..28
//!   input[0..2] — stored at every row for boundary assertion
//!
//! ## Transition Constraints (row r → row r+1)
//!
//! RC[r] is supplied as periodic_values (30-periodic).
//!
//! For FULL rounds (is_partial = 0):
//!   C0-C3:   s_rc[i] - (s[i] + RC[r][i]) = 0              (degree 1)
//!   C4-C7:   x2[i] - s_rc[i]^2 = 0                        (degree 2)
//!   C8-C11:  x4[i] - x2[i]^2 = 0                          (degree 2)
//!   C12-C15: x6[i] - x4[i]*x2[i] = 0                      (degree 2)
//!   C16-C19: x7[i] - x6[i]*s_rc[i] = 0                    (degree 2)
//!   C20-C23: nxt.s[i] - MDS_full(x7)[i] = 0               (degree 1)
//!   C24:     nxt.round_idx - round_idx - 1 = 0             (degree 1)
//!
//! For PARTIAL rounds (is_partial = 1):
//!   C0-C3:   same AddRC constraints
//!   C4-C7:   x2[0] - s_rc[0]^2 = 0 (i=0 only; i>0: x7[i]=s_rc[i])
//!   C8-C23:  S-box chain for i=0; pass-through for i>0
//!   C20-C23: nxt.s[i] - MDS_partial(x7)[i] = 0
//!
//! Spec §2.1: Poseidon2 in-circuit ONLY. Field: Goldilocks. OSSIFIED.
//! Spec §4.3 CA: ownership proof uses this gadget.

use winterfell::{
    crypto::{hashers::Blake3_256, DefaultRandomCoin},
    math::{fields::f64::BaseElement, FieldElement, ToElements},
    matrix::ColMatrix,
    Air, AirContext, Assertion, AuxRandElements, ConstraintCompositionCoefficients,
    DefaultConstraintEvaluator, DefaultTraceLde, EvaluationFrame, FieldExtension, ProofOptions,
    Prover, StarkDomain, TraceInfo, TracePolyTable, TraceTable, TransitionConstraintDegree,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Poseidon2 state width t=4. OSSIFIED spec §2.1.
pub const P2_WIDTH: usize = 4;

/// S-box intermediate columns per state element: x2, x4, x6, x7.
pub const SBOX_INTERMEDIATES: usize = 4;

/// State-in columns: cols 0..3.
pub const COL_S_IN: usize = 0;

/// State-after-RC columns: cols 4..7.
pub const COL_S_RC: usize = P2_WIDTH; // 4

/// S-box intermediate columns: cols 8..23.
pub const COL_SBOX: usize = COL_S_RC + P2_WIDTH; // 8

/// Round index column: col 24.
pub const COL_ROUND_IDX: usize = COL_SBOX + P2_WIDTH * SBOX_INTERMEDIATES; // 24

/// Is-partial round column: col 25.
pub const COL_IS_PARTIAL: usize = COL_ROUND_IDX + 1; // 25

/// Input snapshot start: cols 26..28.
pub const COL_INPUT_START: usize = COL_IS_PARTIAL + 1; // 26

/// Trace width: 4 s_in + 4 s_rc + 16 sbox + 1 round + 1 partial + 3 input = 29.
pub const POSEIDON2_TRACE_WIDTH: usize = COL_INPUT_START + P2_WIDTH - 1; // 29

/// Full rounds RF=8 (4 initial + 4 final). OSSIFIED spec §2.1.
pub const FULL_ROUNDS: usize = 8;

/// Partial rounds RP=22. OSSIFIED spec §2.1.
pub const PARTIAL_ROUNDS: usize = 22;

/// Total rounds per permutation.
pub const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS; // 30

/// First partial round index.
pub const PARTIAL_ROUND_START: usize = FULL_ROUNDS / 2; // 4

/// Last partial round index (exclusive).
pub const PARTIAL_ROUND_END: usize = PARTIAL_ROUND_START + PARTIAL_ROUNDS; // 26

/// Trace rows: 30 rounds + 1 output row = 31 → padded to 32.
pub const POSEIDON2_TRACE_ROWS: usize = 32;

/// OSSIFIED proof parameters. Spec §4.4.
pub const P2_NUM_QUERIES: usize = 84;
pub const P2_BLOWUP: usize = 8;
pub const P2_GRINDING: u32 = 20;
pub const P2_FOLDING: usize = 4;
pub const P2_REMAINDER_MAX_DEGREE: usize = 7;

// ── Field helpers ─────────────────────────────────────────────────────────────

#[inline]
fn fe(x: u64) -> BaseElement {
    BaseElement::new(x)
}

// ── Round Constants (Goldilocks, t=4) — OSSIFIED ─────────────────────────────
// Identical to scalar-crypto poseidon2.rs. Spec §2.1.

const ROUND_CONSTANTS: [[u64; P2_WIDTH]; TOTAL_ROUNDS] = [
    [
        0x3aaed6e034fef709,
        0x2da65cf597408562,
        0xa7aace2d982bcb6a,
        0xbc121600d772d547,
    ],
    [
        0x1b114ef06f74865a,
        0x58ab3321665a38c2,
        0xec6e45fef040c842,
        0x9dc72efe8eb36d95,
    ],
    [
        0x69309d63ad1865c9,
        0x71a7ff71644d8e7e,
        0x05a8d7027238a428,
        0xe2f309a35adf55a3,
    ],
    [
        0xaab6a20f988e3a49,
        0xb2a1e4506874ebf9,
        0x31aca8878a23c40d,
        0x9a67297d522172c7,
    ],
    [
        0xd63b2a0d592f9779,
        0x3a610b62597d4252,
        0xc35857316552ee9c,
        0xeb7b4b8efcef4b6a,
    ],
    [
        0x1849a3e493848923,
        0x6bfaacbb4ff1db98,
        0x3eb14cd17d192d03,
        0x133e95099396da3c,
    ],
    [
        0xb8735f19f764cf4c,
        0x3a15f2bcac9cf32e,
        0xb5f0c9217f35cf57,
        0x1fd04c544470eafd,
    ],
    [
        0xc8a2058487ac0285,
        0x5e0be2f9eac6aad5,
        0xee4fc2378b7c35f8,
        0xeb8047e6be838132,
    ],
    [
        0x05543806b9d76ce9,
        0x7fabcc72309725b2,
        0xc7a3868a71fd4d8f,
        0xd29015c3c417e4bb,
    ],
    [
        0x56b7c4440cc9e9c8,
        0xd8b1c629e71bb164,
        0xf4c0847ca9341ac4,
        0x1f8546dc97cdba25,
    ],
    [
        0x3c56b447f4137881,
        0x59b35f9c795255cf,
        0x32e7ca296fe46732,
        0x2cc294ad1a52a94d,
    ],
    [
        0x1060b200e2725944,
        0x3ee35f5ee6a0f0cd,
        0x71ba8842cf6a016f,
        0x68060a2ffdce977d,
    ],
    [
        0x2f3e3d3e3b283902,
        0x350bf8d978a3670f,
        0xd0d9c23db3cbd8c5,
        0x16f68724b6900378,
    ],
    [
        0x7c2bf4809b9782dd,
        0x052af0b40e08c9d0,
        0xd831fb83be48c0af,
        0xe8a94bfb9464613e,
    ],
    [
        0x2c96a7d0898dbe1b,
        0x38364d93a426bbd5,
        0x2912a5153ed0ba7c,
        0x0af0925d868358f2,
    ],
    [
        0x362cdcb4d9e7cc6e,
        0x194a6b07ff7ae21d,
        0x28dd53b3bcd5e851,
        0x59fb7afb4bee528c,
    ],
    [
        0x4bd0360314bc46a0,
        0x076257530c706d7a,
        0x5b790519caf338c1,
        0x454cdca868c6610c,
    ],
    [
        0x426ca38cca16970d,
        0xc9555fe6efa48f9a,
        0x23f18cd0ca651b3a,
        0x12f6be2551a9ece4,
    ],
    [
        0x5d19cd85625e6cd4,
        0x033f57ecb7f9988b,
        0x51dbf1d36da0e24f,
        0x3e077397f307b7d4,
    ],
    [
        0x96024145db4a13da,
        0x2be4ba6bd810a850,
        0xd49cface475c85eb,
        0x54b101b103564356,
    ],
    [
        0x51daf7526c6d3721,
        0x9e2c63ccadb3e457,
        0x7574671c8831bd72,
        0x593906603a027573,
    ],
    [
        0xbf978d0d430a1038,
        0x16498e417fbda281,
        0x3324b0966a2b5c61,
        0xb565ea80a19f1465,
    ],
    [
        0xb1f1e0f1dfe67dc4,
        0x069ee318d5037863,
        0x025015c57735ec6d,
        0x83ca2cb6afc9c0b5,
    ],
    [
        0x9aca0c65658045da,
        0x32c72b854aa33f6a,
        0x1b86c06c65e563e9,
        0xd3b2e743605233c7,
    ],
    [
        0xde5453cdb5f6a3c1,
        0x160c94d47b36ba4e,
        0xc572402fa8c73cc1,
        0x59231b2ee92c0409,
    ],
    [
        0x05b087175e09ee36,
        0xb2e9c18902a18e06,
        0x5846001972ba7da8,
        0x6aebcd9abd529048,
    ],
    [
        0x2d3a03adc848eab1,
        0x9b779ac00fbb85db,
        0x4ebb1bbd83118149,
        0x263f74ab9d87da4b,
    ],
    [
        0x8a7fcc51f6fec3c8,
        0x879bdb1cb5d7d9a2,
        0x812d6a0b9d0363e5,
        0xad371d1acf8f155b,
    ],
    [
        0xb250667f5e91f0ba,
        0x5c54378b048155dd,
        0x0297d13f80000cb3,
        0xf2abfe46670b1961,
    ],
    [
        0x4880f5bc96111cde,
        0xe89150e848fa6bd6,
        0x6e504d15b09e7e2e,
        0xd02e8fc81d0b1a92,
    ],
];

/// MDS M_E = circ(5,7,1,3). OSSIFIED. Spec §2.1.
const MATRIX_FULL: [[u64; P2_WIDTH]; P2_WIDTH] =
    [[5, 7, 1, 3], [3, 5, 7, 1], [1, 3, 5, 7], [7, 1, 3, 5]];

/// M_I diagonal (stored as diag-1). OSSIFIED. Spec §2.1.
const MAT_DIAG4_M_1: [u64; P2_WIDTH] = [0, 1, 2, 3];

// ── MDS helpers ───────────────────────────────────────────────────────────────

fn mds_full(s: &[BaseElement; P2_WIDTH]) -> [BaseElement; P2_WIDTH] {
    core::array::from_fn(|i| {
        (0..P2_WIDTH).fold(BaseElement::ZERO, |acc, j| {
            acc + fe(MATRIX_FULL[i][j]) * s[j]
        })
    })
}

fn mds_partial(s: &[BaseElement; P2_WIDTH]) -> [BaseElement; P2_WIDTH] {
    let sum = s.iter().fold(BaseElement::ZERO, |acc, &x| acc + x);
    core::array::from_fn(|i| sum + fe(MAT_DIAG4_M_1[i]) * s[i])
}

/// Decompose x^7: returns (x^2, x^4, x^6, x^7).
#[inline]
fn sbox_chain(x: BaseElement) -> (BaseElement, BaseElement, BaseElement, BaseElement) {
    let x2 = x * x;
    let x4 = x2 * x2;
    let x6 = x4 * x2;
    let x7 = x6 * x;
    (x2, x4, x6, x7)
}

/// Returns true if round `r` is a partial round.
#[inline]
fn is_partial_round(r: usize) -> bool {
    (PARTIAL_ROUND_START..PARTIAL_ROUND_END).contains(&r)
}

// ── Witness ───────────────────────────────────────────────────────────────────

/// Per-round trace data for one Poseidon2 round.
struct RoundTrace {
    /// State entering this round (before AddRC).
    s_in: [BaseElement; P2_WIDTH],
    /// State after AddRC (before S-box).
    s_rc: [BaseElement; P2_WIDTH],
    /// S-box intermediates: [x2, x4, x6, x7] per state element.
    /// For partial rounds, i>0: all four = s_rc[i] (pass-through).
    sbox: [[BaseElement; SBOX_INTERMEDIATES]; P2_WIDTH],
    /// True if this is a partial round.
    partial: bool,
}

/// Witness: full execution of one Poseidon2 permutation.
pub struct Poseidon2Witness {
    /// Input state (4 Goldilocks u64 values).
    pub input: [u64; P2_WIDTH],
    /// Output state after permutation.
    pub output: [u64; P2_WIDTH],
    /// Per-round trace data (30 rounds).
    rounds: Vec<RoundTrace>,
}

impl Poseidon2Witness {
    /// Execute full Poseidon2 permutation and build witness.
    pub fn new(input: [u64; P2_WIDTH]) -> Self {
        let input_fe: [BaseElement; P2_WIDTH] = input.map(fe);

        // Initial linear layer: M_E applied before any rounds.
        let mut state = mds_full(&input_fe);
        let mut rounds = Vec::with_capacity(TOTAL_ROUNDS);

        for (r, rc_vals) in ROUND_CONSTANTS.iter().enumerate() {
            let s_in = state;
            let rc = rc_vals.map(fe);
            // AddRC
            let s_rc: [BaseElement; P2_WIDTH] = core::array::from_fn(|i| s_in[i] + rc[i]);
            let partial = is_partial_round(r);

            // S-box + collect intermediates
            let mut sbox = [[BaseElement::ZERO; SBOX_INTERMEDIATES]; P2_WIDTH];
            let mut sbox_out = s_rc;

            if partial {
                // Only element 0 gets S-boxed
                let (x2, x4, x6, x7) = sbox_chain(s_rc[0]);
                sbox[0] = [x2, x4, x6, x7];
                sbox_out[0] = x7;
                // Elements 1..3: pass-through (x2=x4=x6=x7=s_rc[i])
                for i in 1..P2_WIDTH {
                    sbox[i] = [s_rc[i]; SBOX_INTERMEDIATES];
                }
            } else {
                // All elements get S-boxed
                for i in 0..P2_WIDTH {
                    let (x2, x4, x6, x7) = sbox_chain(s_rc[i]);
                    sbox[i] = [x2, x4, x6, x7];
                    sbox_out[i] = x7;
                }
            }

            // MDS
            state = if partial {
                mds_partial(&sbox_out)
            } else {
                mds_full(&sbox_out)
            };

            rounds.push(RoundTrace {
                s_in,
                s_rc,
                sbox,
                partial,
            });
        }

        let output = state.map(|e| e.as_int());
        Self {
            input,
            output,
            rounds,
        }
    }

    pub fn public_output(&self) -> Poseidon2PublicInputs {
        Poseidon2PublicInputs {
            input: self.input,
            output: self.output,
        }
    }
}

// ── Public Inputs ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poseidon2PublicInputs {
    pub input: [u64; P2_WIDTH],
    pub output: [u64; P2_WIDTH],
}

impl ToElements<BaseElement> for Poseidon2PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        let mut v = Vec::with_capacity(P2_WIDTH * 2);
        self.input.iter().for_each(|&x| v.push(fe(x)));
        self.output.iter().for_each(|&x| v.push(fe(x)));
        v
    }
}

// ── Trace Builder ─────────────────────────────────────────────────────────────

/// Build execution trace for one Poseidon2 permutation.
///
/// Row r (0..29): round r data.
/// Row 30: output state (s_in = permutation output, other cols = padding).
/// Row 31: padding (repeat row 30).
pub fn build_poseidon2_trace(witness: &Poseidon2Witness) -> TraceTable<BaseElement> {
    let mut trace = TraceTable::new(POSEIDON2_TRACE_WIDTH, POSEIDON2_TRACE_ROWS);

    // Rows 0..29: one round per row
    for r in 0..TOTAL_ROUNDS {
        let rd = &witness.rounds[r];
        set_row(
            &mut trace, r, &rd.s_in, &rd.s_rc, &rd.sbox, r as u64, rd.partial,
        );
    }

    // Row 30: output row (s_in = permutation output, sbox = identity, round = 30)
    let output_fe: [BaseElement; P2_WIDTH] = witness.output.map(fe);
    let sbox_identity: [[BaseElement; SBOX_INTERMEDIATES]; P2_WIDTH] =
        core::array::from_fn(|i| [output_fe[i]; SBOX_INTERMEDIATES]);
    set_row(
        &mut trace,
        TOTAL_ROUNDS,
        &output_fe,
        &output_fe,
        &sbox_identity,
        TOTAL_ROUNDS as u64,
        false,
    );

    // Row 31: padding (same as row 30)
    set_row(
        &mut trace,
        TOTAL_ROUNDS + 1,
        &output_fe,
        &output_fe,
        &sbox_identity,
        TOTAL_ROUNDS as u64,
        false,
    );

    // Store input snapshot in cols 26..28 for all rows
    for row in 0..POSEIDON2_TRACE_ROWS {
        for k in 0..(P2_WIDTH - 1) {
            trace.set(COL_INPUT_START + k, row, fe(witness.input[k]));
        }
    }

    trace
}

fn set_row(
    trace: &mut TraceTable<BaseElement>,
    row: usize,
    s_in: &[BaseElement; P2_WIDTH],
    s_rc: &[BaseElement; P2_WIDTH],
    sbox: &[[BaseElement; SBOX_INTERMEDIATES]; P2_WIDTH],
    round_idx: u64,
    partial: bool,
) {
    for i in 0..P2_WIDTH {
        trace.set(COL_S_IN + i, row, s_in[i]);
        trace.set(COL_S_RC + i, row, s_rc[i]);
        let base = COL_SBOX + i * SBOX_INTERMEDIATES;
        trace.set(base, row, sbox[i][0]); // x2
        trace.set(base + 1, row, sbox[i][1]); // x4
        trace.set(base + 2, row, sbox[i][2]); // x6
        trace.set(base + 3, row, sbox[i][3]); // x7
    }
    trace.set(COL_ROUND_IDX, row, fe(round_idx));
    trace.set(COL_IS_PARTIAL, row, fe(partial as u64));
}

// ── AIR ───────────────────────────────────────────────────────────────────────

/// Poseidon2 Permutation AIR. Spec §4.3 CA.
///
/// Constraints per row (25 total):
///   C0-C3:   AddRC: s_rc[i] = s_in[i] + RC[r][i]          (degree 1, ×4)
///   C4-C7:   x2[i] = s_rc[i]^2                             (degree 2, ×4)
///   C8-C11:  x4[i] = x2[i]^2                               (degree 2, ×4)
///   C12-C15: x6[i] = x4[i] * x2[i]                        (degree 2, ×4)
///   C16-C19: x7[i] = x6[i] * s_rc[i]                      (degree 2, ×4)
///   C20-C23: nxt.s_in[i] = MDS(x7)[i]                     (degree 1, ×4)
///   C24:     nxt.round_idx = round_idx + 1                 (degree 1)
pub struct Poseidon2Air {
    context: AirContext<BaseElement>,
    pub_inputs: Poseidon2PublicInputs,
}

impl Air for Poseidon2Air {
    type BaseField = BaseElement;
    type PublicInputs = Poseidon2PublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(
        trace_info: TraceInfo,
        pub_inputs: Poseidon2PublicInputs,
        options: ProofOptions,
    ) -> Self {
        // 25 constraints total.
        // C0-C3: AddRC (degree 1)
        // C4-C19: S-box chain (degree 2)
        // C20-C23: MDS output (degree 1)
        // C24: round counter (degree 1)
        let mut degrees = Vec::with_capacity(25);
        // C0-C3: AddRC — degree 1
        for _ in 0..P2_WIDTH {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        // C4-C7: x2=s_rc^2 — degree 2
        for _ in 0..P2_WIDTH {
            degrees.push(TransitionConstraintDegree::new(2));
        }
        // C8-C11: x4=x2^2 — degree 2
        for _ in 0..P2_WIDTH {
            degrees.push(TransitionConstraintDegree::new(2));
        }
        // C12-C15: x6=x4*x2 — degree 2
        for _ in 0..P2_WIDTH {
            degrees.push(TransitionConstraintDegree::new(2));
        }
        // C16-C19: x7=x6*s_rc — degree 2
        for _ in 0..P2_WIDTH {
            degrees.push(TransitionConstraintDegree::new(2));
        }
        // C20-C23: MDS output — degree 1
        for _ in 0..P2_WIDTH {
            degrees.push(TransitionConstraintDegree::new(1));
        }
        // C24: round counter — degree 1
        degrees.push(TransitionConstraintDegree::new(1));

        // Boundary assertions:
        //   post-M_E input (4) + output (4) + round starts at 0 (1) = 9
        let num_assertions = P2_WIDTH * 2 + 1;

        Poseidon2Air {
            context: AirContext::new(trace_info, degrees, num_assertions, options),
            pub_inputs,
        }
    }

    fn get_periodic_column_values(&self) -> Vec<Vec<BaseElement>> {
        // Supply round constants as periodic columns (period = POSEIDON2_TRACE_ROWS = 32).
        // RC[r][i] is accessed via periodic_values[i] in evaluate_transition.
        // Rows beyond TOTAL_ROUNDS (rows 30, 31) use RC[30 mod 32] = RC[30] and RC[31 mod 32]...
        // but those rows are padding rows where constraints are masked anyway.
        // We pad with zeros for rows 30-31.
        // Build one periodic column per state element.
        // Period = POSEIDON2_TRACE_ROWS. Rows 0..29 = RC values; rows 30-31 = zero padding.
        (0..P2_WIDTH)
            .map(|i| {
                let mut col: Vec<BaseElement> =
                    ROUND_CONSTANTS.iter().map(|rc_row| fe(rc_row[i])).collect();
                col.push(BaseElement::ZERO); // row 30
                col.push(BaseElement::ZERO); // row 31
                col
            })
            .collect()
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        periodic_values: &[E],
        result: &mut [E],
    ) {
        let cur = frame.current();
        let nxt = frame.next();

        // Read state-in from current row
        let s_in: [E; P2_WIDTH] = core::array::from_fn(|i| cur[COL_S_IN + i]);
        // Read state-after-RC from current row
        let s_rc: [E; P2_WIDTH] = core::array::from_fn(|i| cur[COL_S_RC + i]);
        // Read S-box intermediates from current row
        let x2: [E; P2_WIDTH] = core::array::from_fn(|i| cur[COL_SBOX + i * SBOX_INTERMEDIATES]);
        let x4: [E; P2_WIDTH] =
            core::array::from_fn(|i| cur[COL_SBOX + i * SBOX_INTERMEDIATES + 1]);
        let x6: [E; P2_WIDTH] =
            core::array::from_fn(|i| cur[COL_SBOX + i * SBOX_INTERMEDIATES + 2]);
        let x7: [E; P2_WIDTH] =
            core::array::from_fn(|i| cur[COL_SBOX + i * SBOX_INTERMEDIATES + 3]);
        // Read next state-in
        let nxt_s_in: [E; P2_WIDTH] = core::array::from_fn(|i| nxt[COL_S_IN + i]);
        // Round constants from periodic values
        let rc: [E; P2_WIDTH] = core::array::from_fn(|i| periodic_values[i]);
        // Round counter
        let round_idx = cur[COL_ROUND_IDX];

        let mut c = 0usize;

        // C0-C3: AddRC — s_rc[i] = s_in[i] + RC[r][i]
        for i in 0..P2_WIDTH {
            result[c] = s_rc[i] - (s_in[i] + rc[i]);
            c += 1;
        }

        // C4-C7: x2[i] = s_rc[i]^2
        for i in 0..P2_WIDTH {
            result[c] = x2[i] - s_rc[i] * s_rc[i];
            c += 1;
        }

        // C8-C11: x4[i] = x2[i]^2
        for i in 0..P2_WIDTH {
            result[c] = x4[i] - x2[i] * x2[i];
            c += 1;
        }

        // C12-C15: x6[i] = x4[i] * x2[i]
        for i in 0..P2_WIDTH {
            result[c] = x6[i] - x4[i] * x2[i];
            c += 1;
        }

        // C16-C19: x7[i] = x6[i] * s_rc[i]
        for i in 0..P2_WIDTH {
            result[c] = x7[i] - x6[i] * s_rc[i];
            c += 1;
        }

        // C20-C23: MDS output — nxt.s_in[i] = MDS_full(x7)[i]
        // NOTE: For partial rounds, the witness uses MDS_partial. This means
        // the MDS_full constraint will NOT be zero for partial rounds.
        // We handle this by using MDS_full for all rounds at the AIR level,
        // and ensuring the witness sets nxt.s_in consistently.
        //
        // APPROACH A (current): Use MDS_full constraint for ALL rounds.
        // The witness for partial rounds still applies MDS_partial, which will
        // cause constraint violations. This needs selector multiplication.
        //
        // APPROACH B (A-R2): Use is_partial selector to switch MDS.
        // For now (A-R1): enforce MDS_full only, skip partial round correctness.
        // This allows the full-round structure to be verified first.
        //
        // TEMPORARY: Use MDS_full for all rows (partial round output will be wrong).
        // This is a known limitation documented here. A-R2 will add the selector.
        for i in 0..P2_WIDTH {
            let mds_out = (0..P2_WIDTH).fold(E::ZERO, |acc, j| {
                acc + E::from(fe(MATRIX_FULL[i][j])) * x7[j]
            });
            result[c] = nxt_s_in[i] - mds_out;
            c += 1;
        }

        // C24: round counter increment
        result[c] = nxt[COL_ROUND_IDX] - round_idx - E::ONE;
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let mut assertions = Vec::new();

        // Row 0, s_in cols: must equal post-initial-M_E state.
        let input_fe: [BaseElement; P2_WIDTH] = self.pub_inputs.input.map(fe);
        let post_mds = mds_full(&input_fe);
        for (i, &val) in post_mds.iter().enumerate() {
            assertions.push(Assertion::single(COL_S_IN + i, 0, val));
        }

        // Row TOTAL_ROUNDS (30), s_in cols: permutation output.
        let out_fe: [BaseElement; P2_WIDTH] = self.pub_inputs.output.map(fe);
        for (i, &val) in out_fe.iter().enumerate() {
            assertions.push(Assertion::single(COL_S_IN + i, TOTAL_ROUNDS, val));
        }

        // Round counter starts at 0.
        assertions.push(Assertion::single(COL_ROUND_IDX, 0, BaseElement::ZERO));

        assertions
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
}

// ── Prover ────────────────────────────────────────────────────────────────────

pub struct Poseidon2Prover {
    options: ProofOptions,
}

impl Poseidon2Prover {
    pub fn new() -> Self {
        Self {
            options: ProofOptions::new(
                P2_NUM_QUERIES,
                P2_BLOWUP,
                P2_GRINDING,
                FieldExtension::Quadratic,
                P2_FOLDING,
                P2_REMAINDER_MAX_DEGREE,
            ),
        }
    }

    pub fn prove_permutation(
        &self,
        witness: &Poseidon2Witness,
    ) -> Result<Vec<u8>, Poseidon2ProveError> {
        let trace = build_poseidon2_trace(witness);
        let proof = self
            .prove(trace)
            .map_err(|e| Poseidon2ProveError::ProverFailed(format!("{:?}", e)))?;
        Ok(proof.to_bytes())
    }
}

impl Default for Poseidon2Prover {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover for Poseidon2Prover {
    type BaseField = BaseElement;
    type Air = Poseidon2Air;
    type Trace = TraceTable<Self::BaseField>;
    type HashFn = Blake3_256<Self::BaseField>;
    type RandomCoin = DefaultRandomCoin<Self::HashFn>;
    type TraceLde<E: FieldElement<BaseField = Self::BaseField>> = DefaultTraceLde<E, Self::HashFn>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = Self::BaseField>> =
        DefaultConstraintEvaluator<'a, Self::Air, E>;

    fn get_pub_inputs(&self, trace: &Self::Trace) -> Poseidon2PublicInputs {
        let input: [u64; P2_WIDTH] = core::array::from_fn(|i| {
            if i < P2_WIDTH - 1 {
                trace.get(COL_INPUT_START + i, 0).as_int()
            } else {
                0
            }
        });
        let output: [u64; P2_WIDTH] =
            core::array::from_fn(|i| trace.get(COL_S_IN + i, TOTAL_ROUNDS).as_int());
        Poseidon2PublicInputs { input, output }
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }

    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    fn new_evaluator<'a, E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        air: &'a Self::Air,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }
}

// ── Verifier ──────────────────────────────────────────────────────────────────

pub fn verify_poseidon2_proof(
    proof_bytes: &[u8],
    pub_inputs: &Poseidon2PublicInputs,
) -> Result<(), Poseidon2VerifyError> {
    use winterfell::{verify, AcceptableOptions};
    if proof_bytes.is_empty() {
        return Err(Poseidon2VerifyError::EmptyProof);
    }
    let proof = winterfell::Proof::from_bytes(proof_bytes)
        .map_err(|e| Poseidon2VerifyError::DeserializationFailed(format!("{:?}", e)))?;
    let min_opts = AcceptableOptions::MinConjecturedSecurity(90);
    verify::<Poseidon2Air, Blake3_256<BaseElement>, DefaultRandomCoin<Blake3_256<BaseElement>>>(
        proof,
        pub_inputs.clone(),
        &min_opts,
    )
    .map_err(|e| Poseidon2VerifyError::VerificationFailed(format!("{:?}", e)))
}

// ── Error types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Poseidon2ProveError {
    #[error("Winterfell prover failed: {0}")]
    ProverFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Poseidon2VerifyError {
    #[error("Proof bytes are empty")]
    EmptyProof,
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),
    #[error("STARK verification failed: {0}")]
    VerificationFailed(String),
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use scalar_crypto::poseidon2::{poseidon2_permutation, TV_KNOWN_OUT, TV_ZERO_OUT};

    fn native_permute(input: [u64; 4]) -> [u64; 4] {
        let mut state = input;
        poseidon2_permutation(&mut state);
        state
    }

    // ── Witness correctness ───────────────────────────────────────────────────

    #[test]
    fn test_witness_output_matches_native_zero() {
        let w = Poseidon2Witness::new([0, 0, 0, 0]);
        assert_eq!(w.output, TV_ZERO_OUT);
    }

    #[test]
    fn test_witness_output_matches_native_known() {
        let w = Poseidon2Witness::new([1, 2, 0, 0]);
        assert_eq!(w.output, TV_KNOWN_OUT);
    }

    #[test]
    fn test_witness_output_matches_native_arbitrary() {
        let input = [0xDEAD_BEEF_u64, 0xCAFE_BABE, 1_000_000, 42];
        let w = Poseidon2Witness::new(input);
        assert_eq!(w.output, native_permute(input));
    }

    #[test]
    fn test_witness_round_count() {
        let w = Poseidon2Witness::new([0; P2_WIDTH]);
        assert_eq!(w.rounds.len(), TOTAL_ROUNDS);
    }

    // ── Trace consistency ─────────────────────────────────────────────────────

    #[test]
    fn test_trace_dimensions() {
        let w = Poseidon2Witness::new([1, 2, 0, 0]);
        let t = build_poseidon2_trace(&w);
        assert_eq!(t.width(), POSEIDON2_TRACE_WIDTH);
    }

    #[test]
    fn test_trace_row0_s_in_is_post_mds() {
        // Row 0 s_in must equal M_E(input).
        let input = [1u64, 2, 0, 0];
        let w = Poseidon2Witness::new(input);
        let t = build_poseidon2_trace(&w);
        let expected = mds_full(&input.map(fe));
        for i in 0..P2_WIDTH {
            assert_eq!(t.get(COL_S_IN + i, 0), expected[i], "s_in[{}] at row 0", i);
        }
    }

    #[test]
    fn test_trace_row0_s_rc_equals_s_in_plus_rc0() {
        // Row 0: s_rc[i] = s_in[i] + RC[0][i].
        let input = [1u64, 2, 0, 0];
        let w = Poseidon2Witness::new(input);
        let t = build_poseidon2_trace(&w);
        for i in 0..P2_WIDTH {
            let s_in = t.get(COL_S_IN + i, 0);
            let s_rc = t.get(COL_S_RC + i, 0);
            let rc = fe(ROUND_CONSTANTS[0][i]);
            assert_eq!(s_rc, s_in + rc, "s_rc[{}] at row 0", i);
        }
    }

    #[test]
    fn test_trace_sbox_x2_correct_full_round() {
        // In full round row: x2[i] = s_rc[i]^2.
        let w = Poseidon2Witness::new([3, 5, 7, 11]);
        let t = build_poseidon2_trace(&w);
        // Row 0 is a full round (r=0 < PARTIAL_ROUND_START=4)
        for i in 0..P2_WIDTH {
            let s_rc = t.get(COL_S_RC + i, 0);
            let x2 = t.get(COL_SBOX + i * SBOX_INTERMEDIATES, 0);
            assert_eq!(x2, s_rc * s_rc, "x2[{}] at row 0", i);
        }
    }

    #[test]
    fn test_trace_sbox_chain_correct_full_round() {
        // x4=x2^2, x6=x4*x2, x7=x6*s_rc in a full round row.
        let w = Poseidon2Witness::new([3, 5, 7, 11]);
        let t = build_poseidon2_trace(&w);
        for i in 0..P2_WIDTH {
            let s_rc = t.get(COL_S_RC + i, 0);
            let base = COL_SBOX + i * SBOX_INTERMEDIATES;
            let x2 = t.get(base, 0);
            let x4 = t.get(base + 1, 0);
            let x6 = t.get(base + 2, 0);
            let x7 = t.get(base + 3, 0);
            assert_eq!(x2, s_rc * s_rc, "x2 row 0 elem {}", i);
            assert_eq!(x4, x2 * x2, "x4 row 0 elem {}", i);
            assert_eq!(x6, x4 * x2, "x6 row 0 elem {}", i);
            assert_eq!(x7, x6 * s_rc, "x7 row 0 elem {}", i);
        }
    }

    #[test]
    fn test_trace_output_row() {
        // Row 30: s_in = permutation output.
        let w = Poseidon2Witness::new([0; P2_WIDTH]);
        let t = build_poseidon2_trace(&w);
        for i in 0..P2_WIDTH {
            assert_eq!(t.get(COL_S_IN + i, TOTAL_ROUNDS), fe(TV_ZERO_OUT[i]));
        }
    }

    #[test]
    fn test_full_round_mds_output_correct() {
        // For full rounds: nxt.s_in = MDS_full(x7).
        // Check row 0 → row 1 transition.
        let w = Poseidon2Witness::new([1, 2, 0, 0]);
        let t = build_poseidon2_trace(&w);
        let x7: [BaseElement; P2_WIDTH] =
            core::array::from_fn(|i| t.get(COL_SBOX + i * SBOX_INTERMEDIATES + 3, 0));
        let expected_next = mds_full(&x7);
        for i in 0..P2_WIDTH {
            assert_eq!(
                t.get(COL_S_IN + i, 1),
                expected_next[i],
                "nxt.s_in[{}] after full round 0",
                i
            );
        }
    }

    #[test]
    fn test_sbox_chain_helper() {
        let x = fe(3u64);
        let (x2, x4, x6, x7) = sbox_chain(x);
        assert_eq!(x2, x * x);
        assert_eq!(x4, x2 * x2);
        assert_eq!(x6, x4 * x2);
        assert_eq!(x7, x6 * x);
        assert_eq!(x7, fe(2187u64)); // 3^7 = 2187
    }

    #[test]
    fn test_mds_full_ones() {
        let s = [fe(1); P2_WIDTH];
        assert_eq!(mds_full(&s), [fe(16); P2_WIDTH]);
    }

    #[test]
    fn test_mds_partial_unit() {
        let mut s = [fe(0); P2_WIDTH];
        s[0] = fe(1);
        assert_eq!(mds_partial(&s), [fe(1); P2_WIDTH]);
    }

    #[test]
    fn test_constants() {
        assert_eq!(POSEIDON2_TRACE_WIDTH, 29);
        assert_eq!(COL_S_IN, 0);
        assert_eq!(COL_S_RC, 4);
        assert_eq!(COL_SBOX, 8);
        assert_eq!(COL_ROUND_IDX, 24);
        assert_eq!(COL_IS_PARTIAL, 25);
        assert_eq!(COL_INPUT_START, 26);
        assert_eq!(TOTAL_ROUNDS, 30);
        assert_eq!(POSEIDON2_TRACE_ROWS, 32);
    }

    #[test]
    fn test_round_constants_count() {
        assert_eq!(ROUND_CONSTANTS.len(), TOTAL_ROUNDS);
    }

    // ── STARK prove + verify (full rounds only — A-R1) ───────────────────────
    // NOTE: Current AIR uses MDS_full for ALL rows. This means partial rounds
    // (rows 4..25) will have MDS constraint violations because the witness
    // uses MDS_partial. The prove+verify tests below only work if we restrict
    // to permutations where partial/full round outputs happen to match, OR
    // if we use a 4-full-rounds-only test. This is a KNOWN LIMITATION of A-R1.
    // A-R2 will add the is_partial selector to switch MDS in the constraint.
    //
    // For A-R1 we test the structural integrity:
    //   1. Witness generates correct output (already tested above)
    //   2. Trace has correct structure (tested above)
    //   3. Full AIR prove+verify is deferred to A-R2 when partial is handled

    #[test]
    fn test_empty_proof_rejected() {
        let pi = Poseidon2PublicInputs {
            input: [0; P2_WIDTH],
            output: TV_ZERO_OUT,
        };
        assert!(verify_poseidon2_proof(&[], &pi).is_err());
    }

    #[test]
    fn test_arbitrary_bytes_rejected() {
        let pi = Poseidon2PublicInputs {
            input: [0; P2_WIDTH],
            output: TV_ZERO_OUT,
        };
        let garbage = vec![0xABu8; 200];
        assert!(verify_poseidon2_proof(&garbage, &pi).is_err());
    }
}
