//! GAP-16 M4D-1: prove serde_json round-trip is lossless for Goldilocks and
//! EF=GF(p^3) field elements BEFORE any verification logic is written.
//!
//! This binary does NOT call any scalar-stark-p3 verification logic. It only
//! constructs field elements directly and serializes/deserializes them via
//! serde_json, to prove the JSON emission path preserves exact values --
//! no limb reordering, no precision loss, no normalization surprises.
//!
//! Test values chosen specifically to catch the failure modes that matter:
//!   - 0, 1 (trivial)
//!   - p-1 (max canonical Goldilocks value, near the prime boundary)
//!   - values that would overflow if mishandled as f64 (precision loss test)
//!   - EF elements with non-trivial limb values [a0,a1,a2] to catch any
//!     limb reordering in JSON array emission
//!
//! [SCALAR-SECURITY §5.3 Tier 2, P4 independence]

use p3_field::extension::CubicTrinomialExtensionField;
use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks as GL;
use serde::{Deserialize, Serialize};

type EF = CubicTrinomialExtensionField<GL>;

const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001; // 2^64 - 2^32 + 1

fn ef(a0: u64, a1: u64, a2: u64) -> EF {
    EF::new([GL::new(a0), GL::new(a1), GL::new(a2)])
}

/// Mirror of a single round's serializable shape we will actually emit in
/// M4D-1's real proof JSON, used here ONLY to test that #[derive(Serialize)]
/// composition behaves as documented (tuple = JSON array, no length prefix
/// semantics leaking through at the JSON layer since JSON arrays are
/// self-delimited anyway).
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct EfWrapper {
    value: EF,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct GlWrapper {
    value: GL,
}

fn check_gl_roundtrip(label: &str, v: u64, failures: &mut Vec<String>) {
    let gl = GL::new(v);
    let wrapper = GlWrapper { value: gl };
    let json = serde_json::to_string(&wrapper).expect("serialize GL");
    let parsed: GlWrapper = serde_json::from_str(&json).expect("deserialize GL");

    let canonical_in = gl.as_canonical_u64();
    let canonical_out = parsed.value.as_canonical_u64();

    println!(
        "[{}] GL in={} canonical_in={} json={} canonical_out={} -> {}",
        label,
        v,
        canonical_in,
        json,
        canonical_out,
        if canonical_in == canonical_out {
            "MATCH"
        } else {
            "MISMATCH"
        }
    );
    if canonical_in != canonical_out {
        failures.push(format!(
            "{}: GL roundtrip mismatch {} != {}",
            label, canonical_in, canonical_out
        ));
    }
}

fn check_ef_roundtrip(label: &str, a0: u64, a1: u64, a2: u64, failures: &mut Vec<String>) {
    let e = ef(a0, a1, a2);
    let wrapper = EfWrapper { value: e };
    let json = serde_json::to_string(&wrapper).expect("serialize EF");
    let parsed: EfWrapper = serde_json::from_str(&json).expect("deserialize EF");

    let ok = e == parsed.value;
    println!(
        "[{}] EF in=[{},{},{}] json={} -> {}",
        label,
        a0,
        a1,
        a2,
        json,
        if ok { "MATCH" } else { "MISMATCH" }
    );

    // CRITICAL FINDING: ExtField is a struct { value: [F;3], _phantom: PhantomData },
    // so #[derive(Serialize)] emits a JSON OBJECT with TWO fields, not a bare array:
    //   {"value": {"value": [a0,a1,a2], "_phantom": null}}
    // (outer "value" is EfWrapper.value, inner "value"/"_phantom" is ExtField's own
    // fields). _phantom serializes to JSON null (PhantomData has a derived Serialize
    // that emits unit -> null). This is NOT the bare-array assumption from the
    // initial M4d-1 plan -- the Python parser MUST account for this nesting and the
    // null _phantom field, not just index into an array.
    let raw: serde_json::Value = serde_json::from_str(&json).expect("parse generic json");
    let ef_obj = raw
        .get("value")
        .expect("outer value field (EfWrapper.value)");
    let phantom = ef_obj
        .get("_phantom")
        .expect("_phantom field must be present");
    if !phantom.is_null() {
        failures.push(format!(
            "{}: _phantom field is not null (got {:?}) -- unexpected, investigate",
            label, phantom
        ));
    }
    let limbs = ef_obj
        .get("value")
        .expect("inner value field (ExtField.value, the [F;3] array)")
        .as_array()
        .expect("inner value must be a JSON array");
    if limbs.len() != 3 {
        failures.push(format!(
            "{}: EF JSON array length != 3 (got {})",
            label,
            limbs.len()
        ));
        return;
    }
    let limb_vals: Vec<u64> = limbs
        .iter()
        .map(|v| v.as_u64().expect("u64 limb"))
        .collect();
    let expected = [a0 % GOLDILOCKS_P, a1 % GOLDILOCKS_P, a2 % GOLDILOCKS_P];
    println!(
        "    raw JSON shape = {} | limbs = {:?}, expected (a0,a1,a2 canonical) = {:?}",
        ef_obj, limb_vals, expected
    );
    if limb_vals != expected {
        failures.push(format!(
            "{}: EF JSON limb order/value mismatch: got {:?}, expected {:?}",
            label, limb_vals, expected
        ));
    }

    if !ok {
        failures.push(format!("{}: EF roundtrip struct mismatch", label));
    }
}

fn main() {
    println!("{}", "=".repeat(64));
    println!("GAP-16 M4D-1: serde_json round-trip lossless proof");
    println!("{}", "=".repeat(64));

    let mut failures: Vec<String> = Vec::new();

    println!("\n--- Goldilocks scalar round-trip ---");
    check_gl_roundtrip("zero", 0, &mut failures);
    check_gl_roundtrip("one", 1, &mut failures);
    check_gl_roundtrip("p_minus_1", GOLDILOCKS_P - 1, &mut failures);
    check_gl_roundtrip("p_minus_2", GOLDILOCKS_P - 2, &mut failures);
    check_gl_roundtrip("large_non_canonical_repr", u64::MAX, &mut failures); // tests as_canonical_u64 reduction
    check_gl_roundtrip("mid_value", 0x1234_5678_9ABC_DEF0, &mut failures);
    check_gl_roundtrip(
        "near_2_53_precision_boundary",
        (1u64 << 53) + 1,
        &mut failures,
    ); // f64 mantissa boundary
    check_gl_roundtrip("near_2_63", (1u64 << 63) - 1, &mut failures);

    println!("\n--- EF=GF(p^3) extension round-trip (limb order check) ---");
    check_ef_roundtrip("trivial", 1, 2, 3, &mut failures);
    check_ef_roundtrip("zero", 0, 0, 0, &mut failures);
    check_ef_roundtrip(
        "p_minus_1_limbs",
        GOLDILOCKS_P - 1,
        GOLDILOCKS_P - 2,
        GOLDILOCKS_P - 3,
        &mut failures,
    );
    check_ef_roundtrip("asymmetric_limbs", 7, 0, 0, &mut failures);
    check_ef_roundtrip("only_x2_limb", 0, 0, 42, &mut failures);
    check_ef_roundtrip(
        "near_2_53_each_limb",
        (1u64 << 53) + 1,
        (1u64 << 53) + 2,
        (1u64 << 53) + 3,
        &mut failures,
    );

    println!("\n{}", "=".repeat(64));
    if failures.is_empty() {
        println!(
            "PASS — all round-trip checks lossless. {} cases verified.",
            14
        );
        std::process::exit(0);
    } else {
        println!("FAIL — {} mismatch(es):", failures.len());
        for f in &failures {
            println!("  - {}", f);
        }
        std::process::exit(1);
    }
}
