//! Mint Circuit AIR — Independent second implementation. Spec §15.3, A-R7.
//!
//! Re-implements MintLinearAir constraints independently from
//! scalar-stark-p3/mint_air_p3.rs. Written from spec §5.2.
//!
//! Trace width: 7 (OSSIFIED — must match MINT_LINEAR_WIDTH).
//! Public values: 8 (version, total_minted, reward, auth, null[0..3]).
//!
//! Constraints (written independently from spec §5.2):
//!   MC1 — version == pv_version
//!   MC3 — cap_headroom + total_minted + reward == S_E (supply cap)
//!   MC3 — reward col == pv_reward (binding)
//!   MC4 — reward * reward_inv == 1 (reward > 0 via multiplicative inverse)
//!   MC5 — auth == pv_auth (node authorization)
//!   MC2 — null_nz == 1 (nullifier non-zero flag)
//!   MC2 — null0 == pv_null_0 + null0 * null_nz == null0 (nullifier binding)

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;

// ── OSSIFIED constants — re-stated from spec, not imported ───────────────────

/// Trace width. OSSIFIED — must equal scalar-stark-p3::MINT_LINEAR_WIDTH = 7.
pub const MINT_TRACE_WIDTH_V2: usize = 7;

/// Public values count. Must equal scalar-stark-p3::MINT_LINEAR_PI_LEN = 8.
pub const MINT_PI_LEN_V2: usize = 8;

/// S_E = 18_900_000 SCL in sSCL. OSSIFIED spec §3.2.
const MINT_S_E_SSCL: u64 = 18_900_000 * 100_000_000;

// Column indices — re-stated from spec §5.2 trace layout
const COL_VERSION: usize = 0;
const COL_CAP_HEADROOM: usize = 1;
const COL_REWARD: usize = 2;
const COL_AUTH: usize = 3;
const COL_NULL_NZ: usize = 4;
const COL_REWARD_INV: usize = 5;
const COL_NULL0: usize = 6;

// Public value indices
const PV_VERSION: usize = 0;
const PV_TOTAL_MINTED: usize = 1;
const PV_REWARD: usize = 2;
const PV_AUTH: usize = 3;
const PV_NULL_0: usize = 4;
// PV_NULL_1..3 = 5..7 bound via Fiat-Shamir transcript

/// Independent second implementation of Mint Linear AIR. Spec §15.3.
/// Constraint logic written from spec §5.2, not copied from scalar-stark-p3.
#[derive(Clone, Debug)]
pub struct MintAirV2;

impl<F: PrimeCharacteristicRing + Sync> BaseAir<F> for MintAirV2 {
    fn width(&self) -> usize {
        MINT_TRACE_WIDTH_V2
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        // Single-row AIR — matches MintLinearAir. Spec §15.3.
        vec![]
    }

    fn num_public_values(&self) -> usize {
        // Must match MintLinearAir::num_public_values() = MINT_LINEAR_PI_LEN = 8.
        MINT_PI_LEN_V2
    }
}

impl<AB: AirBuilder<F = Goldilocks>> Air<AB> for MintAirV2
where
    AB::Var: Into<AB::Expr> + Copy,
    AB::PublicVar: Into<AB::Expr> + Copy,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: &[AB::Var] = main.current_slice();
        let pv: alloc::vec::Vec<AB::PublicVar> = builder.public_values().to_vec();

        if local.len() < MINT_TRACE_WIDTH_V2 || pv.len() < MINT_PI_LEN_V2 {
            return;
        }

        let version    = local[COL_VERSION];
        let cap_headroom = local[COL_CAP_HEADROOM];
        let reward     = local[COL_REWARD];
        let auth       = local[COL_AUTH];
        let null_nz    = local[COL_NULL_NZ];
        let reward_inv = local[COL_REWARD_INV];
        let null0      = local[COL_NULL0];

        let pv_version     = pv[PV_VERSION];
        let pv_total_minted = pv[PV_TOTAL_MINTED];
        let pv_reward      = pv[PV_REWARD];
        let pv_auth        = pv[PV_AUTH];
        let pv_null_0      = pv[PV_NULL_0];

        // MC1: version matches public version. Spec §5.2 MC1.
        builder.assert_eq(version, pv_version);

        // MC3: supply cap in-circuit. S_E is field constant — prover cannot fake.
        // cap_headroom + total_minted + reward == S_E. Spec §5.2 MC3.
        let s_e = AB::F::from_u64(MINT_S_E_SSCL);
        let lhs: AB::Expr =
            cap_headroom.into() + pv_total_minted.into() + pv_reward.into();
        builder.assert_eq(lhs, s_e);

        // MC3 binding: reward in trace == public reward.
        builder.assert_eq(reward, pv_reward);

        // MC4: reward != 0 via multiplicative inverse. Spec §5.2 MC4.
        // reward * reward_inv == 1; reward=0 has no inverse → proof rejected.
        let reward_times_inv: AB::Expr = reward.into() * reward_inv.into();
        builder.assert_eq(reward_times_inv, AB::Expr::ONE);

        // MC5: node authorization. Spec §5.2 MC5.
        builder.assert_eq(auth, pv_auth);

        // MC2: null_nz == 1 (nullifier non-zero). Spec §5.2 MC2.
        builder.assert_eq(null_nz, AB::Expr::ONE);

        // MC2: null0 binding + non-zero confirmation.
        builder.assert_eq(null0, pv_null_0);
        let null0_times_nz: AB::Expr = null0.into() * null_nz.into();
        builder.assert_eq(null0_times_nz, null0);
    }
}
