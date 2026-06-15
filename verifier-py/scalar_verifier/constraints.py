"""
Transfer Circuit PI constraint checker — Python impl#2.

Evaluates check_all_constraints() equivalent against TransferPublicInputsP3 (PI 41-field).
Does NOT import from scalar-stark-p3 or scalar_crypto. [SCALAR-SECURITY §5.3, P4]

Ref: SCALAR-TECHNICAL §2.2 (PI layout), §2.9 (CG-ARITH), §4.3 (CA-CG constraints).
     scalar_stark_p3/src/transfer_public_inputs.rs check_all_constraints().
"""

# ── OSSIFIED constants ────────────────────────────────────────────────────────
# [SCALAR-TECHNICAL §2.9, §9.1; SCALAR-PROTOCOL §13.1]
VALID_CRYPTO_VERSION: int = 0x01   # CG: only version 1 accepted
FEE_FLOOR_SSCL: int = 40           # CD: minimum fee in sSCL
CG_MAX_VALIDITY: int = 1           # CG-ARITH: max validity distance

# ── PI field layout (OSSIFIED §2.2) ──────────────────────────────────────────
TRANSFER_PI_LEN: int = 41

# ── Constraint functions ──────────────────────────────────────────────────────

def check_cd_conservation(pi: dict) -> bool:
    """
    CD: Conservation. sum_inputs == sum_outputs + fee_total.
    [SCALAR-TECHNICAL §2.6 CD, P1]
    """
    return pi["sum_inputs_sscl"] == pi["sum_outputs_sscl"] + pi["fee_total_sscl"]

def check_cd_fee_floor(pi: dict) -> bool:
    """
    CD: Fee floor. fee_total >= FEE_FLOOR_SSCL (40 sSCL). [SCALAR-TECHNICAL §9.1]
    """
    return pi["fee_total_sscl"] >= FEE_FLOOR_SSCL

def check_cg_version(pi: dict) -> bool:
    """
    CG: Crypto version must equal VALID_CRYPTO_VERSION (0x01). [SCALAR-TECHNICAL §4.3 CG]
    """
    return pi["crypto_version"] == VALID_CRYPTO_VERSION

def cg_validity(current_subepoch_id: int, target_subepoch_id: int) -> int | None:
    """
    CG-ARITH: Sequential sub-epoch validity.
    Returns validity distance (0 or 1) if valid, None if invalid.
    [SCALAR-TECHNICAL §2.9 CG-ARITH; cg_arith.rs cg_validity()]

    Order guard: current >= target (prevents Goldilocks underflow in-circuit).
    Validity = current - target; must be <= CG_MAX_VALIDITY = 1.

    Some(0) = intra-sub-epoch commit.
    Some(1) = boundary-spillover (CG-WINDOW gate checks legitimacy downstream).
    None    = order violation OR stale.
    """
    if current_subepoch_id < target_subepoch_id:
        return None  # order guard violation
    validity = current_subepoch_id - target_subepoch_id
    if validity > CG_MAX_VALIDITY:
        return None  # stale
    return validity

def check_cg_validity(pi: dict) -> bool:
    """CG-ARITH: validity in {0,1}. [SCALAR-TECHNICAL §2.9]"""
    return cg_validity(pi["current_subepoch_id"], pi["target_subepoch_id"]) is not None

def check_cb_membership(pi: dict) -> bool:
    """CB: membership verified flag must be True. [SCALAR-TECHNICAL §4.3 CB]"""
    return bool(pi["cb_membership_verified"])

def check_cc_nonmembership(pi: dict) -> bool:
    """CC: dual non-membership verified flag must be True. [SCALAR-TECHNICAL §4.3 CC]"""
    return bool(pi["cc_nonmembership_verified"])

def check_ce_output_nonzero(pi: dict) -> bool:
    """CE: output commitment non-zero. [SCALAR-TECHNICAL §4.3 CE]"""
    return bool(pi["output_nonzero"])

def check_inv46_single_source(pi: dict) -> bool:
    """INV-4.6: exactly one UTXO source. [SCALAR-TECHNICAL §3.1.3]"""
    return bool(pi["single_utxo_source"])

# ── check_all_constraints ─────────────────────────────────────────────────────

CONSTRAINT_NAMES: list[str] = [
    "CD_conservation",        # 0
    "CD_fee_floor",           # 1
    "CG_version",             # 2
    "CG_validity",            # 3
    "CB_membership",          # 4
    "CC_nonmembership",       # 5
    "CE_output_nonzero",      # 6
    "INV46_single_source",    # 7
]

CONSTRAINT_FNS = [
    check_cd_conservation,
    check_cd_fee_floor,
    check_cg_version,
    check_cg_validity,
    check_cb_membership,
    check_cc_nonmembership,
    check_ce_output_nonzero,
    check_inv46_single_source,
]

def check_all_constraints(pi: dict) -> tuple[bool, int | None]:
    """
    Evaluate all transfer circuit constraints against PI dict.
    Returns (valid: bool, fail_idx: int | None).
    fail_idx matches check_all_constraints() in transfer_public_inputs.rs.
    [SCALAR-TECHNICAL §2.2, §4.3; P1]
    """
    for i, fn in enumerate(CONSTRAINT_FNS):
        if not fn(pi):
            return False, i
    return True, None
