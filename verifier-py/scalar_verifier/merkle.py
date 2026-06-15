"""
IMT (Incremental Merkle Tree, binary depth-32) dan QSMT (Quaternary SMT, depth-16)
hash functions dan verifier — Python impl#2.

Does NOT import from scalar-stark-p3 or scalar_crypto. [SCALAR-SECURITY §5.3, P4]
Ref: SCALAR-TECHNICAL §3.1 (IMT), §3.5.4 (QSMT); scalar_crypto/src/imt.rs,
     scalar_nullifier/src/smt_quaternary.rs.
"""

from .proof_params import GOLDILOCKS_P as P
from .poseidon2 import poseidon2_permute_t8, poseidon2_hash_chained, field_reduce

IMT_DEPTH: int = 32
QSMT_DEPTH: int = 16
QSMT_ARITY: int = 4
QSMT_BITS_PER_LEVEL: int = 2  # log2(4)

# ── Byte / field helpers ──────────────────────────────────────────────────────

def bytes32_to_u64s(b: bytes) -> list[int]:
    """Convert 32 bytes to 4 x u64 LE field elements."""
    assert len(b) == 32
    return [
        field_reduce(int.from_bytes(b[i*8:(i+1)*8], 'little'))
        for i in range(4)
    ]

def field8_to_bytes32(state: list[int]) -> bytes:
    """Convert first 4 elements of Poseidon2 state to 32 bytes (LE). [D-010]"""
    result = bytearray(32)
    for i in range(4):
        result[i*8:(i+1)*8] = (state[i] & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little')
    return bytes(result)

def domain_bytes_to_field(domain: bytes) -> list[int]:
    """Split domain bytes into 8-byte LE chunks as field elements."""
    result = []
    for i in range(0, len(domain), 8):
        chunk = domain[i:i+8].ljust(8, b'\x00')
        result.append(field_reduce(int.from_bytes(chunk, 'little')))
    return result

# ── IMT hash functions ────────────────────────────────────────────────────────
# Source: scalar_crypto/src/imt.rs hash_imt_leaf + hash_imt_node [D-010, D-011]

DOMAIN_IMT_LEAF_LO: int = field_reduce(int.from_bytes(b"scalar_i", 'little'))
DOMAIN_IMT_LEAF_HI: int = field_reduce(int.from_bytes(b"mt_leaf\x00", 'little'))
DOMAIN_IMT_NODE_LO: int = field_reduce(int.from_bytes(b"scalar_i", 'little'))
DOMAIN_IMT_NODE_HI: int = field_reduce(int.from_bytes(b"mt_node\x00", 'little'))

def hash_imt_leaf(commitment: bytes, leaf_index: int) -> bytes:
    """
    IMT leaf hash: Poseidon2_t8([domain_lo, domain_hi, c0, c1, c2, c3, leaf_idx, 0]).
    [scalar_crypto/src/imt.rs hash_imt_leaf, D-010]
    """
    c = bytes32_to_u64s(commitment)
    inp = [
        DOMAIN_IMT_LEAF_LO, DOMAIN_IMT_LEAF_HI,
        c[0], c[1], c[2], c[3],
        field_reduce(leaf_index), 0,
    ]
    return field8_to_bytes32(poseidon2_permute_t8(inp))

def hash_imt_node(left: bytes, right: bytes) -> bytes:
    """
    IMT node hash: Poseidon2_t8([domain_lo, domain_hi, l0,l1,l2,l3, r0,r1]).
    Note: r[2] and r[3] dropped to fit WIDTH=8. [scalar_crypto/src/imt.rs hash_imt_node]
    """
    l = bytes32_to_u64s(left)
    r = bytes32_to_u64s(right)
    inp = [
        DOMAIN_IMT_NODE_LO, DOMAIN_IMT_NODE_HI,
        l[0], l[1], l[2], l[3],
        r[0], r[1],
    ]
    return field8_to_bytes32(poseidon2_permute_t8(inp))

# ── IMT empty subtree roots ───────────────────────────────────────────────────

def build_empty_imt_roots() -> list[bytes]:
    """Precompute empty subtree roots for IMT depth-32. Index i = root at depth i."""
    roots = [bytes(32)]  # depth 0: empty leaf = zero
    for _ in range(IMT_DEPTH):
        prev = roots[-1]
        roots.append(hash_imt_node(prev, prev))
    return roots

EMPTY_IMT_ROOTS: list[bytes] = build_empty_imt_roots()

def imt_empty_root() -> bytes:
    return EMPTY_IMT_ROOTS[IMT_DEPTH]

# ── IMT membership verify ─────────────────────────────────────────────────────

def imt_verify_membership(
    commitment: bytes,
    leaf_index: int,
    siblings: list[bytes],  # length = IMT_DEPTH, index 0 = deepest
    root: bytes,
) -> bool:
    """
    Verify IMT membership proof.
    siblings[i] = sibling at depth i from leaf (siblings[0] is at leaf level).
    """
    assert len(siblings) == IMT_DEPTH, f"expected {IMT_DEPTH} siblings, got {len(siblings)}"
    current = hash_imt_leaf(commitment, leaf_index)
    idx = leaf_index
    for i, sibling in enumerate(siblings):
        if idx % 2 == 0:
            current = hash_imt_node(current, sibling)
        else:
            current = hash_imt_node(sibling, current)
        idx >>= 1
    return current == root

# ── QSMT hash functions ───────────────────────────────────────────────────────
# Source: scalar_nullifier/src/smt_quaternary.rs [§3.5.4]

DOMAIN_SMT_ACTIVE: bytes = b"scalar_smt_active"
QSMT_EMPTY_ROOT: bytes = bytes(32)

def _domain_to_3_fields(domain: bytes) -> list[int]:
    """Split domain into 3 field elements (8 bytes each, zero-padded)."""
    result = []
    for i in range(3):
        chunk = domain[i*8:(i+1)*8] if i*8 < len(domain) else b''
        chunk = chunk.ljust(8, b'\x00')
        result.append(field_reduce(int.from_bytes(chunk, 'little')))
    return result

def hash_qsmt_node(children: list[bytes]) -> bytes:
    """
    QSMT node hash: poseidon2_hash_chained([domain(3 fields), child0(4), child1(4), child2(4), child3(4)]).
    Returns QSMT_EMPTY_ROOT if all children are zero. [smt_quaternary.rs hash_qsmt_node]
    """
    assert len(children) == QSMT_ARITY
    if all(c == QSMT_EMPTY_ROOT for c in children):
        return QSMT_EMPTY_ROOT

    inp: list[int] = _domain_to_3_fields(DOMAIN_SMT_ACTIVE)
    for child in children:
        for j in range(4):
            chunk = child[j*8:(j+1)*8]
            inp.append(field_reduce(int.from_bytes(chunk, 'little')))

    out = poseidon2_hash_chained(inp)
    # Convert [u64;4] back to bytes32
    result = bytearray(32)
    for i in range(4):
        result[i*8:(i+1)*8] = (out[i] & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little')
    return bytes(result)

LEAF_MARKER: int = field_reduce(int.from_bytes(b"leaf\x00\x00\x00\x00", 'little'))

def hash_qsmt_leaf(nullifier: bytes, epoch_id: int) -> bytes:
    """
    QSMT leaf hash: poseidon2_hash_chained([domain(3), "leaf"(1), nullifier(4), epoch(1)]).
    [smt_quaternary.rs hash_qsmt_leaf]
    """
    assert len(nullifier) == 32
    inp: list[int] = _domain_to_3_fields(DOMAIN_SMT_ACTIVE)
    inp.append(LEAF_MARKER)
    for j in range(4):
        chunk = nullifier[j*8:(j+1)*8]
        inp.append(field_reduce(int.from_bytes(chunk, 'little')))
    inp.append(field_reduce(epoch_id))
    out = poseidon2_hash_chained(inp)
    result = bytearray(32)
    for i in range(4):
        result[i*8:(i+1)*8] = (out[i] & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little')
    return bytes(result)

def qsmt_child_index_at(key: bytes, level: int) -> int:
    """Get 2-bit child index at given level. [smt_quaternary.rs child_index_at]"""
    bit_offset = level * QSMT_BITS_PER_LEVEL
    byte_idx = bit_offset // 8
    bit_in_byte = bit_offset % 8
    if byte_idx >= 32:
        return 0
    val = key[byte_idx]
    if bit_in_byte + QSMT_BITS_PER_LEVEL <= 8:
        return (val >> bit_in_byte) & 0x3
    # Spans two bytes
    lo = (val >> bit_in_byte) & ((1 << (8 - bit_in_byte)) - 1)
    hi = key[byte_idx + 1] & ((1 << (QSMT_BITS_PER_LEVEL - (8 - bit_in_byte))) - 1)
    return lo | (hi << (8 - bit_in_byte))
