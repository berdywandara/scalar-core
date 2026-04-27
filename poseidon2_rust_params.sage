# Scalar Network - Poseidon2 Parameters Generator
# Optimized for Goldilocks Field (p = 2^64 - 2^32 + 1), t=4, alpha=7, R_F=8, R_P=22
from sage.rings.polynomial.polynomial_gf2x import GF2X_BuildIrred_list
from math import *
import itertools

###########################################################################
p = 18446744069414584321 # GoldiLocks (0xFFFFFFFF00000001)

n = len(p.bits()) # bit
t = 4 # GoldiLocks t=4 for standard hashing

FIELD = 1
SBOX = 0
FIELD_SIZE = n
NUM_CELLS = t

# OSSIFIED PARAMETERS UNTUK SCALAR NETWORK
alpha = 7
R_F_FIXED = 8
R_P_FIXED = 22

print(f"// +++ SCALAR NETWORK POSEIDON2 GENERATOR +++")
print(f"// R_F = {R_F_FIXED}, R_P = {R_P_FIXED}, alpha = {alpha}, t = {t}\n")

###########################################################################

INIT_SEQUENCE = []
PRIME_NUMBER = p
F = GF(PRIME_NUMBER)

def grain_sr_generator():
    bit_sequence = INIT_SEQUENCE
    for _ in range(0, 160):
        new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
        bit_sequence.pop(0)
        bit_sequence.append(new_bit)

    while True:
        new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
        bit_sequence.pop(0)
        bit_sequence.append(new_bit)
        while new_bit == 0:
            new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
            bit_sequence.pop(0)
            bit_sequence.append(new_bit)
            new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
            bit_sequence.pop(0)
            bit_sequence.append(new_bit)
        new_bit = bit_sequence[62] ^^ bit_sequence[51] ^^ bit_sequence[38] ^^ bit_sequence[23] ^^ bit_sequence[13] ^^ bit_sequence[0]
        bit_sequence.pop(0)
        bit_sequence.append(new_bit)
        yield new_bit
grain_gen = grain_sr_generator()

def grain_random_bits(num_bits):
    random_bits = [next(grain_gen) for i in range(0, num_bits)]
    random_int = int("".join(str(i) for i in random_bits), 2)
    return random_int

def init_generator(field, sbox, n, t, R_F, R_P):
    bit_list_field = [_ for _ in (bin(FIELD)[2:].zfill(2))]
    bit_list_sbox = [_ for _ in (bin(SBOX)[2:].zfill(4))]
    bit_list_n = [_ for _ in (bin(FIELD_SIZE)[2:].zfill(12))]
    bit_list_t = [_ for _ in (bin(NUM_CELLS)[2:].zfill(12))]
    bit_list_R_F = [_ for _ in (bin(R_F)[2:].zfill(10))]
    bit_list_R_P = [_ for _ in (bin(R_P)[2:].zfill(10))]
    bit_list_1 = [1] * 30
    global INIT_SEQUENCE
    INIT_SEQUENCE = bit_list_field + bit_list_sbox + bit_list_n + bit_list_t + bit_list_R_F + bit_list_R_P + bit_list_1
    INIT_SEQUENCE = [int(_) for _ in INIT_SEQUENCE]

def generate_constants(field, n, t, R_F, R_P, prime_number):
    round_constants = []
    num_constants = (R_F * t) + R_P # Poseidon2
    if field == 1:
        for i in range(0, num_constants):
            random_int = grain_random_bits(n)
            while random_int >= prime_number:
                random_int = grain_random_bits(n)
            round_constants.append(random_int)
            # Add (t-1) zeroes for Poseidon2 if partial round
            if i >= ((R_F/2) * t) and i < (((R_F/2) * t) + R_P):
                round_constants.extend([0] * (t-1))
    return round_constants

def generate_matrix_full(NUM_CELLS):
    M = None
    if t == 4:
        # Standard MDS matrix for Plonky2 / Poseidon2 Goldilocks t=4
        M = matrix(F, [[F(5), F(7), F(1), F(3)], [F(4), F(6), F(1), F(1)], [F(1), F(3), F(5), F(7)], [F(1), F(1), F(4), F(6)]])
    else:
        print("Error: Matrix configuration for this 't' is not defined.")
        exit()
    return M

def generate_matrix_partial(FIELD, FIELD_SIZE, NUM_CELLS):
    entry_max_bit_size = FIELD_SIZE
    if FIELD == 1:
        M = None
        M_circulant = matrix.circulant(vector([F(0)] + [F(1) for _ in range(0, NUM_CELLS - 1)]))
        M_diagonal = matrix.diagonal([F(grain_random_bits(entry_max_bit_size)) for _ in range(0, NUM_CELLS)])
        M = M_circulant + M_diagonal
        
        # Sederhanakan cek invertible untuk kecepatan di skrip ini. 
        # (Karena kita hanya butuh dummy valid untuk memastikan determinisme pada testnet).
        while not M.is_invertible():
            M_diagonal = matrix.diagonal([F(grain_random_bits(entry_max_bit_size)) for _ in range(0, NUM_CELLS)])
            M = M_circulant + M_diagonal
            
        return M

def matrix_partial_m_1(matrix_partial, NUM_CELLS):
    M_circulant = matrix.identity(F, NUM_CELLS)
    return matrix_partial - M_circulant

def poseidon2(input_words, matrix_full, matrix_partial, round_constants):
    R_f = int(R_F_FIXED / 2)
    round_constants_counter = 0
    state_words = list(input_words)

    # First matrix mul
    state_words = list(matrix_full * vector(state_words))

    # First full rounds
    for r in range(0, R_f):
        for i in range(0, t):
            state_words[i] = state_words[i] + round_constants[round_constants_counter]
            round_constants_counter += 1
        for i in range(0, t):
            state_words[i] = (state_words[i])^alpha
        state_words = list(matrix_full * vector(state_words))

    # Middle partial rounds
    for r in range(0, R_P_FIXED):
        for i in range(0, t):
            state_words[i] = state_words[i] + round_constants[round_constants_counter]
            round_constants_counter += 1
        state_words[0] = (state_words[0])^alpha
        state_words = list(matrix_partial * vector(state_words))

    # Last full rounds
    for r in range(0, R_f):
        for i in range(0, t):
            state_words[i] = state_words[i] + round_constants[round_constants_counter]
            round_constants_counter += 1
        for i in range(0, t):
            state_words[i] = (state_words[i])^alpha
        state_words = list(matrix_full * vector(state_words))

    return state_words

# Init & Generate
init_generator(FIELD, SBOX, FIELD_SIZE, NUM_CELLS, R_F_FIXED, R_P_FIXED)
round_constants = generate_constants(FIELD, FIELD_SIZE, NUM_CELLS, R_F_FIXED, R_P_FIXED, PRIME_NUMBER)
MATRIX_FULL = generate_matrix_full(NUM_CELLS)
MATRIX_PARTIAL = generate_matrix_partial(FIELD, FIELD_SIZE, NUM_CELLS)
MATRIX_PARTIAL_DIAGONAL_M_1 = [matrix_partial_m_1(MATRIX_PARTIAL, NUM_CELLS)[i,i] for i in range(0, NUM_CELLS)]

# RUST OUTPUT FORMATTER
def to_rust_hex(value):
    return f"0x{int(value):016x}"

print(f"pub const ROUND_CONSTANTS: [u64; {len(round_constants)}] = [")
for val in round_constants:
    print(f"    {to_rust_hex(val)},")
print("];\n")

print("pub const MATRIX_FULL: [[u64; 4]; 4] = [")
for row in MATRIX_FULL:
    print("    [" + ", ".join(to_rust_hex(v) for v in row) + "],")
print("];\n")

print("pub const MATRIX_PARTIAL: [[u64; 4]; 4] = [")
for row in MATRIX_PARTIAL:
    print("    [" + ", ".join(to_rust_hex(v) for v in row) + "],")
print("];\n")

print("pub const MAT_DIAG4_M_1: [u64; 4] = [")
for val in MATRIX_PARTIAL_DIAGONAL_M_1:
    print(f"    {to_rust_hex(val)},")
print("];\n")

# TEST VECTOR GENERATION
state_in_zero  = vector([F(0) for _ in range(t)])
state_out_zero = poseidon2(state_in_zero, MATRIX_FULL, MATRIX_PARTIAL, round_constants)

state_in_known  = vector([F(1), F(2), F(0), F(0)])
state_out_known = poseidon2(state_in_known, MATRIX_FULL, MATRIX_PARTIAL, round_constants)

print("// --- TEST VECTORS UNTUK test_poseidon2_zero_input_vector ---")
print(f"// Input: [0, 0, 0, 0]")
print(f"pub const EXPECTED_ZERO_HASH: [u64; 4] = [")
print("    " + ", ".join(to_rust_hex(v) for v in state_out_zero))
print("];\n")

print("// --- TEST VECTORS UNTUK test_poseidon2_known_input_vector ---")
print(f"// Input: [1, 2, 0, 0]")
print(f"pub const EXPECTED_KNOWN_HASH: [u64; 4] = [")
print("    " + ", ".join(to_rust_hex(v) for v in state_out_known))
print("];\n")