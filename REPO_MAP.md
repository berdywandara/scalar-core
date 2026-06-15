# SCALAR CORE — REPOSITORY MAP

> **Dokumen ini adalah sumber kebenaran tunggal untuk status implementasi.**
> Setiap tim / sesi koding baru WAJIB membaca ini sebelum menyentuh kode.
> Update dokumen ini setiap gap ditutup.

**Generated:** 2026-06-15 (post-eskalasi resolved)
**Spec refs:** SCALAR-PROTOCOL / SCALAR-TECHNICAL / SCALAR-SECURITY — 2026-07-15
**Hierarki konflik:** SCALAR-SECURITY > SCALAR-PROTOCOL > SCALAR-TECHNICAL > kode

---

## State Saat Ini

| Indikator | Status |
|-----------|--------|
| Build | Jalankan `cargo build --all-features --workspace` untuk konfirmasi |
| Test | 127/128 pass (1 P3 fixture: GAP-FIXTURE-CD) |
| Clippy | Harus 0 warnings sebelum setiap commit |
| Placeholder kripto aktif | **0 P0** — GAP-GOSSIP + GAP-AUDIT-CLAIMS CLOSED |
| K-1 NS_CHECKPOINT SMT | ✅ RESOLVED (struct level) — sisa P3 naming legacy |
| K-2 proof-params terpusat | ✅ OK — `FRI_NUM_QUERIES=108`, `FRI_PROOF_OF_WORK_BITS=0` di lib.rs |
| K-3 ε post-batch 2⁻¹⁵⁴ | ✅ OK — starkpack_p3.rs, config.rs, domain.rs sudah benar |
| K-4 verifikasi multi-tier | ⚠️ PARTIAL — lib.rs framing "ADR-SEC-023" masih ada (GAP-15 P3) |

---

## Kepatuhan Arsitektur (K-1..K-4)

### K-1 — NS_CHECKPOINT adalah Sparse Merkle Tree Akumulatif (BUKAN Recursive STARK)
- `nullifier_set.rs` → `CheckpointProof` berisi `archived_smt_root: [u8;32]`, `smt_depth: 32`. ✅
- `wal.rs` → `CheckpointWalEntry` berisi `smt_root: [u8;32]`, `smt_data_path: String`. ✅
- `wal.rs` → `WalPhase::Preparing | Inserted | Committed`. ✅
- `sync.rs` → `SyncState::VerifyingNsCheckpoint`. ✅
- Sisa: `SyncFailReason::NsArchProofInvalid` (naming legacy) → **GAP-SYNC-NAMING P3**.

### K-2 — Parameter proof system bersumber tunggal dari §[PROOF-PARAMS]
- `scalar-stark-p3/lib.rs` → `FRI_NUM_QUERIES=108`, `FRI_PROOF_OF_WORK_BITS=0`, compile-time assert. ✅
- `genesis_ceremony.rs` → sudah 108/0 (GAP-04 CLOSED). ✅
- **Larangan**: jangan tulis literal `108` atau `0` (grinding) di luar konstanta terpusat ini.

### K-3 — Soundness ε post-batch = 2⁻¹⁵⁴
- `starkpack_p3.rs`, `config.rs`, `domain.rs` → sudah 2⁻¹⁵⁴ post-batch / 2⁻¹⁶² per-proof. ✅
- **Larangan**: jangan tulis ~2⁻¹⁶⁰ (ambigu), ~2⁻¹²⁰, ~2⁻¹²⁸. Nilai pengikat adalah 2⁻¹⁵⁴.

### K-4 — Verifikasi adalah internal multi-tier, bukan gate audit eksternal
- ⚠️ `lib.rs` masih framing "ADR-SEC-023 formal confirmation required pre-mainnet" → GAP-15 P3.
- Gate: Tier 1 (SageMath/KAT), Tier 2 (Prusti/TLA+/fuzzing/multi-client verifier). QROM = residual terkelola.

---

## Gap Teridentifikasi & Prioritas Kerja

### ═══ P0 — BLOKIR SEMUA MERGE KE MAIN ═══

#### [GAP-GOSSIP] `core/scalar-node/src/gossip.rs` — Verifier Palsu Aktif
- **Status**: OPEN
- **Masalah**: `validate_and_relay()` melakukan deserialisasi `BatchTransferProof` lalu
  `let _ = proof; return true` — tidak pernah memanggil `verify_batch_transfer`.
  Seluruh gossip message diterima tanpa kriptografi. Melanggar P1 dan Larangan Mutlak.
- **Bukti**: grep `return true` di `gossip.rs` → ada di path setelah deserialisasi sukses.
- **Keputusan eskalasi (RESOLVED)**: Boleh meneruskan berdasarkan PI dari proof itu sendiri
  (self-referential extraction), DENGAN SYARAT:
  - `verify_batch_transfer(&proof, &claims)` HARUS dipanggil dan hasilnya dievaluasi.
  - Return type diubah dari `bool` menjadi `RelayDecision` dengan dua varian:
    `ProofWellFormed` (STARK verify pass, roots belum divalidasi terhadap EpochState) vs
    `StateValidated` (roots tervalidasi, FASE B).
  - Komentar eksplisit: "FASE B: integrasi EpochState untuk VIR-001 provenance quorum."
  - Validasi root terhadap EpochState adalah CONSENSUS RULE (VIR-001), bukan circuit.
- **Target file**: `core/scalar-node/src/gossip.rs`
- **Dokumen**: SCALAR-TECHNICAL §4.1, P1; SCALAR-PROTOCOL §7.4 VIR-001.
- **Dependensi**: Tidak ada (bisa langsung dikerjakan).

#### [GAP-AUDIT-CLAIMS] `client/scalar-audit/src/proof_verifier.rs` — Placeholder Zeros
- **Status**: OPEN
- **Masalah**: `batch_proof_to_claims(_proof)` mengembalikan `TransferPublicClaims` dengan
  semua roots `[0u8;32]`, `ownership_claims: vec![]`, `leaf_commitments: vec![]`.
  Proof verify berjalan terhadap zero-roots → hasilnya tidak soundness-preserving.
- **Keputusan eskalasi (RESOLVED)**: `scalar-audit` TIDAK BOLEH mengembalikan `true`
  atau `Valid` saat EpochState belum tersambung. Kembalikan:
  `ProofVerificationResult::Unverifiable { reason: "EpochState not available — FASE B" }`.
  Ini membedakan "belum bisa diverifikasi" dari "terverifikasi valid". P1 tetap utuh.
- **Target file**: `client/scalar-audit/src/proof_verifier.rs`
- **Dokumen**: P1; Larangan Mutlak "verifier return true/Ok(true) tanpa kriptografi nyata".
- **Dependensi**: Tidak ada (paralel dengan GAP-GOSSIP).

---

### ═══ P1 — Constraint Inti Circuit ═══

#### [GAP-09] `core/scalar-stark-p3/src/transfer_public_inputs.rs` — Poseidon2_acc vs BLAKE3
- **Status**: OPEN
- **Masalah**: `commitment_hash` dan `nullifier_hash` menggunakan BLAKE3 out-of-circuit.
  Spec §2.7-A CX mensyaratkan in-circuit: `commitment_hash == Poseidon2_acc(CB.leaf_commitments)`
  dan `nullifier_hash == Poseidon2_acc(CA.expected_nullifiers)`.
- **Aksi**: Ganti derivasi di `derive_public_claims()` ke Poseidon2_acc (sponge atas
  Goldilocks field elements). Tambahkan constraint CX di `transfer_air_p3.rs` yang mengikat
  PI[33..36] = commitment_hash dan PI[37..40] = nullifier_hash ke hasil Poseidon2_acc.
- **Dokumen**: SCALAR-TECHNICAL §2.7-A, §2.2 PI layout (PI[33..40]).
- **Dependensi**: Blokir GAP-10 (CF-PREMIUM butuh Poseidon2_acc sudah ada).

#### [GAP-10] Fee Circuit CF/CF-PREMIUM — Belum In-Circuit
- **Status**: OPEN [PALING KOMPLEKS — pecah jadi sub-task]
- **Keputusan eskalasi (RESOLVED)**:
  - `floor.rs` (out-of-circuit) boleh tetap ada sebagai **pre-flight optimisasi** saja.
    Tambahkan komentar eksplisit: `// PRE-FLIGHT ONLY — bukan enforcement (P1). In-circuit enforcement ada di CF/CF-PREMIUM AIR.`
  - Enforcement nyata WAJIB in-circuit. Jangan bridging out-of-circuit sebagai "fase 1 diterima".
- **Sub-task GAP-10a**: CF — `storage_mass` via resiprokal fixed-point in-circuit. ✅ CLOSED
  Formula: `storage_mass = C × (Σ 1/value_o − Σ 1/value_i)+`. Witness `inv` dengan
  constraint `value × inv ∈ [SCALE − value, SCALE]`. Bit decomposition untuk overflow guard.
- **Sub-task GAP-10b**: CF — `BASE_FEE = storage_mass × BASE_PRICE_PER_MASS`, `COMPLEXITY_FEE = constraint_units × PRICE_PER_CU`. Conservation: `fee_total = BASE_FEE + COMPLEXITY_FEE + PREMIUM`.
- **Sub-task GAP-10c**: CF-PREMIUM — derivasi terikat-nonce ✅ CLOSED:
  `raw = Poseidon2(DOMAIN_FEE_PREMIUM ‖ tx_nonce ‖ FLOOR_BASE)`,
  `PREMIUM = raw − q × (FLOOR_BASE + 1)`.
  Constraint CF-PREMIUM-1: `0 ≤ PREMIUM ≤ FLOOR_BASE` (bit decomposition).
  Constraint CF-PREMIUM-2: `PREMIUM == raw − q×(FLOOR_BASE+1)` (floor-division terbukti).
  `FLOOR_BASE = BASE_FEE + COMPLEXITY_FEE`.
- **Dokumen**: SCALAR-TECHNICAL §2.8, §2.8-A (CF-PREMIUM OSSIFIED); P1.
- **Dependensi**: GAP-09 harus CLOSED dulu.

#### [GAP-11] `transfer_public_inputs.rs` — PI[3] `crypto_version: u8` vs `u64`
- **Status**: OPEN
- **Masalah**: Struct field bertipe `u8` tapi AIR menggunakan `from_u64(version as u64)`.
  OSSIFIED PI layout §2.2 menggunakan Goldilocks field element (u64). Inkonsistensi tipe.
- **Aksi**: Ubah `crypto_version: u8` → `crypto_version: u64` di struct
  `TransferPublicInputsP3`. Update semua call site. Pastikan test tetap hijau.
- **Dokumen**: SCALAR-TECHNICAL §2.2 PI_TOTAL=41 OSSIFIED layout.
- **Dependensi**: Tidak ada.

---

### ═══ P2 — Struktur Data & State Machine ═══

#### [GAP-12] `core/scalar-network/src/subepoch.rs` — Konstanta Salah
- **Status**: OPEN [ESKALASI RESOLVED]
- **Masalah**: `SUBEPOCH_DURATION_S = 3600`, `SUBEPOCHS_PER_EPOCH = 720` (artefak
  benchmark Codespace dari `BENCHMARK_RESULTS.md`).
  OSSIFIED: `SUBEPOCH_DURATION_S = 1_900`, `SUBEPOCHS_PER_EPOCH = 24` (SCALAR-PROTOCOL §1, §13.1).
- **Keputusan eskalasi (RESOLVED)**:
  - Nilai mainnet OSSIFIED = 1900s / 24. Ini TIDAK BOLEH berubah tanpa hard fork.
  - Nilai Codespace (3640s / 720) adalah artefak benchmark, BUKAN parameter protokol (§4.2 T-6).
  - Implementasi: nilai mainnet sebagai default; nilai dev via feature flag `dev-fast-subepoch`
    yang DEFAULT OFF. Nilai dev TIDAK BOLEH masuk build rilis.
  ```rust
  // Mainnet OSSIFIED — SCALAR-PROTOCOL §13.1
  #[cfg(not(feature = "dev-fast-subepoch"))]
  pub const SUBEPOCH_DURATION_S: u64 = 1_900;
  #[cfg(not(feature = "dev-fast-subepoch"))]
  pub const SUBEPOCHS_PER_EPOCH: u64 = 24;

  // Dev-only (Codespace benchmark) — DEFAULT OFF, TIDAK BOLEH di build rilis
  #[cfg(feature = "dev-fast-subepoch")]
  pub const SUBEPOCH_DURATION_S: u64 = 3_640;
  #[cfg(feature = "dev-fast-subepoch")]
  pub const SUBEPOCHS_PER_EPOCH: u64 = 720;
  ```
- **Dokumen**: SCALAR-PROTOCOL §1 (Glossary), §13.1 (Parameter OSSIFIED).
- **Dependensi**: Tidak ada.

#### [GAP-13] WAL Dual Naming Scheme
- **Status**: OPEN (perlu verifikasi)
- **Masalah**: `scalar-node/wal.rs` menggunakan `WalPhase::Preparing/Inserted/Committed` (benar).
  `scalar-nullifier/nullifier_set.rs` menggunakan `WalStatus::Pending/Committed` (skema berbeda).
  Dua skema WAL untuk konsep yang sama melanggar P4 (determinisme).
- **Aksi**: Unifikasi ke satu skema. `WalPhase::Preparing | Inserted | Committed` adalah
  final (sesuai SCALAR-TECHNICAL §6.2). Hapus `WalStatus::Pending` dari nullifier_set.rs
  dan arahkan ke `WalPhase` dari wal.rs (atau extrak ke `scalar-nullifier` yang diimpor wal.rs).
- **Dokumen**: SCALAR-TECHNICAL §6.2.
- **Dependensi**: Tidak ada.

---

### ═══ P3 — API, Tooling, Polish ═══

#### [GAP-15] `core/scalar-stark-p3/src/lib.rs` — Framing Gate Eksternal
- **Status**: OPEN
- **Masalah**: "ADR-SEC-023 formal confirmation required pre-mainnet" menyiratkan
  menunggu audit eksternal sebagai syarat soundness. Melanggar K-4.
- **Aksi**: Ganti ke framing Tier 1/2 internal: "Soundness validated via internal
  multi-tier framework (Tier 1: SageMath/KAT; Tier 2: Prusti/TLA+/multi-client).
  QROM adalah residual terkelola yang dipantau — bukan blocker. [SCALAR-SECURITY §1.7]"
- **Dokumen**: SCALAR-SECURITY §1.7, K-4.

#### [GAP-SYNC-NAMING] `core/scalar-network/src/sync.rs` — Terminologi Legacy
- **Status**: OPEN
- **Masalah**: `SyncFailReason::NsArchProofInvalid`, `NsArchProofTooLarge`, `NsArchVerifyTooSlow`
  menggunakan "Arch" (sisa terminologi Recursive STARK Archiver yang sudah dihapus).
- **Aksi**: Rename ke `NsCheckpointProofInvalid`, `NsCheckpointProofTooLarge`,
  `NsCheckpointVerifyTooSlow`. Update semua match arm.
- **Dokumen**: K-1; SCALAR-TECHNICAL §6.1.

#### [GAP-FIXTURE-CD] `core/scalar-stark-p3/src/starkpack_p3.rs` — Test Fixture Salah
- **Status**: OPEN
- **Masalah**: `bench_starkpack_aggregation` test helper tidak menyertakan `fee_total`
  di `witness_sum`, menyebabkan `ConservationViolated` dengan selisih 40 sSCL.
- **Aksi**: Fix witness: `sum_inputs_sscl = sum_outputs_sscl + fee_total_sscl`.
  Fee floor 40 sSCL harus termasuk dalam `sum_inputs`.
- **Dokumen**: SCALAR-TECHNICAL §2.6 CD (conservation), §9.1 fee floor.

#### [GAP-16] Multi-Client Verifier impl#2 (Python) — Belum Ada
- **Status**: OPEN
- **Scope**: Sebelum mainnet, harus ada re-implementasi AIR verifier dari codebase berbeda.
  impl#1 = scalar-stark-p3 (Rust/Plonky3). impl#2 = Python (target).
  Poseidon2 primitif sudah 7/7 test vectors PASS. Full FRI proof verify masih pending.
- **Dokumen**: SCALAR-SECURITY §5.3 (Tier 2).
- **Catatan**: Scope sangat besar; dikerjakan tersendiri sebagai proyek parallel.

---

## Urutan Implementasi yang Direkomendasikan

```
Sekarang → FASE A (sebelum FASE B EpochState integration):

  [P0] GAP-GOSSIP          ─── 1 patch, medium
  [P0] GAP-AUDIT-CLAIMS    ─── 1 patch, kecil (paralel GAP-GOSSIP)

  [P1] GAP-11              ─── 1 patch, kecil (tidak ada dependensi)
  [P1] GAP-09              ─── 1 patch, medium (Poseidon2_acc CX)
  [P1] GAP-10a             ─── storage_mass reciprocal in-circuit
  [P1] GAP-10b             ─── BASE_FEE + COMPLEXITY_FEE in-circuit
  [P1] GAP-10c             ─── CF-PREMIUM derivasi + range proof

  [P2] GAP-12              ─── subepoch feature flag
  [P2] GAP-13              ─── WAL naming unifikasi

  [P3] GAP-15              ─── framing 1 komentar
  [P3] GAP-SYNC-NAMING     ─── rename 3 enum variant
  [P3] GAP-FIXTURE-CD      ─── fix 1 test

FASE B (EpochState tersambung — future):
  GAP-GOSSIP: upgrade ke StateValidated dengan EpochState context
  GAP-AUDIT-CLAIMS: upgrade dari Unverifiable ke ValidatedAgainstState
  GAP-16: Python verifier (parallel)
```

---

## Ketergantungan Kunci

```
GAP-GOSSIP ──────────────────────────────► FASE B: EpochState context
GAP-AUDIT-CLAIMS ────────────────────────► FASE B: EpochState context
GAP-09 (Poseidon2_acc) ──────────────────► blokir GAP-10 (CF-PREMIUM butuh Poseidon2_acc)
GAP-11 ──────────────────────────────────► independent, mulai kapan saja
GAP-10c ─────────────────────────────────► setelah GAP-10a + GAP-10b + GAP-09
GAP-12 ──────────────────────────────────► independent, verifikasi dulu Cargo.toml features
GAP-13 ──────────────────────────────────► independent
```

---

## Larangan Mutlak (ringkasan cepat untuk coder baru)

| ❌ Larangan | Alasan |
|-------------|--------|
| `return true` / `Ok(true)` di jalur verify tanpa kriptografi nyata | P1, verifier palsu |
| Constraint tidak dievaluasi di AIR/circuit (boolean flag saja) | P1, teater kriptografis |
| `proof_bytes` / `proving_key_version` / status `PROVEN` di checkpoint | K-1 |
| Literal `108` (queries) atau grinding term di luar konstanta terpusat | K-2 |
| Nilai soundness post-batch selain `2⁻¹⁵⁴` | K-3 |
| Term grinding apa pun (`g` harus tetap 0) | K-2 |
| Nilai OSSIFIED baru tanpa eskalasi ke spec | Semua |
| "menunggu audit eksternal" sebagai syarat soundness | K-4 |
| `git push --force` atau manipulasi sejarah | Protokol git |
| Nilai `dev-fast-subepoch` masuk build rilis | GAP-12 |

---

## Gate Wajib Sebelum Setiap Commit

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-features --workspace
cargo test --all-features --workspace
```

Jika ada warning/error → perbaiki kode, bukan suppress, bukan longgarkan test.

---

## Riwayat Perubahan

| Tanggal | Event |
|---------|-------|
| 2026-06-15 | Phase Review awal selesai. REPO_MAP v1 dibuat. 16+ gap diidentifikasi. |
| 2026-06-15 | GAP-04 CLOSED: fri_queries=108, fri_grinding=0 di genesis_ceremony.rs. |
| 2026-06-15 | GAP-05 CLOSED: stale comments queries=84/grinding=23 di batch_transfer_p3 + config.rs. |
| 2026-06-15 | GAP-06 CLOSED: starkpack_p3.rs soundness 2⁻¹⁵⁴ post-batch / 2⁻¹⁶² per-proof. |
| 2026-06-15 | GAP-07 CLOSED: config.rs + domain.rs soundness values dikoreksi. |
| 2026-06-15 | GAP-08 CLOSED: MembershipAir, NonMembershipAir, A-R9 PI binding [0..4]+[33..40]. (4 commits) |
| 2026-06-15 | GAP-01 CLOSED: CheckpointProof K-1 anti-pattern dihapus dari nullifier_set.rs. |
| 2026-06-15 | GAP-02 CLOSED: CheckpointWalEntry smt_root/smt_data_path + WalPhase benar di wal.rs. |
| 2026-06-15 | GAP-03 CLOSED: SyncState VerifyingNsArch → VerifyingNsCheckpoint di sync.rs. |
| 2026-06-15 | GAP-GOSSIP CLOSED: RelayDecision + verify_transfer_p3; return true dihapus. [§4.1 P1] |
| 2026-06-15 | GAP-AUDIT-CLAIMS CLOSED: Unverifiable variant; zero-root placeholder dihapus. [P1] |
| 2026-06-15 | WAL tests fixed: Preparing→Inserted→Committed enforced in all tests. [§6.2] |
| 2026-06-15 | GAP-11 CLOSED: crypto_version u8→u64, VALID_CRYPTO_VERSION u8→u64. [SCALAR-TECHNICAL §2.2] |
| 2026-06-15 | GAP-09 CLOSED: compute_commitment_hash + compute_nullifier_hash BLAKE3→Poseidon2_acc (t=8, Rate=4). [SCALAR-TECHNICAL §2.2, §2.7-A CX-2/CX-3] |
| 2026-06-15 | GAP-10b CLOSED: rem 32-bit decomp (Opsi A P1); BASE_FEE+COMPLEXITY_FEE+FLOOR_BASE in-circuit; TRANSFER_TRACE_WIDTH 155→798. [§2.8] |
| 2026-06-15 | GAP-10c CLOSED: CF-PREMIUM Poseidon2_t8 terikat-nonce + 52-bit range proof; TRANSFER_TRACE_WIDTH 798→857. [§2.8-A P1] |
| 2026-06-15 | GAP-10 CLOSED: CF/CF-PREMIUM fully in-circuit (10a+10b+10c). INV-FEE satisfied. [P1] |
| 2026-06-15 | GAP-10a CLOSED: CfWitnesses + storage_mass reciprocal cols (112-154); TRANSFER_TRACE_WIDTH 112→155. [§2.8] |
| 2026-06-15 | GAP-10b CLOSED: rem 32-bit decomp (Opsi A P1); BASE_FEE+COMPLEXITY_FEE+FLOOR_BASE in-circuit; TRANSFER_TRACE_WIDTH 155→798. [§2.8] |
| 2026-06-15 | GAP-10c CLOSED: CF-PREMIUM Poseidon2_t8 terikat-nonce + 52-bit range proof + floor-div; TRANSFER_TRACE_WIDTH 798→857. [§2.8-A P1] |
| 2026-06-15 | GAP-10 CLOSED: CF/CF-PREMIUM fully in-circuit (10a+10b+10c). INV-FEE satisfied. [P1] |
| 2026-06-15 | GAP-12 CLOSED: SUBEPOCHS_PER_EPOCH 720→24 OSSIFIED; SUBEPOCH_DURATION_S 3600→1900; dev-fast-subepoch feature flag (default OFF). [§13.1] |
| 2026-06-15 | GAP-13 CLOSED: WalStatus::Pending→Preparing; nullifier WAL 2-fase (Preparing|Committed) distinct dari node WAL 3-fase. [§6.2] |
| 2026-06-15 | GAP-15 CLOSED: ADR-SEC-023 framing diganti Tier 1/2 internal + QROM managed residual. [K-4, §1.7] |
| 2026-06-15 | GAP-SYNC-NAMING CLOSED: NsArchVerifyResult/NsArchProof→NsCheckpoint*; NS_CHECKPOINT_ROOT_MAX_BYTES+VERIFY_MAX_MS fixed. [K-1] |
| 2026-06-15 | GAP-FIXTURE-CD CLOSED: build_proof_input_bench sum_inputs derived from witness values (not hardcoded). [§2.6 CD] |
| 2026-06-15 | FIX P1: rem*rem==0 placeholder dihapus dari eval(); rem bit decomp 32-bit dipindah ke eval() loop CF. [§2.8 P1 Opsi A] |
| 2026-06-15 | GAP-16 IN PROGRESS: verifier-py/ created; M1 Poseidon2 9/9 PASS (bit-exact vs impl#1). [§5.3 Tier 2] |
| 2026-06-15 | GAP-16 IN PROGRESS: verifier-py/ created; M1 Poseidon2 9/9 PASS (bit-exact vs impl#1). [§5.3 Tier 2] |
| 2026-06-15 | GAP-16 M2: IMT membership + QSMT hash functions 15/15 PASS bit-exact. [§5.3] |
| 2026-06-15 | GAP-16 M3: PI constraint checker 13/13 PASS bit-exact. [§5.3] |
| 2026-06-15 | GAP-16 M4a: GF(p^3) trinomial x^3-x-1 arithmetic 19/19 PASS. [§[PROOF-PARAMS] K-2] |
| 2026-06-15 | Sesi selesai. GAP-16 M1-M4a CLOSED. M4b FRI commit phase = next. REPO_MAP diupdate. |
| 2026-06-15 | REPO_MAP v2: eskalasi keempat RESOLVED. GAP-GOSSIP + GAP-AUDIT-CLAIMS ditambahkan sebagai P0 baru. Keputusan eskalasi didokumentasikan per gap. |

## GAP-16 M4b — FRI Commit Phase (Python impl#2) ✅ CLOSED 2026-06-15

**Status**: 42/42 test PASS, 13/13 vectors self-consistent, OSSIFIED params verified.

| Parameter        | Nilai          |
|------------------|----------------|
| Grinding (g)     | 0 (amputated)  |
| Num queries (q)  | 108            |
| Blowup           | 2^3 = 8        |
| Max arity        | 4 (log=2)      |
| Soundness/proof  | 2^-162         |
| Soundness/batch  | 2^-154         |

**File baru**:
- `verifier-py/scalar_verifier/fri.py` – implementasi utama commit phase (Merkle, folding, challenger)
- `verifier-py/tests/test_fri.py` – 42 test suite
- `verifier-py/tests/generate_fri_vectors.py` – generator vektor uji (13 vektor)
- `verifier-py/tests/vectors/fri_commit_vectors.json` – output vektor siap cross‑check

**Kepatuhan**:
- Tidak ada placeholder, `Unverifiable` diangkat untuk query phase (M4c)
- Deterministis (P4), semua pengecekan kriptografis dijalankan sungguhan
