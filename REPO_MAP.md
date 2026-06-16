# SCALAR CORE — REPOSITORY MAP

> **Dokumen ini adalah sumber kebenaran tunggal untuk status implementasi.**
> Setiap tim / sesi koding baru WAJIB membaca ini sebelum menyentuh kode.
> Update dokumen ini setiap gap ditutup.

**Generated:** 2026-06-15 (post-eskalasi resolved)
**Last rewrite:** 2026-06-16 (REPO_MAP cleanup: hapus duplikasi histori, fix encoding, M4c status)
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
| K-1 NS_CHECKPOINT SMT | RESOLVED (struct level) — sisa P3 naming legacy CLOSED |
| K-2 proof-params terpusat | OK — `FRI_NUM_QUERIES=108`, `FRI_PROOF_OF_WORK_BITS=0` di lib.rs |
| GAP-FRI-ARITY | CLOSED 2026-06-16 — max_log_arity 4->2, enforced log_arity<=2 per round, vektor di-regenerate |
| K-3 epsilon post-batch 2^-154 | OK — starkpack_p3.rs, config.rs, domain.rs sudah benar |
| K-4 verifikasi multi-tier | OK — GAP-15 CLOSED (framing ADR-SEC-023 sudah diganti) |

---

## Kepatuhan Arsitektur (K-1..K-4)

### K-1 — NS_CHECKPOINT adalah Sparse Merkle Tree Akumulatif (BUKAN Recursive STARK)
- `nullifier_set.rs` -> `CheckpointProof` berisi `archived_smt_root: [u8;32]`, `smt_depth: 32`. OK.
- `wal.rs` -> `CheckpointWalEntry` berisi `smt_root: [u8;32]`, `smt_data_path: String`. OK.
- `wal.rs` -> `WalPhase::Preparing | Inserted | Committed`. OK.
- `sync.rs` -> `SyncState::VerifyingNsCheckpoint`. OK.
- GAP-SYNC-NAMING (P3) CLOSED: legacy "Arch" naming sudah di-rename.

### K-2 — Parameter proof system bersumber tunggal dari §[PROOF-PARAMS]
- `scalar-stark-p3/lib.rs` -> `FRI_NUM_QUERIES=108`, `FRI_PROOF_OF_WORK_BITS=0`, compile-time assert. OK.
- `genesis_ceremony.rs` -> sudah 108/0 (GAP-04 CLOSED). OK.
- `verifier-py/scalar_verifier/proof_params.py` -> impl#2 single source, sama nilai. OK.
- **Larangan**: jangan tulis literal `108` atau `0` (grinding) di luar konstanta terpusat ini.

### K-3 — Soundness epsilon post-batch = 2^-154
- `starkpack_p3.rs`, `config.rs`, `domain.rs` -> sudah 2^-154 post-batch / 2^-162 per-proof. OK.
- `verifier-py/scalar_verifier/proof_params.py` -> SOUNDNESS_POST_BATCH_LOG2=-154, SOUNDNESS_PER_PROOF_LOG2=-162. OK.
- **Larangan**: jangan tulis ~2^-160 (ambigu), ~2^-120, ~2^-128. Nilai pengikat adalah 2^-154.

### K-4 — Verifikasi adalah internal multi-tier, bukan gate audit eksternal
- GAP-15 CLOSED: framing "ADR-SEC-023 formal confirmation required pre-mainnet" sudah diganti
  dengan framing Tier 1/2 internal di lib.rs.
- Gate: Tier 1 (SageMath/KAT), Tier 2 (Prusti/TLA+/fuzzing/multi-client verifier). QROM = residual terkelola.

---

## Gap Teridentifikasi & Prioritas Kerja

### === P0 — BLOKIR SEMUA MERGE KE MAIN ===

#### [GAP-GOSSIP] `core/scalar-node/src/gossip.rs` — Verifier Palsu Aktif
- **Status**: CLOSED
- **Masalah (historis)**: `validate_and_relay()` melakukan deserialisasi `BatchTransferProof` lalu
  `let _ = proof; return true` — tidak pernah memanggil `verify_batch_transfer`.
- **Resolusi**: `RelayDecision` dengan dua varian (`ProofWellFormed`, `StateValidated`);
  `verify_batch_transfer(&proof, &claims)` dipanggil dan hasilnya dievaluasi.
  Validasi root terhadap EpochState adalah CONSENSUS RULE (VIR-001) untuk FASE B, bukan circuit.
- **Dokumen**: SCALAR-TECHNICAL §4.1, P1; SCALAR-PROTOCOL §7.4 VIR-001.

#### [GAP-AUDIT-CLAIMS] `client/scalar-audit/src/proof_verifier.rs` — Placeholder Zeros
- **Status**: CLOSED
- **Masalah (historis)**: `batch_proof_to_claims(_proof)` mengembalikan `TransferPublicClaims` dengan
  semua roots `[0u8;32]`, `ownership_claims: vec![]`, `leaf_commitments: vec![]`.
- **Resolusi**: Mengembalikan `ProofVerificationResult::Unverifiable { reason: "EpochState not available — FASE B" }`
  saat EpochState belum tersambung, membedakan "belum bisa diverifikasi" dari "terverifikasi valid".
- **Dokumen**: P1; Larangan Mutlak "verifier return true/Ok(true) tanpa kriptografi nyata".

---

### === P1 — Constraint Inti Circuit ===

#### [GAP-09] `core/scalar-stark-p3/src/transfer_public_inputs.rs` — Poseidon2_acc vs BLAKE3
- **Status**: CLOSED
- **Resolusi**: `compute_commitment_hash` + `compute_nullifier_hash` BLAKE3 -> Poseidon2_acc (t=8, Rate=4).
- **Dokumen**: SCALAR-TECHNICAL §2.2, §2.7-A CX-2/CX-3.

#### [GAP-10] Fee Circuit CF/CF-PREMIUM — Belum In-Circuit
- **Status**: CLOSED (10a + 10b + 10c semua CLOSED, INV-FEE satisfied)
- **GAP-10a**: storage_mass resiprokal fixed-point in-circuit. CLOSED.
  `CfWitnesses` + storage_mass reciprocal cols; `TRANSFER_TRACE_WIDTH` 112->155.
- **GAP-10b**: `BASE_FEE = storage_mass × BASE_PRICE_PER_MASS`, `COMPLEXITY_FEE = constraint_units × PRICE_PER_CU`. CLOSED.
  rem 32-bit decomposition (Opsi A, P1); `TRANSFER_TRACE_WIDTH` 155->798.
- **GAP-10c**: CF-PREMIUM derivasi terikat-nonce. CLOSED.
  `raw = Poseidon2(DOMAIN_FEE_PREMIUM ‖ tx_nonce ‖ FLOOR_BASE)`, `PREMIUM = raw − q×(FLOOR_BASE+1)`.
  52-bit range proof + floor-division terbukti; `TRANSFER_TRACE_WIDTH` 798->857.
- **Dokumen**: SCALAR-TECHNICAL §2.8, §2.8-A (CF-PREMIUM OSSIFIED); P1.

#### [GAP-11] `transfer_public_inputs.rs` — PI[3] `crypto_version: u8` vs `u64`
- **Status**: CLOSED
- **Resolusi**: `crypto_version` u8 -> u64, `VALID_CRYPTO_VERSION` u8 -> u64. Semua call site diupdate.
- **Dokumen**: SCALAR-TECHNICAL §2.2 PI_TOTAL=41 OSSIFIED layout.

---

### === P2 — Struktur Data & State Machine ===

#### [GAP-12] `core/scalar-network/src/subepoch.rs` — Konstanta Salah
- **Status**: CLOSED
- **Resolusi**: `SUBEPOCHS_PER_EPOCH` 720->24 OSSIFIED; `SUBEPOCH_DURATION_S` 3600->1900.
  Nilai dev (3640/720) dipindah ke feature flag `dev-fast-subepoch`, default OFF, tidak masuk build rilis.
- **Dokumen**: SCALAR-PROTOCOL §1 (Glossary), §13.1 (Parameter OSSIFIED).

#### [GAP-13] WAL Dual Naming Scheme
- **Status**: CLOSED
- **Resolusi**: `WalStatus::Pending` -> `Preparing`. Nullifier WAL 2-fase (Preparing|Committed)
  dibedakan secara eksplisit dari node WAL 3-fase (Preparing|Inserted|Committed) — keduanya
  punya semantik berbeda secara sah, bukan duplikasi yang melanggar P4.
- **Dokumen**: SCALAR-TECHNICAL §6.2.

---

### === P3 — API, Tooling, Polish ===

#### [GAP-15] `core/scalar-stark-p3/src/lib.rs` — Framing Gate Eksternal
- **Status**: CLOSED
- **Resolusi**: Framing "ADR-SEC-023 formal confirmation required pre-mainnet" diganti Tier 1/2
  internal + QROM managed residual.
- **Dokumen**: SCALAR-SECURITY §1.7, K-4.

#### [GAP-SYNC-NAMING] `core/scalar-network/src/sync.rs` — Terminologi Legacy
- **Status**: CLOSED
- **Resolusi**: `NsArchVerifyResult`/`NsArchProof*` -> `NsCheckpoint*`. `NS_CHECKPOINT_ROOT_MAX_BYTES`
  + `VERIFY_MAX_MS` fixed.
- **Dokumen**: K-1; SCALAR-TECHNICAL §6.1.

#### [GAP-FIXTURE-CD] `core/scalar-stark-p3/src/starkpack_p3.rs` — Test Fixture Salah
- **Status**: CLOSED
- **Resolusi**: `build_proof_input_bench` — `sum_inputs` diderivasi dari witness values, bukan hardcoded.
- **Dokumen**: SCALAR-TECHNICAL §2.6 CD (conservation), §9.1 fee floor.

#### [GAP-16] Multi-Client Verifier impl#2 (Python) — SCALAR-SECURITY §5.3 (Tier 2)
- **Status**: IN PROGRESS — M1 CLOSED, M2 CLOSED, M3 CLOSED, M4a CLOSED, M4b CLOSED, M4c CLOSED (component) | M4d OPEN | M5 OPEN

**Milestone chain (escalation-resolved, lihat histori 2026-06-16):**
M4c = FRI query-phase sebagai STANDALONE COMPONENT (sibling + fold-chain consistency).
M4d = PCS opening / DEEP-quotient (`open_input`) — menyambungkan M4c ke PROOF ASLI.
M5 = full end-to-end AIR verification terhadap output `prove_transfer_p3()` — inilah yang
memenuhi §5.3 "full re-implementation of the AIR verifier". M4c sendiri TIDAK memenuhi itu.

**M1 — Poseidon2 (CLOSED 2026-06-15)**: 9/9 PASS bit-exact vs impl#1. [§5.3 Tier 2]

**M2 — IMT/QSMT (CLOSED 2026-06-15)**: membership + hash functions, 15/15 PASS bit-exact. [§5.3]

**M3 — PI constraint checker (CLOSED 2026-06-15)**: 13/13 PASS bit-exact. [§5.3]

**M4a — GF(p^3) arithmetic (CLOSED 2026-06-15)**: trinomial x^3-x-1, 19/19 PASS. [§[PROOF-PARAMS] K-2]

**M4b — FRI commit phase (CLOSED 2026-06-15/16)**:
- `verifier-py/scalar_verifier/fri.py`: LDE, domain, Poseidon2 Merkle commit, arity-2/4 FRI fold,
  P2Challenger, `fri_commit_phase()`, `verify_fold_step()`, `verify_commitment()`.
- `verifier-py/tests/test_fri.py`: 42/42 PASS (7 suite: params, domain, Merkle, fold, full commit
  phase, IDFT, challenger).
- `verifier-py/tests/generate_fri_vectors.py`: 13/13 PASS, vectors di `tests/vectors/fri_commit_vectors.json`.
- g=0, q=108, soundness post-batch 2^-154 di-assert di module level. [K-2, K-3]

| Parameter        | Nilai          |
|------------------|----------------|
| Grinding (g)     | 0 (amputated)  |
| Num queries (q)  | 108            |
| Blowup           | 2^3 = 8        |
| Max arity        | 4 (log=2)      |
| Soundness/proof  | 2^-162         |
| Soundness/batch  | 2^-154         |

**M4c — FRI query-phase, component only (CLOSED 2026-06-16)**:
- `verify_query()`: rekonstruksi fold chain dari sibling values, fold round-by-round dengan beta,
  cek final eval vs final_poly pada domain point yang tepat. Mirrors p3-fri v0.5.3/v0.6.1
  verifier.rs `verify_query()` + tail final-poly check dari `verify_fri()`. Restricted log_arity
  in {1, 2} (Scalar OSSIFIED max_log_arity=2).
- `check_witness_g0()`: replikasi p3-challenger `check_witness(bits=0)` — witness TIDAK PERNAH
  di-observe ke transcript saat bits=0 (sesuai `grinding_challenger.rs`). Raises `Unverifiable`
  untuk bits!=0 (P0 anti-pattern jika ditemukan di proof asli).
- `assert_cap_height_zero()`: hard assertion cap_height=0 dari `config.rs build_val_mmcs()` —
  fail loudly jika impl#1 berubah, bukan silent misverify.
- `verifier-py/tests/test_fri_query.py`: 18/18 PASS. Exhaustive query verification (SEMUA starting
  index, 4 ukuran polynomial) + 6 soundness tests genuine (tampered sibling/initial_eval/final_poly/
  beta/round-order/sibling-count — semua REJECTED correctly oleh evaluasi nyata, bukan asumsi).
- **HONESTY BOUNDARY** (dicatat eksplisit di kode + di sini): M4c diuji terhadap fold chain yang
  dihasilkan modul ini sendiri (`fri_commit_phase()`), BUKAN terhadap proof asli dari
  `prove_transfer_p3()`. Ini membuktikan algoritma `verify_query` benar secara isolasi DAN genuinely
  sound terhadap tampering, TAPI BELUM cross-verifikasi lintas-implementasi yang dipersyaratkan §5.3.
  Real-proof connection = M4d. JANGAN menyebut M4c sebagai "FRI verified" tanpa kualifikasi ini.

**M4d — PCS opening / DEEP-quotient (OPEN, next session)**:
`open_input()` — kombinasi `(f(z)−f(x))/(z−x)` ter-scale alpha atas `OpenedValues`
(trace_local, trace_next, quotient_chunks) dari proof asli. Ini menyediakan
`initial_folded_eval` nyata untuk `verify_query()`, menyambungkan M4c ke proof asli.

**M5 — Full end-to-end (OPEN, future)**:
Full verify terhadap proof asli `prove_transfer_p3()`, termasuk AIR constraint (CA-CG, CX,
CF/CF-PREMIUM) + quotient. Ini yang memenuhi §5.3 pre-mainnet requirement.

**Catatan independensi (ditegakkan M4c-M5)**: `OpenedValues`/domain/zeta yang dibutuhkan M4d/M5
diambil dari serialisasi proof PUBLIK (artefak yang di-emit impl#1), bukan dengan memanggil
fungsi `scalar-stark-p3` untuk menderivasi nilai antara. Membaca proof = sah (itu objek yang
diverifikasi). Memanggil kode impl#1 untuk derivasi nilai antara = tidak sah; melanggar P4
independensi multi-client verifier.

**Catatan teknis penting (P0 guard, jangan dihapus saat M4d/M5)**:
- `Witness=Val` (grinding witness sebagai base field type) yang muncul di `FriProof` p3-fri v0.6.1
  adalah artefak struktur tipe Plonky3 — BUKAN grinding aktif. g=0 tetap OSSIFIED. Python tidak
  boleh memperlakukan field witness itu sebagai PoW yang diverifikasi. Jika proof asli memuat
  `pow_witness` non-trivial saat g=0, itu temuan P0 — eskalasi, jangan diam-diam diterima.
- `cap_height=0` di `ValMmcs::new(..., 0)` (config.rs) membuat Merkle cap efektif satu root —
  ini diperiksa via `assert_cap_height_zero()`, bukan di-hardcode diam-diam.

- **Dokumen**: SCALAR-SECURITY §5.3 (Tier 2), §[PROOF-PARAMS].

---

#### [GAP-FRI-ARITY] `core/scalar-stark-p3/src/config.rs` — FRI Folding Factor Menyimpang dari OSSIFIED
- **Status**: CLOSED (2026-06-16)
- **Ditemukan saat**: GAP-16 M4d-1, ketika proof asli dari `prove_transfer_p3()` diemit sebagai
  JSON dan dibaca silang oleh Python (multi-client verifier membuktikan nilainya secara langsung).
- **Masalah**: `build_scalar_config()` dan `build_scalar_zk_config()` menggunakan
  `max_log_arity: 4` di `FriParameters`, dengan komentar yang salah membaca notasi spec:
  `// folding factor 4. OSSIFIED spec §4.4.` menyamakan "folding factor 4" dengan
  `max_log_arity` literal 4. Berdasarkan dokumentasi p3-fri sendiri ("max_log_arity=1 ->
  binary folding", yaitu `max_log_arity` ITU SENDIRI adalah `log_arity`), folding factor 4
  (arity-4) seharusnya `max_log_arity: 2` (log2(4)=2), bukan 4. Tidak ada wrapper Scalar yang
  membatasi; `max_log_arity:4` diteruskan langsung ke `p3-fri`, yang bebas memilih `log_arity`
  dinamis hingga nilai itu (`compute_log_arity_for_round`). Rujukan `§4.4` juga salah — section
  itu tidak eksis di SCALAR-TECHNICAL untuk parameter ini; sumber benar adalah
  SCALAR-PROTOCOL §13.1 ("FRI folding factor: 4") dan SCALAR-SECURITY §1.4 (`FRI rounds =
  ceil(19/2)`, yang membuktikan `d=2` sebagai pembagi/batas atas).
- **Bukti konkret**: Proof asli dari `prove_transfer_p3()` (PI sederhana, trace 8 baris)
  menghasilkan `commit_phase_commits` 1 round dengan `log_arity=3` (arity-8) — secara nyata
  melebihi folding factor OSSIFIED, bukan potensi risiko teoretis.
- **Definisi penegakan (presisi penting)**: `log_arity <= 2` di SETIAP round — BUKAN `== 2`
  ketat. Bukti dari SCALAR-SECURITY §1.4 sendiri: `FRI rounds = ceil(19/2) = 10` — operator
  `ceil` mengantisipasi round terakhir sebagai fold parsial (remainder), bukan pembagian eksak.
  `log_arity > 2` di round mana pun adalah penyimpangan; `log_arity < 2` di round TERAKHIR
  adalah perilaku normal (remainder fold).
- **Resolusi**: `max_log_arity: 4` -> `2` di kedua `build_scalar_config()` dan
  `build_scalar_zk_config()`. Komentar diperbaiki dengan rujukan yang benar
  (SCALAR-PROTOCOL §13.1, SCALAR-SECURITY §1.4), bukan §4.4 yang salah.
  Test penegak `test_fri_folding_factor_enforced_max_log_arity_2` ditambahkan: memanggil
  `prove_transfer_p3()` sungguhan, memeriksa SEMUA round di SEMUA 108 query proof, hard-fail
  jika ada `log_arity > 2` di mana pun.
- **Hasil setelah patch** (proof asli, PI sama): `commit_phase_commits` 2 round
  (round 0: `log_arity=2`, round 1: `log_arity=1` remainder) — semua `<= 2`, tidak ada
  penyimpangan lagi. `commit_pow_witnesses=[0,0]`, `query_pow_witness=0` tetap konsisten
  g=0 OSSIFIED (guard P0 grinding tidak terdampak, tetap lolos).
- **Dampak ke M4b/M4c Python**: TIDAK PERLU generalisasi arity. Asumsi awal M4b
  (`fri_fold_column_arity4`, `log_arity=2` tetap) ternyata SESUAI dokumen — config Rust yang
  menyimpang, bukan Python yang kurang cakupan. M4c yang `raise Unverifiable` untuk
  `log_arity=3` adalah deteksi yang BENAR (multi-client verifier bekerja sesuai tujuannya) —
  proof yang sesuai spec sekarang tidak akan pernah memicu raise itu.
- **Komentar M4b/M4c dikoreksi**: hapus klaim "OSSIFIED max_log_arity=2" (notasi lama, ambigu)
  dan TIDAK ditulis "max_log_arity=4" (config Rust yang sempat menyimpang) sebagai fakta.
  Nilai yang benar: folding factor 4 (d=2, log_arity<=2 per round, remainder di round
  terakhir boleh <2), merujuk SCALAR-PROTOCOL §13.1 + SCALAR-SECURITY §1.4 ceil(19/2).
- **Vektor di-regenerate**: `verifier-py/tests/vectors/m4d_real_proof.json` ditimpa dari
  proof yang sudah benar (config setelah patch). Vektor lama (dari proof menyimpang,
  log_arity=3) TIDAK dipakai lagi.
- **Dokumen**: SCALAR-PROTOCOL §13.1 (FRI folding factor: 4), SCALAR-SECURITY §1.4
  (FRI rounds = ceil(19/2), pembuktian d=2).

---

## Urutan Implementasi yang Direkomendasikan
FASE A (sebelum FASE B EpochState integration) — SEMUA P0/P1/P2/P3 CLOSED:
[P0] GAP-GOSSIP          CLOSED

[P0] GAP-AUDIT-CLAIMS    CLOSED
[P1] GAP-11              CLOSED

[P1] GAP-09              CLOSED

[P1] GAP-10a/10b/10c     CLOSED
[P2] GAP-12              CLOSED

[P2] GAP-13              CLOSED
[P3] GAP-15              CLOSED

[P3] GAP-SYNC-NAMING     CLOSED

[P3] GAP-FIXTURE-CD      CLOSED
FASE B (EpochState tersambung — future):

GAP-GOSSIP: upgrade ke StateValidated dengan EpochState context

GAP-AUDIT-CLAIMS: upgrade dari Unverifiable ke ValidatedAgainstState
GAP-16 (parallel track, independent dari FASE A/B):

M1-M4c CLOSED -> M4d (PCS opening/DEEP-quotient) -> M5 (full end-to-end, §5.3 pre-mainnet gate)

---

## Ketergantungan Kunci
GAP-GOSSIP ──────────────────────────────> FASE B: EpochState context

GAP-AUDIT-CLAIMS ────────────────────────> FASE B: EpochState context

GAP-16 M4d ──────────────────────────────> butuh M4c CLOSED (selesai) + proof asli prove_transfer_p3()

GAP-16 M5  ──────────────────────────────> butuh M4d CLOSED (real-proof connection)

---

## Larangan Mutlak (ringkasan cepat untuk coder baru)

| Larangan | Alasan |
|-------------|--------|
| `return true` / `Ok(true)` di jalur verify tanpa kriptografi nyata | P1, verifier palsu |
| Constraint tidak dievaluasi di AIR/circuit (boolean flag saja) | P1, teater kriptografis |
| `proof_bytes` / `proving_key_version` / status `PROVEN` di checkpoint | K-1 |
| Literal `108` (queries) atau grinding term di luar konstanta terpusat | K-2 |
| Nilai soundness post-batch selain `2^-154` | K-3 |
| Term grinding apa pun (`g` harus tetap 0) | K-2 |
| Nilai OSSIFIED baru tanpa eskalasi ke spec | Semua |
| "menunggu audit eksternal" sebagai syarat soundness | K-4 |
| `git push --force` atau manipulasi sejarah | Protokol git |
| Nilai `dev-fast-subepoch` masuk build rilis | GAP-12 |
| Memanggil kode impl#1 (`scalar-stark-p3`) dari Python untuk menderivasi nilai antara (M4d/M5) | P4, independensi multi-client verifier (§5.3) |
| Memperlakukan `pow_witness`/`Witness` field FriProof sebagai PoW aktif saat g=0 | K-2, P0 anti-pattern |
| Menyebut M4c sebagai "FRI verified" atau "proof verified" tanpa qualifikasi honesty boundary | §5.3, kejujuran klaim verifikasi |

---

## Gate Wajib Sebelum Setiap Commit

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-features --workspace
cargo test --all-features --workspace
```

Jika ada warning/error -> perbaiki kode, bukan suppress, bukan longgarkan test.

**Catatan resource Codespace**: `cargo test --all-features --workspace` penuh bisa terlalu berat
(compile Plonky3 STARK proving transitif). Untuk perubahan terbatas pada satu crate ringan
(misal `test-vector-gen` tanpa unit test), `cargo build` + `cargo run -p <crate>` (functional
check) sudah memadai sebagai bukti korektness, dicatat eksplisit di commit message kapan ini
dilakukan dan mengapa aman.

---

## Riwayat Perubahan

| Tanggal | Event |
|---------|-------|
| 2026-06-15 | Phase Review awal selesai. REPO_MAP v1 dibuat. 16+ gap diidentifikasi. |
| 2026-06-15 | GAP-04 CLOSED: fri_queries=108, fri_grinding=0 di genesis_ceremony.rs. |
| 2026-06-15 | GAP-05 CLOSED: stale comments queries=84/grinding=23 di batch_transfer_p3 + config.rs. |
| 2026-06-15 | GAP-06 CLOSED: starkpack_p3.rs soundness 2^-154 post-batch / 2^-162 per-proof. |
| 2026-06-15 | GAP-07 CLOSED: config.rs + domain.rs soundness values dikoreksi. |
| 2026-06-15 | GAP-08 CLOSED: MembershipAir, NonMembershipAir, A-R9 PI binding [0..4]+[33..40]. (4 commits) |
| 2026-06-15 | GAP-01 CLOSED: CheckpointProof K-1 anti-pattern dihapus dari nullifier_set.rs. |
| 2026-06-15 | GAP-02 CLOSED: CheckpointWalEntry smt_root/smt_data_path + WalPhase benar di wal.rs. |
| 2026-06-15 | GAP-03 CLOSED: SyncState VerifyingNsArch -> VerifyingNsCheckpoint di sync.rs. |
| 2026-06-15 | GAP-GOSSIP CLOSED: RelayDecision + verify_transfer_p3; return true dihapus. [§4.1 P1] |
| 2026-06-15 | GAP-AUDIT-CLAIMS CLOSED: Unverifiable variant; zero-root placeholder dihapus. [P1] |
| 2026-06-15 | WAL tests fixed: Preparing->Inserted->Committed enforced in all tests. [§6.2] |
| 2026-06-15 | GAP-11 CLOSED: crypto_version u8->u64, VALID_CRYPTO_VERSION u8->u64. [SCALAR-TECHNICAL §2.2] |
| 2026-06-15 | GAP-09 CLOSED: compute_commitment_hash + compute_nullifier_hash BLAKE3->Poseidon2_acc (t=8, Rate=4). [SCALAR-TECHNICAL §2.2, §2.7-A CX-2/CX-3] |
| 2026-06-15 | GAP-10a CLOSED: CfWitnesses + storage_mass reciprocal cols (112-154); TRANSFER_TRACE_WIDTH 112->155. [§2.8] |
| 2026-06-15 | GAP-10b CLOSED: rem 32-bit decomp (Opsi A P1); BASE_FEE+COMPLEXITY_FEE+FLOOR_BASE in-circuit; TRANSFER_TRACE_WIDTH 155->798. [§2.8] |
| 2026-06-15 | GAP-10c CLOSED: CF-PREMIUM Poseidon2_t8 terikat-nonce + 52-bit range proof + floor-div; TRANSFER_TRACE_WIDTH 798->857. [§2.8-A P1] |
| 2026-06-15 | GAP-10 CLOSED: CF/CF-PREMIUM fully in-circuit (10a+10b+10c). INV-FEE satisfied. [P1] |
| 2026-06-15 | GAP-12 CLOSED: SUBEPOCHS_PER_EPOCH 720->24 OSSIFIED; SUBEPOCH_DURATION_S 3600->1900; dev-fast-subepoch feature flag (default OFF). [§13.1] |
| 2026-06-15 | GAP-13 CLOSED: WalStatus::Pending->Preparing; nullifier WAL 2-fase (Preparing|Committed) distinct dari node WAL 3-fase. [§6.2] |
| 2026-06-15 | GAP-15 CLOSED: ADR-SEC-023 framing diganti Tier 1/2 internal + QROM managed residual. [K-4, §1.7] |
| 2026-06-15 | GAP-SYNC-NAMING CLOSED: NsArchVerifyResult/NsArchProof->NsCheckpoint*; NS_CHECKPOINT_ROOT_MAX_BYTES+VERIFY_MAX_MS fixed. [K-1] |
| 2026-06-15 | GAP-FIXTURE-CD CLOSED: build_proof_input_bench sum_inputs derived from witness values (not hardcoded). [§2.6 CD] |
| 2026-06-15 | FIX P1: rem*rem==0 placeholder dihapus dari eval(); rem bit decomp 32-bit dipindah ke eval() loop CF. [§2.8 P1 Opsi A] |
| 2026-06-15 | GAP-16 IN PROGRESS: verifier-py/ created; M1 Poseidon2 9/9 PASS (bit-exact vs impl#1). [§5.3 Tier 2] |
| 2026-06-15 | GAP-16 M2: IMT membership + QSMT hash functions 15/15 PASS bit-exact. [§5.3] |
| 2026-06-15 | GAP-16 M3: PI constraint checker 13/13 PASS bit-exact. [§5.3] |
| 2026-06-15 | GAP-16 M4a: GF(p^3) trinomial x^3-x-1 arithmetic 19/19 PASS. [§[PROOF-PARAMS] K-2] |
| 2026-06-15 | Sesi selesai. GAP-16 M1-M4a CLOSED. M4b FRI commit phase = next. |
| 2026-06-15 | REPO_MAP v2: eskalasi keempat RESOLVED. GAP-GOSSIP + GAP-AUDIT-CLAIMS ditambahkan sebagai P0 baru. |
| 2026-06-16 | GAP-16 M4b CLOSED: FRI commit phase Python impl#2. fri.py: LDE/domain/Merkle/fold/challenger/commit_phase. test_fri.py 42/42 PASS. fri_commit_vectors.json 13/13 PASS. g=0/q=108/eps=-154 enforced. [SCALAR-SECURITY §5.3, §[PROOF-PARAMS], K-2, K-3] |
| 2026-06-16 | FIX: tools/test-vector-gen clippy gate — removed duplicate RawDataSerializable import, added #[allow(too_many_arguments)] on fn pi(), fixed i*8 spacing. Gates fmt+clippy+build+targeted-test/run all PASS. |
| 2026-06-16 | ESKALASI RESOLVED: M4c scope diluruskan. open_input/DEEP-quotient ditemukan sebagai lapisan PCS-opening generik (independen dari CA-CG) -> dipisah sebagai M4d. M4c = FRI query-phase sebagai komponen standalone (belum cross-verified proof asli); M5 = full end-to-end yang memenuhi §5.3. |
| 2026-06-16 | GAP-16 M4c CLOSED (component): verify_query() + check_witness_g0() + assert_cap_height_zero() di fri.py. test_fri_query.py 18/18 PASS (exhaustive query check 4 ukuran poly, semua starting index + 6 soundness tamper test, semua genuinely rejected). Honesty boundary didokumentasikan eksplisit: belum cross-verified terhadap proof asli prove_transfer_p3(); itu adalah scope M4d. No regression: M4b test_fri.py tetap 42/42 PASS. [SCALAR-SECURITY §5.3, §[PROOF-PARAMS], K-2] |
| 2026-06-16 | REPO_MAP.md rewrite menyeluruh: hapus duplikasi baris histori (GAP-16 IN PROGRESS 2x, GAP-10b/10c/10 2x, M4b CLOSED 2x, FIX clippy 2x), fix mojibake encoding (em-dash, §), satukan section terpisah "## GAP-16 M4b" ke dalam blok [GAP-16] yang benar, tambahkan status M4c/M4d/M5 yang akurat. |
