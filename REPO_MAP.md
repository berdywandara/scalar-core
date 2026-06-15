# SCALAR CORE — REPOSITORY MAP

Generated: 2026-06-15 | Phase Review — Static analysis

---

## State Saat Ini

- Build: UNKNOWN (perlu `cargo build` untuk konfirmasi)
- Test: UNKNOWN (perlu `cargo test` untuk konfirmasi)
- Clippy: UNKNOWN
- Placeholder kripto teridentifikasi: 2 confirmed (nullifier_set.rs `is_valid()` + CB/CC boolean flag in circuit)

---

## Kepatuhan Arsitektur (K-1..K-4)

- K-1 NS_CHECKPOINT SMT akumulatif: **VIOLATION** — `CheckpointProof.proof_bytes`, "recursive Winterfell STARK" di nullifier_set.rs; `proof_bytes`+`proving_key_version` di wal.rs; `SyncState::VerifyingNsArch` di sync.rs
- K-2 proof-params terpusat: **PARTIAL VIOLATION** — lib.rs sudah benar (108/0), tapi genesis_ceremony.rs (84/20) dan batch_transfer_p3.rs/config.rs (comments 84/23) masih stale
- K-3 epsilon post-batch 2^-154: **VIOLATION** — starkpack_p3.rs menulis 2^-120; config.rs + domain.rs menulis ~2^-128/~2^-120
- K-4 verifikasi internal multi-tier: **PARTIAL** — lib.rs masih framing "ADR-SEC-023 formal confirmation required pre-mainnet"

---

## Gap Teridentifikasi

- [GAP-01] [P0] scalar-nullifier/nullifier_set.rs — CheckpointProof mengandung proof_bytes + Recursive STARK anti-pattern — OPEN
- [GAP-02] [P0] scalar-node/wal.rs — CheckpointWalEntry mengandung proof_bytes, proving_key_version; fasa WAL salah — OPEN
- [GAP-03] [P0] scalar-network/sync.rs — SyncState::VerifyingNsArch, NS_ARCH constants — Recursive STARK di sync layer — OPEN
- [GAP-04] [P0] scalar-emission/genesis_ceremony.rs — fri_queries=84, fri_grinding=20 (seharusnya 108, 0) — OPEN
- [GAP-05] [P0] scalar-stark-p3/batch_transfer_p3.rs + config.rs — stale comments queries=84, grinding=23 — OPEN
- [GAP-06] [P0→DONE] scalar-stark-p3/starkpack_p3.rs — soundness 2^-154 post-batch, 2^-162 per-proof — CLOSED
- [GAP-07] [P0→DONE] scalar-stark-p3/config.rs + scalar-crypto/domain.rs — soundness dikoreksi ke 2^-154/2^-162 — CLOSED
- [GAP-08] [P0→DONE] scalar-stark-p3: MembershipAir wrapper, NonMembershipAir num_public_values, A-R9 PI binding [0..4]+[33..40] — CLOSED (4 commits)
- [GAP-09] [P1] scalar-stark-p3/transfer_public_inputs.rs — commitment_hash/nullifier_hash menggunakan BLAKE3 bukan Poseidon2_acc — OPEN
- [GAP-10] [P1] Fee circuit CF/CF-PREMIUM — storage_mass, FLOOR_BASE, PREMIUM terikat-nonce tidak ada di AIR — OPEN [ESKALASI]
- [GAP-11] [P1] scalar-stark-p3/transfer_public_inputs.rs — PI[3] crypto_version:u8 vs suite_id:u64 — OPEN
- [GAP-12] [P2] scalar-network/subepoch.rs — SUBEPOCH_DURATION_S=3600, SUBEPOCHS_PER_EPOCH=720 vs OSSIFIED 1900s/24 — OPEN [ESKALASI]
- [GAP-13] [P2] scalar-node/wal.rs — fasa naming Prepared/Committed/Aborted vs PREPARING/INSERTED/COMMITTED; tidak ada smt_data_path — OPEN
- [GAP-14] [P2] scalar-nullifier/nullifier_set.rs — is_valid() bergantung proof_bytes (harus diganti SMT root check) — OPEN (blokir GAP-01)
- [GAP-15] [P3] scalar-stark-p3/lib.rs — framing "ADR-SEC-023 formal confirmation required pre-mainnet" menyiratkan gate eksternal — OPEN
- [GAP-16] [P3] Multi-client verifier impl#2 (Python) belum ada — OPEN

---

- [GAP-FIXTURE-CD] [P3] scalar-stark-p3/starkpack_p3.rs bench_starkpack_aggregation — test helper tidak menyertakan fee_total di witness_sum (ConservationViolated selisih 40) — OPEN

## Ketergantungan Kunci

- GAP-01 → GAP-14 (is_valid logic baru bisa difix setelah CheckpointProof dibenahi)
- GAP-02 → GAP-13 (WAL phase naming koordinat dengan WalEntry struct)
- GAP-03 → GAP-01 (sync VerifyingNsArch harus ganti setelah NS_CHECKPOINT jelas)
- GAP-09 → sebelum GAP-08 (commitment_hash harus Poseidon2_acc sebelum CB/CC dibuktikan)

## Item Eskalasi (menunggu keputusan sebelum implementasi)

- GAP-08: CB/CC full in-circuit Merkle/SMT — apakah membership_air_p3 + nonmembership_air_p3 sudah wired ke batch_transfer?
- GAP-10: Model fee §B.4 vs §2.8/§2.8-A — mana yang berlaku sebagai final?
- GAP-12: subepoch.rs "Research Package §3.2.1" (3600s/720) vs OSSIFIED dokumen final (1900s/24) — mana yang digunakan?

---

## Riwayat Perubahan

- 2026-06-15 | Phase Review selesai, REPO_MAP.md dibuat. 16 gap diidentifikasi (7×P0, 4×P1, 3×P2, 2×P3).
- 2026-06-15 | GAP-04 CLOSED: fri_queries=108, fri_grinding=0 di genesis_ceremony.rs.
- 2026-06-15 | GAP-05 CLOSED: stale comments queries=84/grinding=23 di batch_transfer_p3 + config.rs.
- 2026-06-15 | GAP-08 CLOSED: MembershipAir num_public_values, NonMembershipAir num_public_values, A-R9 PI[0..4]+[33..40] explicit binding. 127/128 tests pass (1 remaining: GAP-FIXTURE-CD P3).
- 2026-06-15 | GAP-FIXTURE-CD ditambahkan (P3): bench_starkpack_aggregation test helper salah, bukan constraint bug.
- 2026-06-15 | GAP-06 CLOSED: starkpack_p3.rs soundness 2^-154 post-batch, 2^-162 per-proof [SCALAR-SECURITY §1.4].
- 2026-06-15 | GAP-07 CLOSED: config.rs + domain.rs soundness dikoreksi, ~2^-120/~2^-128 dihapus.
