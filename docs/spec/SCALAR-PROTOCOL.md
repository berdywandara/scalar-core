# SCALAR-PROTOCOL

> Dokumen tunggal dan mengikat untuk aturan protokol Scalar Network.
> Perubahan dilakukan dengan update langsung, tidak membuat dokumen baru.
> Referensi implementasi: [SCALAR-TECHNICAL](SCALAR-TECHNICAL.md) | Analisis keamanan: [SCALAR-SECURITY](SCALAR-SECURITY.md)

---

## §0 — Empat Prinsip Fundamental

**P1 — Truth by Mathematics, Not by Majority**
Constraint kriptografis dievaluasi di dalam STARK proof. Boolean flag tanpa witness adalah teater kriptografis.

**P2 — Epoch by Sequence, Not by Clock**
Finalitas ditentukan oleh urutan deterministik, bukan timestamp. Wall-clock hanya untuk liveness bound.

**P3 — Governance by Genuine Operation, Not by Stakes**
Partisipasi nyata (uptime, proving, longevity) menentukan bobot. Token tidak memberikan governance power langsung.

**P4 — Hardened by Determinism, Secured by Analysis**
Setiap node jujur dengan data yang sama menghasilkan output identik. Implementasi berbeda = bug protokol.

---

## §1 — Glossary

| Istilah | Definisi |
|---------|----------|
| OSSIFIED | Tidak berubah tanpa hard fork + formal soundness re-proof |
| CONSTRAINED | Dapat berubah via COMMIT 75% governance |
| Epoch | 45,600 detik (~12.67 jam) = 24 sub-epoch |
| Sub-Epoch | 1,900 detik (~31.7 menit) — unit finalitas transaksi |
| Heartbeat | Pesan periodik node setiap 120 detik |
| Anchor | Heartbeat batas epoch dengan SLH-DSA signature |
| MicroCommitment | SubEpochCommitment dipicu threshold tx atau timeout |
| NodeScore | Metrik kesehatan node [0, 1_000_000] |
| Maturity | Akumulasi uptime 180 hari (342 epoch) |
| UTXO | Unspent Transaction Output |
| Nullifier | Hash unik menandai UTXO sudah digunakan |
| NS_ACTIVE | NullifierSet aktif ~15 MB, 3 epoch terakhir |
| NS_CHECKPOINT | NullifierSet arsip ~150 KB, STARK proof |
| fixed-point | Integer dengan denominasi 1_000_000 |
| sSCL | 1 SCL = 10^8 sSCL |
| Tier A | Argon2id 4GB/3600 iter, NodeScore max 1_000_000 |
| Tier B | Argon2id 4GB/3600 iter + TEE, NodeScore max 1_000_000 |
| Tier C | Argon2id 16MB/100 iter, NodeScore max 600_000 |

---

## §2 — Arsitektur Sistem

Privacy-by-default, quantum-resistant, deterministic finality, genuine governance.
Crypto Suite V1 (genesis): Poseidon2 + SLH-DSA + BLAKE3 + FRI + ML-KEM-768 hybrid.

**Trade-off yang disadari:** post-hack tracking tidak mungkin; auditabilitas individual tidak ada; recovery kunci privat hilang tidak ada.

---

## §3 — Node dan Tier System

### NodeScore Formula (OSSIFIED)
NodeScore(i,k) = floor(
UPTIME_COMPONENT × 500_000 +
PROOF_COMPONENT  × 300_000 +
AGE_COMPONENT    × 200_000
) / 1_000_000
- UPTIME = heartbeat valid / expected (fixed-point)
- PROOF  = heartbeat dengan valid SMT root / total
- AGE    = min(epochs_participated, 342) / 342

Tier C cap: `NodeScore = min(NodeScore, 600_000)` jika `node_id_full[0] == 0xFE`

**Contoh:** uptime 95%, proof 90%, age 50% → NodeScore = 845_000

---

## §4 — Epoch, Sub-Epoch, dan Heartbeat

### Time Security Rules
| Rule | Deskripsi |
|------|-----------|
| T-1 | Epoch boundary via seq_num, bukan wall-clock |
| T-2 | Freshness: T_FUTURE_S=60s REJECT; T_PAST_S=3600s DROP |
| T-3 | NMT: 24 peer (23 deterministik + 1 acak), NodeScore >800_000 |
| T-4 | Rate limit: 1 HB per 300s minimum, target 120s |
| T-5 | seq_num monotonic; gap dikonfirmasi quorum ≥5 |
| T-6 | Timestamp hanya TTL/debugging, bukan state determinant |

### MicroCommitment
Trigger: 41 tx pending ATAU 60 detik timeout. Quorum 5/7. STARK proof wajib.

---

## §5 — Maturity dan Governance Weight
maturity(i,k)   = Σ w_i_fp(j) untuk j ∈ [k-342, k]
GP(i,t)         = min(conviction_fp(t) × maturity / 1_000_000, GOV_MAX)
GOV_MAX         = 1_000_000 (Tier A/B) | 200_000 (Tier C)
conviction_fp   = kurva τ=60 hari: hari-1=100k, hari-30=957k, hari-365=1_000_000

---

## §6 — Supply dan Emission

| Parameter | Nilai |
|-----------|-------|
| S_MAX | 21,000,000 SCL |
| S_E | 18,900,000 SCL |
| S_R | 2,100,000 SCL |
| E0 | 126,000 SCL/epoch |
| E_TAIL | 1,000 SCL/epoch |

`E(k) = E0 × (1 - M_E(k-1) / S_E)²`  
Deferred Pool: maks 10% × E0/epoch, maks 12 epoch.

---

## §7 — Transfer dan Finalitas

**Level 1 (Optimistic):** quorum 5/7, "probably final". Default: OFF, opt-in eksplisit.  
**Level 2 (STARK Final):** STARK proof diverifikasi, nullifier masuk NS. IMMUTABLE.

T_MAX_WAIT = 1,800 detik (wajib < 1,900 detik SUBEPOCH_PROVING_DURATION_S)

---

## §8 — Governance

### Thresholds (OSSIFIED)
| Aksi | Threshold |
|------|-----------|
| COMMIT | 75% |
| ABORT | 67% |
| EMERGENCY | 51% (3 kondisi exhaustive saja) |

**Emergency conditions (EXHAUSTIVE):**
1. Confirmed STARK soundness vulnerability
2. Confirmed supply invariant violation (total_minted > S_E)
3. Network halt > 72 jam (> 2 epoch tanpa committed_manifest)

---

## §9 — Genesis Ceremony

- Phase 1: `genesis_params_hash = BLAKE3(serialize(genesis_params))`
- Phase 2: registrasi peserta, deadline 5,040 HB (7 hari)
- Min peserta: 3 node, NodeScore ≥ 800,000
- `genesis_hash = BLAKE3(serialize(genesis_object))` — digunakan untuk NodeID dan wallet key

---

## §10 — Wallet dan Key Derivation (OSSIFIED)
seed       = Argon2id(mnemonic, salt="scalar_wallet_kdf"||genesis_hash, 64MB, 3iter)
MasterKey  = BLAKE3(seed || "scalar_master")
SpendKey   = BLAKE3(AccountKey || "spend")
NodeKey    = BLAKE3(AccountKey || "node")   -- isolated dari SpendKey
DuressKey  = BLAKE3(AccountKey || "duress" || j)
Mnemonic: 12 kata, kata pertama "scalar" wajib, 11 kata bebas → 121-bit entropi.

---

## §11 — Network Protocol

- **Transport A:** libp2p Noise+Yamux / Tor 3-hop (semua pesan >44 byte)
- **Transport B:** LoRa/HF Radio, StateBeacon 44 byte saja
- **P2P:** X25519 + ML-KEM-768 hybrid key exchange
- **Privacy:** Dandelion++ stem probability 70%, batch obfuscation <200 node
- **Anchor limits:** A-1: 1/node/epoch; A-2: NodeScore≥800k; A-3: rate 3600s

---

## §12 — Parameter OSSIFIED

| Parameter | Nilai |
|-----------|-------|
| Goldilocks field | p = 2^64 − 2^32 + 1 |
| Poseidon2 t / alpha / R_F / R_P | 8 / 7 / 8 / 22 |
| FRI blowup / queries / grinding | 8 / 84 / 23 |
| Soundness ε (Scenario B, g=23) | ≤ 2^-120.68 |
| SLH-DSA sig size | 7,856 bytes |
| W_MATURE_DAYS / W_MATURE_EPOCHS | 180 hari / 342 epoch |
| S_MAX / S_E / S_R | 21M / 18.9M / 2.1M SCL |
| COMMIT / ABORT / EMERGENCY | 75% / 67% / 51% |
| τ_CONVICTION | 60 hari |

---

## §13 — Parameter CONSTRAINED

| Parameter | Nilai |
|-----------|-------|
| HEARTBEAT_INTERVAL_S | 120 |
| SUBEPOCH_PROVING_DURATION_S | 1,900 |
| EPOCH_DURATION_S | 45,600 (~12.67 jam) |
| T_MAX_WAIT | 1,800 |
| MICROCOMMITMENT_TRIGGER_TX | 41 |
| MICROCOMMITMENT_TRIGGER_TIMEOUT_S | 60 |
| GENESIS_ANCHOR_DEADLINE_SEQ | 5,040 HB (7 hari) |
| GENESIS_WINDOW_DAYS | 7 |
| DANDELION_FULL_THRESHOLD | 200 node |
| MAX_NULLIFIERS_PER_CHECKPOINT | 200,000 |
| TIER_C_MAX_NODESCORE | 600,000 |
| AGGREGATOR_MIN_NODESCORE | 800,000 |

Daftar lengkap parameter + semua domain separators: lihat [SCALAR-PROTOCOL.md versi lengkap (docx)](../../SCALAR-PROTOCOL.docx)
