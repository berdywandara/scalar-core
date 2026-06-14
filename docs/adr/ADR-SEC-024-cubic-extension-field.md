# ADR-SEC-024 — Polinomial Reduksi Ekstensi Kubik GF(p³)

**Status:** RATIFIED & FROZEN  
**Menutup:** Eskalasi E-1  
**Terkait:** ADR-SEC-023 (audit soundness q=108); SCALAR-SECURITY §[PROOF-PARAMS]  
**Lokasi:** scalar-specs/governance/ADR-SEC-024.md (SCALAR-REPO §6.2)  
**Tanggal ratifikasi:** 2026-06-14  
**Penandatangan:** Arsitek Keamanan Protokol Utama  

---

## §0 — Ringkasan Keputusan

Polinomial reduksi **P(x) = x³ − x − 1** ditetapkan sebagai OSSIFIED
untuk pembentukan ekstensi kubik GF(p³) dalam ekosistem Scalar Network.

| Field | Nilai |
|-------|-------|
| Field prima dasar | p = 2^64 − 2^32 + 1 (Goldilocks) |
| Polinomial reduksi | P(x) = x³ − x − 1 (CubicTrinomial) |
| Field ekstensi | GF(p³) = GF(p)[x] / (x³ − x − 1) |
| Ukuran field | \|F\| = p³ ≈ 2^192 |
| Grinding bits | g = 0 (diamputasi, QROM-safe) |
| Status | RATIFIED & FROZEN |

---

## §1 — Konteks Arsitektur

Eskalasi E-1 menuntut penetapan konstruksi konkret untuk ekstensi kubik
field operasi FRI/DEEP. Parameter terkunci OSSIFIED di SCALAR-SECURITY
§[PROOF-PARAMS]:

- Field prima dasar: p = 2^64 − 2^32 + 1
- Field operasi FRI/DEEP: ekstensi kubik GF(p³), |F| ≈ 2^192
- Grinding bits: g = 0 (diamputasi)
- Round constants Poseidon2: p3-goldilocks v0.5.3, bit-exact identik
  di v0.6 (KAT PASS, G-25b, blocking CI gate commit 1845801)

Elevasi field operasi ke GF(p³) memungkinkan amputasi grinding (g=0)
tanpa kehilangan margin soundness. Soundness bersandar pada ukuran field
dan jumlah query, bukan pada grinding yang QROM-fragile (dipercepat
Grover). Polinomial reduksi adalah komponen yang ditutup ADR ini.

---

## §2 — Definisi Polinomial Reduksi
P(x) = x³ − x − 1   (CubicTrinomial)
GF(p³) = GF(p)[x] / (x³ − x − 1),   p = 2^64 − 2^32 + 1

Trinomial kubik bentuk x³ − x − 1 memberikan aritmetika ekstensi yang
efisien untuk circuit ZK: reduksi modular murah, basis {1, x, x²}.

---

## §3 — Klaim Matematis (Disahkan)

### §3.1 — Irreducibility atas GF(p) Goldilocks

**Klaim:** P(x) = x³ − x − 1 irreducible atas GF(p),
p = 2^64 − 2^32 + 1.

**Kriteria:** Polinomial kubik irreducible jika dan hanya jika tidak ada
akar di GF(p). Yaitu tidak ada a ∈ GF(p) dengan a³ − a − 1 ≡ 0 (mod p).

**Verifikasi SageMath:**
```python
p = 2**64 - 2**32 + 1
R.<x> = GF(p)[]
assert (x^3 - x - 1).is_irreducible()  # True
```

**DISAHKAN — Arsitek Keamanan Protokol Utama:**
Output komputasi aljabar (SageMath, transkrip dari commit d669f71) telah
ditinjau: terbukti definitif tidak ada elemen a ∈ GF(p) yang memenuhi
a³ − a − 1 ≡ 0 (mod p). Polinomial ini adalah trinomial irreducible yang
sah atas lapangan prima Goldilocks.

### §3.2 — Keselarasan dengan |F| ≈ 2^192

**Klaim:** |GF(p³)| = p³ = (2^64 − 2^32 + 1)³ ≈ 2^192.

log₂(p) ≈ 63.9999, sehingga log₂(p³) ≈ 191.9999 — memenuhi |F| ≈ 2^192.

**DISAHKAN — Arsitek Keamanan Protokol Utama:**
Karena P(x) terbukti irreducible berderajat 3, ukuran lapangan ekstensi
secara matematis eksak |GF(p³)| = p³. Selaras absolut dengan |F| ≈ 2^192
yang dikunci di §[PROOF-PARAMS].

### §3.3 — Konsistensi dengan Amputasi Grinding (g = 0)

**DISAHKAN — Arsitek Keamanan Protokol Utama:**
Konstruksi ekstensi kubik ini memvalidasi secara struktural amputasi
grinding (g = 0). Kecukupan margin keamanan numerik (soundness) untuk
q = 108 murni menjadi subjek pengujian ADR-SEC-023 oleh auditor eksternal.

---

## §4 — Kompatibilitas Sistem Pembuktian

| Aspek | Status |
|-------|--------|
| Trait implementasi | CubicTrinomialExtendable di p3-goldilocks 0.6.1 |
| Polinomial aktif | x³ − x − 1 (dikonfirmasi dari source p3-goldilocks 0.6.1 src/extension.rs) |
| Round constants Poseidon2 | Bit-exact identik 0.5→0.6 (KAT PASS) |
| CI gate KAT | test_poseidon2_kat_vector_scalar_technical_s1_1 (blocking) |
| Type alias kode | `pub type EF = CubicTrinomialExtensionField<Goldilocks>` |
| Commit referensi | 1845801 (HEAD main) |

**DISAHKAN — Arsitek Keamanan Protokol Utama:**
CubicTrinomialExtendable di p3-goldilocks 0.6.1 secara natif menggunakan
koefisien yang ekuivalen dengan x³ − x − 1. KAT dikonfigurasi sebagai
blocking CI gate. Determinisme lapangan matematika terkunci secara struktural.

---

## §5 — Batas Lingkup dan Delegasi ke ADR-SEC-023

> ADR-SEC-024 menetapkan KONSTRUKSI (polinomial reduksi).
> Ia TIDAK membuktikan kecukupan soundness.

Asumsi soundness yang bergantung pada pilihan field (termasuk margin
q=108 di atas Johnson bound pada |F| ≈ 2^192) adalah subjek pengujian
formal pada ADR-SEC-023 oleh auditor eksternal.

Bila ADR-SEC-023 menemukan margin tidak cukup pada konstruksi x³−x−1,
ADR-SEC-024 wajib ditinjau ulang.

---

## §6 — Keputusan Final

### Ratifikasi

> "Saya, bertindak sebagai Arsitek Keamanan Protokol Utama, dengan ini
> menetapkan polinomial P(x) = x³ − x − 1 sebagai polinomial reduksi
> OSSIFIED untuk pembentukan Ekstensi Kubik GF(p³) di dalam ekosistem
> Scalar Network. Irreducibilitasnya atas prima Goldilocks telah
> divalidasi, dan keselarasan ukuran lapangannya |F| ≈ 2^192 telah
> disahkan. Keputusan konstruksi (E-1) dinyatakan TUTUP, dengan
> pemisahan tegas bahwa validasi margin soundness akhir (q=108) tetap
> berada di bawah otorisasi audit independen ADR-SEC-023."

**Status: RATIFIED & FROZEN**  
**Tanggal: 2026-06-14**

### Status Komponen

| Komponen | Status |
|----------|--------|
| Polinomial reduksi x³−x−1 | RATIFIED & FROZEN |
| Irreducibility | DISAHKAN (§3.1) |
| Keselarasan \|F\| ≈ 2^192 | DISAHKAN (§3.2) |
| Kecukupan soundness q=108 | TETAP estimasi — ADR-SEC-023 (eksternal) |

### Konsekuensi

- E-1 ditutup secara formal; field kubik tidak lagi menjadi blocker arsitektur.
- Perubahan polinomial reduksi memerlukan ADR baru + hard fork (OSSIFIED).
- Phase 0 RecursiveVerifierAir tetap diblokir secara terpisah.

---

## §7 — Referensi

- SCALAR-SECURITY §[PROOF-PARAMS] — parameter OSSIFIED (sumber tunggal)
- SCALAR-SECURITY §1.3 — kalkulasi ε komponen ekstensi kubik
- SCALAR-TECHNICAL §1.4 — forward reference ke §[PROOF-PARAMS]
- p3-goldilocks 0.6.1 src/extension.rs — CubicTrinomialExtendable
- Commit 1845801 — HEAD main scalar-core
- G-25b — Poseidon2 KAT PASS confirmation
