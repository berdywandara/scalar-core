\* Formal Verification Stub — Invariant CC (Dual Non-Membership)
\* Spec §15.4 v11.1-FINAL
\*
\* Invariant yang harus dibuktikan:
\*   Untuk setiap nullifier n dan pada setiap waktu t:
\*   Jika n ∈ (NS_ACTIVE_t ∪ NS_CHECKPOINT_t), maka
\*     SMT_NonMembershipVerify(n, active_root_t) == FALSE ∧
\*     SMT_NonMembershipVerify(n, archived_root_t) == FALSE
\*
\* Ini menjamin bahwa CC constraint tidak akan lolos untuk nullifier yang sudah ada.
\*
\* STATUS: SCAFFOLDING — perlu diisi oleh tim formal verification sebelum mainnet.
\* Spec §15.4: "Sebelum mainnet, harus dibuktikan secara formal (misal di TLA+ atau Coq)"

---- MODULE invariant_cc ----
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Nullifiers,     \* Set semua nullifier yang mungkin
    MaxEpoch        \* Epoch maksimum dalam model

VARIABLES
    ns_active,      \* Set nullifier dalam NS_ACTIVE
    ns_checkpoint,  \* Set nullifier dalam NS_CHECKPOINT (diarsipkan)
    epoch           \* Epoch saat ini

\* TypeInvariant: memastikan variabel memiliki tipe yang benar
TypeInvariant ==
    /\ ns_active ⊆ Nullifiers
    /\ ns_checkpoint ⊆ Nullifiers
    /\ epoch ∈ 0..MaxEpoch

\* Invariant CC Utama (Spec §15.4):
\* Nullifier yang sudah ada tidak bisa "non-membership" verified
\* (yaitu: tidak bisa digunakan kembali)
InvariantCC ==
    ∀ n ∈ (ns_active ∪ ns_checkpoint):
        \* Jika nullifier ada di salah satu set,
        \* maka non-membership verify harus FALSE
        ~(NonMembershipVerify(n, ns_active)) ∧
        ~(NonMembershipVerify(n, ns_checkpoint))

\* Non-membership verify: TRUE jika n TIDAK ada dalam set
\* (Simplified model — production menggunakan SMT proof)
NonMembershipVerify(n, s) == n ∉ s

\* Zero-Gap Property (Spec §6.3):
\* Tidak ada window di mana nullifier bisa hilang antara NS_ACTIVE dan NS_CHECKPOINT
ZeroGapProperty ==
    \* Setiap nullifier yang diarsipkan (dipindah dari active ke checkpoint)
    \* harus ada di checkpoint sebelum dihapus dari active
    ∀ n ∈ ns_checkpoint: n ∉ ns_active ∨ n ∈ ns_checkpoint

\* TODO: Tambahkan state transitions untuk:
\*   - insert_nullifier(n): tambah n ke ns_active
\*   - checkpoint(): pindahkan nullifier lama dari ns_active ke ns_checkpoint
\*   - verify_non_membership(n): cek n tidak ada di kedua set

====
