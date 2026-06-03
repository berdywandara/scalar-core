# Phase 3 — External Testnet Report

**Date:** 2026-06-03  
**Status:** ✅ PASS — 7-node quorum 5/7

## Node Registry

| Node | Location | Port | NodeID |
|------|----------|------|--------|
| Node-1 | VPS-1 | :17777 | 5da931cf |
| Node-2 | VPS-2 | :17777 | 5da931cf |
| Node-3 | Codespace | :17779 | 10da95c9 |
| Node-4 | Codespace | :17780 | 66b7b22a |
| Node-5 | Codespace | :17781 | fe588e08 |
| Node-6 | Codespace | :17782 | e34275e9 |
| Node-7 | Codespace | :17783 | 4fd142c4 |

## Test Results

| Test | Result | Catatan |
|------|--------|---------|
| 7-node P2P mesh | ✅ PASS | Semua node terhubung |
| Cross-machine HB exchange | ✅ PASS | VPS ↔ Codespace verified |
| Gossipsub propagation (relay) | ✅ PASS | HB relay tanpa dial langsung |
| Persistent PeerID across restart | ✅ PASS | keypair.bin persisted |
| Auto-reconnect 30s | ✅ PASS | libp2p retry + 30s interval |
| SeqNum reset on disconnect | ✅ PASS | Tidak ada SeqNumNotMonotonic |
| Node survival SSH disconnect | ✅ PASS | screen session independent |
| Quorum 5/7 reachable | ✅ PASS | 5 node tetap aktif saat 1 down |
| Tier A restart resilience | ✅ PASS | Node-1 restart, jaringan tidak putus |
| HB continuity during restart | ✅ PASS | 5 node relay HB selama restart |

## Tier A Restart Test

Node-1 (VPS-1) di-restart saat 6 node lain aktif:

- Node-1 reconnect dalam **<5 detik** setelah restart
- Node-2 dan Codespace nodes **tidak kehilangan konektivitas**
- HB dari 5 node Codespace tetap mengalir via gossipsub mesh
- Seq reset otomatis saat disconnect — tidak ada rejection
- Jaringan **tidak pernah turun** selama restart Tier A node

## Gossipsub Mesh Behavior

KeepAliveTimeout dan Closed disconnect adalah behavior normal gossipsub —
mesh secara aktif memprune dan graft koneksi untuk efisiensi.
HB tetap terdelivery melalui jalur alternatif di mesh (relay).

## Fixes Implemented

| Commit | Fix |
|--------|-----|
| d66de3e | Persistent keypair — stable PeerID across restart |
| d5c0749 | Allow seq=1 as valid restart per spec T-5 |
| bf9bee3 | Reset peer seq on disconnect |
| dc34649 | Auto-reconnect bootstrap peers every 30s |
