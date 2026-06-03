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

| Test | Result |
|------|--------|
| 7-node P2P mesh | ✅ PASS |
| Cross-machine HB exchange | ✅ PASS |
| Gossipsub propagation (relay) | ✅ PASS |
| Persistent PeerID across restart | ✅ PASS |
| Auto-reconnect 30s | ✅ PASS |
| SeqNum reset on disconnect | ✅ PASS |
| Node survival SSH disconnect | ✅ PASS |
| Quorum 5/7 reachable | ✅ PASS |
