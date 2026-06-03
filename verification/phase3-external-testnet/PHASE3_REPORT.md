# Phase 3 — External Testnet Report

**Date:** 2026-06-03
**Status:** ✅ PASS

## Nodes

| Node | Location | IP | PeerID |
|------|----------|----|--------|
| Oracle VM-1 | UK London AD-2 | 132.145.39.75 | 12D3KooWQHTh5GuGyG7M2UnikxegxztqRPBVNKb83EzKpCDhF9rU |
| Oracle VM-2 | UK London AD-3 | 132.226.130.138 | 12D3KooWBbUH137REy5W8RLTQ4UWpqh5mwUETeqJmV3wtnafWPGJ |
| Codespace | GitHub (Codespace) | dynamic | 12D3KooWAMZ5XKZ8z8ejWaf6UrmmuszZ7i9MxhjWDkBv1P2CrYrH |

## Results

| Test | Result |
|------|--------|
| Cross-machine P2P connection | ✅ PASS |
| HB exchange verified (ACCEPT) | ✅ PASS |
| Persistent PeerID across restart | ✅ PASS |
| Auto-reconnect after restart (30s) | ✅ PASS |
| SeqNum reset on disconnect | ✅ PASS |
| Node survives SSH disconnect (screen) | ✅ PASS |

## Fixes Implemented

- feat: persistent keypair (d66de3e)
- fix: allow seq=1 as valid restart (d5c0749)
- fix: reset peer seq on disconnect (bf9bee3)
- feat: auto-reconnect bootstrap peers 30s (dc34649)
