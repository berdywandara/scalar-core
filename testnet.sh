#!/usr/bin/env bash
# ============================================================
# SCALAR TESTNET — Minimal 3-Node Setup
# Jalankan di 3 terminal terpisah:
#   Terminal 1: bash testnet.sh node-a
#   Terminal 2: bash testnet.sh node-b
#   Terminal 3: bash testnet.sh node-c
# ============================================================

NODE=$1
BIN="./target/release/scalar-node"

case "$NODE" in
  node-a)
    echo "Starting Node A (bootstrap)"
    $BIN --port=7777 --p2p-port=10000
    ;;
  node-b)
    echo "Starting Node B → dial A"
    sleep 2  # tunggu A ready
    $BIN --port=7778 --p2p-port=10001 \
         --dial=/ip4/127.0.0.1/tcp/10000
    ;;
  node-c)
    echo "Starting Node C → dial A"
    sleep 3  # tunggu A+B ready
    $BIN --port=7779 --p2p-port=10002 \
         --dial=/ip4/127.0.0.1/tcp/10000
    ;;
  *)
    echo "Usage: bash testnet.sh [node-a|node-b|node-c]"
    echo ""
    echo "Terminal 1: bash testnet.sh node-a"
    echo "Terminal 2: bash testnet.sh node-b"
    echo "Terminal 3: bash testnet.sh node-c"
    ;;
esac
