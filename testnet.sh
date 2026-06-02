#!/usr/bin/env bash
# testnet.sh — Scalar 7-node internal testnet
# Usage: ./testnet.sh {start|stop|status|logs|crash-test}
#        FAST=1 ./testnet.sh start     ← epoch 4 menit
#        CRASH=1 ./testnet.sh start    ← epoch 48 detik (WAL test)

set -e
BINARY="./target/release/scalar-node"
LOGDIR="./testnet-logs"
PIDFILE="./testnet.pids"

MODE_FLAG=""
[ "${FAST:-0}"  = "1" ] && MODE_FLAG="--fast"
[ "${CRASH:-0}" = "1" ] && MODE_FLAG="--crash-mode"

start() {
    [ -f "$PIDFILE" ] && { echo "Testnet running. Stop first: ./testnet.sh stop"; exit 1; }
    [ ! -f "$BINARY" ] && { echo "Build first: cargo build --release --bin scalar-node"; exit 1; }
    mkdir -p "$LOGDIR" testnet-wal

    P2P_A="/ip4/127.0.0.1/tcp/17777"

    echo "Starting 7-node testnet ${MODE_FLAG}..."
    "$BINARY" --port=7777 --p2p-port=17777 $MODE_FLAG > "$LOGDIR/node_a.log" 2>&1 & PID_A=$!
    sleep 2

    "$BINARY" --port=7778 --p2p-port=17778 --dial="$P2P_A" $MODE_FLAG > "$LOGDIR/node_b.log" 2>&1 & PID_B=$!
    "$BINARY" --port=7779 --p2p-port=17779 --dial="$P2P_A" $MODE_FLAG > "$LOGDIR/node_c.log" 2>&1 & PID_C=$!
    "$BINARY" --port=7780 --p2p-port=17780 --dial="$P2P_A" $MODE_FLAG > "$LOGDIR/node_d.log" 2>&1 & PID_D=$!
    "$BINARY" --port=7781 --p2p-port=17781 --dial="$P2P_A" $MODE_FLAG > "$LOGDIR/node_e.log" 2>&1 & PID_E=$!
    "$BINARY" --port=7782 --p2p-port=17782 --dial="$P2P_A" $MODE_FLAG > "$LOGDIR/node_f.log" 2>&1 & PID_F=$!
    "$BINARY" --port=7783 --p2p-port=17783 --dial="$P2P_A" $MODE_FLAG > "$LOGDIR/node_g.log" 2>&1 & PID_G=$!

    echo "$PID_A $PID_B $PID_C $PID_D $PID_E $PID_F $PID_G" > "$PIDFILE"
    echo ""
    echo "Nodes: A:7777 B:7778 C:7779 D:7780 E:7781 F:7782 G:7783"
    echo "Commands: ./testnet.sh {stop|status|logs}"
}

stop() {
    [ ! -f "$PIDFILE" ] && { echo "Not running."; exit 0; }
    while read -r pid; do
        kill "$pid" 2>/dev/null && echo "Stopped $pid" || true
    done < <(cat "$PIDFILE" | tr ' ' '\n')
    rm -f "$PIDFILE"
    echo "Testnet stopped."
}

status() {
    echo "=== Testnet Status ==="
    for port in 7777 7778 7779 7780 7781 7782 7783; do
        r=$(curl -s --max-time 1 "http://localhost:$port/get_status" 2>/dev/null | \
            python3 -c "import sys,json; d=json.load(sys.stdin); print(d['result']['status'])" 2>/dev/null || echo "DOWN")
        printf "  Node %s [:%-4s] %s\n" "$(echo $port | python3 -c "import sys; p=int(sys.stdin.read().strip()); print(chr(65+p-7777))")" "$port" "$r"
    done
}

logs() {
    [ ! -d "$LOGDIR" ] && { echo "No logs."; exit 1; }
    tail -f "$LOGDIR"/node_*.log
}

crash_test() {
    echo "=== WAL Crash Recovery Test ==="
    echo "Step 1: Start Node A in crash-mode (epoch=48s) with --crash-after-prepare"
    mkdir -p testnet-wal testnet-logs

    # Bersihkan WAL lama untuk node 7791
    rm -rf testnet-wal/node-7791

    "$BINARY" --port=7791 --p2p-port=17791 --crash-mode --crash-after-prepare \
        > "$LOGDIR/crash_test.log" 2>&1
    EXIT_CODE=$?

    echo ""
    echo "Step 2: Node exited (code=$EXIT_CODE). WAL files:"
    ls -la testnet-wal/node-7791/ 2>/dev/null || echo "  (no WAL files)"

    echo ""
    echo "Step 3: Restart node WITHOUT crash flag — check recovery"
    "$BINARY" --port=7791 --p2p-port=17791 --crash-mode \
        > "$LOGDIR/crash_recovery.log" 2>&1 &
    RPID=$!
    sleep 10
    kill $RPID 2>/dev/null

    echo ""
    echo "=== Crash node log ==="
    grep -E "PREPARE|CRASH|WAL|EPOCH" "$LOGDIR/crash_test.log" | tail -10

    echo ""
    echo "=== Recovery node log ==="
    grep -E "CRASH RECOVERY|PREPARE|WAL|clean start" "$LOGDIR/crash_recovery.log" | head -10

    if grep -q "CRASH RECOVERY" "$LOGDIR/crash_recovery.log"; then
        echo ""
        echo "✅ WAL CRASH RECOVERY VERIFIED"
    else
        echo ""
        echo "⚠️  CRASH RECOVERY not triggered (may need longer wait)"
    fi
}

case "${1:-}" in
    start)      start ;;
    stop)       stop  ;;
    status)     status ;;
    logs)       logs  ;;
    crash-test) crash_test ;;
    *)
        echo "Usage: $0 {start|stop|status|logs|crash-test}"
        echo "  FAST=1 ./testnet.sh start    ← 7 node, epoch ~4 menit"
        echo "  CRASH=1 ./testnet.sh start   ← 7 node, epoch ~48 detik"
        echo "  ./testnet.sh crash-test       ← WAL crash recovery test"
        ;;
esac
