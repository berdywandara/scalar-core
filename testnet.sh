#!/usr/bin/env bash
# testnet.sh — Start 3-node internal testnet
# Usage: ./testnet.sh [start|stop|status|logs]

set -e
BINARY="./target/release/scalar-node"
LOGDIR="./testnet-logs"
PIDFILE="./testnet.pids"

start() {
    [ -f "$PIDFILE" ] && { echo "Testnet already running. Run: ./testnet.sh stop"; exit 1; }
    [ ! -f "$BINARY" ] && { echo "Binary not found. Run: cargo build --release --bin scalar-node"; exit 1; }
    mkdir -p "$LOGDIR"

    echo "Starting Node A (RPC :7777, P2P :17777)..."
    "$BINARY" --port=7777 --p2p-port=17777 \
        > "$LOGDIR/node_a.log" 2>&1 &
    PID_A=$!

    sleep 2  # wait for A to be up and listening

    # Get Node A's actual P2P address
    P2P_A="/ip4/127.0.0.1/tcp/17777"
    echo "  Node A PID=$PID_A, P2P=$P2P_A"

    echo "Starting Node B (RPC :7778, P2P :17778)..."
    "$BINARY" --port=7778 --p2p-port=17778 --dial="$P2P_A" \
        > "$LOGDIR/node_b.log" 2>&1 &
    PID_B=$!
    echo "  Node B PID=$PID_B"

    sleep 1

    echo "Starting Node C (RPC :7779, P2P :17779)..."
    "$BINARY" --port=7779 --p2p-port=17779 --dial="$P2P_A" \
        > "$LOGDIR/node_c.log" 2>&1 &
    PID_C=$!
    echo "  Node C PID=$PID_C"

    echo "$PID_A $PID_B $PID_C" > "$PIDFILE"
    echo ""
    echo "Testnet running. Nodes:"
    echo "  A → http://localhost:7777  (P2P :17777)"
    echo "  B → http://localhost:7778  (P2P :17778)"
    echo "  C → http://localhost:7779  (P2P :17779)"
    echo ""
    echo "Commands:"
    echo "  ./testnet.sh status    — cek semua node"
    echo "  ./testnet.sh logs      — tail logs"
    echo "  ./testnet.sh stop      — matikan semua node"
}

stop() {
    [ ! -f "$PIDFILE" ] && { echo "No testnet running."; exit 0; }
    read -r PID_A PID_B PID_C < "$PIDFILE"
    for pid in $PID_A $PID_B $PID_C; do
        kill "$pid" 2>/dev/null && echo "Stopped PID $pid" || echo "PID $pid already gone"
    done
    rm -f "$PIDFILE"
    echo "Testnet stopped."
}

status() {
    echo "=== Testnet Status ==="
    for port in 7777 7778 7779; do
        label="Node$(( (port - 7777) + 65 ))"  # A, B, C
        result=$(curl -s --max-time 2 "http://localhost:$port/get_status" 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo "[$label :$port] UP — $result"
        else
            echo "[$label :$port] DOWN"
        fi
    done

    if [ -f "$PIDFILE" ]; then
        read -r PID_A PID_B PID_C < "$PIDFILE"
        echo ""
        echo "PIDs: A=$PID_A B=$PID_B C=$PID_C"
        for pid in $PID_A $PID_B $PID_C; do
            kill -0 "$pid" 2>/dev/null && echo "  PID $pid: alive" || echo "  PID $pid: dead"
        done
    fi
}

logs() {
    [ ! -d "$LOGDIR" ] && { echo "No logs found."; exit 1; }
    tail -f "$LOGDIR"/node_*.log
}

case "${1:-}" in
    start)  start ;;
    stop)   stop  ;;
    status) status ;;
    logs)   logs  ;;
    *)
        echo "Usage: $0 {start|stop|status|logs}"
        echo ""
        echo "  start   — jalankan 3 node di background"
        echo "  stop    — matikan semua node"
        echo "  status  — cek status via RPC"
        echo "  logs    — tail semua log"
        ;;
esac
