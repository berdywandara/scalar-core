#!/usr/bin/env bash
# scripts/deploy_node.sh — Deploy scalar-node ke VPS baru
# SCALAR-TECHNICAL §10.5
#
# Usage:
#   bash deploy_node.sh                        # interactive keygen
#   bash deploy_node.sh --node-id=1            # label untuk logging
#
# Jalankan sebagai user biasa (bukan root).
# Script ini akan meminta sudo saat diperlukan.

set -euo pipefail

REPO_URL="https://github.com/berdywandara/scalar-core.git"
INSTALL_DIR="$HOME/scalar-core"
KEYSTORE_DIR="/etc/scalar"
KEYSTORE_FILE="$KEYSTORE_DIR/node_keystore.bin"
PASSPHRASE_FILE="$KEYSTORE_DIR/.passphrase"
SERVICE_FILE="/etc/systemd/system/scalar-node.service"
RPC_PORT=7777
P2P_PORT=17777

# Bootstrap peers (semua Oracle nodes saling dial)
BOOTSTRAP_PEERS=(
  "/ip4/132.145.39.75/tcp/17777"
  "/ip4/132.226.130.138/tcp/17777"
  "/ip4/145.241.205.71/tcp/17777"
  "/ip4/140.238.72.52/tcp/17777"
  "/ip4/140.238.91.78/tcp/17777"
)

echo "=============================================="
echo "  SCALAR NODE DEPLOYMENT"
echo "  Repo  : $REPO_URL"
echo "  Dir   : $INSTALL_DIR"
echo "=============================================="

# ── Step 1: System dependencies ───────────────────────────────────
echo "[1/7] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
  git curl build-essential pkg-config libssl-dev \
  ca-certificates

# ── Step 2: Install Rust ──────────────────────────────────────────
echo "[2/7] Installing Rust..."
if ! command -v cargo &> /dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable
  source "$HOME/.cargo/env"
else
  echo "  Rust already installed: $(rustc --version)"
fi

# Ensure cargo is in PATH
source "$HOME/.cargo/env" 2>/dev/null || true

# ── Step 3: Clone repo ────────────────────────────────────────────
echo "[3/7] Cloning scalar-core..."
if [ -d "$INSTALL_DIR" ]; then
  cd "$INSTALL_DIR"
  git pull origin main
  echo "  Repository updated."
else
  git clone "$REPO_URL" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
fi

# ── Step 4: Build release binary ─────────────────────────────────
echo "[4/7] Building scalar-node (release)..."
echo "  This may take 10-20 minutes on first build..."
cargo build --release -p scalar-node
echo "  Build complete: $INSTALL_DIR/target/release/scalar-node"

# ── Step 5: Keygen ───────────────────────────────────────────────
echo "[5/7] Generating node keystore..."
sudo mkdir -p "$KEYSTORE_DIR"
sudo chown "$(whoami):$(whoami)" "$KEYSTORE_DIR"

if [ -f "$KEYSTORE_FILE" ]; then
  echo "  Keystore already exists: $KEYSTORE_FILE"
  echo "  Skipping keygen. Delete $KEYSTORE_FILE to regenerate."
else
  echo ""
  echo "  NOTICE: Prepare a 12-word mnemonic (first word: 'scalar')"
  echo "  Mnemonic will be prompted securely (hidden input)."
  echo ""
  ./target/release/scalar-node keygen --generate \
    --keystore="$KEYSTORE_FILE" \
    --genesis-hash="$(cat genesis_hash.txt)"
fi

# ── Step 6: Passphrase file for systemd ─────────────────────────────────────
echo "[6/7] Setting up passphrase file..."
if [ ! -f "$PASSPHRASE_FILE" ]; then
  echo "  Enter the same passphrase used during keygen:"
  sudo bash -c "read -rsp '  Passphrase: ' p && echo && printf '%s' \"\$p\" > \"$PASSPHRASE_FILE\" && chmod 600 \"$PASSPHRASE_FILE\" && chown $(whoami):$(whoami) \"$PASSPHRASE_FILE\""
  echo "  Passphrase file created: $PASSPHRASE_FILE (chmod 600)"
else
  echo "  Passphrase file already exists."
fi
fi

# ── Step 7: Systemd service ───────────────────────────────────────
echo "[7/7] Creating systemd service..."

# Build dial arguments
DIAL_ARGS=""
THIS_IP=$(curl -s ifconfig.me 2>/dev/null || echo "")
for peer in "${BOOTSTRAP_PEERS[@]}"; do
  # Skip jika ini adalah IP node sendiri
  if [[ "$peer" != *"$THIS_IP"* ]]; then
    DIAL_ARGS="$DIAL_ARGS --dial=$peer"
  fi
done

sudo tee "$SERVICE_FILE" > /dev/null << SERVICEEOF
[Unit]
Description=Scalar Network Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/target/release/scalar-node run \
  --keystore=$KEYSTORE_FILE \
  --passphrase-file=$PASSPHRASE_FILE \
  --port=$RPC_PORT \
  --p2p-port=$P2P_PORT \
  $DIAL_ARGS
Restart=always
RestartSec=15s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=scalar-node

[Install]
WantedBy=multi-user.target
SERVICEEOF

sudo systemctl daemon-reload
sudo systemctl enable scalar-node
sudo systemctl start scalar-node

echo ""
echo "=============================================="
echo "  DEPLOYMENT SELESAI"
echo "  Status  : $(sudo systemctl is-active scalar-node)"
echo "  Logs    : sudo journalctl -u scalar-node -f"
echo "  Keystore: $KEYSTORE_FILE"
echo "=============================================="
