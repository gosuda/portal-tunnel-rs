#!/usr/bin/env bash
set -euo pipefail

VERSION=${VERSION:-v2.1.8}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${IMAGE:-portal-relay-rs:local}
NAME=${NAME:-portal-relay-rs-v218-tcp-smoke}
API_PORT=${API_PORT:-18118}
SNI_PORT=${SNI_PORT:-18544}
TCP_UPSTREAM_PORT=${TCP_UPSTREAM_PORT:-18181}
LEASE_PORT=${LEASE_PORT:-19181}
LEASE_NAME=${LEASE_NAME:-v218tcp}
STATE_DIR=${STATE_DIR:-$(mktemp -d)}
LOG_DIR=${LOG_DIR:-$(mktemp -d)}
BIN_DIR=${BIN_DIR:-$(mktemp -d)}

cleanup() {
  [[ -n ${CLI_PID:-} ]] && kill "$CLI_PID" >/dev/null 2>&1 || true
  [[ -n ${TCP_PID:-} ]] && kill "$TCP_PID" >/dev/null 2>&1 || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if [[ ${KEEP_ARTIFACTS:-0} != 1 ]]; then
    rm -rf "$STATE_DIR" "$LOG_DIR" "$BIN_DIR"
  else
    echo "kept artifacts: state=$STATE_DIR logs=$LOG_DIR bin=$BIN_DIR" >&2
  fi
}
trap cleanup EXIT

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) ASSET=portal-linux-amd64 ;;
  Linux-aarch64|Linux-arm64) ASSET=portal-linux-arm64 ;;
  *) echo "unsupported host: $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac
BASE_URL="https://github.com/gosuda/portal-tunnel/releases/download/${VERSION}"
PORTAL_BIN="$BIN_DIR/$ASSET"
curl -fsSL "$BASE_URL/$ASSET" -o "$PORTAL_BIN"
curl -fsSL "$BASE_URL/$ASSET.sha256" -o "$BIN_DIR/$ASSET.sha256"
(cd "$BIN_DIR" && sha256sum -c "$ASSET.sha256")
chmod +x "$PORTAL_BIN"
"$PORTAL_BIN" version | tee "$LOG_DIR/portal-version.log"

docker build -t "$IMAGE" "$ROOT" >/dev/null
mkdir -p "$STATE_DIR" "$LOG_DIR"
chmod 0777 "$STATE_DIR"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d \
  --name "$NAME" \
  --network host \
  -e PORTAL_URL="https://localhost:${API_PORT}" \
  -e API_PORT="$API_PORT" \
  -e SNI_PORT="$SNI_PORT" \
  -e MIN_PORT="$LEASE_PORT" \
  -e MAX_PORT="$LEASE_PORT" \
  -e TCP_ENABLED=true \
  -e UDP_ENABLED=false \
  -e DISCOVERY=false \
  -e IDENTITY_PATH=/portal-certs \
  -v "$STATE_DIR:/portal-certs" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 80); do
  curl -kfsS "https://127.0.0.1:${API_PORT}/healthz" >/dev/null && break
  sleep 0.25
done
curl -kfsS "https://127.0.0.1:${API_PORT}/healthz" >/dev/null

python3 - <<PY >"$LOG_DIR/tcp-upstream.log" 2>&1 &
import socketserver
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(4096)
        self.request.sendall(b"tcp-echo:" + data)
class Server(socketserver.TCPServer):
    allow_reuse_address = True
with Server(("127.0.0.1", $TCP_UPSTREAM_PORT), Handler) as server:
    server.serve_forever()
PY
TCP_PID=$!

for _ in $(seq 1 40); do
  python3 - <<PY >/dev/null 2>&1 && break || true
import socket
s=socket.create_connection(("127.0.0.1", $TCP_UPSTREAM_PORT), timeout=0.5)
s.close()
PY
  if ! kill -0 "$TCP_PID" >/dev/null 2>&1; then
    cat "$LOG_DIR/tcp-upstream.log" >&2 || true
    echo "TCP upstream exited before ready" >&2
    exit 1
  fi
  sleep 0.25
done

(
  cd "$LOG_DIR"
  "$PORTAL_BIN" expose "127.0.0.1:${TCP_UPSTREAM_PORT}" \
    --name "$LEASE_NAME" \
    --tcp \
    --relays "https://localhost:${API_PORT}" \
    --discovery=false \
    --ban-mitm=false
) >"$LOG_DIR/portal-cli.log" 2>&1 &
CLI_PID=$!

for _ in $(seq 1 160); do
  grep -q "service ready" "$LOG_DIR/portal-cli.log" && break
  if ! kill -0 "$CLI_PID" >/dev/null 2>&1; then
    cat "$LOG_DIR/portal-cli.log" >&2 || true
    echo "portal $VERSION CLI exited before ready" >&2
    exit 1
  fi
  sleep 0.25
done
grep -q "service ready" "$LOG_DIR/portal-cli.log" || { cat "$LOG_DIR/portal-cli.log" >&2; exit 1; }

BODY=$(python3 - <<PY
import socket
s=socket.create_connection(("127.0.0.1", $LEASE_PORT), timeout=5)
s.sendall(b"hello-v218-tcp")
print(s.recv(4096).decode())
s.close()
PY
)
if [[ "$BODY" != "tcp-echo:hello-v218-tcp" ]]; then
  echo "unexpected TCP body: $BODY" >&2
  cat "$LOG_DIR/portal-cli.log" >&2 || true
  exit 1
fi

echo "official $VERSION CLI TCP smoke passed: 127.0.0.1:${LEASE_PORT} -> $BODY"
