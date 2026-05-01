#!/usr/bin/env bash
set -euo pipefail

VERSION=${VERSION:-v2.1.8}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${IMAGE:-portal-relay-rs:local}
NAME=${NAME:-portal-relay-rs-v218-udp-smoke}
API_PORT=${API_PORT:-18128}
SNI_PORT=${SNI_PORT:-18654}
HTTP_UPSTREAM_PORT=${HTTP_UPSTREAM_PORT:-18182}
UDP_UPSTREAM_PORT=${UDP_UPSTREAM_PORT:-18183}
LEASE_PORT=${LEASE_PORT:-19182}
LEASE_NAME=${LEASE_NAME:-v218udp}
STATE_DIR=${STATE_DIR:-$(mktemp -d)}
LOG_DIR=${LOG_DIR:-$(mktemp -d)}
BIN_DIR=${BIN_DIR:-$(mktemp -d)}

cleanup() {
  [[ -n ${CLI_PID:-} ]] && kill "$CLI_PID" >/dev/null 2>&1 || true
  [[ -n ${HTTP_PID:-} ]] && kill "$HTTP_PID" >/dev/null 2>&1 || true
  [[ -n ${UDP_PID:-} ]] && kill "$UDP_PID" >/dev/null 2>&1 || true
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
  -e TCP_ENABLED=false \
  -e UDP_ENABLED=true \
  -e DISCOVERY=false \
  -e IDENTITY_PATH=/portal-certs \
  -v "$STATE_DIR:/portal-certs" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 80); do
  curl -kfsS "https://127.0.0.1:${API_PORT}/healthz" >/dev/null && break
  sleep 0.25
done
curl -kfsS "https://127.0.0.1:${API_PORT}/healthz" >/dev/null

python3 - <<PY >"$LOG_DIR/http-upstream.log" 2>&1 &
import http.server, socketserver
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=b"udp-http-ready\n"
        self.send_response(200)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args): pass
class Server(socketserver.TCPServer): allow_reuse_address=True
with Server(("127.0.0.1", $HTTP_UPSTREAM_PORT), Handler) as server:
    server.serve_forever()
PY
HTTP_PID=$!

python3 - <<PY >"$LOG_DIR/udp-upstream.log" 2>&1 &
import socket
sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", $UDP_UPSTREAM_PORT))
while True:
    data, addr = sock.recvfrom(4096)
    sock.sendto(b"udp-echo:" + data, addr)
PY
UDP_PID=$!

for _ in $(seq 1 40); do
  curl -fsS "http://127.0.0.1:${HTTP_UPSTREAM_PORT}/" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -fsS "http://127.0.0.1:${HTTP_UPSTREAM_PORT}/" >/dev/null

(
  cd "$LOG_DIR"
  "$PORTAL_BIN" expose "127.0.0.1:${HTTP_UPSTREAM_PORT}" \
    --name "$LEASE_NAME" \
    --udp \
    --udp-addr "127.0.0.1:${UDP_UPSTREAM_PORT}" \
    --relays "https://localhost:${API_PORT}" \
    --discovery=false \
    --ban-mitm=false
) >"$LOG_DIR/portal-cli.log" 2>&1 &
CLI_PID=$!

for _ in $(seq 1 200); do
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
sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.sendto(b"hello-v218-udp", ("127.0.0.1", $LEASE_PORT))
data, addr = sock.recvfrom(4096)
print(data.decode())
PY
)
if [[ "$BODY" != "udp-echo:hello-v218-udp" ]]; then
  echo "unexpected UDP body: $BODY" >&2
  cat "$LOG_DIR/portal-cli.log" >&2 || true
  exit 1
fi

echo "official $VERSION CLI UDP smoke passed: 127.0.0.1:${LEASE_PORT}/udp -> $BODY"
