#!/usr/bin/env bash
set -euo pipefail

VERSION=${VERSION:-v2.1.8}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${IMAGE:-portal-relay-rs:local}
NAME=${NAME:-portal-relay-rs-v218-lifecycle-smoke}
API_PORT=${API_PORT:-18138}
SNI_PORT=${SNI_PORT:-18664}
UPSTREAM_PORT=${UPSTREAM_PORT:-18184}
LEASE_NAME=${LEASE_NAME:-v218life}
ENDURANCE_SECONDS=${ENDURANCE_SECONDS:-45}
STATE_DIR=${STATE_DIR:-$(mktemp -d)}
LOG_DIR=${LOG_DIR:-$(mktemp -d)}
BIN_DIR=${BIN_DIR:-$(mktemp -d)}

cleanup() {
  [[ -n ${CLI_PID:-} ]] && kill "$CLI_PID" >/dev/null 2>&1 || true
  [[ -n ${HTTP_PID:-} ]] && kill "$HTTP_PID" >/dev/null 2>&1 || true
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
  -e DISCOVERY=false \
  -e TCP_ENABLED=false \
  -e UDP_ENABLED=false \
  -e IDENTITY_PATH=/portal-certs \
  -v "$STATE_DIR:/portal-certs" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 80); do
  curl -kfsS "https://127.0.0.1:${API_PORT}/healthz" >/dev/null && break
  sleep 0.25
done
curl -kfsS "https://127.0.0.1:${API_PORT}/healthz" >/dev/null

python3 - <<PY >"$LOG_DIR/upstream.log" 2>&1 &
import http.server, socketserver, time
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=("life-ok:%d\n" % int(time.time())).encode()
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args): pass
class Server(socketserver.TCPServer): allow_reuse_address=True
with Server(("127.0.0.1", $UPSTREAM_PORT), Handler) as server:
    server.serve_forever()
PY
HTTP_PID=$!
for _ in $(seq 1 40); do
  curl -fsS "http://127.0.0.1:${UPSTREAM_PORT}/" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -fsS "http://127.0.0.1:${UPSTREAM_PORT}/" >/dev/null

(
  cd "$LOG_DIR"
  "$PORTAL_BIN" expose "127.0.0.1:${UPSTREAM_PORT}" \
    --name "$LEASE_NAME" \
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

PUBLIC_HOST="${LEASE_NAME}.localhost"
request_public() {
  curl -kfsS --resolve "${PUBLIC_HOST}:${SNI_PORT}:127.0.0.1" "https://${PUBLIC_HOST}:${SNI_PORT}/"
}

START=$(date +%s)
while (( $(date +%s) - START < ENDURANCE_SECONDS )); do
  BODY=$(request_public)
  [[ "$BODY" == life-ok:* ]] || { echo "unexpected body during endurance: $BODY" >&2; exit 1; }
  sleep 5
done
BODY=$(request_public)
[[ "$BODY" == life-ok:* ]] || { echo "unexpected body after endurance: $BODY" >&2; exit 1; }

kill "$CLI_PID" >/dev/null 2>&1 || true
wait "$CLI_PID" >/dev/null 2>&1 || true
unset CLI_PID
sleep 2
if request_public >/tmp/portal-lifecycle-after-kill.out 2>/tmp/portal-lifecycle-after-kill.err; then
  echo "public URL still reachable after CLI shutdown/unregister" >&2
  cat /tmp/portal-lifecycle-after-kill.out >&2 || true
  cat "$LOG_DIR/portal-cli.log" >&2 || true
  exit 1
fi

echo "official $VERSION CLI lifecycle smoke passed: renew endurance ${ENDURANCE_SECONDS}s and unregister cleanup"
