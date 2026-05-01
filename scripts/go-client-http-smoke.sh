#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GO_REPO=${GO_REPO:-/home/inseo/portal-tunnel-main}
IMAGE=${IMAGE:-portal-relay-rs:local}
NAME=${NAME:-portal-relay-rs-go-smoke}
API_PORT=${API_PORT:-18017}
SNI_PORT=${SNI_PORT:-18443}
UPSTREAM_PORT=${UPSTREAM_PORT:-18080}
LEASE_NAME=${LEASE_NAME:-rustsmoke}
STATE_DIR=${STATE_DIR:-$(mktemp -d)}
LOG_DIR=${LOG_DIR:-$(mktemp -d)}

cleanup() {
  [[ -n ${CLI_PID:-} ]] && kill "$CLI_PID" >/dev/null 2>&1 || true
  [[ -n ${HTTP_PID:-} ]] && kill "$HTTP_PID" >/dev/null 2>&1 || true
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if [[ ${KEEP_ARTIFACTS:-0} != 1 ]]; then
    rm -rf "$STATE_DIR" "$LOG_DIR"
  else
    echo "kept artifacts: state=$STATE_DIR logs=$LOG_DIR" >&2
  fi
}
trap cleanup EXIT

if [[ ! -d "$GO_REPO/cmd/portal-tunnel" ]]; then
  echo "Go portal-tunnel repo not found at $GO_REPO" >&2
  exit 2
fi

mkdir -p "$STATE_DIR" "$LOG_DIR"
chmod 0777 "$STATE_DIR"

docker build -t "$IMAGE" "$ROOT" >/dev/null
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
  if curl -kfsS "https://127.0.0.1:${API_PORT}/healthz" >/dev/null; then
    break
  fi
  sleep 0.25
done
curl -kfsS "https://127.0.0.1:${API_PORT}/healthz" >/dev/null

python3 - <<PY >"$LOG_DIR/upstream.log" 2>&1 &
import http.server, socketserver
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"portal-rs-go-smoke-ok\n"
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        pass
with socketserver.TCPServer(("127.0.0.1", $UPSTREAM_PORT), Handler) as httpd:
    httpd.serve_forever()
PY
HTTP_PID=$!

for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:${UPSTREAM_PORT}/" >/dev/null; then
    break
  fi
  sleep 0.25
done
curl -fsS "http://127.0.0.1:${UPSTREAM_PORT}/" >/dev/null

(
  cd "$GO_REPO"
  docker run --rm --network host \
    -v "$GO_REPO:/src" \
    -w /src \
    golang:1 \
    sh -lc "/usr/local/go/bin/go run ./cmd/portal-tunnel expose 127.0.0.1:${UPSTREAM_PORT} --name ${LEASE_NAME} --relays https://localhost:${API_PORT} --discovery=false --ban-mitm=false"
) >"$LOG_DIR/portal-cli.log" 2>&1 &
CLI_PID=$!

for _ in $(seq 1 160); do
  if grep -q "service ready" "$LOG_DIR/portal-cli.log"; then
    break
  fi
  if ! kill -0 "$CLI_PID" >/dev/null 2>&1; then
    cat "$LOG_DIR/portal-cli.log" >&2 || true
    echo "portal CLI exited before ready" >&2
    exit 1
  fi
  sleep 0.25
done
if ! grep -q "service ready" "$LOG_DIR/portal-cli.log"; then
  cat "$LOG_DIR/portal-cli.log" >&2 || true
  echo "portal CLI did not become ready" >&2
  exit 1
fi

PUBLIC_HOST="${LEASE_NAME}.localhost"
BODY=$(curl -kfsS --resolve "${PUBLIC_HOST}:${SNI_PORT}:127.0.0.1" "https://${PUBLIC_HOST}:${SNI_PORT}/")
if [[ "$BODY" != "portal-rs-go-smoke-ok" ]]; then
  echo "unexpected body: $BODY" >&2
  cat "$LOG_DIR/portal-cli.log" >&2 || true
  exit 1
fi

echo "go client http smoke passed: https://${PUBLIC_HOST}:${SNI_PORT}/ -> $BODY"
