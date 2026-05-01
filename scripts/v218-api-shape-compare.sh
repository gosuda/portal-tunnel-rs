#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${IMAGE:-portal-relay-rs:local}
RUST_NAME=${RUST_NAME:-portal-relay-rs-api-compare}
GO_NAME=${GO_NAME:-portal-relay-go-api-compare}
GO_REPO_URL=${GO_REPO_URL:-https://github.com/gosuda/portal-tunnel.git}
GO_TAG=${GO_TAG:-v2.1.8}
GO_API_PORT=${GO_API_PORT:-18217}
GO_SNI_PORT=${GO_SNI_PORT:-18617}
RUST_API_PORT=${RUST_API_PORT:-18218}
RUST_SNI_PORT=${RUST_SNI_PORT:-18618}
WORK_DIR=${WORK_DIR:-$(mktemp -d)}
GO_STATE_DIR=${GO_STATE_DIR:-$(mktemp -d)}
RUST_STATE_DIR=${RUST_STATE_DIR:-$(mktemp -d)}
LOG_DIR=${LOG_DIR:-$(mktemp -d)}

cleanup() {
  [[ -n ${GO_PID:-} ]] && kill "$GO_PID" >/dev/null 2>&1 || true
  docker rm -f "$RUST_NAME" "$GO_NAME" >/dev/null 2>&1 || true
  if [[ ${KEEP_ARTIFACTS:-0} != 1 ]]; then
    rm -rf "$WORK_DIR" "$GO_STATE_DIR" "$RUST_STATE_DIR" "$LOG_DIR"
  else
    echo "kept artifacts: work=$WORK_DIR go_state=$GO_STATE_DIR rust_state=$RUST_STATE_DIR logs=$LOG_DIR" >&2
  fi
}
trap cleanup EXIT

mkdir -p "$WORK_DIR" "$GO_STATE_DIR" "$RUST_STATE_DIR" "$LOG_DIR"
chmod 0777 "$GO_STATE_DIR" "$RUST_STATE_DIR"

git clone --depth 1 --branch "$GO_TAG" "$GO_REPO_URL" "$WORK_DIR/portal-tunnel" >/dev/null

docker build -t "$IMAGE" "$ROOT" >/dev/null

docker run -d \
  --name "$RUST_NAME" \
  --network host \
  -e PORTAL_URL="https://localhost:${RUST_API_PORT}" \
  -e API_PORT="$RUST_API_PORT" \
  -e SNI_PORT="$RUST_SNI_PORT" \
  -e DISCOVERY=true \
  -e TCP_ENABLED=false \
  -e UDP_ENABLED=false \
  -e IDENTITY_PATH=/portal-certs \
  -v "$RUST_STATE_DIR:/portal-certs" \
  "$IMAGE" >/dev/null

(
  cd "$WORK_DIR/portal-tunnel"
  docker run --rm \
    --name "$GO_NAME" \
    --network host \
    -v "$WORK_DIR/portal-tunnel:/src" \
    -v "$GO_STATE_DIR:/go-state" \
    -w /src \
    -e PORTAL_URL="https://localhost:${GO_API_PORT}" \
    -e API_PORT="$GO_API_PORT" \
    -e SNI_PORT="$GO_SNI_PORT" \
    -e DISCOVERY=true \
    -e TCP_ENABLED=false \
    -e UDP_ENABLED=false \
    -e IDENTITY_PATH=/go-state \
    golang:1 \
    sh -lc '/usr/local/go/bin/go run ./cmd/relay-server serve'
) >"$LOG_DIR/go-relay.log" 2>&1 &
GO_PID=$!

for port in "$RUST_API_PORT" "$GO_API_PORT"; do
  for _ in $(seq 1 160); do
    curl -kfsS "https://127.0.0.1:${port}/healthz" >/dev/null 2>&1 && break
    sleep 0.5
  done
  curl -kfsS "https://127.0.0.1:${port}/healthz" >/dev/null || {
    echo "relay on API port $port did not become healthy" >&2
    cat "$LOG_DIR/go-relay.log" >&2 || true
    docker logs "$RUST_NAME" >&2 || true
    exit 1
  }
done

python3 - "$GO_API_PORT" "$RUST_API_PORT" <<'PY'
import json, ssl, sys, urllib.error, urllib.request

go_port, rust_port = sys.argv[1:3]
ctx = ssl._create_unverified_context()
checks = [
    ("healthz", "GET", "/healthz", None),
    ("sdk_domain", "GET", "/sdk/domain", None),
    ("register_challenge_invalid", "POST", "/sdk/register/challenge", b"{}"),
]

def fetch(port, method, path, body):
    req = urllib.request.Request(f"https://127.0.0.1:{port}{path}", data=body, method=method)
    req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
            data = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
        data = e.read()
    try:
        parsed = json.loads(data.decode())
    except Exception:
        parsed = {"_raw": data.decode(errors="replace")}
    return status, parsed

def shape(value):
    if isinstance(value, dict):
        return {k: shape(v) for k, v in sorted(value.items()) if k not in {"release_version", "message", "expires_at", "access_token"}}
    if isinstance(value, list):
        return [shape(v) for v in value]
    return type(value).__name__

failures = []
for name, method, path, body in checks:
    go_status, go_json = fetch(go_port, method, path, body)
    rust_status, rust_json = fetch(rust_port, method, path, body)
    go_shape = shape(go_json)
    rust_shape = shape(rust_json)
    print(f"{name}: go_status={go_status} rust_status={rust_status}")
    print(f"  go_shape={json.dumps(go_shape, sort_keys=True)}")
    print(f"  rs_shape={json.dumps(rust_shape, sort_keys=True)}")
    if go_status != rust_status or go_shape != rust_shape:
        failures.append(name)

# Discovery is intentionally checked as an envelope contract rather than a
# byte-for-byte/list-shape comparison. The official Go relay includes public
# registry bootstrap relays when discovery is enabled; the Rust smoke relay only
# advertises itself. Both must still expose the same top-level v2.1.8 discovery
# envelope and required descriptor fields.
for label, port in (("go", go_port), ("rust", rust_port)):
    status, payload = fetch(port, "GET", "/discovery", None)
    print(f"discovery_{label}: status={status}")
    print(f"  shape={json.dumps(shape(payload), sort_keys=True)}")
    data = payload.get("data") if isinstance(payload, dict) else None
    relays = data.get("relays") if isinstance(data, dict) else None
    if status != 200 or not isinstance(relays, list) or not relays:
        failures.append(f"discovery_{label}")
        continue
    for field in ("protocol_version", "generated_at"):
        if field not in data:
            failures.append(f"discovery_{label}_{field}")
    required_descriptor_fields = {"address", "version", "issued_at", "api_https_addr", "signature"}
    missing = required_descriptor_fields - set(relays[0])
    if missing:
        failures.append(f"discovery_{label}_descriptor_missing_{'_'.join(sorted(missing))}")

if failures:
    raise SystemExit("API shape mismatch: " + ", ".join(failures))
print("v2.1.8 Go relay vs Rust relay API shape comparison passed")
PY
