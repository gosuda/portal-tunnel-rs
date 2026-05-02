#!/usr/bin/env bash
set -euo pipefail

IMAGE=${IMAGE:-portal-relay-rs:local}
API_PORT=${API_PORT:-18017}
SNI_PORT=${SNI_PORT:-18443}
NAME=${NAME:-portal-relay-rs-track0}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
STATE_DIR=${STATE_DIR:-$(mktemp -d)}

cleanup() {
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if [[ ${KEEP_STATE:-0} != 1 && -n ${STATE_DIR:-} && -d ${STATE_DIR:-} ]]; then
    rm -rf "$STATE_DIR"
  fi
}
trap cleanup EXIT

mkdir -p "$STATE_DIR"
chmod 0777 "$STATE_DIR"

docker build -t "$IMAGE" "$ROOT"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d \
  --name "$NAME" \
  -e PORTAL_URL="https://localhost:${API_PORT}" \
  -e API_PORT=4017 \
  -e SNI_PORT=443 \
  -e DISCOVERY=false \
  -e TCP_ENABLED=false \
  -e UDP_ENABLED=false \
  -e IDENTITY_PATH=/portal-certs \
  -v "$STATE_DIR:/portal-certs" \
  -p "127.0.0.1:${API_PORT}:4017/tcp" \
  -p "127.0.0.1:${SNI_PORT}:443/tcp" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 40); do
  if curl -kfsS "https://127.0.0.1:${API_PORT}/healthz" >/tmp/portal-relay-rs-health.json; then
    break
  fi
  sleep 0.25
done

printf 'health: '
cat /tmp/portal-relay-rs-health.json
printf '\n'

printf 'domain: '
curl -kfsS "https://127.0.0.1:${API_PORT}/sdk/domain"
printf '\n'

for file in identity.json fullchain.pem privatekey.pem; do
  test -s "$STATE_DIR/$file" || { echo "missing runtime state file: $file" >&2; exit 1; }
done

echo "runtime state ok: $STATE_DIR"
echo "track0 runtime smoke passed"
