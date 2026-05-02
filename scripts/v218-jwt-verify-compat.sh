#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
GO_REPO_URL=${GO_REPO_URL:-https://github.com/gosuda/portal-tunnel.git}
GO_TAG=${GO_TAG:-v2.1.8}
WORK_DIR=${WORK_DIR:-$(mktemp -d)}
LOG_DIR=${LOG_DIR:-$(mktemp -d)}

cleanup() {
  if [[ ${KEEP_ARTIFACTS:-0} != 1 ]]; then
    rm -rf "$WORK_DIR" "$LOG_DIR"
  else
    echo "kept artifacts: work=$WORK_DIR logs=$LOG_DIR" >&2
  fi
}
trap cleanup EXIT

mkdir -p "$WORK_DIR" "$LOG_DIR"
git clone --depth 1 --branch "$GO_TAG" "$GO_REPO_URL" "$WORK_DIR/portal-tunnel" >/dev/null
cat > "$WORK_DIR/portal-tunnel/zz_jwt_compat_check.go" <<'GO'
package main

import (
  "fmt"
  "time"

  "github.com/gosuda/portal-tunnel/v2/portal/auth"
  "github.com/gosuda/portal-tunnel/v2/types"
)

func main() {
  privateKey := "0000000000000000000000000000000000000000000000000000000000000001"
  publicKey := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  issuer := "https://localhost:4017"
  identity := types.Identity{Name: "demo", Address: "0x000000000000000000000000000000000000dEaD"}
  token, claims, err := auth.IssueLeaseAccessToken(privateKey, "0xrelay", issuer, identity, 10*time.Minute)
  if err != nil { panic(err) }
  verified, err := auth.VerifyLeaseAccessToken(token, publicKey, issuer, time.Now().UTC())
  if err != nil { panic(err) }
  fmt.Println("go_issued_token_verified_by_go=true")
  fmt.Println("go_claim_subject=" + claims.Subject)
  fmt.Println("go_verified_subject=" + verified.Subject)
  fmt.Println("go_token=" + token)
}
GO

GO_OUTPUT=$(cd "$WORK_DIR/portal-tunnel" && docker run --rm -v "$WORK_DIR/portal-tunnel:/src" -w /src golang:1 sh -lc '/usr/local/go/bin/go run ./zz_jwt_compat_check.go')
echo "$GO_OUTPUT" | tee "$LOG_DIR/go-output.txt"
TOKEN=$(printf '%s\n' "$GO_OUTPUT" | awk -F= '/^go_token=/{print $2}')
[[ -n "$TOKEN" ]] || { echo "failed to extract Go-issued token" >&2; exit 1; }

docker run --rm \
  -e GO_V218_TOKEN="$TOKEN" \
  -v "$ROOT:/src" \
  -w /src \
  rust:1 \
  sh -lc '
    . /usr/local/cargo/env
    cargo test relay::leases::tests::verifies_go_v218_issued_lease_token -- --ignored --nocapture
  ' >/tmp/portal-rs-jwt-compat.out 2>&1 || {
  cat /tmp/portal-rs-jwt-compat.out >&2
  echo "Rust verification of Go-issued v2.1.8 token failed" >&2
  exit 1
}
cat /tmp/portal-rs-jwt-compat.out

echo "v2.1.8 Go-issued lease JWT verifies in Rust"
