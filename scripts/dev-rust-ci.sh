#!/usr/bin/env bash
set -euo pipefail

# Run the Rust checks in a Docker toolchain because deployment hosts may not
# have cargo/rustfmt/clippy installed locally.
IMAGE=${RUST_IMAGE:-rust:1}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

docker run --rm \
  -e CARGO_TARGET_DIR=/tmp/portal-relay-target \
  -v "$ROOT:/src" \
  -w /src \
  "$IMAGE" \
  bash -lc 'set -euo pipefail; . /usr/local/cargo/env; rustup component add rustfmt clippy >/dev/null; cargo fmt --check; cargo test --locked; cargo clippy --locked --all-targets -- -D warnings'
