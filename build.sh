#!/usr/bin/env bash
# Local pre-commit gate: format, lint, test. Mirror of the CLAUDE.md workflow.
set -euo pipefail

cd "$(dirname "$0")"

echo "==> cargo fmt"
cargo fmt

echo "==> cargo clippy --all-targets -- -D warnings"
cargo clippy --all-targets -- -D warnings

echo "==> cargo test"
cargo test

echo "==> all checks passed"
