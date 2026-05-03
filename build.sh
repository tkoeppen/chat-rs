#!/usr/bin/env bash
# Local pre-commit gate: format, lint, test. Mirror of the CLAUDE.md workflow.
# `fmt --check` fails (rather than silently rewriting) so the gate catches
# "I forgot to run fmt"; run `cargo fmt` separately to fix.
set -euo pipefail

cd "$(dirname "$0")"

echo "==> cargo fmt --check"
cargo fmt --check

echo "==> cargo clippy (warnings, panics-doc, unwrap, expect)"
cargo clippy --all-targets -- \
    -D warnings \
    -D clippy::missing_panics_doc \
    -D clippy::unwrap_used \
    -D clippy::expect_used

echo "==> cargo test"
cargo test

echo "==> all checks passed"
