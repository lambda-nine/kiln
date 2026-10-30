#!/bin/sh
# Prepared VM compatibility regression: the MSRV and active Rust must agree.
set -eu
cd "$(dirname "$0")/.."
cargo +1.88.0 test --locked
cargo +1.88.0 clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets -- -D warnings
