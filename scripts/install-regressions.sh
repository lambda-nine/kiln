#!/bin/sh
# install.sh pins this target directory, even when Cargo config differs.
set -eu
build_dir=${CARGO_TARGET_DIR:-target}
cmp "$build_dir/release/kiln" "${KILN:-/usr/local/bin/kiln}"
