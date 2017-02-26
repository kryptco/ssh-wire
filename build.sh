#!/bin/sh

set -euo pipefail

# Build the rust project.
#cargo clean
cargo test

cargo lipo --release
cargo build --target armv7-linux-androideabi --release
cargo build --target arm-linux-androideabi --release
