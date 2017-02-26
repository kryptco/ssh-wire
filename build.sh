#!/bin/sh

set -euo pipefail

# Build the rust project.
#cargo clean
cargo test

cargo lipo --release
#CC=gcc CXX=g++ cargo build --target armv7-linux-androideabi --release
CC=gcc CXX=g++ cargo build --target arm-linux-androideabi --release
