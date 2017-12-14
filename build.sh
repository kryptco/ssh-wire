#!/bin/sh

set -euo pipefail

# Build the rust project.
cargo test

#RUSTFLAGS="-C llvm-args=\"-fembed-bitcode\"" cargo lipo --release --verbose
#BITCODE_GENERATION_MODE=bitcode cargo lipo --release --verbose
cargo lipo --release --verbose

if [ ${ANDROID_NDK:-"-"} = "-" ]; then
	echo "ANDROID_NDK unset, skipping android compilation";
else
	cargo build --target arm-linux-androideabi --release
	cargo build --target armv7-linux-androideabi --release
	cargo build --target aarch64-linux-android --release
fi
