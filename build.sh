#!/bin/sh

set -euo pipefail

# Build the rust project.
cargo test

#RUSTFLAGS="-C llvm-args=\"-fembed-bitcode\"" cargo lipo --release --verbose
#BITCODE_GENERATION_MODE=bitcode cargo lipo --release --verbose
cargo lipo --release --verbose

if [ "${ANDROID_NDK:-}"="-" ]; then
	echo "ANDROID_NDK unset, skipping android compilation";
else
	PATH=$ANDROID_NDK/arm/bin/:$PATH CC=arm-linux-androideabi-gcc CXX=arm-linux-androideabi-g++ cargo build --target arm-linux-androideabi --release
	PATH=$ANDROID_NDK/arm/bin/:$PATH CC=arm-linux-androideabi-gcc CXX=arm-linux-androideabi-g++ cargo build --target armv7-linux-androideabi --release
	PATH=$ANDROID_NDK/arm64/bin/:$PATH CC=aarch64-linux-android-gcc CXX=aarch64-linux-android-g++ cargo build --target aarch64-linux-android --release
fi
