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
	CXX=$ANDROID_NDK/arm/bin/arm-linux-androideabi-g++ CC=$ANDROID_NDK/arm/bin/arm-linux-androideabi-gcc AR=$ANDROID_NDK/arm/bin/arm-linux-androideabi-ar cargo build --target armv7-linux-androideabi --release
	CXX=$ANDROID_NDK/x86/bin/i686-linux-android-g++ CC=$ANDROID_NDK/x86/bin/i686-linux-android-gcc AR=$ANDROID_NDK/x86/bin/i686-linux-android-ar cargo build --target i686-linux-android --release

	CXX=$ANDROID_NDK/arm64/bin/aarch64-linux-android-g++ CC=$ANDROID_NDK/arm64/bin/aarch64-linux-android-gcc AR=$ANDROID_NDK/arm64/bin/aarch64-linux-android-ar cargo build --target aarch64-linux-android --release
fi
