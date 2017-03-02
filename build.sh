#!/bin/sh

set -euo pipefail

# Build the rust project.
#cargo clean
cargo test

cargo lipo --release
PATH=$ANDROID_NDK/arm/bin/:$PATH CC=arm-linux-androideabi-gcc CXX=arm-linux-androideabi-g++ cargo build --target arm-linux-androideabi --release
PATH=$ANDROID_NDK/arm64/bin/:$PATH CC=aarch64-linux-android-gcc CXX=aarch64-linux-android-g++ cargo build --target aarch64-linux-android --release
