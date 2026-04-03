#!/bin/sh
# Build shoes as a shared library (.so) for Android targets.
#
# Prerequisites:
#   - Android NDK installed (set ANDROID_NDK_HOME or NDK_HOME)
#   - Rust targets installed:
#     rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#
# Usage:
#   ./build_android.sh          # Build all architectures (release)
#   ./build_android.sh debug    # Build all architectures (debug)
#   ./build_android.sh arm64    # Build only arm64 (release)

set -e

# --- Configuration ---
LIB_NAME="libshoes.so"
OUTPUT_DIR="target/android"

# --- Helper: map rust target to ABI name ---
get_abi() {
    case "$1" in
        aarch64-linux-android)    echo "arm64-v8a" ;;
        armv7-linux-androideabi)  echo "armeabi-v7a" ;;
        x86_64-linux-android)    echo "x86_64" ;;
    esac
}

# --- Helper: map rust target to NDK toolchain prefix ---
get_toolchain_prefix() {
    case "$1" in
        aarch64-linux-android)    echo "aarch64-linux-android" ;;
        armv7-linux-androideabi)  echo "armv7a-linux-androideabi" ;;
        x86_64-linux-android)    echo "x86_64-linux-android" ;;
    esac
}

# All targets
ALL_TARGETS="aarch64-linux-android armv7-linux-androideabi x86_64-linux-android"

# --- Resolve NDK path ---
NDK_PATH="${ANDROID_NDK_HOME:-${NDK_HOME:-}}"
if [ -z "$NDK_PATH" ]; then
    # Try default macOS SDK location
    SDK_DIR="$HOME/Library/Android/sdk"
    if [ -d "$SDK_DIR/ndk" ]; then
        NDK_PATH="$SDK_DIR/ndk/$(ls "$SDK_DIR/ndk" | sort -V | tail -1)"
    elif [ -d "$SDK_DIR/ndk-bundle" ]; then
        NDK_PATH="$SDK_DIR/ndk-bundle"
    fi
fi

if [ -z "$NDK_PATH" ] || [ ! -d "$NDK_PATH" ]; then
    echo "ERROR: Android NDK not found."
    echo "Set ANDROID_NDK_HOME or NDK_HOME, or install NDK via Android Studio."
    exit 1
fi

echo "Using NDK: $NDK_PATH"

# Find the toolchain bin directory
TOOLCHAIN_DIR="$NDK_PATH/toolchains/llvm/prebuilt"
HOST_TAG=$(ls "$TOOLCHAIN_DIR" 2>/dev/null | head -1)
if [ -z "$HOST_TAG" ]; then
    echo "ERROR: Could not find NDK toolchain in $TOOLCHAIN_DIR"
    exit 1
fi
TOOLCHAIN_BIN="$TOOLCHAIN_DIR/$HOST_TAG/bin"

# Android API level (minimum supported)
API_LEVEL=21

# --- Parse arguments ---
BUILD_TYPE="release"
FILTER_ARCH=""

for arg in "$@"; do
    case "$arg" in
        debug)   BUILD_TYPE="debug" ;;
        arm64)   FILTER_ARCH="aarch64-linux-android" ;;
        armv7)   FILTER_ARCH="armv7-linux-androideabi" ;;
        x86_64)  FILTER_ARCH="x86_64-linux-android" ;;
        *)       echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

CARGO_FLAGS=""
if [ "$BUILD_TYPE" = "release" ]; then
    CARGO_FLAGS="--release"
fi

# --- Build ---
mkdir -p "$OUTPUT_DIR"

for TARGET in $ALL_TARGETS; do
    if [ -n "$FILTER_ARCH" ] && [ "$TARGET" != "$FILTER_ARCH" ]; then
        continue
    fi

    ABI=$(get_abi "$TARGET")
    TC_PREFIX=$(get_toolchain_prefix "$TARGET")

    echo ""
    echo "=========================================="
    echo "Building for $ABI ($TARGET)"
    echo "=========================================="

    # Set up cross-compilation environment
    export CC="${TOOLCHAIN_BIN}/${TC_PREFIX}${API_LEVEL}-clang"
    export CXX="${TOOLCHAIN_BIN}/${TC_PREFIX}${API_LEVEL}-clang++"
    export AR="${TOOLCHAIN_BIN}/llvm-ar"
    export RANLIB="${TOOLCHAIN_BIN}/llvm-ranlib"
    export STRIP="${TOOLCHAIN_BIN}/llvm-strip"

    # Uppercase target for CARGO_TARGET env vars (replace - with _)
    TARGET_UPPER=$(echo "$TARGET" | tr '[:lower:]-' '[:upper:]_')
    export "CARGO_TARGET_${TARGET_UPPER}_LINKER=$CC"

    # Build
    cargo build --lib --target "$TARGET" $CARGO_FLAGS

    # Copy output
    OUT_ABI_DIR="$OUTPUT_DIR/$ABI"
    mkdir -p "$OUT_ABI_DIR"

    SRC="target/$TARGET/$BUILD_TYPE/$LIB_NAME"
    if [ -f "$SRC" ]; then
        cp "$SRC" "$OUT_ABI_DIR/$LIB_NAME"
        # Strip debug symbols for release builds
        if [ "$BUILD_TYPE" = "release" ]; then
            "$STRIP" "$OUT_ABI_DIR/$LIB_NAME"
        fi
        SIZE=$(du -h "$OUT_ABI_DIR/$LIB_NAME" | cut -f1)
        echo "  $ABI: $OUT_ABI_DIR/$LIB_NAME ($SIZE)"
    else
        echo "  $ABI: Build output not found at $SRC"
        exit 1
    fi
done

echo ""
echo "=========================================="
echo "Android build complete!"
echo "Output: $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR"/*/libshoes.so 2>/dev/null
echo "=========================================="
