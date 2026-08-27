#!/usr/bin/env bash
#
# Build shoes as an Android AAR.
#
# Output: output/android/shoes-release.aar
#
# Requirements:
#   - Android NDK: set ANDROID_NDK_HOME, or NDK_HOME, or have ANDROID_HOME with NDK installed
#   - cargo-ndk: installed automatically if missing
#   - Gradle 8.6+ available as `gradle` in PATH, or ./gradlew in android/
#   - Java 17+
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ANDROID_DIR="$ROOT_DIR/android"
OUTPUT_DIR="$ROOT_DIR/output/android"
JNI_LIBS_DIR="$ANDROID_DIR/src/main/jniLibs"

cd "$ROOT_DIR"

# Resolve NDK path
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    if [ -n "${NDK_HOME:-}" ]; then
        export ANDROID_NDK_HOME="$NDK_HOME"
    elif [ -n "${ANDROID_HOME:-}" ] && [ -d "$ANDROID_HOME/ndk" ]; then
        ANDROID_NDK_HOME="$(ls -d "$ANDROID_HOME/ndk/"*/ 2>/dev/null | sort -V | tail -1)"
        ANDROID_NDK_HOME="${ANDROID_NDK_HOME%/}"
        export ANDROID_NDK_HOME
    else
        echo "Error: ANDROID_NDK_HOME is not set."
        echo "  Set it to the NDK directory, e.g.:"
        echo "    export ANDROID_NDK_HOME=\$HOME/Library/Android/sdk/ndk/26.3.11579264"
        exit 1
    fi
fi
echo "==> Using NDK: $ANDROID_NDK_HOME"

# Install cargo-ndk if needed
if ! command -v cargo-ndk &>/dev/null; then
    echo "==> Installing cargo-ndk"
    cargo install cargo-ndk
fi

echo "==> Adding Android Rust targets"
rustup target add \
    aarch64-linux-android \
    armv7-linux-androideabi

echo "==> Cleaning JNI libs directory"
rm -rf "$JNI_LIBS_DIR"

# --locked: this produces a distributable artifact, so a Cargo.lock that does
# not already satisfy Cargo.toml should be a hard error rather than something
# cargo quietly resolves differently on each machine.
#
# release-mobile rather than release: opt-level="s" and panic="abort", which
# together take ~38% off the stripped .so. See the profile comment in Cargo.toml.
# --features control-stats: the counters shoes_get_stats / getStats read.
# On for the published artifact because the resident cost is one atomic, a few
# hundred bytes per configured outbound and 8 bytes per live connection --
# 2 KiB at the 256-connection mobile ceiling, below one page. MOBILE.md
# section 10 carries the measurement. control-logs stays off: the log ring is
# exactly the memory an iOS extension cannot spare, and a host reads a log
# file through shoes_set_log_file instead.
echo "==> Building native .so files for all ABIs"
cargo ndk \
    -t arm64-v8a \
    -t armeabi-v7a \
    -t x86_64 \
    -P 21 \
    -o "$JNI_LIBS_DIR" \
    -- build --profile release-mobile --lib --locked --features control-stats

# cargo-ndk copies every cdylib in the dependency graph into the AAR, under
# hashed filenames System.loadLibrary cannot load. awgtun stopped emitting one
# in v0.9.0 (it is a plain rlib now), so today this deletes nothing — it stays
# as a guard so a future dependency's cdylib cannot ship silently. CI verifies
# the same invariant on the finished AAR.
echo "==> Dropping cdylibs other than libshoes.so"
find "$JNI_LIBS_DIR" -name "*.so" ! -name "libshoes.so" -delete

echo "==> Built libraries:"
find "$JNI_LIBS_DIR" -name "*.so" | sort | sed 's|^|  |'

echo "==> Building AAR with Gradle"
cd "$ANDROID_DIR"

# Ensure ANDROID_HOME is set so Gradle can find the SDK
if [ -z "${ANDROID_HOME:-}" ]; then
    if [ -d "$HOME/Library/Android/sdk" ]; then
        export ANDROID_HOME="$HOME/Library/Android/sdk"
    elif [ -d "$HOME/Android/sdk" ]; then
        export ANDROID_HOME="$HOME/Android/sdk"
    fi
fi

if ! command -v gradle &>/dev/null; then
    echo "Error: 'gradle' not found in PATH."
    echo "  Install Gradle: https://gradle.org/install/"
    echo "  Or run: sdk install gradle 8.6  (via SDKMAN)"
    exit 1
fi
gradle assembleRelease --no-daemon

# Copy output
mkdir -p "$OUTPUT_DIR"
AAR="$(find "$ANDROID_DIR/build/outputs/aar" -name "*-release.aar" | head -1)"
if [ -z "$AAR" ]; then
    echo "Error: AAR not found in android/build/outputs/aar/"
    exit 1
fi
cp "$AAR" "$OUTPUT_DIR/shoes-release.aar"

echo ""
echo "Done: $OUTPUT_DIR/shoes-release.aar"
echo ""
echo "Gradle integration (app/build.gradle.kts):"
echo "  implementation(files(\"libs/shoes-release.aar\"))"
