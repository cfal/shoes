#!/usr/bin/env bash
#
# Build shoes as an XCFramework for iOS.
#
# Output: output/ios/Shoes.xcframework
#
# Requirements:
#   - macOS with Xcode installed (xcodebuild)
#   - Rust with rustup (targets added automatically)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$ROOT_DIR/output/ios"
XCFRAMEWORK_NAME="Shoes"
LIB_NAME="libshoes.a"

cd "$ROOT_DIR"

echo "==> Generating C header via cbindgen"
if command -v cbindgen &>/dev/null; then
    cbindgen --config "$ROOT_DIR/cbindgen.toml" --output "$ROOT_DIR/include/shoes.h"
else
    echo "  cbindgen not found, using existing include/shoes.h"
fi

echo "==> Cleaning output directory"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/device" "$OUTPUT_DIR/sim"

# aws-lc-sys uses ___chkstk_darwin which requires iOS 13+.
# Set to 16.0 to match a reasonable modern minimum.
export IPHONEOS_DEPLOYMENT_TARGET="16.0"

echo "==> Adding iOS Rust targets"
rustup target add \
    aarch64-apple-ios \
    aarch64-apple-ios-sim

# release-mobile rather than release: opt-level="s" and panic="abort". See the
# profile comment in Cargo.toml.
PROFILE_DIR="release-mobile"

# --features control-stats: the counters shoes_get_stats / getStats read.
# On for the published artifact because the resident cost is one atomic, a few
# hundred bytes per configured outbound and 8 bytes per live connection --
# 2 KiB at the 256-connection mobile ceiling, below one page. MOBILE.md
# section 10 carries the measurement. control-logs stays off: the log ring is
# exactly the memory an iOS extension cannot spare, and a host reads a log
# file through shoes_set_log_file instead.
echo "==> Building for aarch64-apple-ios (physical device)"
cargo build --profile release-mobile --features control-stats --target aarch64-apple-ios

echo "==> Building for aarch64-apple-ios-sim (Apple Silicon simulator)"
cargo build --profile release-mobile --features control-stats --target aarch64-apple-ios-sim

echo "==> Copying libraries"
cp "target/aarch64-apple-ios/$PROFILE_DIR/$LIB_NAME"     "$OUTPUT_DIR/device/$LIB_NAME"
cp "target/aarch64-apple-ios-sim/$PROFILE_DIR/$LIB_NAME" "$OUTPUT_DIR/sim/$LIB_NAME"

# cargo's `strip = true` (release profile) applies to linked binaries, not to a
# staticlib, so the .a keeps every object file's debug and local symbols and
# ends up very large (~180MB). -S drops debug symbols and -x drops local
# (non-global) symbols; the global symbols the linker needs to resolve the FFI
# surface are preserved, so the framework still links. ranlib rebuilds the
# archive's symbol table afterwards.
echo "==> Stripping symbols from the static libraries"
for lib in "$OUTPUT_DIR/device/$LIB_NAME" "$OUTPUT_DIR/sim/$LIB_NAME"; do
    before=$(du -h "$lib" | cut -f1)
    strip -S -x "$lib"
    ranlib "$lib" >/dev/null 2>&1 || true
    echo "  $(basename "$(dirname "$lib")")/$LIB_NAME: $before -> $(du -h "$lib" | cut -f1)"
done

echo "==> Packaging as XCFramework"
xcodebuild -create-xcframework \
    -library "$OUTPUT_DIR/device/$LIB_NAME" \
    -headers "$ROOT_DIR/include" \
    -library "$OUTPUT_DIR/sim/$LIB_NAME" \
    -headers "$ROOT_DIR/include" \
    -output "$OUTPUT_DIR/$XCFRAMEWORK_NAME.xcframework"

echo ""
echo "Done: $OUTPUT_DIR/$XCFRAMEWORK_NAME.xcframework"
echo ""
echo "Xcode integration:"
echo "  1. Drag $XCFRAMEWORK_NAME.xcframework into your project (check 'Copy if needed')"
echo "  2. Link it under Target > General > Frameworks, Libraries, and Embedded Content"
echo "  3. Add a bridging header that includes: #include \"shoes.h\""
