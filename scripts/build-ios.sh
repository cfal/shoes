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

echo "==> Building for aarch64-apple-ios (physical device)"
cargo build --release --target aarch64-apple-ios

echo "==> Building for aarch64-apple-ios-sim (Apple Silicon simulator)"
cargo build --release --target aarch64-apple-ios-sim

echo "==> Copying libraries"
cp "target/aarch64-apple-ios/release/$LIB_NAME"     "$OUTPUT_DIR/device/$LIB_NAME"
cp "target/aarch64-apple-ios-sim/release/$LIB_NAME" "$OUTPUT_DIR/sim/$LIB_NAME"

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
