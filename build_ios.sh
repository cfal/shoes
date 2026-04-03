#!/bin/sh
# Build shoes as a static library (.a) for iOS targets,
# then combine into a universal XCFramework.
#
# Prerequisites:
#   - Xcode installed with command line tools
#   - Rust targets installed:
#     rustup target add aarch64-apple-ios aarch64-apple-ios-sim
#
# Usage:
#   ./build_ios.sh              # Build XCFramework (release)
#   ./build_ios.sh debug        # Build XCFramework (debug)
#   ./build_ios.sh device       # Build only device (arm64, release)
#   ./build_ios.sh simulator    # Build only simulator (arm64-sim, release)

set -e

# --- Configuration ---
LIB_NAME="libshoes.a"
FRAMEWORK_NAME="Shoes"
OUTPUT_DIR="target/ios"
XCFRAMEWORK_DIR="$OUTPUT_DIR/$FRAMEWORK_NAME.xcframework"
HEADER_FILE="$OUTPUT_DIR/include/shoes.h"

# iOS targets
TARGET_DEVICE="aarch64-apple-ios"
TARGET_SIM="aarch64-apple-ios-sim"

# iOS deployment target (must be >= 13.0 for aws-lc-sys ___chkstk_darwin)
export IPHONEOS_DEPLOYMENT_TARGET=13.0

# --- Parse arguments ---
BUILD_TYPE="release"
FILTER=""

for arg in "$@"; do
    case "$arg" in
        debug)     BUILD_TYPE="debug" ;;
        device)    FILTER="device" ;;
        simulator) FILTER="simulator" ;;
        *)         echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

CARGO_FLAGS=""
if [ "$BUILD_TYPE" = "release" ]; then
    CARGO_FLAGS="--release"
fi

# --- Generate C header ---
mkdir -p "$OUTPUT_DIR/include"
cat > "$HEADER_FILE" << 'EOF'
#ifndef SHOES_H
#define SHOES_H

#include <stdint.h>
#include <stdbool.h>

// Socket protector callback type.
// Called from Rust to protect sockets from VPN routing.
typedef bool (*ProtectSocketCallback)(int fd);

// Initialize the shoes library.
// log_level: "error", "warn", "info", "debug", "trace"
// Returns 0 on success, -1 on error.
int shoes_init(const char *log_level);

// Set the log file path for file-based logging.
// Returns 0 on success, -1 on error.
int shoes_set_log_file(const char *path);

// Start the shoes VPN service.
// config_yaml: YAML configuration string
// protect_callback: callback to protect sockets from VPN routing
// Returns handle (> 0) on success, -1 on error.
long shoes_start(const char *config_yaml, ProtectSocketCallback protect_callback);

// Stop the shoes VPN service.
void shoes_stop(long handle);

// Check if the shoes service is running.
bool shoes_is_running(void);

// Get the shoes library version string.
// Returns a static string, do not free.
const char* shoes_get_version(void);

#endif // SHOES_H
EOF

echo "Generated header: $HEADER_FILE"

# --- Build targets ---
BUILT_DEVICE=""
BUILT_SIM=""

if [ "$FILTER" != "simulator" ]; then
    echo ""
    echo "=========================================="
    echo "Building for iOS Device ($TARGET_DEVICE)"
    echo "=========================================="
    cargo build --lib --target "$TARGET_DEVICE" $CARGO_FLAGS

    DEVICE_LIB="target/$TARGET_DEVICE/$BUILD_TYPE/$LIB_NAME"
    if [ ! -f "$DEVICE_LIB" ]; then
        echo "ERROR: Build output not found at $DEVICE_LIB"
        exit 1
    fi
    SIZE=$(du -h "$DEVICE_LIB" | cut -f1)
    echo "✓ Device: $DEVICE_LIB ($SIZE)"
    BUILT_DEVICE="$DEVICE_LIB"
fi

if [ "$FILTER" != "device" ]; then
    echo ""
    echo "=========================================="
    echo "Building for iOS Simulator ($TARGET_SIM)"
    echo "=========================================="
    cargo build --lib --target "$TARGET_SIM" $CARGO_FLAGS

    SIM_LIB="target/$TARGET_SIM/$BUILD_TYPE/$LIB_NAME"
    if [ ! -f "$SIM_LIB" ]; then
        echo "ERROR: Build output not found at $SIM_LIB"
        exit 1
    fi
    SIZE=$(du -h "$SIM_LIB" | cut -f1)
    echo "✓ Simulator: $SIM_LIB ($SIZE)"
    BUILT_SIM="$SIM_LIB"
fi

# --- Create XCFramework ---
if [ -n "$BUILT_DEVICE" ] && [ -n "$BUILT_SIM" ]; then
    echo ""
    echo "=========================================="
    echo "Creating XCFramework"
    echo "=========================================="

    # Remove old framework
    rm -rf "$XCFRAMEWORK_DIR"

    xcodebuild -create-xcframework \
        -library "$BUILT_DEVICE" -headers "$OUTPUT_DIR/include" \
        -library "$BUILT_SIM" -headers "$OUTPUT_DIR/include" \
        -output "$XCFRAMEWORK_DIR"

    echo ""
    echo "✓ XCFramework: $XCFRAMEWORK_DIR"
    echo ""
    echo "Add to Xcode project:"
    echo "  1. Drag $XCFRAMEWORK_DIR into your project"
    echo "  2. Import with: #import \"shoes.h\""
elif [ -n "$BUILT_DEVICE" ]; then
    # Copy device lib to output
    mkdir -p "$OUTPUT_DIR/device"
    cp "$BUILT_DEVICE" "$OUTPUT_DIR/device/$LIB_NAME"
    echo ""
    echo "✓ Device lib: $OUTPUT_DIR/device/$LIB_NAME"
elif [ -n "$BUILT_SIM" ]; then
    # Copy sim lib to output
    mkdir -p "$OUTPUT_DIR/simulator"
    cp "$BUILT_SIM" "$OUTPUT_DIR/simulator/$LIB_NAME"
    echo ""
    echo "✓ Simulator lib: $OUTPUT_DIR/simulator/$LIB_NAME"
fi

echo ""
echo "=========================================="
echo "iOS build complete!"
echo "=========================================="
