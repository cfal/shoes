//! Stub FFI implementations for non-Android platforms.
//!
//! These are placeholder implementations that allow the code to compile
//! on desktop platforms for testing purposes.

/// Stub: shoes is not compiled for Android on this platform.
pub fn stub_warning() {
    #[cfg(debug_assertions)]
    eprintln!("Warning: FFI functions are stubs on this platform. Compile for Android to use.");
}
