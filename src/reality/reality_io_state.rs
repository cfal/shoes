/// Represents the I/O state after processing packets
#[derive(Debug, Clone, Copy)]
pub struct RealityIoState {
    /// Number of plaintext bytes available to read
    plaintext_bytes_to_read: usize,
}

impl RealityIoState {
    /// Create a new RealityIoState
    pub fn new(plaintext_bytes_to_read: usize) -> Self {
        Self {
            plaintext_bytes_to_read,
        }
    }

    /// How many plaintext bytes could be obtained via Read without further I/O
    pub fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }
}
