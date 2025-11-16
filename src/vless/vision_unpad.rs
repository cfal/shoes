#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnpadCommand {
    Continue = 0,
    End = 1,
    Direct = 2,
}

impl TryFrom<u8> for UnpadCommand {
    type Error = std::io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(UnpadCommand::Continue),
            1 => Ok(UnpadCommand::End),
            2 => Ok(UnpadCommand::Direct),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid padding command: {}", value),
            )),
        }
    }
}

/// Result of a completed padding block
#[derive(Debug, Default)]
pub struct UnpadResult {
    /// Content data extracted from the block
    pub content: Vec<u8>,
    /// The command from the block, or None if this is not XTLS data
    pub command: Option<UnpadCommand>,
}

#[derive(Debug, Clone)]
enum UnpadState {
    /// Initial state: expecting UUID (16 bytes) before first command
    Initial { expected_uuid: [u8; 16] },
    /// Reading the command byte (first of 5 header bytes)
    ReadingCommand,
    /// Reading content length (2 bytes)
    ReadingContentLength {
        command: UnpadCommand,
        first_byte: Option<u8>,
    },
    /// Reading padding length (2 bytes)
    ReadingPaddingLength {
        command: UnpadCommand,
        content_len: u16,
        first_byte: Option<u8>,
    },
    /// Reading content data
    ReadingContent {
        command: UnpadCommand,
        partial_content: Vec<u8>,
        remaining_content_len: u16,
        padding_len: u16,
    },
    /// Reading (skipping) padding data
    ReadingPadding {
        command: UnpadCommand,
        content: Vec<u8>,
        remaining_padding_len: u16,
    },
    /// Finished processing (End or Direct command completed)
    Done,
}

#[derive(Debug, Clone)]
pub struct VisionUnpadder {
    state: UnpadState,
    first_block: bool,
    /// Reusable buffer for accumulated content to avoid allocation on every unpad() call
    accumulated_buffer: Vec<u8>,
}

impl VisionUnpadder {
    pub fn new(expected_uuid: [u8; 16]) -> Self {
        Self {
            state: UnpadState::Initial { expected_uuid },
            first_block: true,
            accumulated_buffer: Vec::new(),
        }
    }

    /// Process input data and extract padding blocks
    /// Returns UnpadResult when a complete block is parsed, empty result if more data is needed
    /// Accumulates content across Continue commands and returns on End/Direct or when needing more data
    pub fn unpad(&mut self, mut data: &[u8]) -> std::io::Result<UnpadResult> {
        // Reuse the accumulated buffer - clear but keep capacity
        self.accumulated_buffer.clear();
        log::debug!(
            "UNPADDER: unpad() called with {} bytes, state before: {:?}, first_block: {}",
            data.len(),
            self.state,
            self.first_block
        );

        loop {
            match &mut self.state {
                UnpadState::Initial { expected_uuid } => {
                    if data.len() < 16 {
                        return Ok(UnpadResult::default()); // Need more data
                    }

                    // Check if this is XTLS padding data
                    if &data[..16] != expected_uuid {
                        // Not XTLS padding data
                        return Ok(UnpadResult {
                            content: data.to_vec(),
                            command: None,
                        });
                    }

                    // Consume UUID
                    data = &data[16..];
                    self.state = UnpadState::ReadingCommand;
                }

                UnpadState::ReadingCommand => {
                    if data.is_empty() {
                        // Out of data
                        if !self.first_block {
                            // We've completed at least one block, return what we have
                            return Ok(UnpadResult {
                                content: std::mem::take(&mut self.accumulated_buffer),
                                command: Some(UnpadCommand::Continue),
                            });
                        }
                        debug_assert!(self.accumulated_buffer.is_empty(), "self.accumulated_buffer should be empty when returning default in ReadingCommand");
                        return Ok(UnpadResult::default());
                    }
                    let command_byte = data[0];
                    data = &data[1..];

                    let command = UnpadCommand::try_from(command_byte)?;

                    self.state = UnpadState::ReadingContentLength {
                        command,
                        first_byte: None,
                    };
                }

                UnpadState::ReadingContentLength {
                    command,
                    first_byte,
                } => {
                    if data.is_empty() {
                        // Out of data - return accumulated content if any
                        if !self.first_block {
                            return Ok(UnpadResult {
                                content: std::mem::take(&mut self.accumulated_buffer),
                                command: Some(UnpadCommand::Continue),
                            });
                        }
                        debug_assert!(self.accumulated_buffer.is_empty(), "self.accumulated_buffer should be empty when returning default in ReadingContentLength");
                        return Ok(UnpadResult::default());
                    }
                    match first_byte {
                        None => {
                            *first_byte = Some(data[0]);
                            data = &data[1..];
                        }
                        Some(high_byte) => {
                            let low_byte = data[0];
                            data = &data[1..];
                            let content_len = ((*high_byte as u16) << 8) | (low_byte as u16);

                            self.state = UnpadState::ReadingPaddingLength {
                                command: *command,
                                content_len,
                                first_byte: None,
                            };
                        }
                    }
                }

                UnpadState::ReadingPaddingLength {
                    command,
                    content_len,
                    first_byte,
                } => {
                    if data.is_empty() {
                        // Out of data - return accumulated content if any
                        if !self.first_block {
                            return Ok(UnpadResult {
                                content: std::mem::take(&mut self.accumulated_buffer),
                                command: Some(UnpadCommand::Continue),
                            });
                        }
                        debug_assert!(self.accumulated_buffer.is_empty(), "self.accumulated_buffer should be empty when returning default in ReadingPaddingLength");
                        return Ok(UnpadResult::default());
                    }
                    match first_byte {
                        None => {
                            *first_byte = Some(data[0]);
                            data = &data[1..];
                        }
                        Some(high_byte) => {
                            let low_byte = data[0];
                            data = &data[1..];
                            let padding_len = ((*high_byte as u16) << 8) | (low_byte as u16);
                            log::debug!("UNPADDER: Parsed header - command={:?}, content_len={}, padding_len={}", *command, *content_len, padding_len);
                            // Pre-allocate based on min of content_len and available data
                            // (we eagerly return when data runs out, so we may not need full content_len)
                            let prealloc_size = (*content_len as usize).min(data.len());
                            self.state = UnpadState::ReadingContent {
                                command: *command,
                                partial_content: Vec::with_capacity(prealloc_size),
                                remaining_content_len: *content_len,
                                padding_len,
                            };
                        }
                    }
                }

                UnpadState::ReadingContent {
                    command,
                    partial_content,
                    remaining_content_len,
                    padding_len,
                } => {
                    if *remaining_content_len > 0 {
                        if data.is_empty() {
                            // Out of data - return accumulated content if any.
                            // We need to return everything we have including the partial content
                            // else some clients will not return - see below.
                            self.accumulated_buffer.append(partial_content);
                            if !self.first_block {
                                return Ok(UnpadResult {
                                    content: std::mem::take(&mut self.accumulated_buffer),
                                    command: Some(UnpadCommand::Continue),
                                });
                            } else {
                                return Ok(UnpadResult {
                                    content: std::mem::take(&mut self.accumulated_buffer),
                                    command: None,
                                });
                            }
                        }
                        let to_read = (*remaining_content_len as usize).min(data.len());
                        partial_content.extend_from_slice(&data[..to_read]);
                        data = &data[to_read..];
                        *remaining_content_len -= to_read as u16;
                    }

                    if *remaining_content_len == 0 {
                        log::debug!("UNPADDER: Content read complete ({} bytes), accumulated at {}, transitioning to padding",
                            partial_content.len(), self.accumulated_buffer.len());
                        let content = std::mem::take(partial_content);
                        self.state = UnpadState::ReadingPadding {
                            command: *command,
                            content,
                            remaining_padding_len: *padding_len,
                        };
                    }
                }

                UnpadState::ReadingPadding {
                    command,
                    content,
                    remaining_padding_len,
                } => {
                    if *remaining_padding_len > 0 {
                        if data.is_empty() {
                            // We need to return _all_ the content including from this incomplete
                            // block because some clients will not write the remaining padding until we've
                            // generated a response to the current content. Waiting for the remaining
                            // padding before returning the current block's content caused a
                            // deadlock. This is also the behavior on the official client:
                            // https://github.com/XTLS/Xray-core/blob/9f5dcb15910aadc7ef450514747576827a389853/proxy/proxy.go#L518
                            //
                            // It's important that we do not return the command until the rest of
                            // the padding has been consumed so that unpad() consumes all of the
                            // padded data before we switch modes due to a Direct or End command.
                            //
                            // Note that append moves all of `content` and leaves it empty.
                            self.accumulated_buffer.append(content);

                            log::debug!("UNPADDER: Out of data in ReadingPadding with {} padding bytes remaining, returning {} bytes (first_block={})",
                                *remaining_padding_len, self.accumulated_buffer.len(), self.first_block);

                            if !self.first_block {
                                return Ok(UnpadResult {
                                    content: std::mem::take(&mut self.accumulated_buffer),
                                    command: Some(UnpadCommand::Continue),
                                });
                            } else {
                                return Ok(UnpadResult {
                                    content: std::mem::take(&mut self.accumulated_buffer),
                                    command: None,
                                });
                            }
                        }
                        let to_skip = (*remaining_padding_len as usize).min(data.len());
                        data = &data[to_skip..];
                        *remaining_padding_len -= to_skip as u16;
                    }

                    if *remaining_padding_len == 0 {
                        self.first_block = false;

                        // Block complete (all padding skipped)
                        self.accumulated_buffer.append(content);

                        log::debug!("UNPADDER: Padding complete for command {:?}, {} accumulated bytes total", *command, self.accumulated_buffer.len());
                        match *command {
                            UnpadCommand::Continue => {
                                // Continue to next block
                                log::debug!("UNPADDER: Continue command - transitioning to ReadingCommand for next block");
                                self.state = UnpadState::ReadingCommand;
                            }
                            end_or_direct_command => {
                                // Return all accumulated content with final command
                                // Any remaining data in the input slice is unconsumed (comes after the final padding)
                                // Append it to content so caller gets everything in one place
                                let remaining_len = data.len();
                                self.accumulated_buffer.extend_from_slice(data);
                                log::debug!("UNPADDER: {:?} command - transitioning to Done state, returning {} bytes content ({} from padding, {} remaining after)",
                                    end_or_direct_command, self.accumulated_buffer.len(), self.accumulated_buffer.len() - remaining_len, remaining_len);
                                self.state = UnpadState::Done;
                                return Ok(UnpadResult {
                                    content: std::mem::take(&mut self.accumulated_buffer),
                                    command: Some(end_or_direct_command),
                                });
                            }
                        }
                    }
                }

                UnpadState::Done => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Already in UnpadState::Done",
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_state_basic() {
        let user_uuid = [0u8; 16];
        let mut state = VisionUnpadder::new(user_uuid);

        let data = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // UUID
            1, // command (End)
            0, 5, // content length = 5
            0, 3, // padding length = 3
            1, 2, 3, 4, 5, // content
            0, 0, 0, // padding
        ];

        let result = state.unpad(&data[..]).unwrap();
        assert_eq!(result.content, vec![1, 2, 3, 4, 5]);
        assert_eq!(result.command, Some(UnpadCommand::End));
        assert!(matches!(state.state, UnpadState::Done));
    }

    #[test]
    fn test_padding_command_continue() {
        let user_uuid = [1u8; 16];
        let mut state = VisionUnpadder::new(user_uuid);

        let mut data = vec![1u8; 16]; // UUID
        data.extend_from_slice(&[
            0, // command (Continue)
            0, 3, // content length = 3
            0, 2, // padding length = 2
            10, 11, 12, // content
            0, 0, // padding
            0, // command (Continue)
            0, 2, // content length = 2
            0, 1, // padding length = 1
            20, 21, // content
            0,  // padding
        ]);

        // Now it processes both Continue blocks and accumulates content
        let result = state.unpad(&data[..]).unwrap();
        assert_eq!(result.content, vec![10, 11, 12, 20, 21]);
        assert_eq!(result.command, Some(UnpadCommand::Continue));
        assert!(!matches!(state.state, UnpadState::Done));
    }

    #[test]
    fn test_non_xtls_data() {
        let user_uuid = [0u8; 16];
        let mut state = VisionUnpadder::new(user_uuid);

        // Data that's less than 16 bytes (too short to check UUID)
        let short_data = vec![1, 2, 3, 4, 5];
        let result = state.unpad(&short_data[..]).unwrap();
        assert!(result.content.is_empty()); // Need more data
        assert!(result.command.is_none());

        // Data that's exactly 16 bytes but doesn't match UUID
        let non_xtls_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let result = state.unpad(&non_xtls_data[..]).unwrap();
        assert_eq!(result.content, non_xtls_data);
        assert_eq!(result.command, None);
        // State remains Initial (doesn't transition to Done for non-XTLS data)
        assert!(!matches!(state.state, UnpadState::Done));
    }

    #[test]
    fn test_direct_command() {
        let user_uuid = [2u8; 16];
        let mut state = VisionUnpadder::new(user_uuid);

        let mut data = vec![2u8; 16]; // UUID
        data.extend_from_slice(&[
            2, // command (Direct)
            0, 3, // content length = 3
            0, 2, // padding length = 2
            10, 11, 12, // content
            0, 0, // padding
            99, 98, 97, // remaining data after Direct
        ]);

        // Process the padded block
        let result = state.unpad(&data[..]).unwrap();
        // Direct command appends remaining data (99, 98, 97) to content
        assert_eq!(result.content, vec![10, 11, 12, 99, 98, 97]);
        assert_eq!(result.command, Some(UnpadCommand::Direct));
        assert!(matches!(state.state, UnpadState::Done))
    }

    #[test]
    fn test_incremental_processing() {
        let user_uuid = [3u8; 16];
        let mut state = VisionUnpadder::new(user_uuid);

        // First chunk: UUID + partial command
        let chunk1 = {
            let mut d = vec![3u8; 16];
            d.extend_from_slice(&[1, 0, 3]); // command (End), content_len high byte, partial
            d
        };

        let result1 = state.unpad(&chunk1[..]).unwrap();
        assert!(result1.content.is_empty()); // Not enough data yet
        assert!(result1.command.is_none());
        assert!(!matches!(state.state, UnpadState::Done));

        // Second chunk: rest of command + content + padding
        let chunk2 = vec![
            0, 2, // rest of content length (=3), padding length = 2
            10, 11, 12, // content
            0, 0, // padding
        ];

        let result2 = state.unpad(&chunk2[..]).unwrap();
        assert_eq!(result2.content, vec![10, 11, 12]);
        assert_eq!(result2.command, Some(UnpadCommand::End));
        assert!(matches!(state.state, UnpadState::Done));
    }

    #[test]
    fn test_empty_content_block() {
        let user_uuid = [4u8; 16];
        let mut state = VisionUnpadder::new(user_uuid);

        let mut data = vec![4u8; 16]; // UUID
        data.extend_from_slice(&[
            0, // command (Continue)
            0, 0, // content length = 0
            0, 5, // padding length = 5
            0, 0, 0, 0, 0, // padding
        ]);

        let result = state.unpad(&data[..]).unwrap();
        assert_eq!(result.content, Vec::<u8>::new());
        assert_eq!(result.command, Some(UnpadCommand::Continue));
        assert!(!matches!(state.state, UnpadState::Done));
    }

    #[test]
    fn test_multiple_continue_with_end() {
        let user_uuid = [5u8; 16];
        let mut state = VisionUnpadder::new(user_uuid);

        let mut data = vec![5u8; 16]; // UUID
        data.extend_from_slice(&[
            0, // command (Continue)
            0, 2, // content length = 2
            0, 1, // padding length = 1
            10, 11, // content
            0,  // padding
            0,  // command (Continue)
            0, 2, // content length = 2
            0, 1, // padding length = 1
            20, 21, // content
            0,  // padding
            1,  // command (End)
            0, 2, // content length = 2
            0, 1, // padding length = 1
            30, 31, // content
            0,  // padding
        ]);

        // Process all blocks - should accumulate and return with End
        let result = state.unpad(&data[..]).unwrap();
        assert_eq!(result.content, vec![10, 11, 20, 21, 30, 31]);
        assert_eq!(result.command, Some(UnpadCommand::End));
        assert!(matches!(state.state, UnpadState::Done));
    }

    #[test]
    fn test_incomplete_padding_returns_content_to_prevent_deadlock() {
        let user_uuid = [6u8; 16];
        let mut state = VisionUnpadder::new(user_uuid);

        // First chunk: UUID + command + header + content + partial padding
        let mut chunk1 = vec![6u8; 16]; // UUID
        chunk1.extend_from_slice(&[
            1, // command (End)
            0, 3, // content length = 3
            0, 5, // padding length = 5
            10, 11, 12, // content
            0, 0, // only 2 bytes of padding (need 5 total)
        ]);

        // Should return content immediately to prevent deadlock
        // (some clients don't send remaining padding until they get a response)
        // However, command should be None because padding is incomplete
        let result1 = state.unpad(&chunk1[..]).unwrap();
        assert_eq!(result1.content, vec![10, 11, 12]);
        assert_eq!(result1.command, None); // Command not returned until padding complete
        assert!(matches!(state.state, UnpadState::ReadingPadding { .. }));

        // Second chunk: remaining padding
        let chunk2 = vec![
            0, 0, 0, // remaining 3 bytes of padding
        ];

        // Now padding is complete, should return End command (no more content since it was already returned)
        let result2 = state.unpad(&chunk2[..]).unwrap();
        assert!(result2.content.is_empty()); // Content already returned in result1
        assert_eq!(result2.command, Some(UnpadCommand::End));
        assert!(matches!(state.state, UnpadState::Done));
    }
}
