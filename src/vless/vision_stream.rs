//! VISION stream implementation
//!
//! VisionStream wraps an IO stream and TLS session, allowing it to:
//! - Use TLS with VISION padding to hide protocol fingerprints
//! - Detect TLS-in-TLS scenarios by analyzing traffic patterns
//! - Switch to direct I/O mode, bypassing TLS for zero-copy performance

use bytes::{Buf, BytesMut};

use futures::ready;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::AsyncStream;

use super::tls_fuzzy_deframer::{DeframeResult, FuzzyTlsDeframer};
use super::vision_filter::VisionFilter;
use super::vision_transport::VisionTransport;
use super::vision_unpad::{UnpadCommand, UnpadResult, VisionUnpadder};

// TODO: consider combining with UnpadCommand
const COMMAND_CONTINUE: u8 = 0x00;
const COMMAND_END: u8 = 0x01;
const COMMAND_DIRECT: u8 = 0x02;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum VisionWriteErrorPolicy {
    Legacy,
    AcknowledgeAccepted,
}

/// Current operating mode of the VISION stream
#[derive(Debug, PartialEq)]
enum VisionMode {
    /// Using TLS with VISION padding/unpadding
    PaddingTls,
    /// Regular TLS (padding ended, but still using TLS encryption)
    Tls,
    /// Direct I/O, TLS bypassed completely
    Direct,
}

impl std::fmt::Display for VisionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VisionMode::PaddingTls => write!(f, "PaddingTls"),
            VisionMode::Tls => write!(f, "Tls"),
            VisionMode::Direct => write!(f, "Direct"),
        }
    }
}

pub struct VisionStream<S> {
    tls: S,
    write_error_policy: VisionWriteErrorPolicy,
    write_error: Option<(io::ErrorKind, String)>,

    /// Current READ operating mode (independent from write mode)
    read_mode: VisionMode,

    /// Current WRITE operating mode (independent from read mode)
    write_mode: VisionMode,

    /// Unpadding state machine for read path
    read_unpadder: VisionUnpadder,

    /// Inner TLS deframer for filtering read packets
    /// Used in PaddingTls mode
    inner_read_deframer: FuzzyTlsDeframer,

    /// Inner TLS deframer for filtering write packets
    /// Used in PaddingTls mode
    inner_write_deframer: FuzzyTlsDeframer,

    /// Whether this is the first write (includes UUID in padding)
    /// Used in PaddingTls mode
    write_first_packet: bool,

    /// User UUID for padding validation
    /// Used in PaddingTls mode
    user_uuid: [u8; 16],

    /// TLS pattern filter for inner TLS
    /// Used in PaddingTls mode
    filter: VisionFilter,

    /// Buffer for leftover data when switching modes or when output buffer is too small
    /// Used in PaddingTls mode
    pending_read: BytesMut,

    /// Whether we need to read VLESS response header (client-side only)
    /// Similar to shadowsocks's `is_initial_read` pattern
    /// Used in PaddingTls mode
    vless_response_pending: bool,

    /// Partial VLESS response data accumulated across multiple TLS records
    /// Used to handle cases where the response header is split across TLS records
    /// Used in PaddingTls mode
    partial_vless_response: BytesMut,

    /// Whether we need to send VLESS response header (server-side only)
    /// The response will be prepended to the first write as per the protocol
    /// Used in PaddingTls mode
    vless_response_to_send: bool,

    /// Flag indicating we should switch to Tls mode on the NEXT write call
    /// Used in PaddingTls mode
    pending_tls_mode_switch: bool,

    /// Buffer for plaintext data waiting to be written to the TLS session buffer
    /// When the rustls Writer buffer fills (write length 0), we store the remainder here
    /// Used in PaddingTls mode - drained immediately before switching modes
    pending_plain_writes: BytesMut,
}

impl<S> VisionStream<S>
where
    S: VisionTransport,
{
    /// Create a new VisionStream for server-side (inbound) connections with VLESS response writing
    pub fn new_server(tls: S, user_uuid: [u8; 16], initial_read_data: &[u8]) -> io::Result<Self> {
        tls.require_record_framing()?;
        if !tls.is_server() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VisionStream::new_server requires a server-side connection",
            ));
        }
        let mut stream = Self::new_common(tls, user_uuid, false, true);
        stream.feed_initial_read_data(initial_read_data)?;
        Ok(stream)
    }

    pub fn new_client(tls: S, user_uuid: [u8; 16]) -> io::Result<Self> {
        tls.require_record_framing()?;
        if !tls.is_client() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VisionStream::new_client requires a client-side connection",
            ));
        }
        Ok(Self::new_common(tls, user_uuid, true, false))
    }

    pub(crate) fn with_write_error_policy(mut self, policy: VisionWriteErrorPolicy) -> Self {
        self.write_error_policy = policy;
        self
    }

    fn output_status(&self) -> io::Result<()> {
        match &self.write_error {
            Some((kind, message)) => Err(io::Error::new(*kind, message.clone())),
            None => Ok(()),
        }
    }

    fn fail_padded_write(&mut self, error: io::Error, accepted: usize) -> Poll<io::Result<usize>> {
        if self.write_error_policy == VisionWriteErrorPolicy::Legacy {
            return Poll::Ready(Err(error));
        }
        self.write_error = Some((error.kind(), error.to_string()));
        self.inner_write_deframer.clear();
        if accepted == 0 {
            Poll::Ready(Err(error))
        } else {
            Poll::Ready(Ok(accepted))
        }
    }

    fn new_common(
        tls: S,
        user_uuid: [u8; 16],
        vless_response_pending: bool,
        vless_response_to_send: bool,
    ) -> Self {
        Self {
            tls,
            write_error_policy: VisionWriteErrorPolicy::Legacy,
            write_error: None,
            read_mode: VisionMode::PaddingTls,
            write_mode: VisionMode::PaddingTls,
            inner_read_deframer: FuzzyTlsDeframer::new(),
            inner_write_deframer: FuzzyTlsDeframer::new(),
            read_unpadder: VisionUnpadder::new(user_uuid),
            write_first_packet: true,
            user_uuid,
            filter: VisionFilter::new(),
            pending_read: BytesMut::new(),
            partial_vless_response: BytesMut::new(),
            vless_response_pending,
            vless_response_to_send,
            pending_tls_mode_switch: false,
            pending_plain_writes: BytesMut::new(),
        }
    }

    fn feed_initial_read_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        log::debug!(
            "VISION: Feeding {} initial decrypted bytes in {} mode",
            data.len(),
            self.read_mode
        );

        match self.read_mode {
            VisionMode::PaddingTls => self.handle_padded_bytes(data)?,
            VisionMode::Tls | VisionMode::Direct => self.pending_read.extend_from_slice(data),
        }

        Ok(())
    }

    fn switch_read_to_direct_mode(&mut self) -> io::Result<()> {
        if self.read_mode != VisionMode::PaddingTls {
            return Err(std::io::Error::other(format!(
                "switch_read_to_direct_mode called from mode {}",
                self.read_mode
            )));
        }

        log::debug!(
            "VISION READ: Switching to direct copy mode (asymmetric - write side may still use padding)"
        );

        // Set read mode to Direct FIRST to avoid inconsistent state
        self.read_mode = VisionMode::Direct;

        log::debug!("VISION READ: Switched to direct mode");

        self.post_padding_cleanup();

        Ok(())
    }

    fn switch_read_to_tls_mode(&mut self) -> io::Result<()> {
        if self.read_mode != VisionMode::PaddingTls {
            return Err(std::io::Error::other(format!(
                "switch_read_to_tls_mode called from mode {}",
                self.read_mode
            )));
        }

        log::debug!("VISION READ: Switching to Tls mode (no XTLS support)");

        // Set read mode to Tls
        self.read_mode = VisionMode::Tls;

        self.post_padding_cleanup();

        Ok(())
    }

    fn switch_write_to_direct_mode(&mut self) -> io::Result<()> {
        if self.write_mode != VisionMode::PaddingTls {
            return Err(std::io::Error::other(format!(
                "switch_write_to_direct_mode called from mode {}",
                self.write_mode
            )));
        }

        log::debug!(
            "VISION WRITE: Switching to direct copy mode (asymmetric - read side may still use padding)"
        );

        self.tls.start_raw_write(&self.pending_plain_writes)?;
        self.pending_plain_writes.clear();
        self.write_mode = VisionMode::Direct;

        self.post_padding_cleanup();

        Ok(())
    }

    /// Switch WRITE side from PaddingTls to Tls mode
    /// This happens when XTLS is not supported or TLS 1.2 is detected
    fn switch_write_to_tls_mode(&mut self) -> io::Result<()> {
        if self.write_mode != VisionMode::PaddingTls {
            return Err(std::io::Error::other(format!(
                "switch_write_to_tls_mode called from mode {}",
                self.write_mode
            )));
        }

        log::debug!("VISION WRITE: Switching to Tls mode (no XTLS support)");

        // Set write mode to Tls
        self.write_mode = VisionMode::Tls;

        self.post_padding_cleanup();

        Ok(())
    }

    fn post_padding_cleanup(&mut self) {
        if self.read_mode == VisionMode::PaddingTls || self.write_mode == VisionMode::PaddingTls {
            return;
        }

        log::debug!("VISION: Cleaning up after read and write padding mode switch");

        // TODO: consider using an Option for all PaddingTls fields instead
        self.inner_read_deframer.deallocate();
        self.inner_write_deframer.deallocate();
        self.pending_plain_writes = BytesMut::new();
    }

    fn queue_padded_write(&mut self, data: &[u8]) {
        self.pending_plain_writes.extend_from_slice(data);
    }

    fn drain_all_writes_padding(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending_plain_writes.is_empty() {
            let written =
                ready!(Pin::new(&mut self.tls).poll_write(cx, &self.pending_plain_writes))?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending_plain_writes.advance(written);
        }
        self.tls.poll_drain_encrypted(cx)
    }

    /// Read the VLESS response header and addons, returning any following plaintext.
    fn poll_read_vless_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<BytesMut>> {
        loop {
            if self.partial_vless_response.len() >= 2 {
                let version = self.partial_vless_response[0];
                if version != 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Invalid VLESS response version: {version}"),
                    )));
                }
                let response_len = 2 + self.partial_vless_response[1] as usize;
                if self.partial_vless_response.len() >= response_len {
                    self.partial_vless_response.advance(response_len);
                    return Poll::Ready(Ok(std::mem::take(&mut self.partial_vless_response)));
                }
            }

            let mut scratch = [0; 8192];
            let mut buf = ReadBuf::new(&mut scratch);
            ready!(Pin::new(&mut self.tls).poll_read(cx, &mut buf))?;
            if buf.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Connection closed while reading VLESS response",
                )));
            }
            self.partial_vless_response.extend_from_slice(buf.filled());
        }
    }

    fn copy_pending_read(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.pending_read.is_empty() {
            return false;
        }
        let len = buf.remaining().min(self.pending_read.len());
        buf.put_slice(&self.pending_read[..len]);
        self.pending_read.advance(len);
        true
    }

    fn poll_read_padding_tls(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut scratch = [0; 8192];
            let mut plaintext = ReadBuf::new(&mut scratch);
            ready!(Pin::new(&mut self.tls).poll_read(cx, &mut plaintext))?;
            if plaintext.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
            self.handle_padded_bytes(plaintext.filled())?;
            if self.copy_pending_read(buf) {
                return Poll::Ready(Ok(()));
            }
            if self.read_mode != VisionMode::PaddingTls {
                return Pin::new(&mut self.tls).poll_read(cx, buf);
            }
        }
    }

    fn handle_padded_bytes(&mut self, decrypted: &[u8]) -> std::io::Result<()> {
        let UnpadResult {
            content: unpadded,
            command: maybe_command,
        } = self.read_unpadder.unpad(decrypted)?;

        log::debug!("VISION READ: Unpadded to {} bytes", unpadded.len());

        if !unpadded.is_empty() && self.filter.is_filtering() {
            // Feed to deframer
            self.inner_read_deframer.feed(&unpadded);

            // Process all complete TLS packets
            loop {
                match self.inner_read_deframer.next_record() {
                    Ok(DeframeResult::TlsRecord(record)) => {
                        self.filter.filter_record(&record);
                        if !self.filter.is_filtering() {
                            break;
                        }
                    }
                    Ok(DeframeResult::UnknownPrefix(prefix)) => {
                        // Skip unknown prefix bytes (e.g., VLESS headers from proxy chain)
                        if prefix.is_empty() {
                            return Err(io::Error::other("FuzzyTlsDeframer returned empty prefix"));
                        }
                        if prefix.len() > 512 {
                            log::warn!(
                                "VISION READ: Unusually large prefix discarded: {} bytes",
                                prefix.len()
                            );
                        }
                        log::debug!("VISION READ: Skipped {} byte prefix", prefix.len());

                        // Decrement once for this chunk
                        self.filter.decrement_filter_count();

                        // Continue processing
                    }
                    Ok(DeframeResult::NeedData) => break, // Need more data
                    Err(e) => {
                        // Invalid TLS packet - stop filtering
                        // This only occurs if we've already seen valid TLS records, and
                        // then encountered invalid ones.
                        log::error!(
                            "VISION READ: Read invalid TLS data after valid records - stopping filtering: {}",
                            e
                        );
                        self.filter
                            .stop_filtering("read invalid TLS data".to_string());
                        break;
                    }
                }
            }
        }

        self.pending_read.extend_from_slice(&unpadded);
        match maybe_command {
            Some(UnpadCommand::Direct) => {
                self.tls.start_raw_read()?;
                self.switch_read_to_direct_mode()?;
            }
            Some(UnpadCommand::End) => {
                self.tls.allow_streaming_reads();
                self.switch_read_to_tls_mode()?;
            }
            Some(UnpadCommand::Continue) | None => {}
        }
        Ok(())
    }

    fn poll_write_padding_tls(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.vless_response_to_send {
            log::debug!("VISION WRITE: Sending VLESS response to TLS session");

            // VLESS response header: [version=0, addon_length=0]
            const VLESS_RESPONSE: [u8; 2] = [0, 0];

            // Write VLESS response to TLS session (will be encrypted)
            self.queue_padded_write(&VLESS_RESPONSE);

            // Clear flag so we don't send it again
            self.vless_response_to_send = false;
        }

        // Finish earlier padded writes before applying END or accepting another record.
        ready!(self.drain_all_writes_padding(cx))?;

        if self.pending_tls_mode_switch {
            log::debug!("VISION WRITE: Switching to Tls mode (flag set by previous write)");
            self.pending_tls_mode_switch = false;
            self.switch_write_to_tls_mode()?;
            return Pin::new(&mut self.tls).poll_write(cx, buf);
        }

        // Feed write buffer to inner deframer and check for ApplicationData
        let existing_inner_len = self.inner_write_deframer.pending_bytes();
        self.inner_write_deframer.feed(buf);
        let accepted_prefix =
            |processed: usize| processed.saturating_sub(existing_inner_len).min(buf.len());

        // Process all complete TLS records in the buffer
        let mut processed_len = 0;
        loop {
            match self.inner_write_deframer.next_record() {
                Ok(DeframeResult::TlsRecord(record)) => {
                    processed_len += record.len();

                    // Feed to filter for TLS pattern detection
                    self.filter.filter_record(&record);

                    // Check if this packet is ApplicationData to switch to Direct mode
                    let is_app_data = self.filter.is_tls() && record.len() >= 3
                        && record[0] == 0x17  // ApplicationData
                        && record[1] == 0x03;

                    // Check if filtering ended and we are not TLS 1.2 or above
                    let non_tls_filtering_ended = !is_app_data
                        && !self.filter.is_filtering()
                        && !self.filter.is_tls12_or_above();

                    if is_app_data || non_tls_filtering_ended {
                        if is_app_data {
                            log::debug!(
                                "VISION WRITE: Detected ApplicationData in {} byte packet",
                                record.len()
                            );
                        } else {
                            log::debug!("VISION WRITE: Filtering ended, not TLS 1.2 or above");
                        }

                        let command = if self.filter.supports_xtls() {
                            COMMAND_DIRECT
                        } else {
                            self.pending_tls_mode_switch = true;
                            COMMAND_END
                        };

                        let final_padded_packet = if self.write_first_packet {
                            self.write_first_packet = false;
                            super::vision_pad::pad_with_uuid_and_command(
                                &record,
                                &self.user_uuid,
                                command,
                                true, // is_tls
                            )
                        } else {
                            super::vision_pad::pad_with_command(
                                &record, command, true, // is_tls
                            )
                        };

                        self.queue_padded_write(&final_padded_packet);
                        if command == COMMAND_DIRECT
                            && let Err(error) = self.switch_write_to_direct_mode()
                        {
                            return self.fail_padded_write(error, accepted_prefix(processed_len));
                        }

                        // this must be true because else we would have a successful next_record call on previous iteration
                        assert!(processed_len > existing_inner_len);

                        // Drain and handle result
                        match self.drain_all_writes_padding(cx) {
                            Poll::Ready(Ok(())) => {
                                // Fully drained, continue
                            }
                            Poll::Ready(Err(e)) => {
                                return self.fail_padded_write(e, accepted_prefix(processed_len));
                            }
                            Poll::Pending => {
                                // Still draining
                            }
                        }

                        // Clear deframer since caller will re-feed remaining data
                        self.inner_write_deframer.clear();

                        // tell caller to resend the next packets after the mode switch
                        return Poll::Ready(Ok(processed_len - existing_inner_len));
                    }

                    // if we got here, it's:
                    // - a non-TLS packet of data and we're still filtering
                    // - a TLS record that is not app data, and we have not yet seen app data, even
                    //   though we might be done filtering
                    // .. so we need to continue padding
                    // ref: https://github.com/XTLS/Xray-core/blob/9f5dcb15910aadc7ef450514747576827a389853/proxy/proxy.go#L371

                    let padded_packet = if self.write_first_packet {
                        self.write_first_packet = false;
                        super::vision_pad::pad_with_uuid_and_command(
                            &record,
                            &self.user_uuid,
                            COMMAND_CONTINUE,
                            self.filter.is_tls(),
                        )
                    } else {
                        super::vision_pad::pad_with_command(
                            &record,
                            COMMAND_CONTINUE,
                            self.filter.is_tls(),
                        )
                    };

                    self.queue_padded_write(&padded_packet);
                    match self.drain_all_writes_padding(cx) {
                        Poll::Pending => {
                            let unprocessed_buf_len =
                                buf.len() - (processed_len - existing_inner_len);
                            // sanity check
                            assert!(
                                self.inner_write_deframer.pending_bytes() == unprocessed_buf_len
                            );
                            // Discard the unaccepted tail, but keep TLS recognition for resubmission.
                            self.inner_write_deframer.discard_buffered();
                            return Poll::Ready(Ok(processed_len - existing_inner_len));
                        }
                        Poll::Ready(Ok(())) => {
                            // continue since it drained
                        }
                        Poll::Ready(Err(e)) => {
                            return self.fail_padded_write(e, accepted_prefix(processed_len));
                        }
                    }
                }
                Ok(DeframeResult::NeedData) => {
                    // TODO: There's a theoretical edge case where non-TLS data ends with bytes
                    // that look like a valid TLS record prefix (e.g., [0x16, 0x03, 0x03]).
                    // The deframer would hold onto these bytes waiting for more data to
                    // complete the "TLS record", but since it's not actually TLS, no more
                    // data will come. This would cause a hang.
                    //
                    // This is extremely unlikely in practice, so we choose not to handle this edge
                    // case to keep the code simple.
                    break;
                }
                Ok(DeframeResult::UnknownPrefix(prefix)) => {
                    // TODO: check lengths and see if we need to split into multiple packets, see
                    // https://github.com/XTLS/Xray-core/blob/9f5dcb15910aadc7ef450514747576827a389853/proxy/proxy.go#L390

                    processed_len += prefix.len();

                    self.filter.decrement_filter_count();

                    if self.filter.is_filtering() {
                        // We don't assume the deframer won't return any more packets,
                        // so we continue here, and stop if we're no longer filtering.
                        let padded_packet = if self.write_first_packet {
                            self.write_first_packet = false;
                            super::vision_pad::pad_with_uuid_and_command(
                                &prefix,
                                &self.user_uuid,
                                COMMAND_CONTINUE,
                                self.filter.is_tls(),
                            )
                        } else {
                            super::vision_pad::pad_with_command(
                                &prefix,
                                COMMAND_CONTINUE,
                                self.filter.is_tls(),
                            )
                        };

                        self.queue_padded_write(&padded_packet);
                        match self.drain_all_writes_padding(cx) {
                            Poll::Pending => {}
                            Poll::Ready(Ok(())) => {}
                            Poll::Ready(Err(e)) => {
                                return self.fail_padded_write(e, accepted_prefix(processed_len));
                            }
                        }

                        // Continue processing
                    } else {
                        // Sending end command to switch to TLS, there are no more padded packets.
                        self.pending_tls_mode_switch = true;

                        let padded_packet = if self.write_first_packet {
                            self.write_first_packet = false;
                            super::vision_pad::pad_with_uuid_and_command(
                                &prefix,
                                &self.user_uuid,
                                COMMAND_END,
                                self.filter.is_tls(),
                            )
                        } else {
                            super::vision_pad::pad_with_command(
                                &prefix,
                                COMMAND_END,
                                self.filter.is_tls(),
                            )
                        };

                        // Clear deframe, not really necessary since deallocate will occur and this
                        // will never be used again.
                        self.inner_write_deframer.clear();

                        self.queue_padded_write(&padded_packet);
                        // Drain and handle result
                        match self.drain_all_writes_padding(cx) {
                            Poll::Ready(Ok(())) => {
                                // Fully drained
                            }
                            Poll::Ready(Err(e)) => {
                                return self.fail_padded_write(e, accepted_prefix(processed_len));
                            }
                            Poll::Pending => {
                                // Still draining
                            }
                        }

                        // tell caller to resend the next packets after the mode switch
                        return Poll::Ready(Ok(processed_len - existing_inner_len));
                    }
                }
                Err(e) => {
                    // Deframing failed, this error means we've already seen a valid TLS record on
                    // the write side and then invalid TLS data is encountered.
                    // Switch immediately to TLS mode and send the invalid data as a single packet.
                    // TODO: check lengths and see if we need to split into multiple packets, see
                    // https://github.com/XTLS/Xray-core/blob/9f5dcb15910aadc7ef450514747576827a389853/proxy/proxy.go#L390
                    //
                    log::error!(
                        "VISION WRITE: Deframing failed, invalid data after valid records - stopping filtering: {}",
                        e
                    );

                    self.pending_tls_mode_switch = true;

                    self.filter
                        .stop_filtering("write invalid TLS data".to_string());

                    let remaining_data = self.inner_write_deframer.remaining_data();

                    let padded_packet = if self.write_first_packet {
                        self.write_first_packet = false;
                        super::vision_pad::pad_with_uuid_and_command(
                            remaining_data,
                            &self.user_uuid,
                            COMMAND_END,
                            self.filter.is_tls(),
                        )
                    } else {
                        super::vision_pad::pad_with_command(
                            remaining_data,
                            COMMAND_END,
                            self.filter.is_tls(),
                        )
                    };

                    self.queue_padded_write(&padded_packet);

                    match self.drain_all_writes_padding(cx) {
                        Poll::Pending => {}
                        Poll::Ready(Ok(())) => {}
                        // The final END packet includes the entire unprocessed tail.
                        Poll::Ready(Err(e)) => return self.fail_padded_write(e, buf.len()),
                    }

                    self.inner_write_deframer.clear();

                    return Poll::Ready(Ok(buf.len()));
                }
            }
        }

        // we processed all records if we got here
        Poll::Ready(Ok(buf.len()))
    }
}

impl<S: VisionTransport> AsyncRead for VisionStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if this.copy_pending_read(buf) {
            return Poll::Ready(Ok(()));
        }

        if this.vless_response_pending {
            let decrypted_data = ready!(this.poll_read_vless_response(cx))?;
            this.vless_response_pending = false;
            this.feed_initial_read_data(&decrypted_data)?;
            if this.copy_pending_read(buf) {
                return Poll::Ready(Ok(()));
            }
        }

        match this.read_mode {
            VisionMode::PaddingTls => this.poll_read_padding_tls(cx, buf),
            VisionMode::Tls | VisionMode::Direct => Pin::new(&mut this.tls).poll_read(cx, buf),
        }
    }
}

impl<S: VisionTransport> AsyncWrite for VisionStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.output_status()?;
        match this.write_mode {
            VisionMode::PaddingTls => this.poll_write_padding_tls(cx, buf),
            VisionMode::Tls | VisionMode::Direct => Pin::new(&mut this.tls).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.output_status()?;
        if this.write_mode == VisionMode::PaddingTls {
            ready!(this.drain_all_writes_padding(cx))?;
        }
        Pin::new(&mut this.tls).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.tls).poll_shutdown(cx)
    }
}

impl<S: VisionTransport> crate::async_stream::AsyncPing for VisionStream<S> {
    fn supports_ping(&self) -> bool {
        self.tls.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let this = self.get_mut();
        this.output_status()?;
        Pin::new(&mut this.tls).poll_write_ping(cx)
    }
}

impl<S: VisionTransport> AsyncStream for VisionStream<S> {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.tls.peer_addr()
    }
    #[cfg(target_os = "linux")]
    fn plain_tcp(&self) -> Option<&tokio::net::TcpStream> {
        if self.read_mode != VisionMode::Direct
            || self.write_error.is_some()
            || self.write_mode != VisionMode::Direct
            || !self.pending_read.is_empty()
            || self.vless_response_pending
            || !self.partial_vless_response.is_empty()
            || self.vless_response_to_send
            || !self.pending_plain_writes.is_empty()
            || self.pending_tls_mode_switch
            || self.inner_write_deframer.pending_bytes() != 0
        {
            return None;
        }
        self.tls.plain_tcp()
    }
}

#[cfg(test)]
mod tests;
