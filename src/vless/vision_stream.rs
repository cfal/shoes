//! VISION stream implementation
//!
//! VisionStream wraps an IO stream and TLS session, allowing it to:
//! - Use TLS with VISION padding to hide protocol fingerprints
//! - Detect TLS-in-TLS scenarios by analyzing traffic patterns
//! - Switch to direct I/O mode, bypassing TLS for zero-copy performance

use bytes::{Buf, BytesMut};

use crate::crypto::CryptoTlsStream;
use futures::ready;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::AsyncStream;

use super::tls_fuzzy_deframer::{DeframeResult, FuzzyTlsDeframer};
use super::vision_filter::VisionFilter;
use super::vision_unpad::{UnpadCommand, UnpadResult, VisionUnpadder};

// TODO: consider combining with UnpadCommand
const COMMAND_CONTINUE: u8 = 0x00;
const COMMAND_END: u8 = 0x01;
const COMMAND_DIRECT: u8 = 0x02;

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

pub struct VisionStream<IO> {
    tls: CryptoTlsStream<IO>,

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

impl<IO> VisionStream<IO>
where
    IO: AsyncStream,
{
    /// Create a new VisionStream for server-side (inbound) connections with VLESS response writing
    pub fn new_server(
        tls: CryptoTlsStream<IO>,
        user_uuid: [u8; 16],
        initial_read_data: &[u8],
    ) -> io::Result<Self> {
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

    pub fn new_client(tls: CryptoTlsStream<IO>, user_uuid: [u8; 16]) -> io::Result<Self> {
        tls.require_record_framing()?;
        if !tls.is_client() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VisionStream::new_client requires a client-side connection",
            ));
        }
        Ok(Self::new_common(tls, user_uuid, true, false))
    }

    fn new_common(
        tls: CryptoTlsStream<IO>,
        user_uuid: [u8; 16],
        vless_response_pending: bool,
        vless_response_to_send: bool,
    ) -> Self {
        Self {
            tls,
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
        self.tls.poll_drain_tls(cx)
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
                        if command == COMMAND_DIRECT {
                            self.switch_write_to_direct_mode()?;
                        }

                        // this must be true because else we would have a successful next_record call on previous iteration
                        assert!(processed_len > existing_inner_len);

                        // Drain and handle result
                        match self.drain_all_writes_padding(cx) {
                            Poll::Ready(Ok(())) => {
                                // Fully drained, continue
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
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
                            // clear since the user will re-feed
                            self.inner_write_deframer.clear();
                            return Poll::Ready(Ok(processed_len - existing_inner_len));
                        }
                        Poll::Ready(Ok(())) => {
                            // continue since it drained
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
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
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
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
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
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
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
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

impl<IO: AsyncStream> AsyncRead for VisionStream<IO> {
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

impl<IO: AsyncStream> AsyncWrite for VisionStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.write_mode {
            VisionMode::PaddingTls => this.poll_write_padding_tls(cx, buf),
            VisionMode::Tls | VisionMode::Direct => Pin::new(&mut this.tls).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
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

impl<IO: AsyncStream> crate::async_stream::AsyncPing for VisionStream<IO> {
    fn supports_ping(&self) -> bool {
        self.tls.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.get_mut().tls).poll_write_ping(cx)
    }
}

impl<IO: AsyncStream> AsyncStream for VisionStream<IO> {
    #[cfg(target_os = "linux")]
    fn plain_tcp(&self) -> Option<&tokio::net::TcpStream> {
        if self.read_mode != VisionMode::Direct
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
mod tests {
    #[cfg(target_os = "linux")]
    mod splice;

    use super::*;
    use crate::address::{Address, NetLocation};
    use crate::async_stream::AsyncPing;
    use crate::crypto::tls_deframer::TlsDeframer;
    use crate::crypto::{CryptoConnection, TlsReadMode, feed_crypto_connection};
    use crate::reality::{
        RealityClientConfig, RealityClientConnection, RealityServerConfig, RealityServerConnection,
    };
    use futures::task::noop_waker_ref;
    use std::collections::VecDeque;
    use std::io::Write;
    use std::sync::Arc;

    fn feed_and_process_crypto_connection(
        session: &mut CryptoConnection,
        data: &[u8],
    ) -> io::Result<()> {
        feed_crypto_connection(session, data)?;
        session.process_new_packets().map(|_| ())
    }

    struct ScriptedIo {
        reads: VecDeque<bytes::Bytes>,
    }

    impl AsyncRead for ScriptedIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let Some(chunk) = this.reads.front_mut() else {
                return Poll::Pending;
            };
            let len = buf.remaining().min(chunk.len());
            buf.put_slice(&chunk[..len]);
            chunk.advance(len);
            if chunk.is_empty() {
                this.reads.pop_front();
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for ScriptedIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncPing for ScriptedIo {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for ScriptedIo {}

    #[derive(Default)]
    struct WriteGate {
        blocked: bool,
        flush_blocked: bool,
        output: Vec<u8>,
    }

    struct GatedIo {
        input: ScriptedIo,
        gate: Arc<std::sync::Mutex<WriteGate>>,
    }

    impl AsyncRead for GatedIo {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().input).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for GatedIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut gate = self.gate.lock().unwrap();
            if gate.blocked {
                return Poll::Pending;
            }
            gate.output.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.gate.lock().unwrap().flush_blocked {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    impl AsyncPing for GatedIo {
        fn supports_ping(&self) -> bool {
            false
        }

        fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
            Poll::Ready(Ok(false))
        }
    }

    impl AsyncStream for GatedIo {}

    #[derive(Clone, Copy)]
    enum Backend {
        Tls12,
        Tls13,
        Reality,
    }

    const BACKENDS: [Backend; 3] = [Backend::Tls12, Backend::Tls13, Backend::Reality];

    fn new_connections(backend: Backend) -> (CryptoConnection, CryptoConnection) {
        let version = match backend {
            Backend::Tls12 => &rustls::version::TLS12,
            Backend::Tls13 => &rustls::version::TLS13,
            Backend::Reality => return reality_connections(),
        };
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_protocol_versions(&[version])
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
        config.send_tls13_tickets = 0;
        let client_config = rustls::ClientConfig::builder_with_protocol_versions(&[version])
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client = CryptoConnection::new_rustls_client(
            rustls::ClientConnection::new(Arc::new(client_config), "localhost".try_into().unwrap())
                .unwrap(),
        );
        let server = CryptoConnection::new_rustls_server(
            rustls::ServerConnection::new(Arc::new(config)).unwrap(),
        );
        (client, server)
    }

    fn reality_connections() -> (CryptoConnection, CryptoConnection) {
        use aws_lc_rs::agreement;
        let private_key = [1; 32];
        let public_key = agreement::PrivateKey::from_private_key(&agreement::X25519, &private_key)
            .unwrap()
            .compute_public_key()
            .unwrap();
        let mut client = RealityClientConnection::new(RealityClientConfig {
            public_key: public_key.as_ref().try_into().unwrap(),
            short_id: [0; 8],
            server_name: "localhost".into(),
            cipher_suites: Vec::new(),
        })
        .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let mut server = RealityServerConnection::new(RealityServerConfig {
            private_key,
            short_ids: vec![[0; 8]],
            dest: NetLocation::new(Address::Hostname("localhost".into()), 443),
            max_time_diff: None,
            min_client_version: None,
            max_client_version: None,
            cipher_suites: Vec::new(),
        })
        .unwrap();
        server.validate_client_hello(&hello).unwrap();
        server.build_server_response(Vec::new()).unwrap();
        (
            CryptoConnection::new_reality_client(client),
            CryptoConnection::new_reality_server(server),
        )
    }

    fn connection_pair(backend: Backend) -> (CryptoConnection, CryptoConnection) {
        let (mut client, mut server) = new_connections(backend);
        for _ in 0..8 {
            transfer_tls(&mut client, &mut server);
            transfer_tls(&mut server, &mut client);
            if !client.is_handshaking() && !server.is_handshaking() {
                return (client, server);
            }
        }
        panic!("in-memory TLS handshake did not finish");
    }

    fn transfer_tls(sender: &mut CryptoConnection, receiver: &mut CryptoConnection) {
        let mut bytes = Vec::new();
        sender.write_tls(&mut bytes).unwrap();
        if !bytes.is_empty() {
            feed_and_process_crypto_connection(receiver, &bytes).unwrap();
        }
    }

    fn encrypt(session: &mut CryptoConnection, plaintext: &[u8]) -> Vec<u8> {
        session.writer().write_all(plaintext).unwrap();
        let mut ciphertext = Vec::new();
        session.write_tls(&mut ciphertext).unwrap();
        ciphertext
    }

    fn inner_server_hello() -> bytes::Bytes {
        let (mut client, mut server) = new_connections(Backend::Tls13);
        transfer_tls(&mut client, &mut server);
        let mut flight = Vec::new();
        server.write_tls(&mut flight).unwrap();
        let mut deframer = TlsDeframer::new();
        deframer.feed(&flight);
        deframer.next_record().unwrap().unwrap()
    }

    fn assert_buffered_reads(stream: &mut (impl AsyncRead + Unpin), expected: &[u8]) {
        let mut received = Vec::new();
        let mut cx = Context::from_waker(noop_waker_ref());
        while received.len() < expected.len() {
            let mut bytes = [0; 3];
            let mut buf = ReadBuf::new(&mut bytes);
            match Pin::new(&mut *stream).poll_read(&mut cx, &mut buf) {
                Poll::Ready(Ok(())) => {}
                result => panic!("expected buffered data: {result:?}"),
            }
            assert!(!buf.filled().is_empty());
            received.extend_from_slice(buf.filled());
        }
        assert_eq!(received, expected);

        let mut bytes = [0; 3];
        let mut buf = ReadBuf::new(&mut bytes);
        assert!(Pin::new(stream).poll_read(&mut cx, &mut buf).is_pending());
        assert!(buf.filled().is_empty());
    }

    #[test]
    fn vision_rejects_streams_without_record_preservation() {
        let (client, server) = connection_pair(Backend::Tls13);
        for session in [client, server] {
            let is_server = session.is_server();
            let io = ScriptedIo {
                reads: VecDeque::new(),
            };
            let tls = CryptoTlsStream::new(io, session, None);
            let result = if is_server {
                VisionStream::new_server(tls, [7; 16], b"")
            } else {
                VisionStream::new_client(tls, [7; 16])
            };
            let error = result.err().expect("missing framing must be rejected");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn direct_write_waits_for_pending_tls_and_transport_flush() {
        use std::io::Read;

        for backend in BACKENDS {
            let (mut peer, session) = connection_pair(backend);
            let gate = Arc::new(std::sync::Mutex::new(WriteGate {
                blocked: true,
                flush_blocked: true,
                output: Vec::new(),
            }));
            let io = GatedIo {
                input: ScriptedIo {
                    reads: VecDeque::new(),
                },
                gate: gate.clone(),
            };
            let mut tls = CryptoTlsStream::new(io, session, Some(TlsDeframer::new()));
            let mut cx = Context::from_waker(noop_waker_ref());
            assert!(matches!(
                Pin::new(&mut tls).poll_write(&mut cx, b"before handoff"),
                Poll::Ready(Ok(14))
            ));
            let mut vision = VisionStream::new_server(tls, [7; 16], b"").unwrap();
            vision.vless_response_to_send = false;
            vision.queue_padded_write(b"-final padded record");
            vision.switch_write_to_direct_mode().unwrap();
            assert!(
                Pin::new(&mut vision)
                    .poll_write(&mut cx, b"raw")
                    .is_pending()
            );
            assert!(gate.lock().unwrap().output.is_empty());

            gate.lock().unwrap().blocked = false;
            assert!(
                Pin::new(&mut vision)
                    .poll_write(&mut cx, b"raw")
                    .is_pending()
            );
            let ciphertext = gate.lock().unwrap().output.clone();
            feed_and_process_crypto_connection(&mut peer, &ciphertext).unwrap();
            let mut plaintext = [0; 34];
            peer.reader().read_exact(&mut plaintext).unwrap();
            assert_eq!(&plaintext, b"before handoff-final padded record");

            gate.lock().unwrap().flush_blocked = false;
            assert!(matches!(
                Pin::new(&mut vision).poll_write(&mut cx, b"raw"),
                Poll::Ready(Ok(3))
            ));
            assert!(matches!(
                Pin::new(&mut vision).poll_shutdown(&mut cx),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(
                gate.lock().unwrap().output,
                [ciphertext.as_slice(), b"raw"].concat()
            );
        }
    }

    #[test]
    fn raw_write_direction_never_sends_tls_alerts() {
        let (_, session) = connection_pair(Backend::Tls13);
        let gate = Arc::new(std::sync::Mutex::new(WriteGate::default()));
        let io = GatedIo {
            input: ScriptedIo {
                reads: VecDeque::from([bytes::Bytes::from_static(b"\x17\x03\x03\x00\x03bad")]),
            },
            gate: gate.clone(),
        };
        let mut tls = CryptoTlsStream::new(io, session, Some(TlsDeframer::new()));
        let mut cx = Context::from_waker(noop_waker_ref());
        tls.start_raw_write(b"").unwrap();
        let mut bytes = [0; 8];
        let result = Pin::new(&mut tls).poll_read(&mut cx, &mut ReadBuf::new(&mut bytes));
        assert!(matches!(result, Poll::Ready(Err(_))));
        assert!(gate.lock().unwrap().output.is_empty());
    }

    #[test]
    fn direct_write_never_sends_later_tls_alerts() {
        use std::io::{BufRead, Read};

        let hello = inner_server_hello();
        let application = b"\x17\x03\x03\x00\x03app";
        let uuid = [7; 16];
        for backend in BACKENDS {
            for flush_first in [false, true] {
                for blocked in [false, true] {
                    let (mut peer, session) = connection_pair(backend);
                    let gate = Arc::new(std::sync::Mutex::new(WriteGate::default()));
                    let io = GatedIo {
                        input: ScriptedIo {
                            reads: VecDeque::from([bytes::Bytes::from_static(
                                b"\x17\x03\x03\x00\x03bad",
                            )]),
                        },
                        gate: gate.clone(),
                    };
                    let tls = CryptoTlsStream::new(io, session, Some(TlsDeframer::new()));
                    let mut vision = VisionStream::new_server(tls, uuid, b"").unwrap();
                    let mut cx = Context::from_waker(noop_waker_ref());
                    assert!(matches!(
                        Pin::new(&mut vision).poll_write(&mut cx, &hello),
                        Poll::Ready(Ok(n)) if n == hello.len()
                    ));
                    gate.lock().unwrap().blocked = blocked;
                    assert!(matches!(
                        Pin::new(&mut vision).poll_write(&mut cx, application),
                        Poll::Ready(Ok(n)) if n == application.len()
                    ));
                    if flush_first {
                        let result = Pin::new(&mut vision).poll_flush(&mut cx);
                        if blocked {
                            assert!(result.is_pending());
                        } else {
                            assert!(matches!(result, Poll::Ready(Ok(()))));
                        }
                    }
                    let sent_before_read = gate.lock().unwrap().output.clone();
                    let mut bytes = [0; 8];
                    assert!(matches!(
                        Pin::new(&mut vision).poll_read(&mut cx, &mut ReadBuf::new(&mut bytes)),
                        Poll::Ready(Err(_))
                    ));
                    assert_eq!(gate.lock().unwrap().output, sent_before_read);

                    gate.lock().unwrap().blocked = false;
                    assert!(matches!(
                        Pin::new(&mut vision).poll_flush(&mut cx),
                        Poll::Ready(Ok(()))
                    ));
                    assert!(matches!(
                        Pin::new(&mut vision).poll_shutdown(&mut cx),
                        Poll::Ready(Ok(()))
                    ));
                    let ciphertext = gate.lock().unwrap().output.clone();
                    feed_and_process_crypto_connection(&mut peer, &ciphertext).unwrap();
                    let mut plaintext = Vec::new();
                    if let Err(error) = peer.reader().read_to_end(&mut plaintext) {
                        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                    }
                    assert!(matches!(peer.reader().fill_buf(),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                    assert_eq!(&plaintext[..2], &[0, 0]);
                    let result = VisionUnpadder::new(uuid).unpad(&plaintext[2..]).unwrap();
                    assert_eq!(result.command, Some(UnpadCommand::Direct));
                    assert_eq!(result.content, [hello.as_ref(), application].concat());
                }
            }
        }
    }

    #[test]
    fn direct_transition_keeps_reads_live_under_output_backpressure() {
        let hello = inner_server_hello();
        let application = b"\x17\x03\x03\x00\x03app";
        let uuid = [7; 16];
        for backend in BACKENDS {
            let (mut peer, session) = connection_pair(backend);
            let mut reply = uuid.to_vec();
            reply.extend_from_slice(&[COMMAND_CONTINUE, 0, 5, 0, 0]);
            reply.extend_from_slice(b"reply");
            let gate = Arc::new(std::sync::Mutex::new(WriteGate::default()));
            let io = GatedIo {
                input: ScriptedIo {
                    reads: VecDeque::from([encrypt(&mut peer, &reply).into()]),
                },
                gate: gate.clone(),
            };
            let tls = CryptoTlsStream::new(io, session, Some(TlsDeframer::new()));
            let mut vision = VisionStream::new_server(tls, uuid, b"").unwrap();
            let mut cx = Context::from_waker(noop_waker_ref());
            assert!(matches!(
                Pin::new(&mut vision).poll_write(&mut cx, &hello),
                Poll::Ready(Ok(n)) if n == hello.len()
            ));
            gate.lock().unwrap().blocked = true;
            gate.lock().unwrap().flush_blocked = true;
            assert!(matches!(
                Pin::new(&mut vision).poll_write(&mut cx, application),
                Poll::Ready(Ok(n)) if n == application.len()
            ));
            assert!(
                Pin::new(&mut vision)
                    .poll_write(&mut cx, b"raw")
                    .is_pending()
            );
            let mut bytes = [0; 8];
            let mut buf = ReadBuf::new(&mut bytes);
            assert!(matches!(
                Pin::new(&mut vision).poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(buf.filled(), b"reply");

            gate.lock().unwrap().blocked = false;
            assert!(
                Pin::new(&mut vision)
                    .poll_write(&mut cx, b"raw")
                    .is_pending()
            );
            let ciphertext = gate.lock().unwrap().output.clone();
            gate.lock().unwrap().flush_blocked = false;
            assert!(matches!(
                Pin::new(&mut vision).poll_write(&mut cx, b"raw"),
                Poll::Ready(Ok(3))
            ));
            assert_eq!(
                gate.lock().unwrap().output,
                [ciphertext.as_slice(), b"raw"].concat()
            );
        }
    }

    #[test]
    fn record_preservation_survives_pending_between_fragments() {
        for backend in BACKENDS {
            let (mut sender, session) = connection_pair(backend);
            let uuid = [7; 16];
            let mut plaintext = uuid.to_vec();
            plaintext.extend_from_slice(&[COMMAND_DIRECT, 0, 3, 0, 0]);
            plaintext.extend_from_slice(b"one");
            let ciphertext = encrypt(&mut sender, &plaintext);
            let (io, mut peer) = tokio::io::duplex(4096);
            let mut cx = Context::from_waker(noop_waker_ref());
            assert!(matches!(
                Pin::new(&mut peer).poll_write(&mut cx, &ciphertext[..3]),
                Poll::Ready(Ok(3))
            ));
            let tls = CryptoTlsStream::new(io, session, Some(TlsDeframer::new()));
            let mut vision = VisionStream::new_server(tls, uuid, b"").unwrap();
            let mut bytes = [0; 16];
            let mut buf = ReadBuf::new(&mut bytes);
            assert!(
                Pin::new(&mut vision)
                    .poll_read(&mut cx, &mut buf)
                    .is_pending()
            );
            assert!(buf.filled().is_empty());
            let tail = [&ciphertext[3..], b"-raw"].concat();
            assert!(matches!(
                Pin::new(&mut peer).poll_write(&mut cx, &tail),
                Poll::Ready(Ok(n)) if n == tail.len()
            ));
            assert_buffered_reads(&mut vision, b"one-raw");
        }
    }

    #[tokio::test]
    async fn vision_target_plain_udp_preserves_preread_and_following_records() {
        use crate::client_proxy_selector::ClientProxySelector;
        use crate::resolver::{NativeResolver, Resolver};
        use crate::tcp::tcp_handler::TcpServerSetupResult;

        for backend in BACKENDS {
            let (mut client, server) = connection_pair(backend);
            let uuid = [7; 16];
            let mut request = vec![0];
            request.extend_from_slice(&uuid);
            request.extend_from_slice(&[0, 2, 0, 53, 1, 127, 0, 0, 1]);
            request.extend_from_slice(&1000u16.to_be_bytes());
            request.extend_from_slice(&[42; 1000]);
            let mut first = encrypt(&mut client, &request);
            let second = encrypt(&mut client, b"\x00\x03two");
            first.extend_from_slice(&second[..3]);
            let io = ScriptedIo {
                reads: VecDeque::from([first.into(), second[3..].to_vec().into()]),
            };
            let tls = CryptoTlsStream::new(io, server, Some(TlsDeframer::new()));
            let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
            let result =
                super::super::vless_server_handler::setup_custom_tls_vision_vless_server_stream(
                    tls,
                    &uuid,
                    true,
                    Arc::new(ClientProxySelector::new(Vec::new())),
                    &resolver,
                    None,
                )
                .await
                .unwrap();
            let TcpServerSetupResult::BidirectionalUdp { mut stream, .. } = result else {
                panic!("expected ordinary UDP on the Vision-enabled target");
            };
            for expected in [vec![42; 1000], b"two".to_vec()] {
                let mut bytes = [0; 1024];
                let mut buf = ReadBuf::new(&mut bytes);
                futures::future::poll_fn(|cx| {
                    Pin::new(&mut *stream).poll_read_message(cx, &mut buf)
                })
                .await
                .unwrap();
                assert_eq!(buf.filled(), expected);
            }
        }
    }

    #[tokio::test]
    async fn vision_target_auth_fallback_preserves_all_plaintext() {
        use crate::client_proxy_selector::ClientProxySelector;
        use crate::resolver::{NativeResolver, Resolver};
        use crate::tcp::tcp_handler::TcpServerSetupResult;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for backend in BACKENDS {
            for invalid_version in [false, true] {
                let (mut client, server) = connection_pair(backend);
                let mut expected = vec![u8::from(invalid_version)];
                expected.extend_from_slice(&[8; 16]);
                let mut first = encrypt(&mut client, &expected);
                let suffix = vec![42; 1000];
                let second = encrypt(&mut client, &suffix);
                expected.extend_from_slice(&suffix);
                first.extend_from_slice(&second[..3]);
                let mut remaining = second[3..].to_vec();
                client.send_close_notify();
                client.write_tls(&mut remaining).unwrap();
                let io = ScriptedIo {
                    reads: VecDeque::from([first.into(), remaining.into()]),
                };
                let tls = CryptoTlsStream::new(io, server, Some(TlsDeframer::new()));
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let fallback = NetLocation::new(
                    Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    listener.local_addr().unwrap().port(),
                );
                let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
                let result = super::super::vless_server_handler::setup_custom_tls_vision_vless_server_stream(
                    tls, &[7; 16], true, Arc::new(ClientProxySelector::new(Vec::new())),
                    &resolver, Some(fallback),
                ).await.unwrap();
                let TcpServerSetupResult::Session(session) = result else {
                    panic!("expected authentication fallback");
                };
                tokio::time::timeout(std::time::Duration::from_secs(2), async {
                    tokio::join!(session, async {
                        let (mut socket, _) = listener.accept().await.unwrap();
                        let mut received = Vec::new();
                        socket.read_to_end(&mut received).await.unwrap();
                        assert_eq!(received, expected);
                        socket.shutdown().await.unwrap();
                    });
                })
                .await
                .unwrap();
            }
        }
    }

    #[test]
    fn closure_framed_tls_rejects_unclean_eof() {
        for backend in [Backend::Tls12, Backend::Tls13] {
            for framed in [false, true] {
                let (_, session) = connection_pair(backend);
                let io = ScriptedIo {
                    reads: VecDeque::from([bytes::Bytes::new()]),
                };
                let mut stream = CryptoTlsStream::new(io, session, framed.then(TlsDeframer::new));
                let mut cx = Context::from_waker(noop_waker_ref());
                let mut bytes = [0; 8];
                let mut buf = ReadBuf::new(&mut bytes);
                let result = Pin::new(&mut stream).poll_read(&mut cx, &mut buf);
                assert!(
                    matches!(result, Poll::Ready(Err(ref error)) if error.kind() == io::ErrorKind::UnexpectedEof),
                    "framed={framed}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn closure_vision_recognizes_close_notify_without_tcp_eof() {
        for backend in BACKENDS {
            let (mut client, server) = connection_pair(backend);
            let uuid = [7; 16];
            let mut plaintext = uuid.to_vec();
            plaintext.extend_from_slice(&[COMMAND_CONTINUE, 0, 3, 0, 0]);
            plaintext.extend_from_slice(b"one");
            let mut ciphertext = encrypt(&mut client, &plaintext);
            client.send_close_notify();
            client.write_tls(&mut ciphertext).unwrap();
            let io = ScriptedIo {
                reads: VecDeque::from([ciphertext.into()]),
            };
            let mut stream = VisionStream::new_server(
                CryptoTlsStream::new(io, server, Some(TlsDeframer::new())),
                uuid,
                b"",
            )
            .unwrap();
            let mut cx = Context::from_waker(noop_waker_ref());
            let mut bytes = [0; 8];
            let mut buf = ReadBuf::new(&mut bytes);
            assert!(matches!(
                Pin::new(&mut stream).poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(buf.filled(), b"one");
            buf.clear();
            let result = Pin::new(&mut stream).poll_read(&mut cx, &mut buf);
            assert!(matches!(result, Poll::Ready(Ok(()))), "{result:?}");
            assert!(buf.filled().is_empty());
        }
    }

    #[test]
    fn tls_handoff_preserves_partial_record() {
        for backend in BACKENDS {
            for split in [1, 2, 3, 4, 5, 10, 5000, usize::MAX] {
                let (mut client, server) = connection_pair(backend);
                let uuid = [7; 16];
                let mut first = vec![0];
                first.extend_from_slice(&uuid);
                first.extend_from_slice(&[COMMAND_CONTINUE, 0, 3, 0, 0]);
                first.extend_from_slice(b"one");
                let mut ciphertext = encrypt(&mut client, &first);
                let mut second = vec![COMMAND_CONTINUE];
                second.extend_from_slice(&10_000u16.to_be_bytes());
                second.extend_from_slice(&[0, 0]);
                second.resize(10_005, b'Z');
                let next_record = encrypt(&mut client, &second);
                let split = split.min(next_record.len() - 1);
                ciphertext.extend_from_slice(&next_record[..split]);
                let io = ScriptedIo {
                    reads: VecDeque::from([
                        ciphertext.into(),
                        next_record[split..].to_vec().into(),
                    ]),
                };
                let mut tls = CryptoTlsStream::new(io, server, Some(TlsDeframer::new()));
                let mut cx = Context::from_waker(noop_waker_ref());
                let mut header = [255];
                let mut buf = ReadBuf::new(&mut header);
                assert!(matches!(
                    Pin::new(&mut tls).poll_read(&mut cx, &mut buf),
                    Poll::Ready(Ok(()))
                ));
                assert_eq!(header, [0]);

                let mut vision = VisionStream::new_server(tls, uuid, b"").unwrap();
                let mut expected = b"one".to_vec();
                expected.resize(10_003, b'Z');
                assert_buffered_reads(&mut vision, &expected);
            }
        }
    }

    #[test]
    fn direct_read_preserves_plaintext_beyond_the_read_buffer() {
        for backend in BACKENDS {
            for is_server in [false, true] {
                let (client, server) = connection_pair(backend);
                let (session, mut peer) = if is_server {
                    (server, client)
                } else {
                    (client, server)
                };
                let uuid = [7; 16];
                let mut plaintext = if is_server { Vec::new() } else { vec![0, 0] };
                plaintext.extend_from_slice(&uuid);
                plaintext.extend_from_slice(&[COMMAND_DIRECT, 0, 3, 0, 0]);
                plaintext.extend_from_slice(b"one");
                plaintext.extend_from_slice(&[b'Z'; 10_000]);
                let mut ciphertext = encrypt(&mut peer, &plaintext);
                ciphertext.extend_from_slice(b"\x17\x03\x03\x00\x03raw");
                let io = ScriptedIo {
                    reads: VecDeque::from([ciphertext.into()]),
                };
                let tls = CryptoTlsStream::new(io, session, Some(TlsDeframer::new()));
                let mut vision = if is_server {
                    VisionStream::new_server(tls, uuid, b"").unwrap()
                } else {
                    VisionStream::new_client(tls, uuid).unwrap()
                };
                let mut expected = b"one".to_vec();
                expected.extend_from_slice(&[b'Z'; 10_000]);
                expected.extend_from_slice(b"\x17\x03\x03\x00\x03raw");
                assert_buffered_reads(&mut vision, &expected);
            }
        }
    }

    #[test]
    fn tls_handoff_preserves_coalesced_direct_bytes() {
        for backend in BACKENDS {
            for raw_tail in [b"-three".as_slice(), b"\x17\x03\x03\x00\x03raw"] {
                let (mut client, server) = connection_pair(backend);
                let uuid = [7; 16];
                let mut first = vec![0];
                first.extend_from_slice(&uuid);
                first.extend_from_slice(&[COMMAND_DIRECT, 0, 3, 0, 0]);
                first.extend_from_slice(b"one-two");
                let mut ciphertext = encrypt(&mut client, &first);
                ciphertext.extend_from_slice(raw_tail);
                let io = ScriptedIo {
                    reads: VecDeque::from([ciphertext.into()]),
                };
                let mut tls = CryptoTlsStream::new(io, server, Some(TlsDeframer::new()));
                let mut cx = Context::from_waker(noop_waker_ref());
                let mut header = [255];
                let mut buf = ReadBuf::new(&mut header);
                assert!(matches!(
                    Pin::new(&mut tls).poll_read(&mut cx, &mut buf),
                    Poll::Ready(Ok(()))
                ));
                assert_eq!(header, [0]);

                let mut vision = VisionStream::new_server(tls, uuid, b"").unwrap();
                let mut expected = b"one-two".to_vec();
                expected.extend_from_slice(raw_tail);
                assert_buffered_reads(&mut vision, &expected);
                assert_eq!(vision.read_mode, VisionMode::Direct);
            }
        }
    }

    #[test]
    fn client_response_preserves_coalesced_direct_bytes() {
        for backend in BACKENDS {
            for header_split in [0, 1, 3] {
                let (client, mut server) = connection_pair(backend);
                let uuid = [7; 16];
                let mut ciphertext = Vec::new();
                let mut response = vec![0, 3, 1, 2, 3];
                if header_split != 0 {
                    ciphertext.extend(encrypt(&mut server, &response[..header_split]));
                    response.drain(..header_split);
                }
                response.extend_from_slice(&uuid);
                response.extend_from_slice(&[COMMAND_DIRECT, 0, 3, 0, 0]);
                response.extend_from_slice(b"one-two");
                ciphertext.extend(encrypt(&mut server, &response));
                ciphertext.extend_from_slice(b"\x17\x03\x03\x00\x03raw");
                let io = ScriptedIo {
                    reads: VecDeque::from([ciphertext.into()]),
                };
                let mut vision = VisionStream::new_client(
                    CryptoTlsStream::new(io, client, Some(TlsDeframer::new())),
                    uuid,
                )
                .unwrap();
                assert_buffered_reads(&mut vision, b"one-two\x17\x03\x03\x00\x03raw");
                assert_eq!(vision.read_mode, VisionMode::Direct);
            }
        }
    }

    #[tokio::test]
    async fn handshake_handoff_preserves_partial_record() {
        for backend in [Backend::Tls13, Backend::Reality] {
            let (mut client, mut server) = new_connections(backend);
            transfer_tls(&mut client, &mut server);
            transfer_tls(&mut server, &mut client);
            assert!(!client.is_handshaking());
            assert!(server.is_handshaking());

            let mut flight = Vec::new();
            client.write_tls(&mut flight).unwrap();
            let uuid = [7; 16];
            let mut first = vec![0];
            first.extend_from_slice(&uuid);
            first.extend_from_slice(&[COMMAND_CONTINUE, 0, 3, 0, 0]);
            first.extend_from_slice(b"one");
            flight.extend(encrypt(&mut client, &first));
            let next_record = encrypt(&mut client, b"\x00\x00\x04\x00\x00-two");
            flight.extend_from_slice(&next_record[..10]);
            let io: Box<dyn AsyncStream> = Box::new(ScriptedIo {
                reads: VecDeque::from([
                    flight[3..].to_vec().into(),
                    next_record[10..].to_vec().into(),
                ]),
            });
            let mut tls = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                CryptoTlsStream::handshake(io, server, TlsReadMode::PreserveRecords, &flight[..3]),
            )
            .await
            .unwrap()
            .unwrap();
            let mut cx = Context::from_waker(noop_waker_ref());
            let mut header = [255];
            let mut buf = ReadBuf::new(&mut header);
            assert!(matches!(
                Pin::new(&mut tls).poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(header, [0]);
            let mut vision = VisionStream::new_server(tls, uuid, b"").unwrap();
            assert_buffered_reads(&mut vision, b"one-two");
        }
    }

    #[tokio::test]
    async fn tls12_client_handshake_preserves_buffered_response() {
        let (mut client, mut server) = new_connections(Backend::Tls12);
        transfer_tls(&mut client, &mut server);
        transfer_tls(&mut server, &mut client);
        transfer_tls(&mut client, &mut server);
        assert!(client.is_handshaking());

        let mut flight = Vec::new();
        server.write_tls(&mut flight).unwrap();
        let uuid = [7; 16];
        let mut response = vec![0, 0];
        response.extend_from_slice(&uuid);
        response.extend_from_slice(&[COMMAND_DIRECT, 0, 3, 0, 0]);
        response.extend_from_slice(b"one");
        let application_record = encrypt(&mut server, &response);
        assert!(!application_record.is_empty());
        flight.extend(application_record);
        flight.extend_from_slice(b"-two");
        let io: Box<dyn AsyncStream> = Box::new(ScriptedIo {
            reads: VecDeque::from([flight.into()]),
        });
        let tls = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            CryptoTlsStream::handshake(io, client, TlsReadMode::PreserveRecords, &[]),
        )
        .await
        .unwrap()
        .unwrap();
        let mut vision = VisionStream::new_client(tls, uuid).unwrap();
        assert_buffered_reads(&mut vision, b"one-two");
    }

    #[test]
    fn transferred_records_are_read_before_polling_the_socket() {
        for backend in BACKENDS {
            let (client, mut server) = connection_pair(backend);
            let uuid = [7; 16];
            let mut response = vec![0, 0];
            response.extend_from_slice(&uuid);
            response.extend_from_slice(&[COMMAND_CONTINUE, 0, 3, 0, 0]);
            response.extend_from_slice(b"one");
            let mut deframer = TlsDeframer::new();
            deframer.feed(&encrypt(&mut server, &response));
            deframer.feed(&encrypt(&mut server, b"\x00\x00\x04\x00\x00-two"));
            let io = ScriptedIo {
                reads: VecDeque::new(),
            };
            let mut vision =
                VisionStream::new_client(CryptoTlsStream::new(io, client, Some(deframer)), uuid)
                    .unwrap();
            assert_buffered_reads(&mut vision, b"one-two");
        }
    }

    #[test]
    fn initial_direct_orders_plaintext_before_deframer_tail() {
        for backend in BACKENDS {
            let (mut client, mut server) = connection_pair(backend);
            let uuid = [7; 16];
            let mut initial = uuid.to_vec();
            initial.extend_from_slice(&[COMMAND_DIRECT, 0, 3, 0, 0]);
            initial.extend_from_slice(b"one");
            feed_and_process_crypto_connection(&mut server, &encrypt(&mut client, b"-two"))
                .unwrap();
            let mut deframer = TlsDeframer::new();
            deframer.feed(b"-three");
            let io = ScriptedIo {
                reads: VecDeque::new(),
            };
            let mut vision = VisionStream::new_server(
                CryptoTlsStream::new(io, server, Some(deframer)),
                uuid,
                &initial,
            )
            .unwrap();
            assert_buffered_reads(&mut vision, b"one-two-three");
        }
    }

    #[test]
    fn initial_end_preserves_queued_records_and_partial_ciphertext() {
        for backend in BACKENDS {
            let (mut client, mut server) = connection_pair(backend);
            let uuid = [7; 16];
            let mut initial = uuid.to_vec();
            initial.extend_from_slice(&[COMMAND_END, 0, 3, 0, 0]);
            initial.extend_from_slice(b"one");
            feed_and_process_crypto_connection(&mut server, &encrypt(&mut client, b"-two"))
                .unwrap();
            let mut deframer = TlsDeframer::new();
            deframer.feed(&encrypt(&mut client, b"-three"));
            let last = encrypt(&mut client, b"-four");
            deframer.feed(&last[..10]);
            let io = ScriptedIo {
                reads: VecDeque::from([last[10..].to_vec().into()]),
            };
            let mut vision = VisionStream::new_server(
                CryptoTlsStream::new(io, server, Some(deframer)),
                uuid,
                &initial,
            )
            .unwrap();
            assert_buffered_reads(&mut vision, b"one-two-three-four");
        }
    }

    #[test]
    fn framed_tls_drains_large_preread_in_both_directions() {
        let payload = vec![b'Q'; 40_000];
        for backend in BACKENDS {
            let (mut client, mut server) = connection_pair(backend);
            let request = encrypt(&mut client, &payload);
            let response = encrypt(&mut server, &payload);
            for (session, ciphertext) in [(server, request), (client, response)] {
                let mut deframer = TlsDeframer::new();
                deframer.feed(&ciphertext);
                let io = ScriptedIo {
                    reads: VecDeque::new(),
                };
                let mut stream = CryptoTlsStream::new(io, session, Some(deframer));
                assert_buffered_reads(&mut stream, &payload);
            }
        }
    }

    #[test]
    fn framed_tls_without_vision_handoff_preserves_both_directions() {
        for backend in BACKENDS {
            let (mut client, mut server) = connection_pair(backend);
            let request = [encrypt(&mut client, b"one"), encrypt(&mut client, b"-two")].concat();
            let response = [
                encrypt(&mut server, b"three"),
                encrypt(&mut server, b"-four"),
            ]
            .concat();
            for (session, ciphertext, expected) in [
                (server, request, b"one-two".as_slice()),
                (client, response, b"three-four".as_slice()),
            ] {
                let mut deframer = TlsDeframer::new();
                deframer.feed(&ciphertext[..8]);
                let io = ScriptedIo {
                    reads: VecDeque::from([ciphertext[8..].to_vec().into()]),
                };
                let mut stream = CryptoTlsStream::new(io, session, Some(deframer));
                assert_buffered_reads(&mut stream, expected);
            }
        }
    }

    fn completed_reality_connection() -> CryptoConnection {
        let config = RealityServerConfig {
            private_key: [0; 32],
            short_ids: vec![[0; 8]],
            dest: NetLocation::new(Address::UNSPECIFIED, 443),
            max_time_diff: None,
            min_client_version: None,
            max_client_version: None,
            cipher_suites: Vec::new(),
        };
        CryptoConnection::new_reality_server(
            RealityServerConnection::new(config)
                .unwrap()
                .complete_for_test()
                .unwrap(),
        )
    }

    fn assert_initial_mode_transition(command: UnpadCommand, session_plaintext: &[u8]) {
        let uuid = [7; 16];
        let mut initial = uuid.to_vec();
        initial.extend_from_slice(&[command as u8, 0, 3, 0, 2]);
        initial.extend_from_slice(b"one\0\0-two");

        let mut session = completed_reality_connection();
        if !session_plaintext.is_empty() {
            let mut peer = completed_reality_connection();
            peer.writer().write_all(session_plaintext).unwrap();
            let mut ciphertext = Vec::new();
            peer.write_tls(&mut ciphertext).unwrap();
            feed_and_process_crypto_connection(&mut session, &ciphertext).unwrap();
        }

        let (io, _peer) = tokio::io::duplex(64);
        let mut stream = VisionStream::new_server(
            CryptoTlsStream::new(io, session, Some(TlsDeframer::new())),
            uuid,
            &initial,
        )
        .unwrap();
        let expected_mode = match command {
            UnpadCommand::End => VisionMode::Tls,
            UnpadCommand::Direct => VisionMode::Direct,
            UnpadCommand::Continue => panic!("expected a final padding command"),
        };
        assert_eq!(stream.read_mode, expected_mode);

        let mut expected = b"one-two".to_vec();
        expected.extend_from_slice(session_plaintext);
        assert_buffered_reads(&mut stream, &expected);
        assert!(stream.pending_read.is_empty());
    }

    #[test]
    fn initial_end_preserves_session_plaintext() {
        assert_initial_mode_transition(UnpadCommand::End, b"-three");
    }

    #[test]
    fn initial_end_accepts_empty_session() {
        assert_initial_mode_transition(UnpadCommand::End, b"");
    }

    #[test]
    fn initial_direct_preserves_session_plaintext() {
        assert_initial_mode_transition(UnpadCommand::Direct, b"-three");
    }

    #[test]
    fn initial_direct_accepts_empty_session() {
        assert_initial_mode_transition(UnpadCommand::Direct, b"");
    }
}
