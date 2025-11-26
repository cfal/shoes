use crate::crypto::CryptoConnection;
/// VISION stream implementation
///
/// VisionStream wraps an IO stream and TLS session, allowing it to:
/// 1. Use TLS with VISION padding to hide protocol fingerprints
/// 2. Detect TLS-in-TLS scenarios by analyzing traffic patterns
/// 3. Switch to direct I/O mode, bypassing TLS for zero-copy performance
use bytes::{Buf, BytesMut};
use futures::ready;
use std::io::{self, BufRead, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::async_stream::AsyncStream;
use crate::crypto::feed_crypto_connection;
use crate::sync_adapter::{SyncReadAdapter, SyncWriteAdapter};
use crate::util::allocate_vec;

use super::tls_deframer::TlsDeframer;
use super::tls_fuzzy_deframer::{DeframeResult, FuzzyTlsDeframer};
use super::vision_filter::VisionFilter;
use super::vision_unpad::{UnpadCommand, UnpadResult, VisionUnpadder};

#[inline]
fn feed_and_process_crypto_connection(
    session: &mut CryptoConnection,
    data: &[u8],
) -> std::io::Result<usize> {
    feed_crypto_connection(session, data)?;
    Ok(session
        .process_new_packets()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?
        .plaintext_bytes_to_read())
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

pub struct VisionStream<IO> {
    /// The underlying transport stream (e.g., TcpStream)
    tcp: IO,

    /// rustls session for TLS encryption and decryption
    /// Used in PaddingTls and Tls mode
    session: CryptoConnection,

    /// Current READ operating mode (independent from write mode)
    read_mode: VisionMode,

    /// Current WRITE operating mode (independent from read mode)
    write_mode: VisionMode,

    /// Outer TLS deframer for read path
    /// Deframes TCP stream into complete TLS records before feeding to rustls
    /// Used in PaddingTls mode
    outer_read_deframer: Option<TlsDeframer>,

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

    /// Flag indicating we should switch to direct mode on the NEXT write call
    /// Used in PaddingTls mode
    pending_direct_mode_switch: bool,

    /// Flag indicating we should switch to Tls mode on the NEXT write call
    /// Used in PaddingTls mode
    pending_tls_mode_switch: bool,

    /// Reusable buffer for TLS read operations (TCP → read_tls → decrypt)
    /// Used in PaddingTls mode
    tls_read_buffer: Vec<u8>,

    /// Buffer for plaintext data waiting to be written to the TLS session buffer
    /// When the rustls Writer buffer fills (write length 0), we store the remainder here
    /// Used in PaddingTls mode - drained immediately before switching modes
    pending_plain_writes: BytesMut,

    /// Caches whether we've hit EOF when reading
    /// Used in PaddingTls and Tls mode
    is_read_eof: bool,
}

impl<IO> VisionStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new VisionStream for server-side (inbound) connections with VLESS response writing
    pub fn new_server(
        tcp: IO,
        session: CryptoConnection,
        user_uuid: [u8; 16],
        initial_read_data: &[u8],
    ) -> std::io::Result<Self> {
        // Validate that this is a server connection
        if !session.is_server() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "VisionStream::new_server requires a server-side connection",
            ));
        }

        let mut stream = Self::new_common(
            tcp, session, user_uuid, false, // vless_response_pending
            true,  // vless_response_to_send
        );

        // feed in the initial read data that came from reading the VLESS request
        stream.feed_initial_read_data(initial_read_data)?;
        // read all the remaining plaintext data from the session since we start directly
        // with TCP reads in poll_read_padding_tls
        stream.feed_initial_session_data()?;

        Ok(stream)
    }

    /// Create a new VisionStream for client-side connections with VLESS response handling
    pub fn new_client(tcp: IO, session: CryptoConnection, user_uuid: [u8; 16]) -> Self {
        // Validate that this is a client connection
        if !session.is_client() {
            panic!("VisionStream::new_client requires a client-side connection");
        }

        Self::new_common(
            tcp, session, user_uuid, true,  // vless_response_pending
            false, // vless_response_to_send
        )
    }

    fn new_common(
        tcp: IO,
        session: CryptoConnection,
        user_uuid: [u8; 16],
        vless_response_pending: bool,
        vless_response_to_send: bool,
    ) -> Self {
        Self {
            tcp,
            session,
            // this should be somewhat smaller than TLS_MAX_RECORD_SIZE when used with session.read_tls,
            // else we will hit "message buffer full" (see other comment) - because if we set it at
            // TLS_MAX_RECORD_SIZE, and a small record is read first, there can be a large partial record
            // left in the buffer and then prevoius_record_size + TLS_MAX_RECORD_SIZE > TLS_MAX_RECORD_SIZE
            // will trigger the error.
            tls_read_buffer: allocate_vec(8192),
            read_mode: VisionMode::PaddingTls,
            write_mode: VisionMode::PaddingTls,
            outer_read_deframer: Some(TlsDeframer::new()),
            inner_read_deframer: FuzzyTlsDeframer::new(),
            inner_write_deframer: FuzzyTlsDeframer::new(),
            read_unpadder: VisionUnpadder::new(user_uuid),
            write_first_packet: true,
            user_uuid,
            filter: VisionFilter::new(),
            pending_read: BytesMut::new(),
            vless_response_pending,
            partial_vless_response: BytesMut::new(),
            vless_response_to_send,
            pending_direct_mode_switch: false,
            pending_tls_mode_switch: false,
            pending_plain_writes: BytesMut::new(),
            is_read_eof: false,
        }
    }

    /// Feed initial read data that was already decrypted by TLS but needs VISION unpadding
    /// This is used when the VLESS header parser read extra bytes from the TLS stream.
    /// This can be called multiple times in order to successfully drain the session.
    /// Those bytes are already TLS-decrypted but still VISION-padded.
    fn feed_initial_read_data(&mut self, data: &[u8]) -> std::io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        log::debug!(
            "VISION: Feeding {} initial bytes (already TLS-decrypted, needs unpadding)",
            data.len()
        );

        self.handle_padded_bytes(data)?;

        Ok(())
    }

    // Read all the available plaintext data from the session.
    // This should only be necessary for server streams since a read occurred in order to read the
    // VLESS request before the session is passed to VisionStream.
    fn feed_initial_session_data(&mut self) -> std::io::Result<()> {
        let plaintext_len = self
            .session
            .process_new_packets()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?
            .plaintext_bytes_to_read();
        let mut decrypted = Vec::with_capacity(plaintext_len);

        let mut reader = self.session.reader();
        let mut i = 0;
        while i < plaintext_len {
            match reader.fill_buf() {
                Ok(buf) => {
                    let len = buf.len();
                    if len == 0 {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "TLS session filled buffer with zero bytes",
                        ));
                    }
                    decrypted.extend_from_slice(buf);
                    reader.consume(len);
                    log::debug!("VISION: Filled more unparsed data of length {}", len);
                    i += len;
                }
                Err(e) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("failed to read TLS session: {e}"),
                    ));
                }
            }
        }

        self.handle_padded_bytes(&decrypted)
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

    /// Switch WRITE side from TLS mode to direct I/O mode
    /// This doesn't need to preserve any data, just updates the mode
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

        // Set write mode to Direct
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
        self.tls_read_buffer = Vec::new();
        self.pending_plain_writes = BytesMut::new();
    }

    /// Drain pending plaintext writes to TLS session buffer
    /// Returns Poll::Ready(Ok(())) when fully drained
    /// Returns Poll::Pending if session buffer is full (needs TLS/TCP drain first)
    fn drain_pending_plain_writes(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_plain_writes.is_empty() {
            return Poll::Ready(Ok(()));
        }

        log::debug!(
            "VISION WRITE: Draining {} pending plaintext bytes",
            self.pending_plain_writes.len()
        );

        // Try to write pending plaintext to TLS session
        while !self.pending_plain_writes.is_empty() {
            match self.session.writer().write(&self.pending_plain_writes) {
                Ok(n) => {
                    if n == 0 {
                        // Session buffer full - return Pending so drain_all_writes can drain TLS/TCP first
                        log::debug!(
                            "VISION WRITE: Session buffer full ({} plaintext bytes remaining), returning Pending",
                            self.pending_plain_writes.len()
                        );
                        return Poll::Pending;
                    }

                    self.pending_plain_writes.advance(n);
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        Poll::Ready(Ok(()))
    }

    /// Drain all pending writes in PaddingTls mode: plain → TLS → TCP
    ///
    /// This drains the write pipeline in priority order:
    /// 1. TLS session → TCP socket (highest priority, creates space in session)
    /// 2. Plain buffer → TLS session (writes to session)
    ///
    /// Returns Poll::Ready(Ok(())) when all buffers are fully drained
    /// Returns Poll::Pending if TCP blocks (backpressure - nothing else can make progress)
    fn drain_all_writes_padding(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.session.wants_write() {
                match self.write_tls_direct(cx) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(_)) => {
                        // Wrote some data. This might have freed up space in session buffer.
                        // Loop back to try draining plaintext buffer again.
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        // TCP is blocked. We can't drain session, so we can't drain plain writes either.
                        return Poll::Pending;
                    }
                }
            }

            if !self.pending_plain_writes.is_empty() {
                match self.drain_pending_plain_writes(cx) {
                    Poll::Ready(Ok(())) => {
                        // Drained plain writes, session now likely wants to write.
                        continue;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        // Session buffer full. But we didn't drain session above (wants_write was false).
                        // So we are stuck.
                        // TODO: this is probably an error
                        return Poll::Pending;
                    }
                }
            }

            // If we are here, everything is empty.
            return Poll::Ready(Ok(()));
        }
    }

    /// Drain all pending writes in Tls mode
    ///
    /// This is simpler than PaddingTls mode because `pending_plain_writes` is no longer used.
    ///
    /// Returns Poll::Ready(Ok(())) when fully drained
    /// Returns Poll::Pending if TCP blocks
    fn drain_all_writes_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Drain TLS session output directly to TCP
        while self.session.wants_write() {
            if ready!(self.write_tls_direct(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }

        Poll::Ready(Ok(()))
    }

    /// Write data to TLS session, handling buffer full by saving to pending buffer
    /// Used in PaddingTls mode
    fn write_to_session(&mut self, data: &[u8]) -> io::Result<()> {
        if !self.pending_plain_writes.is_empty() {
            // If there's already pending data, just append to it
            // (don't try to write, as that would require cx for polling)
            self.pending_plain_writes.extend_from_slice(data);
            return Ok(());
        }

        let mut written = 0;
        while written < data.len() {
            match self.session.writer().write(&data[written..]) {
                Ok(n) => {
                    if n == 0 {
                        // Session buffer full, save remainder
                        log::debug!(
                            "VISION WRITE: Session buffer full, saving {} bytes to pending",
                            data.len() - written
                        );
                        self.pending_plain_writes
                            .extend_from_slice(&data[written..]);
                        return Ok(());
                    }
                    written += n;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    /// Write TLS session output directly to TCP stream
    /// Returns the number of bytes written from TLS session to TCP
    fn write_tls_direct(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut writer = SyncWriteAdapter {
            io: &mut self.tcp,
            cx,
        };

        // Write TLS output DIRECTLY to TCP (zero intermediate copies)
        match self.session.write_tls(&mut writer) {
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    /// Write data in Tls mode
    fn poll_write_tls(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut pos = 0;

        while pos < buf.len() {
            let mut would_block = false;

            // Write plaintext to TLS session
            match self.session.writer().write(&buf[pos..]) {
                Ok(n) => pos += n,
                Err(e) => return Poll::Ready(Err(e)),
            };

            // Drain TLS output to TCP stream
            while self.session.wants_write() {
                match self.write_tls_direct(cx) {
                    Poll::Ready(Ok(0)) | Poll::Pending => {
                        would_block = true;
                        break;
                    }
                    Poll::Ready(Ok(_)) => (),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }

            return match (pos, would_block) {
                (0, true) => Poll::Pending,
                (n, true) => Poll::Ready(Ok(n)), // Partial write
                (_, false) => continue,          // Keep writing
            };
        }

        Poll::Ready(Ok(pos))
    }

    /// Read the VLESS response header from the TLS session
    ///
    /// The VLESS response consists of:
    /// - 1 byte: version (must be 0)
    /// - 1 byte: addon length
    /// - N bytes: addon data (if addon_length > 0)
    ///
    /// This is called lazily on the first read when vless_response_pending is true.
    /// Uses packetization to feed TLS records one at a time to avoid bad MAC errors.
    ///
    /// Returns any unused data that came after the response
    fn poll_read_vless_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<BytesMut>> {
        log::debug!(
            "VLESS: poll_read_vless_response called, partial_vless_response has {} bytes",
            self.partial_vless_response.len()
        );

        loop {
            // Always read from TCP to feed the deframer
            let mut read_buf = ReadBuf::new(&mut self.tls_read_buffer);
            match ready!(Pin::new(&mut self.tcp).poll_read(cx, &mut read_buf)) {
                Ok(()) => {}
                Err(e) => return Poll::Ready(Err(e)),
            };

            let tcp_bytes = read_buf.filled();

            if tcp_bytes.is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Connection closed while reading VLESS response",
                )));
            }

            log::debug!(
                "VLESS: Read {} bytes from TCP for response header",
                tcp_bytes.len()
            );

            // Feed to outer read deframer
            self.outer_read_deframer
                .as_mut()
                .expect("outer_read_deframer must exist in PaddingTls mode")
                .feed(tcp_bytes);

            // We have to handle all packets and drain the outer_read_deframer because
            // poll_read_padded_tls() will always read from the TCP and assume there's outstanding
            // data.
            // We don't have to worry about consuming some data post-Direct command because the TLS
            // flow is one-directional atm and it's not possible to complete a handshake.
            // If the peer sends a Direct command without handshake completing, this will error out
            // when we feed the TLS record to the session.
            let tls_records = self
                .outer_read_deframer
                .as_mut()
                .expect("outer_read_deframer must exist in PaddingTls mode")
                .next_records()?;

            for tls_record in tls_records.into_iter() {
                // Feed single TLS record to session
                let plaintext_len =
                    feed_and_process_crypto_connection(&mut self.session, tls_record.as_ref())?;

                // Access the decrypted buffer and accumulate into partial_vless_response
                let mut reader = self.session.reader();

                let mut i = 0;
                while i < plaintext_len {
                    let decrypted_buf = match reader.fill_buf() {
                        Ok(buf) => buf,
                        Err(e) => return Poll::Ready(Err(e)),
                    };

                    if decrypted_buf.is_empty() {
                        return Poll::Ready(Err(io::Error::other(
                            "no plaintext data when some is available",
                        )));
                    }

                    // Accumulate decrypted data into partial buffer
                    self.partial_vless_response.extend_from_slice(decrypted_buf);

                    let consumed_len = decrypted_buf.len();
                    reader.consume(consumed_len);
                    i += consumed_len;
                }
            }

            log::debug!(
                "VLESS: Accumulated vless response with {} bytes",
                self.partial_vless_response.len()
            );

            // Try to parse the VLESS response from accumulated data
            if self.partial_vless_response.len() < 2 {
                // Need at least 2 bytes for header, try to read from the TCP stream again
                continue;
            }

            // Read the 2-byte header
            let version = self.partial_vless_response[0];
            let addon_length = self.partial_vless_response[1];

            // Validate version
            if version != 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid VLESS response version: {}", version),
                )));
            }

            // Check if we have enough data for the full response
            let total_response_len = 2 + addon_length as usize;
            if self.partial_vless_response.len() < total_response_len {
                // Need more data - read more TCP
                continue;
            }

            // We have the complete VLESS response! Consume it from the buffer
            self.partial_vless_response.advance(total_response_len);

            log::debug!(
                "VLESS: Successfully parsed {} byte response header (version={}, addon_length={}), {} bytes remaining in buffer",
                total_response_len,
                version,
                addon_length,
                self.partial_vless_response.len()
            );

            // If there's any remaining data in partial buffer, it belongs to the actual payload
            let remaining_data = std::mem::take(&mut self.partial_vless_response);
            return Poll::Ready(Ok(remaining_data));
        }
    }

    fn poll_read_padding_tls(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.is_read_eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            // Read from TCP to feed the deframer.
            // At this point, there is no data ready in neither the session or the outer read
            // deframer.
            let mut read_buf = ReadBuf::new(&mut self.tls_read_buffer);
            match ready!(Pin::new(&mut self.tcp).poll_read(cx, &mut read_buf)) {
                Ok(()) => {}
                Err(e) => return Poll::Ready(Err(e)),
            };

            let tcp_bytes = read_buf.filled();

            if tcp_bytes.is_empty() {
                log::debug!("VISION READ: TCP connection EOF in PaddingTls mode");
                self.is_read_eof = true;
                return Poll::Ready(Ok(()));
            }

            log::debug!("VISION READ: Read {} bytes from TCP", tcp_bytes.len());

            // Feed to outer TLS deframer
            self.outer_read_deframer
                .as_mut()
                .expect("outer_read_deframer must exist in PaddingTls mode")
                .feed(tcp_bytes);

            // Process TLS records one at a time
            loop {
                let tls_record = match self
                    .outer_read_deframer
                    .as_mut()
                    .expect("outer_read_deframer must exist in PaddingTls mode")
                    .next_record()?
                {
                    Some(record) => record,
                    None => {
                        log::debug!(
                            "VISION READ: No more complete TLS records in deframer, need more TCP data"
                        );
                        break; // Need more TCP data
                    }
                };

                log::debug!(
                    "VISION READ: Processing {} byte TLS record",
                    tls_record.len()
                );

                // Feed single TLS record to session
                let plaintext_len =
                    feed_and_process_crypto_connection(&mut self.session, tls_record.as_ref())?;

                if plaintext_len == 0 {
                    continue; // Process next TLS record
                }

                let mut reader = self.session.reader();

                let mut decrypted = Vec::with_capacity(plaintext_len);
                let mut i = 0;
                while i < plaintext_len {
                    let decrypted_part = match reader.fill_buf() {
                        Ok(buf) => buf,
                        Err(e) => {
                            // TODO: better error eg expected available plaintext but got error
                            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)));
                        }
                    };

                    let part_len = decrypted_part.len();
                    decrypted.extend_from_slice(decrypted_part);
                    reader.consume(part_len);
                    i += part_len;
                }

                log::debug!("VISION READ: Got {} decrypted bytes", decrypted.len());
                self.handle_padded_bytes(&decrypted)?;

                // If the mode changed, the outer read deframer has been consumed and
                // we should return any pending read data and use the new mode's read function
                match self.read_mode {
                    VisionMode::PaddingTls => {
                        // Need more TCP data, loop back to read
                    }
                    VisionMode::Tls => {
                        if !self.pending_read.is_empty() {
                            let len = buf.remaining().min(self.pending_read.len());
                            buf.put_slice(&self.pending_read[..len]);
                            self.pending_read.advance(len);
                            return Poll::Ready(Ok(()));
                        }
                        return self.poll_read_tls(cx, buf);
                    }
                    VisionMode::Direct => {
                        if !self.pending_read.is_empty() {
                            let len = buf.remaining().min(self.pending_read.len());
                            buf.put_slice(&self.pending_read[..len]);
                            self.pending_read.advance(len);
                            return Poll::Ready(Ok(()));
                        }
                        return Pin::new(&mut self.tcp).poll_read(cx, buf);
                    }
                }
            }

            // Finished iterating through all TLS records, return data if we have any, else loop
            // back to read more TCP data
            if !self.pending_read.is_empty() {
                let len = buf.remaining().min(self.pending_read.len());
                buf.put_slice(&self.pending_read[..len]);
                self.pending_read.advance(len);
                return Poll::Ready(Ok(()));
            }
        }
    }

    fn handle_padded_bytes(&mut self, decrypted: &[u8]) -> std::io::Result<()> {
        // Feed newly decrypted bytes to the unpadder.
        // All data should be consumed from the rustls session, as any actual content
        // will eventually be returned by the unpadder.
        // The unpadder maintains internal state for partial parsing
        let UnpadResult {
            content: mut unpadded,
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

        match maybe_command {
            Some(UnpadCommand::Direct) => {
                log::debug!(
                    "VISION READ: Received DIRECT command with {} bytes",
                    unpadded.len()
                );

                // The unpadded data already contains:
                // 1. The Direct command content
                // 2. Any remaining bytes after the padding (already appended by unpadder)

                // Extract remaining data from outer read deframer (raw TCP data in Direct mode)
                let remaining = self
                    .outer_read_deframer
                    .take()
                    .expect("outer_read_deframer must exist")
                    .into_remaining_data();

                if !remaining.is_empty() {
                    log::debug!(
                        "VISION READ: Extracted {} bytes from deframer as raw data",
                        remaining.len()
                    );
                    unpadded.extend_from_slice(&remaining);
                }

                self.pending_read.extend_from_slice(&unpadded);

                self.switch_read_to_direct_mode()?;
            }
            Some(UnpadCommand::End) => {
                log::debug!("VISION READ: Received END command, switching to Tls mode");

                // The `unpadded` data is already decrypted, store it in pending_read to be
                // returned
                if !unpadded.is_empty() {
                    log::debug!(
                        "VISION READ: Storing {} decrypted bytes in pending_read (End command - already decrypted)",
                        unpadded.len()
                    );
                    self.pending_read.extend_from_slice(&unpadded);
                }

                // Process the remaining data from the outer read deframer.
                // Previously we called into_remaining_data and fed it all at once to
                // feed_and_process_crypto_connection, but if there was too much outstanding
                // data, we hit "message buffer full" at
                // https://github.com/rustls/rustls/blob/58fbe9e7ad91951a7df148c2854f57db728a717c/rustls/src/msgs/deframer/buffers.rs#L235

                let mut outer_read_deframer = self
                    .outer_read_deframer
                    .take()
                    .expect("outer_read_deframer must exist");

                while let Some(record) = outer_read_deframer.next_record()? {
                    // Feed the encrypted TLS records to the session
                    let plaintext_len =
                        feed_and_process_crypto_connection(&mut self.session, &record)?;

                    if plaintext_len > 0 {
                        // Extract the decrypted data
                        let mut reader = self.session.reader();

                        // Read all available decrypted data, possibly in multiple chunks
                        let mut total_read = 0;
                        while total_read < plaintext_len {
                            let chunk = match reader.fill_buf() {
                                Ok(buf) => buf,
                                Err(e) => {
                                    return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                                }
                            };

                            let chunk_len = chunk.len();
                            self.pending_read.extend_from_slice(chunk);
                            reader.consume(chunk_len);
                            total_read += chunk_len;
                        }

                        log::debug!(
                            "VISION READ: Decrypted {} bytes from deframer remaining data (End command)",
                            total_read
                        );
                    }
                }

                let remaining = outer_read_deframer.into_remaining_data();

                // The `remaining` data from the deframer is ENCRYPTED TLS record bytes
                // We need to feed it to the TLS session for decryption, not append to unpadded
                if !remaining.is_empty() {
                    // This should only be a partial TLS record so there should be no new plaintext
                    // to read
                    let plaintext_len =
                        feed_and_process_crypto_connection(&mut self.session, &remaining)?;
                    assert!(plaintext_len == 0);
                }

                // Switch to Tls mode - End command means: stop padding, continue normal relay through outer TLS
                self.switch_read_to_tls_mode()?;
            }
            Some(UnpadCommand::Continue) => {
                self.pending_read.extend_from_slice(&unpadded);
            }
            None => {
                self.pending_read.extend_from_slice(&unpadded);
            }
        }
        Ok(())
    }

    fn poll_read_tls(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Check if rustls buffer has decrypted data available first
        {
            let mut reader = self.session.reader();
            match reader.fill_buf() {
                Ok(available) if !available.is_empty() => {
                    // Copy directly from rustls buffer to user buffer (single copy)
                    let len = buf.remaining().min(available.len());
                    buf.put_slice(&available[..len]);
                    reader.consume(len);
                    // If we didn't consume all data, it stays in rustls buffer for next read
                    return Poll::Ready(Ok(()));
                }
                Ok(_) => {
                    // Empty buffer, fall through to slow path
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No data available, fall through to slow path
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        if self.is_read_eof {
            return Poll::Ready(Ok(()));
        }

        // No data in rustls buffer, need to read from TCP
        // To prevent "message buffer full", we use a SyncReadAdapter to allow
        // rustls to decide how much to read from TCP, versus reading to a buffer
        // and then feeding like in PaddingTls mode.
        //
        // In read_tls, rustls will internally:
        // 1. Check if it has buffer space via prepare_read()
        // 2. Read only up to 4KB at a time
        // 3. Prevent "message buffer full" by reading less
        let mut reader = SyncReadAdapter {
            io: &mut self.tcp,
            cx,
        };

        loop {
            match self.session.read_tls(&mut reader) {
                Ok(n) => {
                    if n == 0 {
                        log::debug!("VISION READ: TCP connection EOF in Tls mode");
                        self.is_read_eof = true;
                        return Poll::Ready(Ok(()));
                    }

                    log::debug!("VISION READ: Read {} bytes from TCP via rustls", n);

                    // Process the encrypted data
                    let plaintext_len = self
                        .session
                        .process_new_packets()
                        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?
                        .plaintext_bytes_to_read();

                    if plaintext_len == 0 {
                        // No plaintext yet, need more TCP data
                        continue;
                    }

                    // Extract plaintext from rustls and return it
                    let mut reader = self.session.reader();
                    match reader.fill_buf() {
                        Ok(available) => {
                            // TODO: this should probably be a debug_assert!
                            if available.is_empty() {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "Read zero bytes when plaintext is available",
                                )));
                            }
                            let len = buf.remaining().min(available.len());
                            buf.put_slice(&available[..len]);
                            reader.consume(len);
                            return Poll::Ready(Ok(()));
                        }
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)));
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Poll::Pending;
                }
                Err(e) => {
                    return Poll::Ready(Err(e));
                }
            }
        }
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
            self.write_to_session(&VLESS_RESPONSE)?;

            // Clear flag so we don't send it again
            self.vless_response_to_send = false;
        }

        // Drain all pending writes - this must be done before mode switch
        // as the session could contain the DIRECT/END packet that triggered the mode switch flag,
        // and because we no longer use `pending_plain_writes` afterwards.
        if !self.pending_plain_writes.is_empty() || self.session.wants_write() {
            ready!(self.drain_all_writes_padding(cx))?;
        }

        if self.pending_direct_mode_switch {
            log::debug!("VISION WRITE: Switching to direct mode (flag set by previous write)");
            self.pending_direct_mode_switch = false;
            self.switch_write_to_direct_mode()?;
            return Pin::new(&mut self.tcp).poll_write(cx, buf);
        }

        if self.pending_tls_mode_switch {
            log::debug!("VISION WRITE: Switching to Tls mode (flag set by previous write)");
            self.pending_tls_mode_switch = false;
            self.switch_write_to_tls_mode()?;
            return self.poll_write_tls(cx, buf);
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

                        // DIRECT or END command
                        // Toggle mode switch flag, if `non_tls_filtering_ended`, it never supports XTLS
                        let command = if self.filter.supports_xtls() {
                            self.pending_direct_mode_switch = true;
                            0x02
                        } else {
                            self.pending_tls_mode_switch = true;
                            0x01
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

                        self.write_to_session(&final_padded_packet)?;

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
                            0x00, // CONTINUE
                            self.filter.is_tls(),
                        )
                    } else {
                        super::vision_pad::pad_with_command(
                            &record,
                            0x00, // CONTINUE
                            self.filter.is_tls(),
                        )
                    };

                    self.write_to_session(&padded_packet)?;
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
                    // need more data
                    // TODO: investigate this case. it's possible that this is not TLS data and the deframer is waiting
                    // for more writes from the caller to complete a full TLS record, but no more writes are coming.
                    // do we need to change our deframer approach?
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
                                0x0,
                                self.filter.is_tls(),
                            )
                        } else {
                            super::vision_pad::pad_with_command(&prefix, 0x0, self.filter.is_tls())
                        };

                        self.write_to_session(&padded_packet)?;
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
                                0x1,
                                self.filter.is_tls(),
                            )
                        } else {
                            super::vision_pad::pad_with_command(&prefix, 0x1, self.filter.is_tls())
                        };

                        // Clear deframe, not really necessary since deallocate will occur and this
                        // will never be used again.
                        self.inner_write_deframer.clear();

                        self.write_to_session(&padded_packet)?;
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

                    self.filter
                        .stop_filtering("write invalid TLS data".to_string());

                    let remaining_data = self.inner_write_deframer.remaining_data();

                    let padded_packet = if self.write_first_packet {
                        self.write_first_packet = false;
                        super::vision_pad::pad_with_uuid_and_command(
                            remaining_data,
                            &self.user_uuid,
                            0x1,
                            self.filter.is_tls(),
                        )
                    } else {
                        super::vision_pad::pad_with_command(
                            remaining_data,
                            0x1,
                            self.filter.is_tls(),
                        )
                    };

                    self.write_to_session(&padded_packet)?;

                    match self.drain_all_writes_padding(cx) {
                        Poll::Pending => {}
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    }

                    return Poll::Ready(Ok(buf.len()));
                }
            }
        }

        // we processed all records if we got here
        Poll::Ready(Ok(buf.len()))
    }
}

// AsyncRead implementation
impl<IO> AsyncRead for VisionStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // If we have leftover buffered data, return it first
        if !this.pending_read.is_empty() {
            let len = buf.remaining().min(this.pending_read.len());
            buf.put_slice(&this.pending_read[..len]);
            this.pending_read.advance(len);
            return Poll::Ready(Ok(()));
        }

        match this.read_mode {
            VisionMode::PaddingTls => {
                if this.vless_response_pending {
                    let decrypted_data = ready!(this.poll_read_vless_response(cx))?;
                    this.vless_response_pending = false;
                    if !decrypted_data.is_empty() {
                        this.handle_padded_bytes(&decrypted_data)?;
                        if !this.pending_read.is_empty() {
                            let len = buf.remaining().min(this.pending_read.len());
                            buf.put_slice(&this.pending_read[..len]);
                            this.pending_read.advance(len);
                            return Poll::Ready(Ok(()));
                        }
                        match this.read_mode {
                            VisionMode::PaddingTls => {
                                // Fall-through
                            }
                            VisionMode::Tls => {
                                return this.poll_read_tls(cx, buf);
                            }
                            VisionMode::Direct => {
                                return Pin::new(&mut this.tcp).poll_read(cx, buf);
                            }
                        }
                    }
                }
                this.poll_read_padding_tls(cx, buf)
            }
            VisionMode::Tls => this.poll_read_tls(cx, buf),
            VisionMode::Direct => Pin::new(&mut this.tcp).poll_read(cx, buf),
        }
    }
}

// AsyncWrite implementation
impl<IO> AsyncWrite for VisionStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        match this.write_mode {
            VisionMode::PaddingTls => this.poll_write_padding_tls(cx, buf),
            VisionMode::Tls => this.poll_write_tls(cx, buf),
            VisionMode::Direct => Pin::new(&mut this.tcp).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        match this.write_mode {
            VisionMode::PaddingTls => {
                ready!(this.drain_all_writes_padding(cx))?;
                Pin::new(&mut this.tcp).poll_flush(cx)
            }
            VisionMode::Tls => {
                ready!(this.drain_all_writes_tls(cx))?;
                Pin::new(&mut this.tcp).poll_flush(cx)
            }
            VisionMode::Direct => Pin::new(&mut this.tcp).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().tcp).poll_shutdown(cx)
    }
}

// Implement AsyncPing trait
impl<IO> crate::async_stream::AsyncPing for VisionStream<IO>
where
    IO: AsyncStream,
{
    fn supports_ping(&self) -> bool {
        self.tcp.supports_ping()
    }

    fn poll_write_ping(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Pin::new(&mut self.get_mut().tcp).poll_write_ping(cx)
    }
}

impl<IO> AsyncStream for VisionStream<IO> where IO: AsyncStream {}
