use super::{SniffOutcome, Sniffed, SniffedProtocol, normalize_host};

const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
const EXTENSION_SERVER_NAME: u16 = 0x0000;
const NAME_TYPE_HOST_NAME: u8 = 0x00;

/// Reads big-endian fields out of a slice. Every accessor returns `None` when
/// the slice runs out, which the caller turns into "read more" — never into a
/// rejection, because a short buffer is the normal case here.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|s| ((s[0] as usize) << 16) | ((s[1] as usize) << 8) | s[2] as usize)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }
}

pub fn sniff(buf: &[u8]) -> SniffOutcome {
    // `None` anywhere below means the buffer ended early, which is always
    // "read more"; a definite rejection is returned explicitly.
    parse(buf).unwrap_or(SniffOutcome::NeedMore)
}

fn found(domain: Option<String>) -> SniffOutcome {
    SniffOutcome::Found(Sniffed {
        protocol: SniffedProtocol::Tls,
        domain,
    })
}

fn parse(buf: &[u8]) -> Option<SniffOutcome> {
    let mut record = Cursor::new(buf);

    if record.u8()? != CONTENT_TYPE_HANDSHAKE {
        return Some(SniffOutcome::NotThisOne);
    }

    // The record-layer version is legacy and is 3.1 or 3.3 in practice, never
    // the negotiated version.
    let major = record.u8()?;
    let minor = record.u8()?;
    if major != 0x03 || (minor != 0x01 && minor != 0x03) {
        return Some(SniffOutcome::NotThisOne);
    }

    let record_len = record.u16()? as usize;
    let fragment = record.take(record_len)?;

    let mut handshake = Cursor::new(fragment);
    if handshake.u8()? != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Some(SniffOutcome::NotThisOne);
    }

    let body_len = handshake.u24()?;
    if body_len > handshake.remaining() {
        // The ClientHello is split across records. Reassembling the record
        // layer to chase it is out of proportion to how rarely this happens,
        // and returning NeedMore would spin until the deadline for a buffer
        // that can never satisfy the parse.
        return Some(SniffOutcome::NotThisOne);
    }
    let body = handshake.take(body_len)?;

    let mut hello = Cursor::new(body);
    hello.skip(2)?; // legacy_version
    hello.skip(32)?; // random
    let session_id_len = hello.u8()? as usize;
    hello.skip(session_id_len)?;
    let cipher_suites_len = hello.u16()? as usize;
    hello.skip(cipher_suites_len)?;
    let compression_len = hello.u8()? as usize;
    hello.skip(compression_len)?;

    // A ClientHello with no extensions block at all is legal, and has no SNI.
    if hello.remaining() == 0 {
        return Some(found(None));
    }

    let extensions_len = hello.u16()? as usize;
    let extensions = hello.take(extensions_len)?;

    // From here the whole ClientHello is in hand, so it is TLS whatever else
    // happens; a malformed extension block costs us the name, not the verdict.
    Some(found(find_server_name(extensions)))
}

fn find_server_name(extensions: &[u8]) -> Option<String> {
    let mut cursor = Cursor::new(extensions);
    while cursor.remaining() > 0 {
        let extension_type = cursor.u16()?;
        let extension_len = cursor.u16()? as usize;
        let data = cursor.take(extension_len)?;
        if extension_type == EXTENSION_SERVER_NAME {
            return parse_server_name_list(data);
        }
    }
    None
}

fn parse_server_name_list(data: &[u8]) -> Option<String> {
    let mut cursor = Cursor::new(data);
    let list_len = cursor.u16()? as usize;
    let list = cursor.take(list_len)?;

    let mut entries = Cursor::new(list);
    while entries.remaining() > 0 {
        let name_type = entries.u8()?;
        let name_len = entries.u16()? as usize;
        let name = entries.take(name_len)?;
        if name_type == NAME_TYPE_HOST_NAME {
            return normalize_host(name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a ClientHello record around an extensions block.
    fn client_hello(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id length
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        body.extend_from_slice(&[0x01, 0x00]); // compression methods
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let len = body.len() as u32;
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&[0x03, 0x01]); // legacy record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// A `server_name` extension carrying one host_name entry.
    fn sni_extension(name: &str) -> Vec<u8> {
        let name = name.as_bytes();
        let mut entry = Vec::new();
        entry.push(0x00); // host_name
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name);

        let mut data = Vec::new();
        data.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        data.extend_from_slice(&entry);

        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]); // server_name
        ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&data);
        ext
    }

    fn found(name: Option<&str>) -> SniffOutcome {
        SniffOutcome::Found(Sniffed {
            protocol: SniffedProtocol::Tls,
            domain: name.map(str::to_string),
        })
    }

    #[test]
    fn finds_the_server_name() {
        let hello = client_hello(&sni_extension("Example.COM"));
        assert_eq!(sniff(&hello), found(Some("example.com")));
    }

    #[test]
    fn recognises_tls_without_sni() {
        let hello = client_hello(&[]);
        assert_eq!(sniff(&hello), found(None));
    }

    #[test]
    fn takes_the_first_host_name_entry() {
        let mut ext = sni_extension("first.example");
        ext.extend_from_slice(&sni_extension("second.example"));
        let hello = client_hello(&ext);
        assert_eq!(sniff(&hello), found(Some("first.example")));
    }

    #[test]
    fn skips_extensions_before_server_name() {
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x0d, 0x00, 0x02, 0x04, 0x03]); // signature_algorithms
        ext.extend_from_slice(&sni_extension("example.com"));
        let hello = client_hello(&ext);
        assert_eq!(sniff(&hello), found(Some("example.com")));
    }

    #[test]
    fn needs_more_when_the_record_is_incomplete() {
        let hello = client_hello(&sni_extension("example.com"));
        for cut in [1, 3, 5, 10, hello.len() - 1] {
            assert_eq!(
                sniff(&hello[..cut]),
                SniffOutcome::NeedMore,
                "a {cut}-byte prefix should ask for more"
            );
        }
    }

    #[test]
    fn rejects_non_tls_bytes() {
        assert_eq!(sniff(b"GET / HTTP/1.1\r\n"), SniffOutcome::NotThisOne);
        assert_eq!(
            sniff(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]),
            SniffOutcome::NotThisOne
        );
    }

    #[test]
    fn rejects_a_handshake_that_is_not_a_client_hello() {
        let mut hello = client_hello(&[]);
        // Overwrite the handshake type: 0x02 is ServerHello.
        hello[5] = 0x02;
        assert_eq!(sniff(&hello), SniffOutcome::NotThisOne);
    }

    #[test]
    fn rejects_a_client_hello_fragmented_across_records() {
        let mut hello = client_hello(&sni_extension("example.com"));
        // Shrink the record so the handshake body no longer fits inside it.
        let shorter = (hello.len() - 5 - 10) as u16;
        hello[3..5].copy_from_slice(&shorter.to_be_bytes());
        hello.truncate(5 + shorter as usize);
        assert_eq!(sniff(&hello), SniffOutcome::NotThisOne);
    }

    #[test]
    fn discards_a_server_name_that_is_not_a_hostname() {
        let hello = client_hello(&sni_extension("has space"));
        assert_eq!(sniff(&hello), found(None));
    }
}
