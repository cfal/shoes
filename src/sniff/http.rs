use super::{SniffOutcome, Sniffed, SniffedProtocol, normalize_host};

/// Methods, with the separating space, so that a prefix comparison also tells
/// us whether a short buffer could still become one of them.
const METHODS: [&[u8]; 9] = [
    b"GET ",
    b"PUT ",
    b"HEAD ",
    b"POST ",
    b"PATCH ",
    b"TRACE ",
    b"DELETE ",
    b"CONNECT ",
    b"OPTIONS ",
];

/// Past this much buffered data without a complete header block, stop waiting.
/// Well above any real request head, and below the peek loop's own ceiling.
const MAX_HEADER_BYTES: usize = 8 * 1024;

enum MethodMatch {
    Full,
    Partial,
    No,
}

pub fn sniff(buf: &[u8]) -> SniffOutcome {
    match method_match(buf) {
        MethodMatch::No => return SniffOutcome::NotThisOne,
        MethodMatch::Partial => return SniffOutcome::NeedMore,
        MethodMatch::Full => {}
    }

    let line_end = match find(buf, b"\r\n") {
        Some(i) => i,
        None if buf.len() < MAX_HEADER_BYTES => return SniffOutcome::NeedMore,
        None => return SniffOutcome::NotThisOne,
    };

    let mut parts = buf[..line_end].split(|&b| b == b' ');
    let method = match parts.next() {
        Some(m) => m,
        None => return SniffOutcome::NotThisOne,
    };
    let target = match parts.next() {
        Some(t) => t,
        None => return SniffOutcome::NotThisOne,
    };
    let version = match parts.next() {
        Some(v) => v,
        None => return SniffOutcome::NotThisOne,
    };
    if parts.next().is_some() {
        return SniffOutcome::NotThisOne;
    }
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return SniffOutcome::NotThisOne;
    }

    if method == b"CONNECT" {
        return found(normalize_host(target));
    }

    if let Some(rest) = strip_http_scheme(target) {
        let end = rest
            .iter()
            .position(|&b| b == b'/' || b == b'?' || b == b'#')
            .unwrap_or(rest.len());
        return found(normalize_host(&rest[..end]));
    }

    let headers = &buf[line_end + 2..];
    if let Some(value) = host_header(headers) {
        return found(normalize_host(value));
    }

    // No Host yet. Either the header block is finished and there is none, or
    // more is coming.
    if find(headers, b"\r\n\r\n").is_some() {
        return found(None);
    }
    if buf.len() < MAX_HEADER_BYTES {
        SniffOutcome::NeedMore
    } else {
        found(None)
    }
}

fn found(domain: Option<String>) -> SniffOutcome {
    SniffOutcome::Found(Sniffed {
        protocol: SniffedProtocol::Http,
        domain,
    })
}

fn method_match(buf: &[u8]) -> MethodMatch {
    let mut partial = false;
    for method in METHODS {
        if buf.len() >= method.len() {
            if &buf[..method.len()] == method {
                return MethodMatch::Full;
            }
        } else if method.starts_with(buf) {
            partial = true;
        }
    }
    if partial {
        MethodMatch::Partial
    } else {
        MethodMatch::No
    }
}

fn strip_http_scheme(target: &[u8]) -> Option<&[u8]> {
    for scheme in [&b"http://"[..], &b"https://"[..]] {
        if target.len() > scheme.len() && target[..scheme.len()].eq_ignore_ascii_case(scheme) {
            return Some(&target[scheme.len()..]);
        }
    }
    None
}

/// The value of the first complete `Host:` line, or `None` when there is no
/// complete one — which covers both "not sent" and "not yet arrived". The
/// caller distinguishes them by looking for the end of the header block.
fn host_header(headers: &[u8]) -> Option<&[u8]> {
    let mut rest = headers;
    loop {
        let end = find(rest, b"\r\n")?;
        let line = &rest[..end];
        if line.is_empty() {
            return None; // end of the header block
        }
        if line.len() > 5 && line[..5].eq_ignore_ascii_case(b"host:") {
            return Some(&line[5..]);
        }
        rest = &rest[end + 2..];
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(name: Option<&str>) -> SniffOutcome {
        SniffOutcome::Found(Sniffed {
            protocol: SniffedProtocol::Http,
            domain: name.map(str::to_string),
        })
    }

    #[test]
    fn finds_the_host_header() {
        let request = b"GET /index.html HTTP/1.1\r\nHost: Example.COM\r\n\r\n";
        assert_eq!(sniff(request), found(Some("example.com")));
    }

    #[test]
    fn accepts_any_header_case() {
        let request = b"GET / HTTP/1.1\r\nhOsT:example.com\r\n\r\n";
        assert_eq!(sniff(request), found(Some("example.com")));
    }

    #[test]
    fn strips_the_port_from_the_host_header() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(sniff(request), found(Some("example.com")));
    }

    #[test]
    fn reads_the_connect_target() {
        let request = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n";
        assert_eq!(sniff(request), found(Some("example.com")));
    }

    #[test]
    fn prefers_the_absolute_uri_over_the_host_header() {
        let request = b"GET http://uri.example/path?q=1 HTTP/1.1\r\nHost: header.example\r\n\r\n";
        assert_eq!(sniff(request), found(Some("uri.example")));
    }

    #[test]
    fn recognises_http_without_a_host_header() {
        let request = b"GET / HTTP/1.0\r\nUser-Agent: x\r\n\r\n";
        assert_eq!(sniff(request), found(None));
    }

    #[test]
    fn needs_more_while_the_request_line_is_partial() {
        for prefix in [&b""[..], &b"G"[..], &b"GET"[..], &b"GET / HTTP/1."[..]] {
            assert_eq!(sniff(prefix), SniffOutcome::NeedMore, "prefix {prefix:?}");
        }
    }

    #[test]
    fn needs_more_while_the_host_header_is_partial() {
        let request = b"GET / HTTP/1.1\r\nHost: exam";
        assert_eq!(sniff(request), SniffOutcome::NeedMore);
    }

    #[test]
    fn rejects_non_http_bytes() {
        assert_eq!(sniff(b"\x16\x03\x01\x00\x05"), SniffOutcome::NotThisOne);
        assert_eq!(sniff(b"SSH-2.0-OpenSSH_9.6\r\n"), SniffOutcome::NotThisOne);
    }

    #[test]
    fn rejects_an_unknown_protocol_version() {
        assert_eq!(sniff(b"GET / HTTP/2.0\r\n\r\n"), SniffOutcome::NotThisOne);
        assert_eq!(sniff(b"GET / RTSP/1.0\r\n\r\n"), SniffOutcome::NotThisOne);
    }

    #[test]
    fn rejects_a_malformed_request_line() {
        assert_eq!(sniff(b"GET HTTP/1.1\r\n\r\n"), SniffOutcome::NotThisOne);
        assert_eq!(sniff(b"GET / / HTTP/1.1\r\n\r\n"), SniffOutcome::NotThisOne);
    }

    #[test]
    fn gives_up_on_an_endless_header_block() {
        let mut request = b"GET / HTTP/1.1\r\nX: ".to_vec();
        request.extend(std::iter::repeat_n(b'a', 9000));
        assert_eq!(sniff(&request), found(None));
    }
}
