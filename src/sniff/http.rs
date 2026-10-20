use std::net::IpAddr;

use rustls::pki_types::DnsName;

use crate::address::NetLocation;

const MAX_HEADERS: usize = 128;

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(super) enum Inspection {
    NeedMore,
    Finished(Option<String>),
}

#[derive(Default)]
pub(super) struct HttpProbe {
    scanned: usize,
    line_start: usize,
    request_line_complete: bool,
    method_end: Option<usize>,
    #[cfg(test)]
    work: ProbeWork,
}

#[cfg(test)]
#[derive(Default)]
struct ProbeWork {
    scanned_bytes: usize,
    request_line_parses: usize,
    head_parses: usize,
}

impl HttpProbe {
    pub(super) fn inspect(&mut self, prefix: &[u8]) -> Inspection {
        // Scan each byte once, then parse the completed head once. Tiny TCP fragments
        // must not repeatedly reparse an ever-growing header section.
        for index in self.scanned..prefix.len() {
            #[cfg(test)]
            {
                self.work.scanned_bytes += 1;
            }
            let byte = prefix[index];
            if (index > 0 && prefix[index - 1] == b'\r' && byte != b'\n')
                || (byte == b'\n' && (index == 0 || prefix[index - 1] != b'\r'))
                || (byte.is_ascii_control() && !matches!(byte, b'\r' | b'\n' | b'\t'))
            {
                return Inspection::Finished(None);
            }
            if !self.request_line_complete {
                if !byte.is_ascii() {
                    return Inspection::Finished(None);
                }
                if let Some(method_end) = self.method_end {
                    if index == method_end + 1 && !matches!(byte, b'/' | b'*') {
                        return Inspection::Finished(None);
                    }
                } else if byte == b' ' {
                    if ::http::Method::from_bytes(&prefix[..index]).is_err() {
                        return Inspection::Finished(None);
                    }
                    self.method_end = Some(index);
                }
            }
            if byte != b'\n' {
                continue;
            }
            let end = index + 1;
            if !self.request_line_complete {
                #[cfg(test)]
                {
                    self.work.request_line_parses += 1;
                }
                let mut request = httparse::Request::new(&mut []);
                if request.parse(&prefix[..end]).is_err() || !supported_request(&request) {
                    return Inspection::Finished(None);
                }
                self.request_line_complete = true;
            } else if end - self.line_start == 2 {
                #[cfg(test)]
                {
                    self.work.head_parses += 1;
                }
                return Inspection::Finished(parse_host(&prefix[..end]));
            }
            self.line_start = end;
        }
        self.scanned = prefix.len();
        Inspection::NeedMore
    }
}

fn supported_request(request: &httparse::Request<'_, '_>) -> bool {
    if !matches!(request.version, Some(0 | 1)) || request.method == Some("CONNECT") {
        return false;
    }
    match request.path {
        Some("*") => request.method == Some("OPTIONS"),
        Some(path) => valid_origin_form(path),
        None => false,
    }
}

fn valid_origin_form(target: &str) -> bool {
    if !target.starts_with('/') {
        return false;
    }
    // httparse checks request-line syntax, not RFC 3986 path/query characters.
    let mut bytes = target.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            if !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
                || !bytes.next().is_some_and(|byte| byte.is_ascii_hexdigit())
            {
                return false;
            }
        } else if !byte.is_ascii_alphanumeric() && !b"-._~!$&'()*+,;=:@/?".contains(&byte) {
            return false;
        }
    }
    true
}

fn parse_host(bytes: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    if !request.parse(bytes).ok()?.is_complete() || !supported_request(&request) {
        return None;
    }
    let mut hosts = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"));
    let value = hosts.next()?.value;
    if hosts.next().is_some() {
        return None;
    }
    let authority = std::str::from_utf8(value).ok()?.trim_matches([' ', '\t']);
    if let Some((_, port)) = authority.rsplit_once(':')
        && (port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    let location = NetLocation::from_authority(authority, Some(80)).ok()?;
    let name = location.address().hostname()?;
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.ends_with('.') || name.parse::<IpAddr>().is_ok() || DnsName::try_from(name).is_err() {
        return None;
    }
    Some(name.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fragmented(bytes: &[u8], chunk_size: usize) -> Inspection {
        let mut probe = HttpProbe::default();
        let mut result = Inspection::NeedMore;
        for end in (chunk_size..bytes.len())
            .step_by(chunk_size)
            .chain([bytes.len()])
        {
            result = probe.inspect(&bytes[..end]);
            if matches!(result, Inspection::Finished(_)) {
                break;
            }
        }
        result
    }

    fn inspect(bytes: &[u8]) -> Option<String> {
        let expected = HttpProbe::default().inspect(bytes);
        for split in 0..=bytes.len() {
            let mut probe = HttpProbe::default();
            let mut result = probe.inspect(&bytes[..split]);
            if matches!(result, Inspection::NeedMore) {
                result = probe.inspect(bytes);
            }
            assert_eq!(result, expected, "split {split}: {bytes:?}");
        }
        for chunk_size in [1, 3, 17] {
            assert_eq!(
                fragmented(bytes, chunk_size),
                expected,
                "chunk {chunk_size}: {bytes:?}"
            );
        }
        match expected {
            Inspection::Finished(name) => name,
            Inspection::NeedMore => panic!("expected completed inspection: {bytes:?}"),
        }
    }

    #[test]
    fn origin_form_and_options_use_one_valid_host() {
        for line in [
            "GET / HTTP/1.0",
            "POST /path?q=yes HTTP/1.1",
            "GET /a%20b/%2F?q=%FF&next=/a?b HTTP/1.1",
            "GET /a%2fb?q=%ff HTTP/1.1",
            "GET /AZaz09-._~!$&'()*+,;=:@/? HTTP/1.1",
            "CUSTOM / HTTP/1.1",
            "OPTIONS * HTTP/1.1",
        ] {
            for host in [
                "example.com",
                "ExAmPlE.CoM.",
                "example.com:8080",
                "example.com.:0",
            ] {
                let request = format!("{line}\r\nhOsT:\t {host}\t \r\nOther: ok\r\n\r\nbody");
                assert_eq!(inspect(request.as_bytes()).as_deref(), Some("example.com"));
            }
        }
    }

    #[test]
    fn invalid_or_ambiguous_heads_are_misses() {
        for headers in [
            "",
            "Host: \r\n",
            "Host: example.com\r\nHost: example.com\r\n",
            "Host: example.com\r\nhost: other.example\r\n",
            "Host: example.com,other.example\r\n",
            "Host: user@example.com\r\n",
            "Host: example.com/path\r\n",
            "Host: example.com?x\r\n",
            "Host: example.com#x\r\n",
            "Host: example.com..\r\n",
            "Host: example.com:+80\r\n",
            "Host: example.com:65536\r\n",
            "Host: example.com:abc\r\n",
            "Host: example.com:\r\n",
            "Host: 192.0.2.1\r\n",
            "Host: 192.0.2.1.:80\r\n",
            "Host: 127.1\r\n",
            "Host: 0177.0.0.1\r\n",
            "Host: [::1]\r\n",
            "Host: [::1]:80\r\n",
            "Host: ::1\r\n",
            "Host: \u{e9}.example\r\n",
            "Host : example.com\r\n",
            "Host: example.com\r\n folded: value\r\n",
            "Host: example.com\r\nBad header: x\r\n",
            "Host: example.com\r\nMissing colon\r\n",
            "Host: example.com\r\nBad: \0\r\n",
        ] {
            let request = format!("GET / HTTP/1.1\r\n{headers}\r\n");
            assert_eq!(inspect(request.as_bytes()), None, "{headers:?}");
        }
        for line in [
            "CONNECT proxy.example:80 HTTP/1.1",
            "CONNECT / HTTP/1.1",
            "GET http://example.com/ HTTP/1.1",
            "GET https://example.com/ HTTP/1.1",
            "GET * HTTP/1.1",
            "GET /#fragment HTTP/1.1",
            "GET /bad\\path HTTP/1.1",
            "GET /bad%zz HTTP/1.1",
            "GET /bad% HTTP/1.1",
            "GET /bad%2 HTTP/1.1",
            "GET /bad|path HTTP/1.1",
            "GET /bad[path] HTTP/1.1",
            "GET /bad{path} HTTP/1.1",
            "GET /path?q=%zz HTTP/1.1",
            "GET /path?q=\\ HTTP/1.1",
            "GET / HTTP/2.0",
            "GET / HTTP/1.2",
            "GET / HTTP/0.9",
            "GET /",
            "BAD(METHOD / HTTP/1.1",
            "",
        ] {
            let request = format!("{line}\r\nHost: example.com\r\n\r\n");
            assert_eq!(inspect(request.as_bytes()), None, "{line:?}");
        }
        for request in [
            &b"GET / HTTP/1.1\nHost: example.com\n\n"[..],
            &b"GET / HTTP/1.1\r\nHost: example.com\rwrong\r\n\r\n"[..],
            &b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..],
            &b"SSH-2.0\r\n"[..],
        ] {
            assert_eq!(inspect(request), None);
        }
    }

    #[test]
    fn header_count_is_bounded_and_duplicates_are_not_hidden() {
        for count in [127, 128, 129] {
            let mut request = "GET / HTTP/1.1\r\nHost: example.com\r\n".to_owned();
            request.push_str(&"X: y\r\n".repeat(count - 1));
            request.push_str("\r\n");
            assert_eq!(inspect(request.as_bytes()).is_some(), count <= MAX_HEADERS);
        }
        for duplicate_at in [MAX_HEADERS - 1, MAX_HEADERS, MAX_HEADERS + 1] {
            let mut request = "GET / HTTP/1.1\r\nHost: example.com\r\n".to_owned();
            request.push_str(&"X: y\r\n".repeat(duplicate_at - 2));
            request.push_str("hOsT: other.example\r\n\r\n");
            assert_eq!(inspect(request.as_bytes()), None, "header {duplicate_at}");
        }
    }

    #[test]
    fn bounded_mutations_are_independent_of_fragment_boundaries() {
        for seed in [
            &b"GET /a%2fb?q=yes HTTP/1.1\r\nHost: Example.com.:80\r\n\r\nbody"[..],
            &b"OPTIONS * HTTP/1.0\r\nHost: first.example\r\nHost: second.example\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: example.com\r\n"[..],
        ] {
            for index in 0..seed.len() {
                for replacement in [0, b'\r', b'\n', b'\t', b' ', b'%', b':', 0xff] {
                    let mut bytes = seed.to_vec();
                    bytes[index] = replacement;
                    let expected = HttpProbe::default().inspect(&bytes);
                    for chunk_size in [1, 3, 17, 4096] {
                        assert_eq!(
                            fragmented(&bytes, chunk_size),
                            expected,
                            "index {index}, byte {replacement}, chunk {chunk_size}"
                        );
                    }
                    if let Inspection::Finished(Some(name)) = expected {
                        assert_eq!(name, name.to_ascii_lowercase());
                        assert!(!name.ends_with('.'));
                        assert!(name.parse::<IpAddr>().is_err());
                    }
                }
            }
        }
    }

    #[test]
    fn request_body_and_later_requests_are_not_parsed() {
        for first in ["Host: first.example\r\n", ""] {
            let request = format!(
                "POST / HTTP/1.1\r\n{first}Content-Length: 999\r\nExpect: 100-continue\r\n\r\n\0Host: body.example\r\nGET / HTTP/1.1\r\nHost: second.example\r\n\r\n"
            );
            assert_eq!(
                inspect(request.as_bytes()).as_deref(),
                (!first.is_empty()).then_some("first.example")
            );
        }
    }

    #[test]
    fn tiny_fragments_advance_the_scan_without_reparsing_the_head() {
        let request = format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nX: {}\r\n\r\n",
            "a".repeat(60000)
        );
        let request_line_end = request.find("\r\n").unwrap() + 2;
        let mut probe = HttpProbe::default();
        for end in 1..request.len() {
            assert!(matches!(
                probe.inspect(&request.as_bytes()[..end]),
                Inspection::NeedMore
            ));
            assert_eq!(probe.scanned, end);
            assert_eq!(probe.work.scanned_bytes, end);
            assert_eq!(
                probe.work.request_line_parses,
                usize::from(end >= request_line_end)
            );
            assert_eq!(probe.work.head_parses, 0);
        }
        assert!(matches!(
            probe.inspect(request.as_bytes()),
            Inspection::Finished(Some(_))
        ));
        assert_eq!(probe.work.scanned_bytes, request.len());
        assert_eq!(probe.work.request_line_parses, 1);
        assert_eq!(probe.work.head_parses, 1);
    }
}
