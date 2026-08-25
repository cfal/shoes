use std::collections::HashMap;

use crate::async_stream::AsyncStream;
use crate::stream_reader::StreamReader;

/// An HTTP/1.x start line plus its header block, read off a stream.
///
/// Header names are lowercased; values are trimmed. The `StreamReader` is
/// handed back because whatever it buffered past the blank line belongs to
/// whoever asked for the parse -- for an upgrade transport those bytes are the
/// tunnel's first payload, and dropping them is silent corruption.
pub struct ParsedHttpData {
    pub first_line: String,
    pub headers: HashMap<String, String>,
    pub stream_reader: StreamReader,
}

impl ParsedHttpData {
    pub async fn parse(stream: &mut Box<dyn AsyncStream>) -> std::io::Result<Self> {
        let mut stream_reader = StreamReader::new();
        let mut first_line: Option<String> = None;
        // don't use FxHashMap for unvalidated user data
        let mut headers: HashMap<String, String> = HashMap::new();

        let mut line_count = 0;
        loop {
            let line = stream_reader.read_line(stream).await?;
            if line.is_empty() {
                break;
            }

            if line.len() >= 4096 {
                return Err(std::io::Error::other("http request line is too long"));
            }

            if first_line.is_none() {
                first_line = Some(line.to_string());
            } else {
                let tokens: Vec<&str> = line.splitn(2, ':').collect();
                if tokens.len() != 2 {
                    return Err(std::io::Error::other(format!(
                        "invalid http request line: {line}"
                    )));
                }
                let header_key = tokens[0].trim().to_lowercase();
                let header_value = tokens[1].trim().to_string();
                headers.insert(header_key, header_value);
            }

            line_count += 1;
            if line_count >= 40 {
                return Err(std::io::Error::other("http request is too long"));
            }
        }

        let first_line = first_line.ok_or_else(|| std::io::Error::other("empty http request"))?;

        Ok(Self {
            first_line,
            headers,
            stream_reader,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::async_stream::testing::TestStream;
    use tokio::io::AsyncWriteExt;

    async fn parse_from(bytes: &[u8]) -> std::io::Result<ParsedHttpData> {
        let (near, mut far) = tokio::io::duplex(4096);
        far.write_all(bytes).await.unwrap();
        let mut stream: Box<dyn AsyncStream> = Box::new(TestStream(near));
        ParsedHttpData::parse(&mut stream).await
    }

    #[tokio::test]
    async fn header_names_are_lowercased_and_values_trimmed() {
        let parsed = parse_from(b"GET /p HTTP/1.1\r\nX-Secret:  value \r\n\r\n")
            .await
            .unwrap();
        assert_eq!(parsed.first_line, "GET /p HTTP/1.1");
        assert_eq!(
            parsed.headers.get("x-secret").map(String::as_str),
            Some("value")
        );
    }

    /// The bytes after the blank line are the caller's, not ours. An upgrade
    /// transport puts its first payload there.
    #[tokio::test]
    async fn bytes_after_the_blank_line_are_kept() {
        let parsed = parse_from(b"GET /p HTTP/1.1\r\n\r\nPAYLOAD").await.unwrap();
        assert_eq!(parsed.stream_reader.unparsed_data(), b"PAYLOAD");
    }
}
