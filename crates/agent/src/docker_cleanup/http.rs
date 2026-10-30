//! Small bounded HTTP/1 framing for local Docker JSON requests. Streaming
//! endpoints are relayed by the proxy without buffering their payloads.

use std::io::{self, Read};

use super::invalid;

pub const MAX_JSON: usize = 8 * 1024 * 1024;
const MAX_HEADERS: usize = 32 * 1024;

#[derive(Debug)]
pub struct Head {
    pub first: String,
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn read(reader: &mut impl Read) -> io::Result<Self> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = [0];
            reader.read_exact(&mut byte)?;
            bytes.push(byte[0]);
            if bytes.len() > MAX_HEADERS {
                return Err(invalid("Docker HTTP headers too large"));
            }
            if bytes.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let text = std::str::from_utf8(&bytes).map_err(invalid)?;
        let mut lines = text[..text.len() - 4].split("\r\n");
        let first = lines
            .next()
            .ok_or_else(|| invalid("missing HTTP start line"))?
            .to_owned();
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| invalid("invalid HTTP header"))?;
            if name.is_empty()
                || name
                    .bytes()
                    .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-')
            {
                return Err(invalid("invalid HTTP header name"));
            }
            headers.push((name.into(), value.trim().into()));
        }
        Ok(Self { first, headers })
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn encode_for_relay(&self) -> Vec<u8> {
        let upgrade = self.get("Upgrade").is_some();
        let mut text = format!("{}\r\n", self.first);
        for (name, value) in &self.headers {
            if !upgrade && name.eq_ignore_ascii_case("Connection") {
                continue;
            }
            text.push_str(&format!("{name}: {value}\r\n"));
        }
        if !upgrade {
            text.push_str("Connection: close\r\n");
        }
        text.push_str("\r\n");
        text.into_bytes()
    }

    pub fn body(&self, reader: &mut impl Read) -> io::Result<Vec<u8>> {
        let lengths: Vec<_> = self
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("Content-Length"))
            .collect();
        if lengths.len() > 1 || (!lengths.is_empty() && self.get("Transfer-Encoding").is_some()) {
            return Err(invalid("ambiguous HTTP framing"));
        }
        if let Some(encoding) = self.get("Transfer-Encoding") {
            if !encoding.eq_ignore_ascii_case("chunked") {
                return Err(invalid("unsupported HTTP encoding"));
            }
            let mut body = Vec::new();
            loop {
                let line = read_line(reader, 128)?;
                let size = usize::from_str_radix(line.split(';').next().unwrap_or_default(), 16)
                    .map_err(invalid)?;
                if size > MAX_JSON.saturating_sub(body.len()) {
                    return Err(invalid("Docker JSON too large"));
                }
                if size == 0 {
                    let mut total = 0;
                    loop {
                        let trailer = read_line(reader, MAX_HEADERS)?;
                        total += trailer.len() + 2;
                        if total > MAX_HEADERS {
                            return Err(invalid("HTTP trailers too large"));
                        }
                        if trailer.is_empty() {
                            return Ok(body);
                        }
                    }
                }
                let start = body.len();
                body.resize(start + size, 0);
                reader.read_exact(&mut body[start..])?;
                let mut ending = [0; 2];
                reader.read_exact(&mut ending)?;
                if ending != *b"\r\n" {
                    return Err(invalid("invalid HTTP chunk ending"));
                }
            }
        }
        let size: usize = self
            .get("Content-Length")
            .unwrap_or("0")
            .parse()
            .map_err(invalid)?;
        if size > MAX_JSON {
            return Err(invalid("Docker JSON too large"));
        }
        let mut body = vec![0; size];
        reader.read_exact(&mut body)?;
        Ok(body)
    }
}

fn read_line(reader: &mut impl Read, limit: usize) -> io::Result<String> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        reader.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.len() > limit {
            return Err(invalid("HTTP line too large"));
        }
        if bytes.ends_with(b"\r\n") {
            bytes.truncate(bytes.len() - 2);
            return String::from_utf8(bytes).map_err(invalid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_chunked_json_and_consumes_bounded_trailers() {
        let mut wire = &b"POST /containers/create HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\nX-Fixture: trailer\r\n\r\nnext"[..];
        let head = Head::read(&mut wire).unwrap();
        assert_eq!(head.body(&mut wire).unwrap(), b"{\"a\":1}");
        assert_eq!(wire, b"next");
    }

    #[test]
    fn rejects_ambiguous_framing_and_oversized_payloads() {
        for headers in [
            "Content-Length: 1\r\nContent-Length: 1",
            "Content-Length: 1\r\nTransfer-Encoding: chunked",
            "Content-Length: 9000000",
            "Transfer-Encoding: gzip",
        ] {
            let bytes = format!("POST /containers/create HTTP/1.1\r\n{headers}\r\n\r\nx");
            let mut wire = bytes.as_bytes();
            let head = Head::read(&mut wire).unwrap();
            assert!(head.body(&mut wire).is_err(), "{headers}");
        }
    }

    #[test]
    fn ordinary_relays_close_the_connection_but_attach_upgrades_remain_bidirectional() {
        let mut ordinary =
            &b"GET /info HTTP/1.1\r\nConnection: keep-alive\r\nHost: docker\r\n\r\n"[..];
        let head = Head::read(&mut ordinary).unwrap();
        let relayed = String::from_utf8(head.encode_for_relay()).unwrap();
        assert!(relayed.contains("Connection: close\r\n"));
        assert!(!relayed.contains("keep-alive"));
        let wire = b"POST /containers/fixture/attach HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n";
        let mut input = &wire[..];
        let head = Head::read(&mut input).unwrap();
        assert_eq!(head.encode_for_relay(), wire);
    }
}
