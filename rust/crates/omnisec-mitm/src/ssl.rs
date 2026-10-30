use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::capture::{HttpRequestCapture, HttpResponseCapture, MitmCapture};

fn unix_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn ensure_root_ca(out_dir: &str) -> crate::MitmResult<()> {
    let dir = Path::new(out_dir);
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }

    let key_path = dir.join("root_ca.key");
    let cert_path = dir.join("root_ca.crt");

    if key_path.exists() && cert_path.exists() {
        omnisec_log::info!("Root CA already exists in {}", out_dir);
        return Ok(());
    }

    omnisec_log::info!("Generating new Root CA in {}", out_dir);

    let (key_pair, certificate) = crate::cert::generate_ca("OmniSec MITM Root CA")?;

    write_private_key_0600(
        &key_path,
        crate::cert::private_key_pem(&key_pair).as_bytes(),
    )?;
    fs::write(&cert_path, certificate.pem())?;

    Ok(())
}

#[cfg(unix)]
fn write_private_key_0600(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

#[cfg(not(unix))]
fn write_private_key_0600(path: &Path, data: &[u8]) -> std::io::Result<()> {
    fs::write(path, data)
}

/// A rudimentary HTTP proxy that performs SSL stripping by replacing text-body
/// `https://` links with `http://` and removing HSTS headers. It reads and
/// forwards by bytes (not lossy UTF-8 strings) and reads upstream responses to
/// EOF so bodies are not truncated at 64 KiB.
///
/// Every successfully parsed request and response is appended to `capture_sink`
/// so callers can drain real observed traffic after the session ends instead of
/// relying on synthesized stand-ins.
///
/// Blocking std version: one thread per client connection.
pub fn run_ssl_strip_proxy(
    listen_addr: &str,
    capture_sink: Arc<Mutex<MitmCapture>>,
) -> crate::MitmResult<()> {
    omnisec_log::info!("SSL Strip Proxy starting on {}", listen_addr);

    let listener = TcpListener::bind(listen_addr)?;

    for client in listener.incoming() {
        let mut client_stream = match client {
            Ok(s) => s,
            Err(e) => {
                omnisec_log::warn!("Failed to accept client: {}", e);
                continue;
            }
        };

        let sink = capture_sink.clone();
        thread::spawn(move || {
            let initial = match read_request_head(&mut client_stream) {
                Ok(data) if !data.is_empty() => data,
                _ => return,
            };

            // Basic check if it's HTTP. Work on raw bytes to avoid corrupting binary bodies.
            if !starts_with_any(
                &initial,
                &[
                    b"GET ".as_ref(),
                    b"POST ".as_ref(),
                    b"CONNECT ".as_ref(),
                    b"PUT ".as_ref(),
                    b"PATCH ".as_ref(),
                    b"DELETE ".as_ref(),
                    b"HEAD ".as_ref(),
                ],
            ) {
                return;
            }

            // CONNECT: capture the TLS handshake metadata, then tunnel. This
            // finally gives TlsHandshakeCapture a live producer (see tls.rs).
            if initial.starts_with(b"CONNECT ") {
                match crate::tls::parse_connect_target(&initial) {
                    Some(target) if host_allowed(&target) => {
                        crate::tls::intercept_connect(client_stream, &target, sink);
                    }
                    Some(_) => {
                        let _ = client_stream
                            .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
                    }
                    None => {
                        let _ = client_stream
                            .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
                    }
                }
                return;
            }

            let host = match extract_host_header(&initial) {
                Some(h) if !h.is_empty() => h,
                _ => return,
            };

            if !host_allowed(&host) {
                let _ =
                    client_stream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
                return;
            }

            let target_addr = if host.contains(':') {
                host.clone()
            } else {
                format!("{}:80", host)
            };

            omnisec_log::info!("SSL Strip proxying request to {}", target_addr);

            let mut upstream = if let Ok(s) = TcpStream::connect(&target_addr) {
                s
            } else {
                let _ = client_stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
                return;
            };

            let request_capture = parse_request_capture(&initial);
            if let Some(capture) = &request_capture {
                omnisec_log::debug!(?capture, "http request captured");
                if let Ok(mut sink) = sink.lock() {
                    sink.http_requests.push(capture.clone());
                }
            }

            let req_mod = rewrite_request_headers(&initial);
            if upstream.write_all(&req_mod).is_err() {
                return;
            }

            let mut client_read = match client_stream.try_clone() {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut client_write = client_stream;
            let mut up_read = match upstream.try_clone() {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut up_write = upstream;

            // Forward any remaining request body/chunks without buffering/truncating.
            // Detached: unblocked below via shutdown(Both) once the response is done.
            thread::spawn(move || {
                let _ = std::io::copy(&mut client_read, &mut up_write);
                let _ = up_write.shutdown(Shutdown::Write);
            });

            let mut resp = Vec::new();
            if up_read.read_to_end(&mut resp).is_ok() && !resp.is_empty() {
                if let Some(capture) = parse_response_capture(&resp, request_capture.as_ref()) {
                    omnisec_log::debug!(?capture, "http response captured");
                    if let Ok(mut sink) = sink.lock() {
                        sink.http_responses.push(capture);
                    }
                }
                let stripped = strip_response_bytes(&resp);
                let _ = client_write.write_all(&stripped);
            }
            // Unblock the detached body-relay thread, then close.
            let _ = client_write.shutdown(Shutdown::Both);
        });
    }
    // `incoming()` only ends on accept failure; keep the same
    // never-returning server contract as the other runners.
    #[allow(unreachable_code)]
    Ok(())
}

fn read_request_head(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    const MAX_HEADER_BYTES: usize = 64 * 1024;
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP headers too large",
            ));
        }
    }
    Ok(buf)
}

fn starts_with_any(data: &[u8], prefixes: &[&[u8]]) -> bool {
    prefixes.iter().any(|p| data.starts_with(p))
}

fn header_body_split(data: &[u8]) -> Option<(usize, usize)> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| (idx, idx + 4))
}

fn extract_host_header(req: &[u8]) -> Option<String> {
    let (hdr_end, _) = header_body_split(req)?;
    for line in req[..hdr_end].split(|b| *b == b'\n') {
        let line = trim_ascii(line.strip_suffix(b"\r").unwrap_or(line));
        if line.len() >= 5 && line[..5].eq_ignore_ascii_case(b"host:") {
            return Some(String::from_utf8_lossy(trim_ascii(&line[5..])).into_owned());
        }
    }
    None
}

fn host_allowed(hostport: &str) -> bool {
    let host = hostport
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(hostport)
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host == "localhost" {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
        };
    }
    let allowed = std::env::var("OMNISEC_MITM_ALLOWED_DOMAINS").unwrap_or_default();
    if allowed.trim().is_empty() {
        return false;
    }
    allowed.split(',').any(|entry| {
        let entry = entry.trim().trim_end_matches('.').to_ascii_lowercase();
        !entry.is_empty() && (host == entry || host.ends_with(&format!(".{entry}")))
    })
}

fn parse_header_lines<'a>(lines: impl Iterator<Item = &'a [u8]>) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    for line in lines {
        let line = trim_ascii(trim_line_cr(line));
        if let Some(colon) = line.iter().position(|b| *b == b':') {
            let name = String::from_utf8_lossy(trim_ascii(&line[..colon])).into_owned();
            let value = String::from_utf8_lossy(trim_ascii(&line[colon + 1..])).into_owned();
            if !name.is_empty() {
                headers.insert(name.to_ascii_lowercase(), value);
            }
        }
    }
    headers
}

/// Parses a captured HTTP request head (request line + headers) into an
/// [`HttpRequestCapture`]. Returns `None` if the request line doesn't have
/// the expected `METHOD SP target SP version` shape.
fn parse_request_capture(head: &[u8]) -> Option<HttpRequestCapture> {
    let (hdr_end, _) = header_body_split(head).unwrap_or((head.len(), head.len()));
    let mut lines = head[..hdr_end].split(|b| *b == b'\n');
    let request_line = trim_ascii(trim_line_cr(lines.next()?));
    let mut parts = request_line.split(|b| *b == b' ').filter(|p| !p.is_empty());
    let method = String::from_utf8_lossy(parts.next()?).into_owned();
    let url = String::from_utf8_lossy(parts.next()?).into_owned();

    Some(HttpRequestCapture {
        timestamp_ms: unix_epoch_ms(),
        method,
        url,
        headers: parse_header_lines(lines),
    })
}

/// Parses a captured HTTP response head (status line + headers) into an
/// [`HttpResponseCapture`]. Returns `None` if the status line doesn't have
/// the expected `version SP status SP reason` shape or the status code isn't
/// numeric. `request` is the capture of the request this response answers
/// (this proxy handles one request/response per connection synchronously),
/// used to populate `request_method`/`request_url` so a response can later
/// be correlated back to the request that caused it.
fn parse_response_capture(
    head: &[u8],
    request: Option<&HttpRequestCapture>,
) -> Option<HttpResponseCapture> {
    let (hdr_end, _) = header_body_split(head).unwrap_or((head.len(), head.len()));
    let mut lines = head[..hdr_end].split(|b| *b == b'\n');
    let status_line = trim_ascii(trim_line_cr(lines.next()?));
    let mut parts = status_line.split(|b| *b == b' ').filter(|p| !p.is_empty());
    let _version = parts.next()?;
    let status: u16 = std::str::from_utf8(parts.next()?).ok()?.parse().ok()?;

    Some(HttpResponseCapture {
        timestamp_ms: unix_epoch_ms(),
        status,
        headers: parse_header_lines(lines),
        request_method: request.map(|r| r.method.clone()),
        request_url: request.map(|r| r.url.clone()),
    })
}

fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while matches!(s.first(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        s = &s[1..];
    }
    while matches!(s.last(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        s = &s[..s.len() - 1];
    }
    s
}

fn rewrite_request_headers(req: &[u8]) -> Vec<u8> {
    let Some((hdr_end, body_start)) = header_body_split(req) else {
        return req.to_vec();
    };
    let mut lines = req[..hdr_end].split(|b| *b == b'\n');
    let mut out = Vec::with_capacity(req.len() + 64);
    if let Some(status) = lines.next() {
        out.extend_from_slice(trim_line_cr(status));
        out.extend_from_slice(b"\r\n");
    }

    let mut saw_accept_encoding = false;
    let mut saw_connection = false;
    for line in lines {
        let clean = trim_line_cr(line);
        let lower = ascii_lower(clean);
        if lower.starts_with(b"accept-encoding:") {
            out.extend_from_slice(b"Accept-Encoding: identity\r\n");
            saw_accept_encoding = true;
        } else if lower.starts_with(b"connection:") || lower.starts_with(b"proxy-connection:") {
            out.extend_from_slice(b"Connection: close\r\n");
            saw_connection = true;
        } else {
            out.extend_from_slice(clean);
            out.extend_from_slice(b"\r\n");
        }
    }
    if !saw_accept_encoding {
        out.extend_from_slice(b"Accept-Encoding: identity\r\n");
    }
    if !saw_connection {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&req[body_start..]);
    out
}

fn strip_response_bytes(resp: &[u8]) -> Vec<u8> {
    let Some((hdr_end, body_start)) = header_body_split(resp) else {
        return resp.to_vec();
    };
    let body = &resp[body_start..];
    let headers = &resp[..hdr_end];
    let is_chunked = header_contains(headers, b"transfer-encoding:", b"chunked");
    let is_text = is_text_response(headers);

    let new_body = if is_text && !is_chunked {
        replace_all(body, b"https://", b"http://")
    } else {
        body.to_vec()
    };

    let mut out = Vec::with_capacity(resp.len());
    let mut lines = headers.split(|b| *b == b'\n');
    if let Some(status) = lines.next() {
        out.extend_from_slice(trim_line_cr(status));
        out.extend_from_slice(b"\r\n");
    }

    let mut saw_content_length = false;
    let mut saw_connection = false;
    for line in lines {
        let clean = trim_line_cr(line);
        let lower = ascii_lower(clean);
        if lower.starts_with(b"strict-transport-security:") {
            continue;
        }
        if lower.starts_with(b"content-length:") && !is_chunked {
            out.extend_from_slice(format!("Content-Length: {}\r\n", new_body.len()).as_bytes());
            saw_content_length = true;
            continue;
        }
        if lower.starts_with(b"connection:") {
            out.extend_from_slice(b"Connection: close\r\n");
            saw_connection = true;
            continue;
        }
        out.extend_from_slice(clean);
        out.extend_from_slice(b"\r\n");
    }
    if !saw_content_length && !is_chunked {
        out.extend_from_slice(format!("Content-Length: {}\r\n", new_body.len()).as_bytes());
    }
    if !saw_connection {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&new_body);
    out
}

fn trim_line_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn ascii_lower(s: &[u8]) -> Vec<u8> {
    s.iter().map(u8::to_ascii_lowercase).collect()
}

fn header_contains(headers: &[u8], name: &[u8], needle: &[u8]) -> bool {
    let needle_l = ascii_lower(needle);
    for line in headers.split(|b| *b == b'\n') {
        let clean = trim_line_cr(line);
        let lower = ascii_lower(clean);
        if lower.starts_with(name)
            && lower
                .windows(needle_l.len())
                .any(|w| w == needle_l.as_slice())
        {
            return true;
        }
    }
    false
}

fn is_text_response(headers: &[u8]) -> bool {
    for line in headers.split(|b| *b == b'\n') {
        let clean = trim_line_cr(line);
        let lower = ascii_lower(clean);
        if lower.starts_with(b"content-type:") {
            return lower.windows(5).any(|w| w == b"text/")
                || lower.windows(4).any(|w| w == b"html")
                || lower.windows(10).any(|w| w == b"javascript")
                || lower.windows(4).any(|w| w == b"json")
                || lower.windows(3).any(|w| w == b"xml")
                || lower.windows(3).any(|w| w == b"css");
        }
    }
    false
}

fn replace_all(haystack: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if i + from.len() <= haystack.len() && &haystack[i..i + from.len()] == from {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_capture_extracts_method_url_and_headers() {
        let head = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n";
        let capture = parse_request_capture(head).expect("request capture");
        assert_eq!(capture.method, "GET");
        assert_eq!(capture.url, "/index.html");
        assert_eq!(
            capture.headers.get("host").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            capture.headers.get("accept").map(String::as_str),
            Some("text/html")
        );
    }

    #[test]
    fn parse_request_capture_rejects_malformed_request_line() {
        assert!(parse_request_capture(b"garbage\r\n\r\n").is_none());
    }

    #[test]
    fn parse_response_capture_extracts_status_and_headers() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        let capture = parse_response_capture(head, None).expect("response capture");
        assert_eq!(capture.status, 200);
        assert_eq!(
            capture.headers.get("content-type").map(String::as_str),
            Some("text/html")
        );
        assert_eq!(capture.request_method, None);
        assert_eq!(capture.request_url, None);
    }

    #[test]
    fn parse_response_capture_rejects_non_numeric_status() {
        assert!(parse_response_capture(b"HTTP/1.1 OK\r\n\r\n", None).is_none());
    }

    #[test]
    fn parse_response_capture_attaches_request_method_and_url_when_provided() {
        let request_head = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let request = parse_request_capture(request_head).expect("request capture");

        let response_head = b"HTTP/1.1 200 OK\r\n\r\n";
        let capture =
            parse_response_capture(response_head, Some(&request)).expect("response capture");

        assert_eq!(capture.request_method.as_deref(), Some("GET"));
        assert_eq!(capture.request_url.as_deref(), Some("/index.html"));
    }
}
