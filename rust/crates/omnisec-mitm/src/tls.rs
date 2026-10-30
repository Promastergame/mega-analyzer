//! Live TLS handshake capture for the `CONNECT` path.
//!
//! Before this module, `ssl.rs`'s `CONNECT` handler answered `501 Not
//! Implemented` and `TlsHandshakeCapture` had no live producer anywhere in the
//! tree. Now, when a client issues `CONNECT host:port`, we accept the tunnel,
//! read and dissect the client's ClientHello (SNI, cipher suites, extensions,
//! ALPN, JA3) via `omnisec_capture`, record a [`TlsHandshakeCapture`], and then
//! transparently relay the encrypted bytes to the upstream — forwarding the
//! ClientHello we buffered first so the handshake completes normally.
//!
//! This is a *metadata-capturing passthrough*: we fingerprint the handshake
//! without terminating TLS, which needs no leaf-certificate minting and keeps
//! the operator's trust model unchanged, while finally giving NCER real
//! `tls_handshake` events to reason about. Full termination (leaf minting from
//! the `ensure_root_ca` output + rustls re-encryption) can layer on top of the
//! same capture step later. Every tunnel remains gated by the existing
//! `host_allowed` allowlist.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use omnisec_capture::parse_client_hello;

use crate::capture::{MitmCapture, TlsHandshakeCapture};

fn unix_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Maps the common TLS 1.2/1.3 cipher-suite code points to their IANA names.
/// Unknown suites render as `0xXXXX` so nothing is silently dropped.
#[must_use]
pub fn cipher_suite_name(code: u16) -> String {
    match code {
        0x1301 => "TLS_AES_128_GCM_SHA256".to_string(),
        0x1302 => "TLS_AES_256_GCM_SHA384".to_string(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
        other => format!("0x{other:04x}"),
    }
}

/// Dissects a raw ClientHello record into a [`TlsHandshakeCapture`].
///
/// `cipher_suite` is set to the client's *first-offered* suite name (the one it
/// most prefers), since a passthrough tunnel never sees the server's choice.
/// Returns `None` when the bytes are not a parseable ClientHello.
#[must_use]
pub fn build_tls_capture(client_hello: &[u8], timestamp_ms: u64) -> Option<TlsHandshakeCapture> {
    let info = parse_client_hello(client_hello)?;
    let cipher_suite = info
        .cipher_suites
        .first()
        .map_or_else(|| "unknown".to_string(), |c| cipher_suite_name(*c));
    Some(TlsHandshakeCapture {
        timestamp_ms,
        sni: info.sni.unwrap_or_default(),
        cipher_suite,
        cert_chain_fingerprints: Vec::new(),
        ja3: info.ja3,
        ja3_hash: info.ja3_hash,
        alpn: info.alpn,
    })
}

/// Reads exactly one TLS record (5-byte header + declared body) from `stream`,
/// tolerating short reads by looping until the full record is buffered or the
/// peer closes / times out. Returns whatever was read on timeout so a partial
/// ClientHello can still be relayed.
///
/// Blocking std version: bounds the wait with a 5s read timeout (set and
/// cleared here so the later relay phase has no deadline, matching the old
/// async behavior where only this phase was timed).
fn read_tls_record(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    const MAX_RECORD: usize = 18 * 1024; // 16 KiB payload + slack
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];
    loop {
        // Bound the wait so a silent client can't hang the tunnel thread.
        let n = match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                break;
            } // timeout: return what we have
            Err(e) => {
                let _ = stream.set_read_timeout(None);
                return Err(e);
            }
        };
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() >= 5 {
            let rec_len = ((buf[3] as usize) << 8) | buf[4] as usize;
            if buf.len() >= 5 + rec_len || buf.len() >= MAX_RECORD {
                break;
            }
        }
    }
    stream.set_read_timeout(None)?;
    Ok(buf)
}

/// Parses the target `host:port` from a `CONNECT` request head.
#[must_use]
pub fn parse_connect_target(head: &[u8]) -> Option<String> {
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(head.len());
    let line = &head[..line_end];
    let mut parts = line.split(|b| *b == b' ').filter(|p| !p.is_empty());
    let method = parts.next()?;
    if !method.eq_ignore_ascii_case(b"CONNECT") {
        return None;
    }
    let target = parts.next()?;
    Some(String::from_utf8_lossy(target).into_owned())
}

/// Handles a `CONNECT` tunnel: capture the handshake, then transparently relay.
///
/// `target` is the already-validated `host:port` (the caller enforces
/// `host_allowed`). The handshake capture, if any, is appended to `sink`.
///
/// Blocking std version: runs on the caller's connection thread.
pub fn intercept_connect(mut client: TcpStream, target: &str, sink: Arc<Mutex<MitmCapture>>) {
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }

    let client_hello = match read_tls_record(&mut client) {
        Ok(data) if !data.is_empty() => data,
        _ => return,
    };

    if let Some(capture) = build_tls_capture(&client_hello, unix_epoch_ms()) {
        omnisec_log::info!(
            "captured TLS ClientHello sni={} ja3={}",
            capture.sni,
            capture.ja3_hash
        );
        if let Ok(mut guard) = sink.lock() {
            guard.tls_handshakes.push(capture);
        }
    }

    let target_addr = if target.contains(':') {
        target.to_string()
    } else {
        format!("{target}:443")
    };

    let mut upstream = match TcpStream::connect(&target_addr) {
        Ok(s) => s,
        Err(e) => {
            omnisec_log::warn!("CONNECT upstream {} failed: {}", target_addr, e);
            return;
        }
    };

    // Forward the buffered ClientHello, then splice both directions.
    if upstream.write_all(&client_hello).is_err() {
        return;
    }
    let _ = copy_bidirectional(&mut client, &mut upstream);
}

/// Blocking equivalent of `tokio::io::copy_bidirectional`: relays both
/// directions until each side hits EOF, with the same half-close dance
/// (FIN is propagated so the peer sees EOF instead of hanging).
fn copy_bidirectional(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
) -> std::io::Result<(u64, u64)> {
    let mut up_write = upstream.try_clone()?;
    let mut client_read = client.try_clone()?;
    // client -> upstream; then propagate FIN upstream-side.
    let c2u = thread::spawn(move || -> std::io::Result<u64> {
        let n = std::io::copy(&mut client_read, &mut up_write)?;
        let _ = up_write.shutdown(Shutdown::Write);
        Ok(n)
    });
    // upstream -> client; then propagate FIN client-side.
    let u2c = std::io::copy(upstream, client);
    let _ = client.shutdown(Shutdown::Write);
    let n = c2u
        .join()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "relay thread panicked"))??;
    Ok((n, u2c?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal ClientHello record advertising cipher 0x1301 and SNI.
    fn client_hello() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher list len
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1);
        body.push(0); // compression
        // SNI extension for "game.example".
        let host = b"game.example";
        let mut sni = Vec::new();
        sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        let mut exts = Vec::new();
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01];
        let l = body.len();
        hs.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        hs.extend_from_slice(&body);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn build_tls_capture_populates_sni_ja3_and_cipher() {
        let cap = build_tls_capture(&client_hello(), 42).expect("capture");
        assert_eq!(cap.timestamp_ms, 42);
        assert_eq!(cap.sni, "game.example");
        assert_eq!(cap.cipher_suite, "TLS_AES_128_GCM_SHA256");
        assert_eq!(cap.ja3, "771,4865,0,,");
        assert_eq!(cap.ja3_hash.len(), 32);
    }

    #[test]
    fn build_tls_capture_rejects_non_handshake() {
        assert!(build_tls_capture(b"GET / HTTP/1.1\r\n\r\n", 0).is_none());
    }

    #[test]
    fn cipher_suite_name_falls_back_to_hex() {
        assert_eq!(cipher_suite_name(0x1301), "TLS_AES_128_GCM_SHA256");
        assert_eq!(cipher_suite_name(0xabcd), "0xabcd");
    }

    #[test]
    fn parse_connect_target_extracts_host_port() {
        let head = b"CONNECT game.example:443 HTTP/1.1\r\nHost: game.example:443\r\n\r\n";
        assert_eq!(
            parse_connect_target(head).as_deref(),
            Some("game.example:443")
        );
    }

    #[test]
    fn parse_connect_target_rejects_non_connect() {
        assert!(parse_connect_target(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }
}
