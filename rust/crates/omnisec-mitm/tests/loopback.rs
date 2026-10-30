//! Loopback integration tests for the std-based MITM servers.
//!
//! Each test spins a server on 127.0.0.1 (background thread) and talks to
//! it with blocking std clients. No external processes, no tokio, fully
//! offline — the servers' offline/allowlist policy permits loopback, so
//! these also prove the policy didn't break in the tokio→std rewrite.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use omnisec_mitm::capture::MitmCapture;

fn new_sink() -> Arc<Mutex<MitmCapture>> {
    Arc::new(Mutex::new(MitmCapture::default()))
}

/// Run `f` until it returns `Some`, or panic after ~4s. Servers bind in a
/// background thread, so the first attempt usually races the listen call.
fn retry<T>(mut f: impl FnMut() -> Option<T>, what: &str) -> T {
    for _ in 0..40 {
        if let Some(v) = f() {
            return v;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {what}");
}

/// Build a minimal DNS A-query for `name` with `id`.
fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&[0u8; 6]); // AN/NS/AR = 0
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // A
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
    q
}

#[test]
fn dns_spoof_answers_and_captures() {
    let addr = "127.0.0.1:18053";
    let sink = new_sink();
    let s = sink.clone();
    thread::spawn(move || {
        let _ = omnisec_mitm::dns::run_dns_spoof_server(addr, "game.example", "10.9.9.9", s);
    });

    let client = UdpSocket::bind("127.0.0.1:0").expect("udp bind");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");

    // Matching domain → spoofed A record, RCODE 0.
    let resp = retry(
        || {
            client
                .send_to(&dns_query(0x1234, "game.example"), addr)
                .ok()?;
            let mut buf = [0u8; 512];
            let (n, _) = client.recv_from(&mut buf).ok()?;
            (n >= 12).then(|| buf[..n].to_vec())
        },
        "dns spoof response",
    );
    assert_eq!(&resp[0..2], &0x1234u16.to_be_bytes(), "id echoed");
    assert_eq!(resp[3] & 0x0f, 0, "rcode NOERROR");
    assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "one answer");
    assert_eq!(&resp[resp.len() - 4..], &[10, 9, 9, 9], "spoofed ip");

    // Subdomain also matches (suffix rule).
    client
        .send_to(&dns_query(0x1235, "a.game.example"), addr)
        .expect("send");
    let mut buf = [0u8; 512];
    let (n, _) = client.recv_from(&mut buf).expect("subdomain answer");
    assert_eq!(&buf[n - 4..n], &[10, 9, 9, 9]);

    // Unrelated domain, no upstream configured → REFUSED (rcode 5).
    client
        .send_to(&dns_query(0x1236, "other.example"), addr)
        .expect("send");
    let (n, _) = client.recv_from(&mut buf).expect("refused answer");
    assert!(n >= 12);
    assert_eq!(buf[3] & 0x0f, 5, "rcode REFUSED, got {buf:?}");

    // Both spoofed queries were captured with their response IPs.
    let guard = sink.lock().expect("sink");
    assert_eq!(guard.dns_queries.len(), 2, "captures: {guard:?}");
    assert!(
        guard
            .dns_queries
            .iter()
            .all(|q| q.response_ips.iter().any(|ip| ip.octets() == [10, 9, 9, 9]))
    );
}

/// Build a minimal DHCP DISCOVER (BOOTREQUEST + magic cookie + msg type).
fn dhcp_discover(xid: [u8; 4], msg_type: u8) -> Vec<u8> {
    let mut p = vec![0u8; 240];
    p[0] = 1; // BOOTREQUEST
    p[1] = 1; // ethernet
    p[2] = 6; // mac len
    p[4..8].copy_from_slice(&xid);
    p[28..34].copy_from_slice(&[0x02, 0x42, 0xAC, 0x11, 0x00, 0x02]); // chaddr
    p[236..240].copy_from_slice(&[99, 130, 83, 99]); // magic cookie
    p.extend_from_slice(&[53, 1, msg_type, 255]); // msg type + end
    p
}

#[test]
fn dhcp_offers_an_address() {
    // The server always replies to 255.255.255.255:68, so the client must
    // hold port 68 — skip gracefully where that bind is not permitted.
    let client = match UdpSocket::bind("0.0.0.0:68") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SKIP dhcp test: cannot bind :68 ({e})");
            return;
        }
    };
    client.set_broadcast(true).expect("broadcast");
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");

    let addr = "127.0.0.1:18067";
    thread::spawn(move || {
        let _ = omnisec_mitm::dhcp::run_rogue_dhcp_server(addr, "10.0.0.1");
    });

    // DISCOVER → OFFER (type 2) for 10.0.0.1 + 100 = 10.0.0.101.
    let resp = retry(
        || {
            client.send_to(&dhcp_discover([1, 2, 3, 4], 1), addr).ok()?;
            let mut buf = [0u8; 1500];
            let (n, _) = client.recv_from(&mut buf).ok()?;
            (n >= 240).then(|| buf[..n].to_vec())
        },
        "dhcp offer",
    );
    assert_eq!(resp[0], 2, "BOOTREPLY");
    assert_eq!(&resp[4..8], &[1, 2, 3, 4], "xid echoed");
    assert_eq!(&resp[16..20], &[10, 0, 0, 101], "offered ip");
    // Options contain message type 2 (OFFER).
    let opts = &resp[240..];
    let pos = opts
        .windows(3)
        .position(|w| w[0] == 53 && w[1] == 1)
        .expect("msg type opt");
    assert_eq!(opts[pos + 2], 2, "OFFER");

    // REQUEST → ACK (type 5). Note: this lab server hands out `next_ip`
    // without lease tracking, so the ACK carries the pool cursor, not a
    // repeat of the OFFER — assert shape, xid and type, not the address.
    client
        .send_to(&dhcp_discover([5, 6, 7, 8], 3), addr)
        .expect("send");
    let mut buf = [0u8; 1500];
    let (n, _) = client.recv_from(&mut buf).expect("dhcp ack");
    assert!(n >= 240);
    assert_eq!(buf[0], 2, "BOOTREPLY");
    assert_eq!(&buf[4..8], &[5, 6, 7, 8], "xid echoed");
    assert_eq!(&buf[16..20][..3], &[10, 0, 0], "pool address");
    let pos = buf[240..n]
        .windows(3)
        .position(|w| w[0] == 53 && w[1] == 1)
        .expect("msg type");
    assert_eq!(buf[240 + pos + 2], 5, "ACK");
}

/// Read a full HTTP response head (up to `\r\n\r\n`) plus whatever body
/// arrives within the read timeout.
fn read_http_response(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 4096];
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&tmp[..n]);
                if out.windows(4).any(|w| w == b"\r\n\r\n") {
                    // Head done; grab the announced body if already here.
                    thread::sleep(Duration::from_millis(200));
                    match stream.read(&mut tmp) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            out.extend_from_slice(&tmp[..n]);
                            break;
                        }
                    }
                }
            }
            Err(_) => break,
        }
        if out.len() > 64 * 1024 {
            break;
        }
    }
    out
}

/// Fixed HTTP/1.1 upstream: reads one request head, answers with a text
/// body containing an `https://` link and an HSTS header (both must be
/// stripped by the proxy), then closes.
fn spawn_text_upstream(body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("upstream bind");
    let addr = listener.local_addr().expect("addr").to_string();
    thread::spawn(move || {
        for client in listener.incoming() {
            let mut s = match client {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut head = Vec::new();
            let mut tmp = [0u8; 4096];
            s.set_read_timeout(Some(Duration::from_secs(3)))
                .expect("timeout");
            loop {
                match s.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        head.extend_from_slice(&tmp[..n]);
                        if head.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nStrict-Transport-Security: max-age=999\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(resp.as_bytes());
            // Close: the proxy reads the response to EOF.
        }
    });
    addr
}

#[test]
fn ssl_strip_forwards_and_strips() {
    let upstream = spawn_text_upstream("go to https://evil.example/x now");
    let proxy = "127.0.0.1:18080";
    let sink = new_sink();
    let s = sink.clone();
    thread::spawn(move || {
        let _ = omnisec_mitm::ssl::run_ssl_strip_proxy(proxy, s);
    });

    let mut client = retry(|| TcpStream::connect(proxy).ok(), "ssl proxy accept");
    let upstream_host = upstream.clone();
    write!(
        client,
        "GET /page HTTP/1.1\r\nHost: {upstream_host}\r\nConnection: close\r\n\r\n"
    )
    .expect("write");
    let resp = read_http_response(&mut client);
    let text = String::from_utf8_lossy(&resp);

    assert!(
        text.starts_with("HTTP/1.1 200"),
        "upstream status relayed: {text:?}"
    );
    assert!(
        text.contains("http://evil.example/x"),
        "https downgraded: {text:?}"
    );
    assert!(
        !text.contains("https://evil.example"),
        "no https left: {text:?}"
    );
    assert!(
        !text
            .to_ascii_lowercase()
            .contains("strict-transport-security"),
        "hsts removed: {text:?}"
    );

    let guard = sink.lock().expect("sink");
    assert_eq!(guard.http_requests.len(), 1, "request captured");
    assert_eq!(guard.http_requests[0].method, "GET");
    assert_eq!(guard.http_responses.len(), 1, "response captured");
    assert_eq!(guard.http_responses[0].status, 200);
}

#[test]
fn ssl_strip_rejects_disallowed_hosts() {
    let proxy = "127.0.0.1:18084";
    let sink = new_sink();
    let s = sink.clone();
    thread::spawn(move || {
        let _ = omnisec_mitm::ssl::run_ssl_strip_proxy(proxy, s);
    });

    // example.com is public, not loopback, and no allowlist env is set.
    let mut client = retry(|| TcpStream::connect(proxy).ok(), "ssl proxy accept");
    write!(
        client,
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
    )
    .expect("write");
    let resp = read_http_response(&mut client);
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.contains("403"),
        "offline policy blocks public hosts: {text:?}"
    );
}

/// Raw echo upstream for the obfuscated proxy and CONNECT tunnels.
fn spawn_echo_upstream() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("echo bind");
    let addr = listener.local_addr().expect("addr").to_string();
    thread::spawn(move || {
        for client in listener.incoming() {
            let mut s = match client {
                Ok(s) => s,
                Err(_) => continue,
            };
            thread::spawn(move || {
                let mut other = s.try_clone().expect("clone");
                let _ = std::io::copy(&mut s, &mut other);
            });
        }
    });
    addr
}

fn frame_send(stream: &mut TcpStream, frame: &[u8]) {
    stream
        .write_all(&(frame.len() as u32).to_be_bytes())
        .expect("len");
    stream.write_all(frame).expect("frame");
}

fn frame_recv(stream: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).expect("len");
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    stream.read_exact(&mut buf).expect("body");
    buf
}

#[test]
fn obfs_proxy_roundtrips() {
    use omnisec_net_obfs::Obfuscator;

    let upstream = spawn_echo_upstream();
    let proxy = "127.0.0.1:18082";
    let sink = new_sink();
    let s = sink.clone();
    let key = [7u8; 32];
    let up = upstream.clone();
    thread::spawn(move || {
        let _ = omnisec_mitm::obfs::run_obfuscated_proxy(proxy, &up, key, s);
    });

    let obfs = Obfuscator::new(&key);
    let mut client = retry(|| TcpStream::connect(proxy).ok(), "obfs proxy accept");
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");

    let cipher = obfs.obfuscate(b"hello-proxy", 16, 128).expect("obfuscate");
    frame_send(&mut client, &cipher);
    let reply_cipher = frame_recv(&mut client);
    let plain = obfs.deobfuscate(&reply_cipher).expect("deobfuscate");
    assert_eq!(plain, b"hello-proxy");

    // Flow summary is pushed when the relay thread finishes: close our end
    // (unblocks the proxy's frame read) and wait for the capture.
    drop(client);
    retry(
        || {
            let guard = sink.lock().ok()?;
            (!guard.flow_summaries.is_empty()).then(|| ())
        },
        "flow capture",
    );
    let guard = sink.lock().expect("sink");
    assert!(
        guard
            .flow_summaries
            .iter()
            .any(|f| f.bytes >= b"hello-proxy".len() as u64)
    );
}

#[test]
fn connect_tunnel_relays_bytes() {
    let upstream = spawn_echo_upstream();
    let proxy = "127.0.0.1:18085";
    let sink = new_sink();
    let s = sink.clone();
    thread::spawn(move || {
        let _ = omnisec_mitm::ssl::run_ssl_strip_proxy(proxy, s);
    });

    let mut client = retry(|| TcpStream::connect(proxy).ok(), "ssl proxy accept");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    write!(
        client,
        "CONNECT {upstream} HTTP/1.1\r\nHost: {upstream}\r\n\r\n"
    )
    .expect("connect");
    let mut head = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = client.read(&mut tmp).expect("read 200");
        head.extend_from_slice(&tmp[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "tunnel established: {head:?}"
    );

    // A well-formed (but unparseable) TLS record completes the record read
    // without the 5s timeout; capture is skipped, relay proceeds. Real
    // ClientHello parsing is covered by the tls unit tests.
    let record = [0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5];
    client.write_all(&record).expect("record");
    // The record itself is relayed verbatim through the tunnel (echoed back).
    let mut record_echo = [0u8; 10];
    client.read_exact(&mut record_echo).expect("record echo");
    assert_eq!(&record_echo, &record);
    // Opaque bytes round-trip through the tunnel (echoed by upstream).
    client.write_all(b"ping-tunnel").expect("write");
    let mut echo = [0u8; 11];
    client.read_exact(&mut echo).expect("echo");
    assert_eq!(&echo, b"ping-tunnel");
}
