use omnisec_net_obfs::Obfuscator;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::capture::{FlowSummaryCapture, MitmCapture};

fn unix_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

const MAX_OBFS_FRAME_LEN: usize = 1024 * 1024;

/// Starts a proxy that receives length-prefixed obfuscated TCP frames,
/// deobfuscates the payload, and forwards it to the target upstream server.
///
/// When a flow completes its `FlowSummaryCapture` is appended to `capture_sink`
/// so callers can accumulate real network flow observations.
///
/// Blocking std version: one thread per client, plus two relay threads
/// (client→upstream inline in the client thread, upstream→client spawned).
pub fn run_obfuscated_proxy(
    listen_addr: &str,
    upstream_addr: &str,
    key: [u8; 32],
    capture_sink: Arc<Mutex<MitmCapture>>,
) -> crate::MitmResult<()> {
    omnisec_log::info!(
        "Obfuscated Proxy starting on {} -> {}",
        listen_addr,
        upstream_addr
    );

    if !addr_allowed(upstream_addr) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("upstream {upstream_addr} is not allowed by offline/allowlist policy"),
        )
        .into());
    }

    let listener = TcpListener::bind(listen_addr)?;
    let obfuscator = Arc::new(Obfuscator::new(&key));

    let upstream_addr = upstream_addr.to_string();

    for client in listener.incoming() {
        let client_stream = match client {
            Ok(s) => s,
            Err(e) => {
                omnisec_log::warn!("Failed to accept client: {}", e);
                continue;
            }
        };

        let upstream_addr = upstream_addr.clone();
        let obfs = obfuscator.clone();
        let sink = capture_sink.clone();

        thread::spawn(move || {
            let client_addr = client_stream.peer_addr().ok();

            let upstream = match TcpStream::connect(&upstream_addr) {
                Ok(s) => s,
                Err(e) => {
                    omnisec_log::warn!("Failed to connect to upstream {}: {}", upstream_addr, e);
                    return;
                }
            };
            let upstream_peer_addr = upstream.peer_addr().ok();

            let started_at = Instant::now();
            let bytes_transferred = Arc::new(AtomicU64::new(0));

            let mut client_read = match client_stream.try_clone() {
                Ok(s) => s,
                Err(e) => {
                    omnisec_log::warn!("Failed to split client stream: {}", e);
                    return;
                }
            };
            let mut client_write = client_stream;
            let mut up_read = match upstream.try_clone() {
                Ok(s) => s,
                Err(e) => {
                    omnisec_log::warn!("Failed to split upstream stream: {}", e);
                    return;
                }
            };
            let mut up_write = upstream;

            let obfs_c = obfs.clone();
            let bytes_c2u = bytes_transferred.clone();
            // Client (length-prefixed Obfuscated) -> Upstream (Plain)
            let c2u = thread::spawn(move || {
                loop {
                    let frame = match read_frame(&mut client_read) {
                        Ok(Some(frame)) => frame,
                        Ok(None) => break,
                        Err(e) => {
                            omnisec_log::warn!("Obfuscated frame read error: {}", e);
                            break;
                        }
                    };
                    match obfs_c.deobfuscate(&frame) {
                        Ok(plain) => {
                            bytes_c2u.fetch_add(plain.len() as u64, Ordering::Relaxed);
                            if up_write.write_all(&plain).is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            omnisec_log::warn!("Deobfuscation error: {}", e);
                            break;
                        }
                    }
                }
                let _ = up_write.shutdown(Shutdown::Write);
            });

            let bytes_u2c = bytes_transferred.clone();
            // Upstream (Plain) -> Client (length-prefixed Obfuscated)
            // Runs inline; the c2u thread is joined below.
            let mut buf = vec![0u8; 65535];
            loop {
                let n = match up_read.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                match obfs.obfuscate(&buf[..n], 16, 128) {
                    Ok(cipher) => {
                        bytes_u2c.fetch_add(n as u64, Ordering::Relaxed);
                        if write_frame(&mut client_write, &cipher).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        omnisec_log::warn!("Obfuscation error: {}", e);
                        break;
                    }
                }
            }
            let _ = client_write.shutdown(Shutdown::Write);

            let _ = c2u.join();

            if let (Some(src), Some(dst)) = (client_addr, upstream_peer_addr) {
                let capture = FlowSummaryCapture {
                    timestamp_ms: unix_epoch_ms(),
                    src_ip: src.ip(),
                    src_port: src.port(),
                    dst_ip: dst.ip(),
                    dst_port: dst.port(),
                    bytes: bytes_transferred.load(Ordering::Relaxed),
                    duration_ms: started_at.elapsed().as_millis() as u64,
                    protocol: "tcp".to_string(),
                };
                omnisec_log::debug!(?capture, "flow summary captured");
                if let Ok(mut sink) = sink.lock() {
                    sink.flow_summaries.push(capture);
                }
            }
        });
    }
    // `incoming()` only ends on accept failure; keep the same
    // never-returning server contract as the other runners.
    #[allow(unreachable_code)]
    Ok(())
}

fn addr_allowed(addr: &str) -> bool {
    let host = addr
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(addr)
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

fn read_frame<R>(reader: &mut R) -> crate::MitmResult<Option<Vec<u8>>>
where
    R: Read,
{
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_OBFS_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid obfuscated frame length: {len}"),
        )
        .into());
    }
    let mut frame = vec![0u8; len];
    reader.read_exact(&mut frame)?;
    Ok(Some(frame))
}

fn write_frame<W>(writer: &mut W, frame: &[u8]) -> crate::MitmResult<()>
where
    W: Write,
{
    if frame.is_empty() || frame.len() > MAX_OBFS_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid obfuscated frame length: {}", frame.len()),
        )
        .into());
    }
    writer.write_all(&(frame.len() as u32).to_be_bytes())?;
    writer.write_all(frame)?;
    Ok(())
}
