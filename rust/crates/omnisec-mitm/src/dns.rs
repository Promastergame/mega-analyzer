use std::net::{Ipv4Addr, UdpSocket};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::capture::{DnsQueryCapture, MitmCapture};

const DNS_MAX_PACKET: usize = 4096;

/// Runs a UDP DNS server that spoofs A responses for `target_domain` to `spoofed_ip`.
///
/// Non-matching queries are refused by default to preserve offline/lab isolation. If
/// forwarding is explicitly needed, set `OMNISEC_MITM_DNS_UPSTREAM=host:port` in the
/// process environment.
///
/// Every spoofed A response is also appended to `capture_sink` so callers can
/// accumulate real DNS observations instead of only reading `omnisec_log::debug!` output.
///
/// Blocking std version: one thread serves the socket loop.
pub fn run_dns_spoof_server(
    listen_addr: &str,
    target_domain: &str,
    spoofed_ip: &str,
    capture_sink: Arc<Mutex<MitmCapture>>,
) -> crate::MitmResult<()> {
    omnisec_log::info!(
        "DNS Spoofing Server starting on {} (Target: {} -> {})",
        listen_addr,
        target_domain,
        spoofed_ip
    );

    let spoof_ip_addr = Ipv4Addr::from_str(spoofed_ip).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid spoofed IPv4 address {spoofed_ip:?}: {e}"),
        )
    })?;
    let socket = UdpSocket::bind(listen_addr)?;
    let upstream = std::env::var("OMNISEC_MITM_DNS_UPSTREAM")
        .ok()
        .filter(|s| !s.trim().is_empty());

    let mut buf = [0u8; DNS_MAX_PACKET];
    loop {
        let (len, src_addr) = match socket.recv_from(&mut buf) {
            Ok(res) => res,
            Err(e) => {
                omnisec_log::warn!("Failed to read from DNS socket: {}", e);
                continue;
            }
        };

        if len < 12 {
            continue; // Too small to be a DNS packet
        }

        let packet = &buf[..len];
        let Some(question) = parse_first_question(packet) else {
            let _ = socket.send_to(&build_refused(packet), src_addr);
            continue;
        };

        if domain_matches(&question.name, target_domain) {
            omnisec_log::info!("DNS Spoofing: {} -> {}", question.name, spoof_ip_addr);

            if question.qtype == 1 && question.qclass == 1 {
                let response = build_a_response(packet, question.q_section_end, spoof_ip_addr);
                let _ = socket.send_to(&response, src_addr);

                let capture = DnsQueryCapture {
                    timestamp_ms: unix_epoch_ms(),
                    query_name: question.name.clone(),
                    record_type: question.qtype,
                    response_ips: vec![spoof_ip_addr],
                };
                omnisec_log::debug!(?capture, "dns query captured");
                if let Ok(mut sink) = capture_sink.lock() {
                    sink.dns_queries.push(capture);
                }
            } else {
                // Matched domain, unsupported qtype: NOERROR with no answer keeps protocol valid.
                let response = build_empty_noerror(packet, question.q_section_end);
                let _ = socket.send_to(&response, src_addr);
            }
        } else if let Some(upstream_addr) = upstream.as_deref() {
            if let Ok(resp) = forward_dns(packet, upstream_addr) {
                let _ = socket.send_to(&resp, src_addr);
            } else {
                let _ = socket.send_to(&build_refused(packet), src_addr);
            }
        } else {
            // Explicit offline-by-default behavior: do not leak DNS queries to the internet.
            let _ = socket.send_to(&build_refused(packet), src_addr);
        }
    }
}

fn unix_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct Question {
    name: String,
    qtype: u16,
    qclass: u16,
    q_section_end: usize,
}

fn parse_first_question(packet: &[u8]) -> Option<Question> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut offset = 12;
    let mut labels = Vec::new();

    while offset < packet.len() {
        let label_len = packet[offset] as usize;
        if label_len == 0 {
            offset += 1; // root label
            break;
        }
        if label_len & 0xC0 == 0xC0 {
            // Compression pointer in the question is unusual but legal enough to skip.
            if offset + 1 >= packet.len() {
                return None;
            }
            offset += 2;
            break;
        }
        if label_len > 63 {
            return None;
        }

        offset += 1;
        if offset + label_len > packet.len() {
            return None;
        }

        let label = &packet[offset..offset + label_len];
        let s = std::str::from_utf8(label).ok()?;
        labels.push(s.to_ascii_lowercase());

        offset += label_len;
    }

    if offset + 4 > packet.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let qclass = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    let q_section_end = offset + 4;

    Some(Question {
        name: labels.join("."),
        qtype,
        qclass,
        q_section_end,
    })
}

fn normalize_domain(d: &str) -> String {
    d.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn domain_matches(domain: &str, target: &str) -> bool {
    let domain = normalize_domain(domain);
    let target = normalize_domain(target);
    if domain.is_empty() || target.is_empty() {
        return false;
    }
    domain == target || domain.ends_with(&format!(".{target}"))
}

fn response_header(packet: &[u8], ancount: u16, rcode: u8) -> Vec<u8> {
    let id: &[u8] = if packet.len() >= 2 {
        &packet[0..2]
    } else {
        &[0, 0]
    };
    let rd = if packet.len() >= 3 {
        packet[2] & 0x01
    } else {
        0
    };
    let flags1 = 0x80 | rd; // QR + preserve RD
    let flags2 = (rcode & 0x0f) | 0x80; // RA + RCODE

    let mut response = Vec::with_capacity(512);
    response.extend_from_slice(id); // ID
    response.extend_from_slice(&[flags1, flags2]); // Flags
    response.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    response.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    response
}

fn build_a_response(packet: &[u8], q_section_end: usize, spoof_ip_addr: Ipv4Addr) -> Vec<u8> {
    let mut response = response_header(packet, 1, 0);
    response.extend_from_slice(&packet[12..q_section_end]);

    response.extend_from_slice(&[0xC0, 0x0C]); // Name pointer
    response.extend_from_slice(&[0x00, 0x01]); // Type A
    response.extend_from_slice(&[0x00, 0x01]); // Class IN
    response.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL
    response.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
    response.extend_from_slice(&spoof_ip_addr.octets()); // RDATA
    response
}

fn build_empty_noerror(packet: &[u8], q_section_end: usize) -> Vec<u8> {
    let mut response = response_header(packet, 0, 0);
    if packet.len() >= q_section_end && q_section_end >= 12 {
        response.extend_from_slice(&packet[12..q_section_end]);
    }
    response
}

fn build_refused(packet: &[u8]) -> Vec<u8> {
    let q_section_end = parse_first_question(packet)
        .map(|q| q.q_section_end)
        .unwrap_or(12.min(packet.len()));
    let mut response = response_header(packet, 0, 5); // REFUSED
    if packet.len() >= q_section_end && q_section_end >= 12 {
        response.extend_from_slice(&packet[12..q_section_end]);
    }
    response
}

fn forward_dns(query: &[u8], upstream_addr: &str) -> crate::MitmResult<Vec<u8>> {
    let upstream = UdpSocket::bind("0.0.0.0:0")?;
    upstream.connect(upstream_addr)?;
    // Mirror the old 2s tokio timeout with a blocking read timeout; any
    // failure (timeout or error) maps to the same call-site error.
    upstream.set_read_timeout(Some(Duration::from_secs(2)))?;
    upstream.send(query)?;

    let mut buf = vec![0u8; DNS_MAX_PACKET];
    match upstream.recv(&mut buf) {
        Ok(n) => {
            buf.truncate(n);
            Ok(buf)
        }
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "DNS upstream timeout or error",
        )
        .into()),
    }
}
