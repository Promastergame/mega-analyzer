//! A dependency-free reader and writer for the classic `libpcap` file format
//! (`.pcap`), plus the L2→L4 decode that turns each record into a [`Frame`].
//!
//! We parse the format ourselves rather than linking `libpcap` so the analyzer
//! keeps its offline, single-static-binary guarantee. Both the little- and
//! big-endian magic numbers and the microsecond/nanosecond timestamp variants
//! are handled. Link types Ethernet, raw IPv4/IPv6, BSD loopback (NULL) and
//! Linux "cooked" (SLL) are decoded; anything else is skipped rather than
//! aborting the whole read, mirroring the "never wedge on one bad record"
//! philosophy already in `netproxy.relayFramed`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::frame::{FlowKey, Frame, TcpFlags, Transport};

/// Errors that can arise while reading a `.pcap` stream.
#[derive(Debug, PartialEq, Eq)]
pub enum PcapError {
    /// The global header was shorter than 24 bytes.
    TruncatedHeader(usize),
    /// The magic number matched neither endianness nor the nanosecond variants.
    BadMagic(u32),
}

impl std::fmt::Display for PcapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedHeader(n) => {
                write!(f, "pcap: truncated global header ({n} bytes, need 24)")
            }
            Self::BadMagic(magic) => write!(f, "pcap: unrecognised magic number {magic:#010x}"),
        }
    }
}

impl std::error::Error for PcapError {}

/// The subset of pcap link-layer header types we decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// `LINKTYPE_ETHERNET` (1).
    Ethernet,
    /// `LINKTYPE_RAW` (101) — the packet begins at the IP header.
    Raw,
    /// `LINKTYPE_NULL` (0) — 4-byte BSD loopback family header.
    Null,
    /// `LINKTYPE_LINUX_SLL` (113) — 16-byte Linux "cooked" header.
    LinuxSll,
    /// Any other link type; records are skipped.
    Unsupported(u32),
}

impl LinkType {
    fn from_u32(v: u32) -> LinkType {
        match v {
            1 => LinkType::Ethernet,
            101 => LinkType::Raw,
            0 => LinkType::Null,
            113 => LinkType::LinuxSll,
            other => LinkType::Unsupported(other),
        }
    }
}

/// A streaming reader over the records of a `.pcap` buffer.
///
/// The whole buffer is held as a `Vec<u8>`, so every payload a record decodes
/// into is a zero-copy slice of it rather than a fresh allocation.
pub struct PcapReader {
    data: Vec<u8>,
    pos: usize,
    little_endian: bool,
    nanos: bool,
    link_type: LinkType,
}

impl PcapReader {
    /// Parses the 24-byte global header and positions the reader at the first
    /// record. Accepts both endiannesses and the `usec`/`nsec` magic variants.
    pub fn new(data: impl Into<Vec<u8>>) -> Result<PcapReader, PcapError> {
        let data = data.into();
        if data.len() < 24 {
            return Err(PcapError::TruncatedHeader(data.len()));
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let (little_endian, nanos) = match magic {
            0xa1b2_c3d4 => (true, false),
            0xd4c3_b2a1 => (false, false),
            0xa1b2_3c4d => (true, true),
            0x4d3c_b2a1 => (false, true),
            other => return Err(PcapError::BadMagic(other)),
        };
        let read_u32 = |b: &[u8]| {
            if little_endian {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            } else {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]])
            }
        };
        let link_type = LinkType::from_u32(read_u32(&data[20..24]));
        Ok(PcapReader {
            data,
            pos: 24,
            little_endian,
            nanos,
            link_type,
        })
    }

    /// The link-layer type declared in the global header.
    #[must_use]
    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    fn read_u32(&self, off: usize) -> u32 {
        let b = &self.data[off..off + 4];
        if self.little_endian {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }
    }

    /// Yields the next `(timestamp_us, link_layer_bytes)` record, or `None` at
    /// end of stream. A truncated trailing record is treated as end of stream.
    fn next_record(&mut self) -> Option<(u64, Vec<u8>)> {
        if self.pos + 16 > self.data.len() {
            return None;
        }
        let ts_sec = u64::from(self.read_u32(self.pos));
        let ts_frac = u64::from(self.read_u32(self.pos + 4));
        let incl_len = self.read_u32(self.pos + 8) as usize;
        // orig_len at +12 is ignored; we only have incl_len bytes.
        let data_start = self.pos + 16;
        let data_end = data_start.checked_add(incl_len)?;
        if data_end > self.data.len() {
            return None; // truncated final record
        }
        let ts_us = if self.nanos {
            ts_sec * 1_000_000 + ts_frac / 1_000
        } else {
            ts_sec * 1_000_000 + ts_frac
        };
        let slice = self.data[data_start..data_end].to_vec();
        self.pos = data_end;
        Some((ts_us, slice))
    }

    /// Decodes every record into a [`Frame`], skipping records whose link type
    /// or L3/L4 headers we don't understand.
    pub fn frames(mut self) -> Vec<Frame> {
        let mut out = Vec::new();
        let link = self.link_type;
        while let Some((ts_us, pkt)) = self.next_record() {
            if let Some(frame) = decode_link(link, ts_us, &pkt) {
                out.push(frame);
            }
        }
        out
    }
}

/// Convenience: read all decodable frames from an in-memory `.pcap` buffer.
pub fn read_frames(data: impl Into<Vec<u8>>) -> Result<Vec<Frame>, PcapError> {
    Ok(PcapReader::new(data)?.frames())
}

/// Strips the link-layer header and dispatches to IP decoding.
fn decode_link(link: LinkType, ts_us: u64, pkt: &[u8]) -> Option<Frame> {
    match link {
        LinkType::Ethernet => {
            if pkt.len() < 14 {
                return None;
            }
            let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
            match ethertype {
                0x0800 => decode_ipv4(ts_us, pkt, 14),
                0x86dd => decode_ipv6(ts_us, pkt, 14),
                0x8100 => {
                    // 802.1Q VLAN tag: 4 bytes, then a real ethertype.
                    if pkt.len() < 18 {
                        return None;
                    }
                    match u16::from_be_bytes([pkt[16], pkt[17]]) {
                        0x0800 => decode_ipv4(ts_us, pkt, 18),
                        0x86dd => decode_ipv6(ts_us, pkt, 18),
                        _ => None,
                    }
                }
                _ => None,
            }
        }
        LinkType::Raw => match pkt.first().map(|b| b >> 4) {
            Some(4) => decode_ipv4(ts_us, pkt, 0),
            Some(6) => decode_ipv6(ts_us, pkt, 0),
            _ => None,
        },
        LinkType::Null => {
            if pkt.len() < 4 {
                return None;
            }
            // BSD family: 2 (AF_INET) native-endian, 24/28/30 (AF_INET6).
            let fam_le = u32::from_le_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
            let fam_be = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
            match (fam_le, fam_be) {
                (2, _) | (_, 2) => decode_ipv4(ts_us, pkt, 4),
                (24 | 28 | 30, _) | (_, 24 | 28 | 30) => decode_ipv6(ts_us, pkt, 4),
                _ => None,
            }
        }
        LinkType::LinuxSll => {
            if pkt.len() < 16 {
                return None;
            }
            match u16::from_be_bytes([pkt[14], pkt[15]]) {
                0x0800 => decode_ipv4(ts_us, pkt, 16),
                0x86dd => decode_ipv6(ts_us, pkt, 16),
                _ => None,
            }
        }
        LinkType::Unsupported(_) => None,
    }
}

fn decode_ipv4(ts_us: u64, pkt: &[u8], off: usize) -> Option<Frame> {
    let hdr = pkt.get(off..off + 20)?;
    let ihl = ((hdr[0] & 0x0f) as usize) * 4;
    if ihl < 20 {
        return None;
    }
    let total_len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    let proto = hdr[9];
    let src = IpAddr::V4(Ipv4Addr::new(hdr[12], hdr[13], hdr[14], hdr[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(hdr[16], hdr[17], hdr[18], hdr[19]));
    let l4_start = off + ihl;
    // total_len counts from the IP header; clamp to what we actually captured.
    let l4_end = (off + total_len).min(pkt.len());
    if l4_end < l4_start {
        return None;
    }
    decode_l4(ts_us, pkt, proto, src, dst, l4_start, l4_end)
}

fn decode_ipv6(ts_us: u64, pkt: &[u8], off: usize) -> Option<Frame> {
    let hdr = pkt.get(off..off + 40)?;
    let payload_len = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
    let next_header = hdr[6];
    let mut src_octets = [0u8; 16];
    let mut dst_octets = [0u8; 16];
    src_octets.copy_from_slice(&hdr[8..24]);
    dst_octets.copy_from_slice(&hdr[24..40]);
    let src = IpAddr::V6(Ipv6Addr::from(src_octets));
    let dst = IpAddr::V6(Ipv6Addr::from(dst_octets));
    let l4_start = off + 40;
    let l4_end = (l4_start + payload_len).min(pkt.len());
    if l4_end < l4_start {
        return None;
    }
    // We do not walk IPv6 extension headers; TCP/UDP directly is the common case.
    decode_l4(ts_us, pkt, next_header, src, dst, l4_start, l4_end)
}

#[allow(clippy::too_many_arguments)]
fn decode_l4(
    ts_us: u64,
    pkt: &[u8],
    proto: u8,
    src: IpAddr,
    dst: IpAddr,
    l4_start: usize,
    l4_end: usize,
) -> Option<Frame> {
    let seg = pkt.get(l4_start..l4_end)?;
    match proto {
        6 => {
            if seg.len() < 20 {
                return None;
            }
            let src_port = u16::from_be_bytes([seg[0], seg[1]]);
            let dst_port = u16::from_be_bytes([seg[2], seg[3]]);
            let seq = u32::from_be_bytes([seg[4], seg[5], seg[6], seg[7]]);
            let data_off = ((seg[12] >> 4) as usize) * 4;
            if data_off < 20 || data_off > seg.len() {
                return None;
            }
            let flags = TcpFlags::from_bits(seg[13]);
            let payload = pkt[l4_start + data_off..l4_end].to_vec();
            let (flow, direction) =
                FlowKey::from_endpoints(Transport::Tcp, src, src_port, dst, dst_port);
            Some(Frame {
                flow,
                direction,
                src_ip: src,
                src_port,
                dst_ip: dst,
                dst_port,
                timestamp_us: ts_us,
                tcp_seq: seq,
                tcp_flags: flags,
                payload,
            })
        }
        17 => {
            if seg.len() < 8 {
                return None;
            }
            let src_port = u16::from_be_bytes([seg[0], seg[1]]);
            let dst_port = u16::from_be_bytes([seg[2], seg[3]]);
            let udp_len = u16::from_be_bytes([seg[4], seg[5]]) as usize;
            let payload_end = (l4_start + udp_len).min(l4_end);
            let payload = pkt[(l4_start + 8).min(payload_end)..payload_end].to_vec();
            let (flow, direction) =
                FlowKey::from_endpoints(Transport::Udp, src, src_port, dst, dst_port);
            Some(Frame {
                flow,
                direction,
                src_ip: src,
                src_port,
                dst_ip: dst,
                dst_port,
                timestamp_us: ts_us,
                tcp_seq: 0,
                tcp_flags: TcpFlags::default(),
                payload,
            })
        }
        other => {
            // Non-TCP/UDP: record the flow with ports 0 so higher layers can
            // still see that an L3 conversation happened.
            let (flow, direction) =
                FlowKey::from_endpoints(Transport::Other(other), src, 0, dst, 0);
            Some(Frame {
                flow,
                direction,
                src_ip: src,
                src_port: 0,
                dst_ip: dst,
                dst_port: 0,
                timestamp_us: ts_us,
                tcp_seq: 0,
                tcp_flags: TcpFlags::default(),
                payload: pkt[l4_start..l4_end].to_vec(),
            })
        }
    }
}

// ─── Writer ────────────────────────────────────────────────────────────────

/// A minimal `.pcap` writer used for round-trip testing and for persisting
/// synthesised captures. It emits little-endian, microsecond-resolution files
/// with the given link type.
pub struct PcapWriter {
    buf: Vec<u8>,
}

impl PcapWriter {
    /// Starts a writer, emitting the 24-byte global header for `link`.
    #[must_use]
    pub fn new(link: LinkType) -> PcapWriter {
        let linktype: u32 = match link {
            LinkType::Ethernet => 1,
            LinkType::Raw => 101,
            LinkType::Null => 0,
            LinkType::LinuxSll => 113,
            LinkType::Unsupported(v) => v,
        };
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes()); // magic (usec, LE)
        buf.extend_from_slice(&2u16.to_le_bytes()); // version major
        buf.extend_from_slice(&4u16.to_le_bytes()); // version minor
        buf.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        buf.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        buf.extend_from_slice(&linktype.to_le_bytes());
        PcapWriter { buf }
    }

    /// Appends one record carrying the given link-layer bytes.
    pub fn write_packet(&mut self, ts_us: u64, link_bytes: &[u8]) {
        let ts_sec = (ts_us / 1_000_000) as u32;
        let ts_frac = (ts_us % 1_000_000) as u32;
        self.buf.extend_from_slice(&ts_sec.to_le_bytes());
        self.buf.extend_from_slice(&ts_frac.to_le_bytes());
        self.buf
            .extend_from_slice(&(link_bytes.len() as u32).to_le_bytes());
        self.buf
            .extend_from_slice(&(link_bytes.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(link_bytes);
    }

    /// Consumes the writer, returning the encoded `.pcap` bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Builds a raw-IP (LINKTYPE_RAW) IPv4/TCP packet with the given payload.
    fn ipv4_tcp(
        src: Ipv4Addr,
        sp: u16,
        dst: Ipv4Addr,
        dp: u16,
        seq: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut p = Vec::with_capacity(total);
        // IPv4 header (IHL=5, no options).
        p.push(0x45);
        p.push(0);
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes()); // id
        p.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
        p.push(64); // ttl
        p.push(6); // proto TCP
        p.extend_from_slice(&0u16.to_be_bytes()); // checksum (ignored)
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        // TCP header (data offset = 5).
        p.extend_from_slice(&sp.to_be_bytes());
        p.extend_from_slice(&dp.to_be_bytes());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes()); // ack
        p.push(0x50); // data offset 5<<4
        p.push(flags);
        p.extend_from_slice(&65535u16.to_be_bytes()); // window
        p.extend_from_slice(&0u16.to_be_bytes()); // checksum
        p.extend_from_slice(&0u16.to_be_bytes()); // urg
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn round_trips_a_raw_ipv4_tcp_packet() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(93, 184, 216, 34);
        let pkt = ipv4_tcp(src, 51000, dst, 443, 1000, 0x18, b"hello");

        let mut w = PcapWriter::new(LinkType::Raw);
        w.write_packet(1_500_000, &pkt);
        let bytes = w.into_bytes();

        let frames = read_frames(bytes).expect("read");
        assert_eq!(frames.len(), 1);
        let f = &frames[0];
        assert_eq!(f.src_ip, IpAddr::V4(src));
        assert_eq!(f.dst_port, 443);
        assert_eq!(f.tcp_seq, 1000);
        assert!(f.tcp_flags.psh && f.tcp_flags.ack);
        assert_eq!(&f.payload[..], b"hello");
        assert_eq!(f.timestamp_us, 1_500_000);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut junk = vec![0u8; 24];
        junk[0] = 0xff;
        assert!(matches!(read_frames(junk), Err(PcapError::BadMagic(_))));
    }

    #[test]
    fn truncated_header_is_an_error() {
        assert_eq!(
            read_frames(vec![0u8; 10]),
            Err(PcapError::TruncatedHeader(10))
        );
    }

    #[test]
    fn truncated_final_record_is_skipped_not_fatal() {
        let src = Ipv4Addr::new(1, 2, 3, 4);
        let dst = Ipv4Addr::new(5, 6, 7, 8);
        let pkt = ipv4_tcp(src, 1, dst, 2, 0, 0x02, b"");
        let mut w = PcapWriter::new(LinkType::Raw);
        w.write_packet(1, &pkt);
        let mut bytes = w.into_bytes();
        // Append a partial record header — must be ignored.
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        let frames = read_frames(bytes).expect("read");
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn both_directions_share_a_flow_key() {
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let b = Ipv4Addr::new(20, 0, 0, 1);
        let c2s = ipv4_tcp(a, 5000, b, 80, 1, 0x02, b"");
        let s2c = ipv4_tcp(b, 80, a, 5000, 1, 0x12, b"");
        let mut w = PcapWriter::new(LinkType::Raw);
        w.write_packet(1, &c2s);
        w.write_packet(2, &s2c);
        let frames = read_frames(w.into_bytes()).expect("read");
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].flow, frames[1].flow);
        assert_ne!(frames[0].direction, frames[1].direction);
    }
}
