//! Flow tracking, TCP stream reassembly, and session reconstruction.
//!
//! Frames arrive out of order, retransmitted, and interleaved across many
//! conversations. This module keeps a table keyed by [`FlowKey`] and, for TCP,
//! reassembles each direction's byte stream in sequence-number order —
//! trimming overlaps from retransmissions and holding out-of-order segments
//! until the gap ahead of them fills. UDP "streams" are simply the datagram
//! payloads concatenated in arrival order. The result is a per-flow
//! [`Session`]: the client→server and server→client byte streams a higher
//! layer can hand to the HTTP/TLS/WebSocket decoders without ever touching a
//! raw packet.

use std::collections::{BTreeMap, HashMap};

use omnisec_json::{FromJson, ToJson};

use crate::classify::{Protocol, classify, tls_sni};
use crate::frame::{Direction, FlowKey, Frame, Transport};

/// Compares TCP sequence numbers with wraparound (RFC 1982 serial arithmetic).
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn dir_index(d: Direction) -> usize {
    match d {
        Direction::ClientToServer => 0,
        Direction::ServerToClient => 1,
    }
}

/// Reassembles one direction of a TCP stream (or accumulates a UDP one).
#[derive(Debug, Default)]
pub struct DirectionalReassembler {
    next_seq: Option<u32>,
    pending: BTreeMap<u32, Vec<u8>>,
    stream: Vec<u8>,
    gaps: usize,
}

impl DirectionalReassembler {
    /// Records the initial sequence number from a SYN so the first data byte
    /// (ISN+1) lands at stream offset 0.
    pub fn note_syn(&mut self, isn: u32) {
        if self.next_seq.is_none() {
            self.next_seq = Some(isn.wrapping_add(1));
        }
    }

    /// Feeds one TCP segment. Overlapping bytes from retransmissions are
    /// trimmed; segments ahead of the current position are buffered until the
    /// intervening gap is filled.
    pub fn push_tcp(&mut self, seq: u32, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if self.next_seq.is_none() {
            // Mid-stream capture with no SYN: anchor at the first data seq.
            self.next_seq = Some(seq);
        }
        let next = self.next_seq.unwrap();
        if seq_lt(seq, next) {
            // Wholly or partly retransmitted. Trim the already-seen prefix.
            let overlap = next.wrapping_sub(seq) as usize;
            if overlap < data.len() {
                self.append(&data[overlap..]);
            }
        } else if seq == next {
            self.append(data);
        } else {
            // Future segment: buffer and try to drain once the gap fills.
            self.pending.entry(seq).or_insert_with(|| data.to_vec());
        }
        self.drain_pending();
    }

    /// Appends a UDP datagram payload in arrival order.
    pub fn push_udp(&mut self, data: &[u8]) {
        self.stream.extend_from_slice(data);
    }

    fn append(&mut self, data: &[u8]) {
        self.stream.extend_from_slice(data);
        let n = self.next_seq.get_or_insert(0);
        *n = n.wrapping_add(data.len() as u32);
    }

    fn drain_pending(&mut self) {
        loop {
            let next = match self.next_seq {
                Some(n) => n,
                None => return,
            };
            // Find the earliest buffered segment that starts at or before `next`.
            let key = self.pending.keys().copied().find(|&k| !seq_lt(next, k)); // k <= next
            let Some(k) = key else { break };
            let data = self.pending.remove(&k).unwrap();
            let overlap = next.wrapping_sub(k) as usize;
            if overlap < data.len() {
                self.append(&data[overlap..]);
            }
        }
    }

    /// The contiguous reassembled bytes for this direction.
    #[must_use]
    pub fn stream(&self) -> &[u8] {
        &self.stream
    }

    /// Whether any out-of-order segments are still buffered (an unfilled gap).
    #[must_use]
    pub fn has_gap(&self) -> bool {
        !self.pending.is_empty()
    }
}

/// A single tracked transport flow with reassembled per-direction streams.
#[derive(Debug)]
pub struct Flow {
    /// Canonical 5-tuple.
    pub key: FlowKey,
    /// Earliest frame timestamp (Unix epoch microseconds).
    pub first_seen_us: u64,
    /// Latest frame timestamp.
    pub last_seen_us: u64,
    /// Total frames observed.
    pub packets: u64,
    /// Bytes observed client→server (payload only).
    pub bytes_c2s: u64,
    /// Bytes observed server→client.
    pub bytes_s2c: u64,
    /// Classified application protocol (best guess so far).
    pub protocol: Protocol,
    /// SNI extracted from a TLS ClientHello, if any.
    pub tls_sni: Option<String>,
    /// Set once a FIN or RST has been seen.
    pub finished: bool,
    saw_syn: bool,
    initiator: Option<Direction>,
    first_data_dir: Option<Direction>,
    reassemblers: [DirectionalReassembler; 2],
}

impl Flow {
    fn new(key: FlowKey, ts: u64) -> Flow {
        Flow {
            key,
            first_seen_us: ts,
            last_seen_us: ts,
            packets: 0,
            bytes_c2s: 0,
            bytes_s2c: 0,
            protocol: Protocol::Unknown,
            tls_sni: None,
            finished: false,
            saw_syn: false,
            initiator: None,
            first_data_dir: None,
            reassemblers: [
                DirectionalReassembler::default(),
                DirectionalReassembler::default(),
            ],
        }
    }

    /// The direction that carries client→server traffic: the SYN sender when
    /// known, else whichever side sent data first, else canonical order.
    #[must_use]
    pub fn client_direction(&self) -> Direction {
        self.initiator
            .or(self.first_data_dir)
            .unwrap_or(Direction::ClientToServer)
    }

    /// The reassembled client→server byte stream.
    #[must_use]
    pub fn client_stream(&self) -> &[u8] {
        self.reassemblers[dir_index(self.client_direction())].stream()
    }

    /// The reassembled server→client byte stream.
    #[must_use]
    pub fn server_stream(&self) -> &[u8] {
        self.reassemblers[dir_index(self.client_direction().flip())].stream()
    }

    fn observe(&mut self, frame: &Frame) {
        self.packets += 1;
        self.last_seen_us = self.last_seen_us.max(frame.timestamp_us);
        self.first_seen_us = self.first_seen_us.min(frame.timestamp_us);

        match frame.direction {
            Direction::ClientToServer => self.bytes_c2s += frame.len() as u64,
            Direction::ServerToClient => self.bytes_s2c += frame.len() as u64,
        }

        let idx = dir_index(frame.direction);
        if frame.flow.transport == Transport::Tcp {
            let f = &frame.tcp_flags;
            if f.syn && !f.ack {
                // A lone SYN identifies the connection initiator.
                self.saw_syn = true;
                self.initiator.get_or_insert(frame.direction);
            }
            if f.syn {
                self.reassemblers[idx].note_syn(frame.tcp_seq);
            }
            if f.fin || f.rst {
                self.finished = true;
            }
            if !frame.is_empty() {
                self.first_data_dir.get_or_insert(frame.direction);
                self.reassemblers[idx].push_tcp(frame.tcp_seq, &frame.payload);
            }
        } else if !frame.is_empty() {
            self.first_data_dir.get_or_insert(frame.direction);
            self.reassemblers[idx].push_udp(&frame.payload);
        }

        self.reclassify();
    }

    fn reclassify(&mut self) {
        // Prefer the client stream (requests, ClientHello, banners live there);
        // fall back to the server stream for server-first protocols.
        let client = self.client_stream();
        let mut proto = classify(client, self.key.transport);
        if proto == Protocol::Unknown {
            let server = self.server_stream();
            proto = classify(server, self.key.transport);
        }
        if proto != Protocol::Unknown {
            self.protocol = proto;
        }
        if self.protocol == Protocol::Tls && self.tls_sni.is_none() {
            self.tls_sni = tls_sni(self.client_stream());
        }
    }

    /// Snapshots this flow into an owned [`Session`].
    #[must_use]
    pub fn to_session(&self) -> Session {
        Session {
            key: self.key,
            protocol: self.protocol,
            tls_sni: self.tls_sni.clone(),
            first_seen_us: self.first_seen_us,
            last_seen_us: self.last_seen_us,
            packets: self.packets,
            bytes_c2s: self.bytes_c2s,
            bytes_s2c: self.bytes_s2c,
            finished: self.finished,
            client_stream: self.client_stream().to_vec(),
            server_stream: self.server_stream().to_vec(),
        }
    }
}

/// An owned, serialisable reconstruction of one conversation.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct Session {
    /// Canonical 5-tuple.
    pub key: FlowKey,
    /// Classified protocol.
    pub protocol: Protocol,
    /// TLS SNI, if observed.
    pub tls_sni: Option<String>,
    /// First frame timestamp.
    pub first_seen_us: u64,
    /// Last frame timestamp.
    pub last_seen_us: u64,
    /// Frame count.
    pub packets: u64,
    /// Client→server payload bytes.
    pub bytes_c2s: u64,
    /// Server→client payload bytes.
    pub bytes_s2c: u64,
    /// Whether the flow was cleanly torn down (FIN/RST seen).
    pub finished: bool,
    /// Reassembled client→server byte stream.
    #[json(with = "serde_bytes_vec")]
    pub client_stream: Vec<u8>,
    /// Reassembled server→client byte stream.
    #[json(with = "serde_bytes_vec")]
    pub server_stream: Vec<u8>,
}

/// Serialises a `Vec<u8>` as a base64 string so binary streams survive JSON.
mod serde_bytes_vec {
    use omnisec_json::{JsonError, JsonValue};

    pub fn to_json(v: &[u8]) -> JsonValue {
        JsonValue::Str(omnisec_json::b64_encode(v))
    }

    pub fn from_json(v: &JsonValue) -> Result<Vec<u8>, JsonError> {
        let s = v
            .as_str()
            .ok_or_else(|| JsonError("expected string".into()))?;
        omnisec_json::b64_decode(s)
    }
}

/// A table of tracked flows fed frame by frame.
#[derive(Debug, Default)]
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
}

impl FlowTable {
    /// Creates an empty flow table.
    #[must_use]
    pub fn new() -> FlowTable {
        FlowTable::default()
    }

    /// Feeds one decoded frame, creating or updating its flow.
    pub fn observe(&mut self, frame: &Frame) {
        let flow = self
            .flows
            .entry(frame.flow)
            .or_insert_with(|| Flow::new(frame.flow, frame.timestamp_us));
        flow.observe(frame);
    }

    /// Number of distinct flows tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Looks up a flow by key.
    #[must_use]
    pub fn get(&self, key: &FlowKey) -> Option<&Flow> {
        self.flows.get(key)
    }

    /// Iterates over all tracked flows.
    pub fn flows(&self) -> impl Iterator<Item = &Flow> {
        self.flows.values()
    }

    /// Snapshots every flow into an owned session, sorted by first-seen time
    /// then flow key so output is deterministic.
    #[must_use]
    pub fn sessions(&self) -> Vec<Session> {
        let mut out: Vec<Session> = self.flows.values().map(Flow::to_session).collect();
        out.sort_by(|a, b| {
            a.first_seen_us
                .cmp(&b.first_seen_us)
                .then_with(|| a.key.cmp(&b.key))
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::TcpFlags;
    use std::net::{IpAddr, Ipv4Addr};
    use std::vec::Vec;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn tcp_frame(
        src: IpAddr,
        sp: u16,
        dst: IpAddr,
        dp: u16,
        seq: u32,
        flags: TcpFlags,
        ts: u64,
        data: &[u8],
    ) -> Frame {
        let (flow, direction) = FlowKey::from_endpoints(Transport::Tcp, src, sp, dst, dp);
        Frame {
            flow,
            direction,
            src_ip: src,
            src_port: sp,
            dst_ip: dst,
            dst_port: dp,
            timestamp_us: ts,
            tcp_seq: seq,
            tcp_flags: flags,
            payload: data.to_vec(),
        }
    }

    #[test]
    fn reassembles_out_of_order_segments() {
        let mut r = DirectionalReassembler::default();
        r.note_syn(1000); // first data byte at seq 1001
        r.push_tcp(1006, b"world"); // future, buffered
        assert!(r.has_gap());
        r.push_tcp(1001, b"hello"); // fills the gap; both drain
        assert_eq!(r.stream(), b"helloworld");
        assert!(!r.has_gap());
    }

    #[test]
    fn trims_retransmitted_overlap() {
        let mut r = DirectionalReassembler::default();
        r.push_tcp(1, b"abcdef");
        r.push_tcp(4, b"defghi"); // overlaps "def", should append only "ghi"
        assert_eq!(r.stream(), b"abcdefghi");
    }

    #[test]
    fn reconstructs_http_request_session_and_classifies() {
        let client = ip(10, 0, 0, 9);
        let server = ip(93, 1, 2, 3);
        let syn = TcpFlags {
            syn: true,
            ..Default::default()
        };
        let psh = TcpFlags {
            psh: true,
            ack: true,
            ..Default::default()
        };

        let mut table = FlowTable::new();
        // Client SYN (ISN=100).
        table.observe(&tcp_frame(client, 5000, server, 80, 100, syn, 1, b""));
        // Server SYN-ACK (ISN=900).
        let synack = TcpFlags {
            syn: true,
            ack: true,
            ..Default::default()
        };
        table.observe(&tcp_frame(server, 80, client, 5000, 900, synack, 2, b""));
        // Client request (seq=101 = ISN+1).
        table.observe(&tcp_frame(
            client,
            5000,
            server,
            80,
            101,
            psh,
            3,
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        ));
        // Server response (seq=901 = ISN+1).
        table.observe(&tcp_frame(
            server,
            80,
            client,
            5000,
            901,
            psh,
            4,
            b"HTTP/1.1 200 OK\r\n\r\nhi",
        ));

        assert_eq!(table.len(), 1);
        let flow = table.flows().next().unwrap();
        assert_eq!(flow.protocol, Protocol::Http1);
        assert_eq!(flow.client_stream(), b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(flow.server_stream(), b"HTTP/1.1 200 OK\r\n\r\nhi");
        // The SYN sender (client) must be recognised as the initiator.
        assert!(!flow.finished);
    }

    #[test]
    fn session_round_trips_through_json() {
        let client = ip(1, 1, 1, 1);
        let server = ip(2, 2, 2, 2);
        let psh = TcpFlags {
            psh: true,
            ack: true,
            ..Default::default()
        };
        let mut table = FlowTable::new();
        table.observe(&tcp_frame(
            client,
            40000,
            server,
            443,
            1,
            psh,
            10,
            &[0x16, 0x03, 0x03, 0, 1, 0],
        ));
        let sessions = table.sessions();
        assert_eq!(sessions.len(), 1);
        let json = omnisec_json::to_json_string(&sessions[0]);
        let decoded: Session = omnisec_json::from_json_str(&json).unwrap();
        assert_eq!(decoded, sessions[0]);
    }

    #[test]
    fn udp_streams_accumulate_in_arrival_order() {
        let a = ip(10, 0, 0, 1);
        let b = ip(8, 8, 8, 8);
        let (flow, direction) = FlowKey::from_endpoints(Transport::Udp, a, 5300, b, 53);
        let frame = Frame {
            flow,
            direction,
            src_ip: a,
            src_port: 5300,
            dst_ip: b,
            dst_port: 53,
            timestamp_us: 1,
            tcp_seq: 0,
            tcp_flags: TcpFlags::default(),
            payload: vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
        };
        let mut table = FlowTable::new();
        table.observe(&frame);
        let flow = table.flows().next().unwrap();
        assert_eq!(flow.protocol, Protocol::Dns);
    }
}
