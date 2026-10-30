//! The canonical, zero-copy frame model shared by every capture source.
//!
//! A [`Frame`] is what a [`crate::source::PacketSource`] yields after the
//! link/network/transport headers of one packet have been peeled off. It
//! deliberately carries *borrowed* payload bytes via [`Vec<u8>`] so a
//! whole `.pcap` file (or a live ring buffer) can be sliced into thousands of
//! frames without copying a single payload byte — the previous MITM code
//! `read_to_end`'d entire bodies into fresh `Vec`s, which this design avoids.

use std::net::IpAddr;

use omnisec_json::{FromJson, ToJson};

/// Transport-layer protocol carried by a [`Frame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum Transport {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// Anything we decoded an L3 header for but not an L4 one (ICMP, ...).
    Other(u8),
}

impl Transport {
    /// The IANA protocol number, mirroring the IPv4 `protocol` / IPv6
    /// `next_header` byte this transport was decoded from.
    #[must_use]
    pub fn proto_number(self) -> u8 {
        match self {
            Transport::Tcp => 6,
            Transport::Udp => 17,
            Transport::Other(n) => n,
        }
    }
}

/// Which side of a flow a frame travelled on.
///
/// Direction is defined *relative to the flow's initiator*: the first endpoint
/// we ever see sending on a 5-tuple is the client, so its packets are
/// [`Direction::ClientToServer`]. This mirrors the netproxy convention and lets
/// reassembly reconstruct request/response ordering without a separate hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum Direction {
    /// From the flow initiator toward the peer it first contacted.
    ClientToServer,
    /// From the peer back toward the initiator.
    ServerToClient,
}

impl Direction {
    /// The opposite direction.
    #[must_use]
    pub fn flip(self) -> Direction {
        match self {
            Direction::ClientToServer => Direction::ServerToClient,
            Direction::ServerToClient => Direction::ClientToServer,
        }
    }
}

/// A bidirectional, order-independent key identifying a single transport flow.
///
/// The two endpoints are stored in a canonical (sorted) order so that a packet
/// and its reply hash to the *same* key. [`FlowKey::from_endpoints`] returns
/// both the key and the [`Direction`] the observed packet travelled, so callers
/// never have to re-derive orientation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, ToJson, FromJson)]
pub struct FlowKey {
    /// Transport protocol.
    pub transport: Transport,
    /// Lower (canonical "a") endpoint address.
    pub a_ip: IpAddr,
    /// Lower endpoint port.
    pub a_port: u16,
    /// Higher (canonical "b") endpoint address.
    pub b_ip: IpAddr,
    /// Higher endpoint port.
    pub b_port: u16,
}

impl FlowKey {
    /// Builds a canonical flow key from an observed `(src, dst)` pair and
    /// reports which [`Direction`] that observed packet was travelling.
    ///
    /// The endpoint that sorts smaller becomes the canonical "a" side. When the
    /// observed source is the "a" side, the packet is client→server; otherwise
    /// it is server→client. The *first* packet seen on a fresh key therefore
    /// establishes the client as whichever endpoint sent it — that final
    /// determination is made by the flow table, not here, because ordering
    /// alone can't distinguish a mid-stream capture. This function only
    /// reports orientation relative to canonical order.
    #[must_use]
    pub fn from_endpoints(
        transport: Transport,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> (FlowKey, Direction) {
        let src = (src_ip, src_port);
        let dst = (dst_ip, dst_port);
        if src <= dst {
            (
                FlowKey {
                    transport,
                    a_ip: src_ip,
                    a_port: src_port,
                    b_ip: dst_ip,
                    b_port: dst_port,
                },
                Direction::ClientToServer,
            )
        } else {
            (
                FlowKey {
                    transport,
                    a_ip: dst_ip,
                    a_port: dst_port,
                    b_ip: src_ip,
                    b_port: src_port,
                },
                Direction::ServerToClient,
            )
        }
    }

    /// A short, stable, human-readable rendering, e.g. `tcp 10.0.0.1:1234<->93.1.2.3:443`.
    #[must_use]
    pub fn display(&self) -> String {
        let proto = match self.transport {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
            Transport::Other(_) => "ip",
        };
        format!(
            "{proto} {}:{}<->{}:{}",
            self.a_ip, self.a_port, self.b_ip, self.b_port
        )
    }
}

/// TCP control-flag bits, decoded once so downstream code never re-parses the
/// header byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ToJson, FromJson)]
pub struct TcpFlags {
    /// SYN — connection establishment.
    pub syn: bool,
    /// ACK — acknowledgement field significant.
    pub ack: bool,
    /// FIN — sender finished sending.
    pub fin: bool,
    /// RST — connection reset.
    pub rst: bool,
    /// PSH — push buffered data to the application.
    pub psh: bool,
}

impl TcpFlags {
    /// Decodes the low control bits of a TCP header's flags byte.
    #[must_use]
    pub fn from_bits(bits: u8) -> TcpFlags {
        TcpFlags {
            fin: bits & 0x01 != 0,
            syn: bits & 0x02 != 0,
            rst: bits & 0x04 != 0,
            psh: bits & 0x08 != 0,
            ack: bits & 0x10 != 0,
        }
    }
}

/// One decoded packet: its flow, direction, transport metadata, and a
/// zero-copy view of its L4 payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Canonical flow this frame belongs to.
    pub flow: FlowKey,
    /// Direction relative to canonical flow order (see [`FlowKey::from_endpoints`]).
    pub direction: Direction,
    /// Observed source address (as seen on the wire, pre-canonicalisation).
    pub src_ip: IpAddr,
    /// Observed source port.
    pub src_port: u16,
    /// Observed destination address.
    pub dst_ip: IpAddr,
    /// Observed destination port.
    pub dst_port: u16,
    /// Capture timestamp in Unix epoch microseconds.
    pub timestamp_us: u64,
    /// TCP sequence number of the first payload byte (0 for UDP).
    pub tcp_seq: u32,
    /// Decoded TCP flags (all false for UDP).
    pub tcp_flags: TcpFlags,
    /// Zero-copy L4 payload (may be empty, e.g. a bare SYN/ACK).
    pub payload: Vec<u8>,
}

impl Frame {
    /// Number of payload bytes carried by this frame.
    #[must_use]
    pub fn len(&self) -> usize {
        self.payload.len()
    }

    /// Whether this frame carries no L4 payload.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn flow_key_is_direction_independent() {
        let client = ip(10, 0, 0, 5);
        let server = ip(93, 1, 2, 3);
        let (k1, d1) = FlowKey::from_endpoints(Transport::Tcp, client, 51000, server, 443);
        let (k2, d2) = FlowKey::from_endpoints(Transport::Tcp, server, 443, client, 51000);
        assert_eq!(k1, k2, "both directions must map to the same key");
        assert_ne!(d1, d2, "directions must be opposite");
    }

    #[test]
    fn canonical_order_places_smaller_endpoint_first() {
        let lo = ip(1, 1, 1, 1);
        let hi = ip(2, 2, 2, 2);
        let (k, dir) = FlowKey::from_endpoints(Transport::Udp, hi, 100, lo, 200);
        assert_eq!(k.a_ip, lo);
        assert_eq!(k.b_ip, hi);
        // Source (hi) sorts after dest (lo), so this observed packet is s->c.
        assert_eq!(dir, Direction::ServerToClient);
    }

    #[test]
    fn tcp_flags_decode_expected_bits() {
        let f = TcpFlags::from_bits(0x12); // SYN|ACK
        assert!(f.syn && f.ack);
        assert!(!f.fin && !f.rst && !f.psh);
    }

    #[test]
    fn transport_proto_numbers() {
        assert_eq!(Transport::Tcp.proto_number(), 6);
        assert_eq!(Transport::Udp.proto_number(), 17);
        assert_eq!(Transport::Other(1).proto_number(), 1);
    }

    #[test]
    fn direction_flip_is_involution() {
        assert_eq!(
            Direction::ClientToServer.flip().flip(),
            Direction::ClientToServer
        );
    }
}
