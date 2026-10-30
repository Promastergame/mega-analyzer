//! `omnisec-capture` — the unified capture ingest and reassembly foundation
//! for the network-interception subsystem.
//!
//! The review found the old design had "no real packet capture" and only an
//! application-layer TCP relay: everything was buffered in whole-body `Vec`s,
//! there was no `.pcap` ingest, no flow table, no reassembly, and only three
//! protocols were told apart from the first five bytes. This crate is the
//! replacement foundation:
//!
//! * [`frame`] — a zero-copy [`frame::Frame`] model over [`Vec<u8>`] with
//!   a direction-independent [`frame::FlowKey`].
//! * [`pcap`] — a dependency-free `.pcap` reader/writer plus L2→L4 decode, so
//!   captures can be ingested from disk offline without linking `libpcap`.
//! * [`flow`] — a [`flow::FlowTable`] with TCP stream reassembly (out-of-order
//!   and retransmit handling) that reconstructs full [`flow::Session`]s.
//! * [`classify`] — port-independent, nDPI-style protocol classification.
//! * [`tls`] — TLS ClientHello dissection and JA3 fingerprinting, finally
//!   giving the dead `TlsHandshakeCapture` a live producer.
//!
//! Everything is `#![forbid(unsafe_code)]`, deterministic, and CPU/offline
//! friendly, matching the platform's hard constraints. The [`PacketSource`]
//! trait gives every ingest path (pcap file, live proxy, future AF_PACKET/XDP)
//! one shape the [`CaptureEngine`] consumes.

#![forbid(unsafe_code)]

/// Port-independent protocol classification.
pub mod classify;
/// Flow tracking, TCP reassembly, and session reconstruction.
pub mod flow;
/// The zero-copy frame model.
pub mod frame;
/// `.pcap` file reading/writing and L2→L4 decode.
pub mod pcap;
/// TLS ClientHello dissection and JA3 fingerprinting.
pub mod tls;

use omnisec_crypto::Sha256;

pub use classify::Protocol;
pub use flow::{Flow, FlowTable, Session};
pub use frame::{Direction, FlowKey, Frame, TcpFlags, Transport};
pub use pcap::{LinkType, PcapError, PcapReader, PcapWriter, read_frames};
pub use tls::{ClientHelloInfo, parse_client_hello};

/// A source of decoded [`Frame`]s.
///
/// Implemented by every ingest path so [`CaptureEngine`] doesn't care whether
/// frames came from a `.pcap` on disk, a live MITM proxy, or (later) an
/// AF_PACKET ring. `next_frame` returns `None` at end of stream.
pub trait PacketSource {
    /// Yields the next decoded frame, or `None` when exhausted.
    fn next_frame(&mut self) -> Option<Frame>;
}

/// A [`PacketSource`] backed by an in-memory queue of frames — handy for tests
/// and for adapting a live proxy that pushes frames as it observes them.
#[derive(Debug, Default)]
pub struct InMemorySource {
    frames: std::collections::VecDeque<Frame>,
}

impl InMemorySource {
    /// Creates a source from an iterator of frames.
    pub fn from_frames(frames: impl IntoIterator<Item = Frame>) -> InMemorySource {
        InMemorySource {
            frames: frames.into_iter().collect(),
        }
    }

    /// Pushes one more frame onto the back of the queue.
    pub fn push(&mut self, frame: Frame) {
        self.frames.push_back(frame);
    }
}

impl PacketSource for InMemorySource {
    fn next_frame(&mut self) -> Option<Frame> {
        self.frames.pop_front()
    }
}

/// Drives frames from any [`PacketSource`] through a [`FlowTable`], producing
/// reassembled, classified [`Session`]s.
#[derive(Debug, Default)]
pub struct CaptureEngine {
    table: FlowTable,
    frames_ingested: u64,
}

impl CaptureEngine {
    /// Creates an empty engine.
    #[must_use]
    pub fn new() -> CaptureEngine {
        CaptureEngine::default()
    }

    /// Feeds a single decoded frame.
    pub fn ingest_frame(&mut self, frame: &Frame) {
        self.frames_ingested += 1;
        self.table.observe(frame);
    }

    /// Drains a whole [`PacketSource`] into the engine, returning the number of
    /// frames consumed.
    pub fn ingest_source(&mut self, source: &mut impl PacketSource) -> u64 {
        let mut n = 0;
        while let Some(frame) = source.next_frame() {
            self.ingest_frame(&frame);
            n += 1;
        }
        n
    }

    /// Ingests an in-memory `.pcap` buffer, returning how many frames decoded.
    pub fn ingest_pcap(&mut self, data: impl Into<Vec<u8>>) -> Result<u64, PcapError> {
        let frames = read_frames(data)?;
        let n = frames.len() as u64;
        for f in &frames {
            self.ingest_frame(f);
        }
        Ok(n)
    }

    /// Total frames ingested so far.
    #[must_use]
    pub fn frames_ingested(&self) -> u64 {
        self.frames_ingested
    }

    /// Number of distinct flows tracked.
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.table.len()
    }

    /// Read-only access to the underlying flow table.
    #[must_use]
    pub fn table(&self) -> &FlowTable {
        &self.table
    }

    /// Snapshots all reconstructed sessions.
    #[must_use]
    pub fn sessions(&self) -> Vec<Session> {
        self.table.sessions()
    }
}

/// A stable, content-addressed identifier for a session, derived from its
/// 5-tuple and reassembled streams. The same conversation always hashes to the
/// same id, mirroring the "hash the payload" scheme used by the NCER adapters
/// so sessions can be threaded into the evidence store without collisions.
#[must_use]
pub fn session_id(session: &Session) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut h = Sha256::new();
    h.update(session.key.display().as_bytes());
    h.update(&[0]);
    h.update(&session.client_stream);
    h.update(&[0]);
    h.update(&session.server_stream);
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Builds a raw-IP pcap with a two-packet HTTP exchange.
    fn http_pcap() -> Vec<u8> {
        fn ipv4_tcp(
            src: Ipv4Addr,
            sp: u16,
            dst: Ipv4Addr,
            dp: u16,
            seq: u32,
            flags: u8,
            payload: &[u8],
        ) -> Vec<u8> {
            let total = 40 + payload.len();
            let mut p = vec![0x45, 0];
            p.extend_from_slice(&(total as u16).to_be_bytes());
            p.extend_from_slice(&[0, 0, 0, 0, 64, 6, 0, 0]);
            p.extend_from_slice(&src.octets());
            p.extend_from_slice(&dst.octets());
            p.extend_from_slice(&sp.to_be_bytes());
            p.extend_from_slice(&dp.to_be_bytes());
            p.extend_from_slice(&seq.to_be_bytes());
            p.extend_from_slice(&0u32.to_be_bytes());
            p.push(0x50);
            p.push(flags);
            p.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
            p.extend_from_slice(payload);
            p
        }
        let c = Ipv4Addr::new(10, 0, 0, 2);
        let s = Ipv4Addr::new(93, 1, 2, 3);
        let mut w = PcapWriter::new(LinkType::Raw);
        w.write_packet(1, &ipv4_tcp(c, 5000, s, 80, 100, 0x02, b"")); // SYN
        w.write_packet(
            2,
            &ipv4_tcp(c, 5000, s, 80, 101, 0x18, b"GET / HTTP/1.1\r\n\r\n"),
        );
        w.write_packet(
            3,
            &ipv4_tcp(s, 80, c, 5000, 900, 0x18, b"HTTP/1.1 200 OK\r\n\r\nok"),
        );
        w.into_bytes()
    }

    #[test]
    fn engine_ingests_pcap_and_reconstructs_a_session() {
        let mut engine = CaptureEngine::new();
        let n = engine.ingest_pcap(http_pcap()).expect("pcap");
        assert_eq!(n, 3);
        assert_eq!(engine.flow_count(), 1);
        let sessions = engine.sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].protocol, Protocol::Http1);
        assert_eq!(sessions[0].client_stream, b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(sessions[0].server_stream, b"HTTP/1.1 200 OK\r\n\r\nok");
    }

    #[test]
    fn session_id_is_stable_and_content_addressed() {
        let mut engine = CaptureEngine::new();
        engine.ingest_pcap(http_pcap()).unwrap();
        let s = &engine.sessions()[0];
        assert_eq!(session_id(s), session_id(s));
        assert_eq!(session_id(s).len(), 64);
    }

    #[test]
    fn in_memory_source_drives_the_engine() {
        let frames = read_frames(http_pcap()).unwrap();
        let mut source = InMemorySource::from_frames(frames);
        let mut engine = CaptureEngine::new();
        let n = engine.ingest_source(&mut source);
        assert_eq!(n, 3);
        assert_eq!(engine.flow_count(), 1);
    }
}
