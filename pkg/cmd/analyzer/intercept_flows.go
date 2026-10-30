package main

import (
	"net"
	"strconv"

	"mega-analyzer/pkg/internal/netflow"
	"mega-analyzer/pkg/internal/netproxy"
)

// Use the client's real ephemeral port so parallel connections to the same
// upstream never share the protocol reassembly buffer or traffic counters.
func observeInterceptPacket(table *netflow.FlowTable, packet netproxy.Packet) netflow.Record {
	endpoint := func(addr string) (string, uint16) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return addr, 0
		}
		n, _ := strconv.ParseUint(port, 10, 16)
		return host, uint16(n)
	}
	srcIP, srcPort := endpoint(packet.ClientAddr)
	dstIP, dstPort := endpoint(packet.ServerAddr)
	dir := netflow.C2S
	if packet.Direction == netproxy.DirectionServerToClient {
		dir = netflow.S2C
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}
	if table != nil {
		record, _ := table.Observe("tcp", srcIP, srcPort, dstIP, dstPort, dir, packet.Timestamp, packet.Data)
		return record
	}
	return netflow.Record{
		Protocol: netflow.Classify(packet.Data, "tcp"),
		SrcIP:    srcIP, SrcPort: srcPort, DstIP: dstIP, DstPort: dstPort,
		Direction: string(dir), Length: packet.Size,
		SNI: netflow.TLSSNI(packet.Data), Payload: packet.Data,
	}
}
