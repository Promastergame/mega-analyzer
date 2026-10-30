package main

import (
	"testing"
	"time"

	"mega-analyzer/pkg/internal/netflow"
	"mega-analyzer/pkg/internal/netproxy"
)

func TestInterceptFlowsSeparateClientsAndJoinReplies(t *testing.T) {
	table := netflow.NewFlowTable()
	for i, addr := range []string{"127.0.0.1:51001", "127.0.0.1:51002"} {
		request := []string{"GET /one HTTP/1.1\r\n\r\n", "SSH-2.0-test\r\n"}[i]
		packet := netproxy.Packet{ClientAddr: addr, ServerAddr: "127.0.0.1:9339", Direction: netproxy.DirectionClientToServer, Data: []byte(request), Timestamp: time.Now()}
		record := observeInterceptPacket(table, packet)
		if record.SrcPort != uint16(51001+i) || record.DstPort != 9339 {
			t.Fatalf("synthetic endpoints in flow: %+v", record)
		}
		packet.Direction = netproxy.DirectionServerToClient
		packet.Data = []byte("reply")
		record = observeInterceptPacket(table, packet)
		if record.SrcPort != 9339 || record.DstPort != uint16(51001+i) {
			t.Fatalf("reply endpoints not reversed: %+v", record)
		}
	}
	if table.Len() != 2 {
		t.Fatalf("got %d flows for two clients", table.Len())
	}
	for _, flow := range table.Flows() {
		if flow.Packets != 2 || flow.BytesS2C != 5 || string(flow.ServerStream()) != "reply" {
			t.Fatalf("reply not joined to its request: %+v", flow)
		}
		if string(flow.ClientStream()) != "GET /one HTTP/1.1\r\n\r\n" && string(flow.ClientStream()) != "SSH-2.0-test\r\n" {
			t.Fatalf("client streams were mixed: %q", flow.ClientStream())
		}
	}
}

func TestInterceptPacketIPv6Endpoints(t *testing.T) {
	record := observeInterceptPacket(nil, netproxy.Packet{
		ClientAddr: "[::1]:50001", ServerAddr: "[::1]:9339",
		Direction: netproxy.DirectionClientToServer, Data: []byte("hello"), Size: 5,
	})
	if record.SrcIP != "::1" || record.DstIP != "::1" || record.SrcPort != 50001 || record.DstPort != 9339 || record.Length != 5 {
		t.Fatalf("IPv6 endpoints lost: %+v", record)
	}
}

func TestInterceptManagedStopFlag(t *testing.T) {
	opts, err := NewCLIParser().Parse([]string{"-intercept", "-intercept-stop-on-eof", "-upstream", "127.0.0.1:9339"})
	if err != nil || !opts.InterceptStopOnEOF {
		t.Fatalf("managed proxy cannot accept stop control: opts=%+v err=%v", opts, err)
	}
	for _, editing := range []string{"-interactive", "-net-remote-edit"} {
		if _, err := NewCLIParser().Parse([]string{"-intercept", "-intercept-stop-on-eof", editing}); err == nil {
			t.Fatalf("accepted competing stdin consumers: %s", editing)
		}
	}
}
