package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/netflow"
	"mega-analyzer/pkg/internal/netproxy"
)

// ═══════════════════════════════════════════════════════════════════════════════
// INTERCEPT SCREEN — Live MITM dashboard
// ═══════════════════════════════════════════════════════════════════════════════

const interceptListenAddr = ":9339"

// localInterceptIP labels the client half of a flow. The proxy reports a
// direction per packet rather than a full 5-tuple, so each half is labelled
// from the listener/upstream config and both then canonicalise to one key.
const localInterceptIP = "127.0.0.1"

type interceptScreen struct {
	t               *tuiState
	mu              sync.Mutex // guards packets/selected/vpStart: addPacket runs on the proxy's relay goroutine
	packets         []netproxy.Packet
	selected        int
	vpStart         int
	proxy           *netproxy.TCPProxy
	editChan        chan editRequest
	interceptActive bool
	netFilter       *netflow.Filter    // -net-filter: nil shows everything
	flows           *netflow.FlowTable // -net-flows: nil disables reassembly
	upstreamIP      string
	upstreamPort    uint16
	listenPort      uint16
}

type editRequest struct {
	pkt        netproxy.Packet
	payloadOff int
	resp       chan []byte
}

func newInterceptScreen(t *tuiState) *interceptScreen {
	return &interceptScreen{
		t:               t,
		packets:         make([]netproxy.Packet, 0),
		editChan:        make(chan editRequest),
		interceptActive: false, // Default to OFF so client traffic is not frozen
	}
}

// startProxy starts the intercept proxy, forwarding to upstreamAddr. Returns
// an error if the proxy is already running, upstreamAddr is invalid, or
// upstreamAddr would make the proxy dial itself (listen and upstream sharing
// the same port causes an unbounded self-connect loop).
func (i *interceptScreen) startProxy(upstreamAddr string) error {
	if i.proxy != nil {
		return nil
	}

	if _, upstreamPort, err := net.SplitHostPort(upstreamAddr); err == nil {
		if _, listenPort, err := net.SplitHostPort(interceptListenAddr); err == nil && upstreamPort == listenPort {
			return fmt.Errorf("upstream %q must not use the same port as the intercept listener (%s)", upstreamAddr, interceptListenAddr)
		}
	}

	// Honour -net-filter / -net-flows for proxies launched from the TUI.
	i.netFilter, i.flows = nil, nil
	if expr := strings.TrimSpace(i.t.opts.NetFilter); expr != "" {
		compiled, err := netflow.Compile(expr)
		if err != nil {
			return fmt.Errorf("-net-filter: %w", err)
		}
		i.netFilter = compiled
	}
	if i.t.opts.NetFlows {
		i.flows = netflow.NewFlowTable()
	}

	i.upstreamIP, i.upstreamPort = upstreamAddr, 0
	if host, port, err := net.SplitHostPort(upstreamAddr); err == nil {
		i.upstreamIP = host
		if v, perr := strconv.ParseUint(port, 10, 16); perr == nil {
			i.upstreamPort = uint16(v)
		}
	}
	if _, port, err := net.SplitHostPort(interceptListenAddr); err == nil {
		if v, perr := strconv.ParseUint(port, 10, 16); perr == nil {
			i.listenPort = uint16(v)
		}
	}

	config := netproxy.ProxyConfig{
		ListenAddr:   interceptListenAddr,
		UpstreamAddr: upstreamAddr,
		Interactive:  true,
		OnPacket: func(p netproxy.Packet) {
			i.addPacket(p)
		},
		InterceptEdit: func(pkt netproxy.Packet, payloadOff int) []byte {
			if !i.interceptActive {
				return nil
			}
			// Send request to TUI thread
			respCh := make(chan []byte)
			i.editChan <- editRequest{pkt: pkt, payloadOff: payloadOff, resp: respCh}
			return <-respCh
		},
	}

	proxy := netproxy.NewTCPProxy(config)
	if err := proxy.Start(); err != nil {
		return err
	}
	i.proxy = proxy
	return nil
}

// stopProxy stops the proxy in the background so the TUI event loop is not
// blocked waiting for in-flight connections to drain.
func (i *interceptScreen) stopProxy() {
	if i.proxy == nil {
		return
	}
	// Report what -net-flows reassembled before the screen goes away.
	if i.flows != nil {
		list := i.flows.Flows()
		if i.netFilter != nil {
			list = i.flows.Select(i.netFilter)
		}
		if len(list) == 0 {
			i.t.log("warn", "net-flows: no flows matched")
		}
		for n, fl := range list {
			if n == 8 {
				i.t.log("info", fmt.Sprintf("net-flows: +%d more flows", len(list)-8))
				break
			}
			i.t.log("ok", fmt.Sprintf("net-flows: %s  %s  c2s=%dB s2c=%dB pkts=%d",
				fl.Key.String(), string(fl.Protocol), fl.BytesC2S, fl.BytesS2C, fl.Packets))
		}
	}

	proxy := i.proxy
	i.proxy = nil
	go proxy.Stop()
}

// addPacket adds a new packet to the live list, after classification and
// display filtering. Both run before the lock is taken: FlowTable guards
// itself and a compiled filter is read-only, so there is no reason to hold
// the display lock across them.
func (i *interceptScreen) addPacket(p netproxy.Packet) {
	if i.flows != nil || i.netFilter != nil {
		dir := netflow.C2S
		srcIP, dstIP := localInterceptIP, i.upstreamIP
		srcPort, dstPort := i.listenPort, i.upstreamPort
		if p.Direction == netproxy.DirectionServerToClient {
			dir = netflow.S2C
			srcIP, dstIP = i.upstreamIP, localInterceptIP
			srcPort, dstPort = i.upstreamPort, i.listenPort
		}

		var rec netflow.Record
		if i.flows != nil {
			rec, _ = i.flows.Observe("tcp", srcIP, srcPort, dstIP, dstPort, dir, p.Timestamp, p.Data)
		} else {
			rec = netflow.Record{
				Protocol:  netflow.Classify(p.Data, "tcp"),
				SrcIP:     srcIP,
				DstIP:     dstIP,
				SrcPort:   srcPort,
				DstPort:   dstPort,
				Direction: string(dir),
				Length:    p.Size,
				SNI:       netflow.TLSSNI(p.Data),
				Payload:   p.Data,
			}
		}

		// A filtered packet is still relayed to the upstream untouched; the
		// filter only decides what the operator is shown.
		if i.netFilter != nil && !i.netFilter.Match(rec) {
			return
		}
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	i.packets = append(i.packets, p)
	// Auto-scroll if at bottom
	if len(i.packets) > 0 && i.selected == len(i.packets)-2 {
		i.selected = len(i.packets) - 1
	}
}

func (i *interceptScreen) handleKey(ev keyEvent) bool {
	switch ev.kind {
	case keyUp:
		i.mu.Lock()
		i.selected--
		if i.selected < 0 {
			i.selected = 0
		}
		i.mu.Unlock()
		return true
	case keyDown:
		i.mu.Lock()
		i.selected++
		if i.selected >= len(i.packets) {
			i.selected = len(i.packets) - 1
		}
		i.mu.Unlock()
		return true
	case keyChar:
		switch ev.r {
		case 'q', 'Q', 27: // Esc
			i.stopProxy()
			i.t.screen = "settings"
			return true
		case 'c', 'C':
			i.mu.Lock()
			i.packets = nil
			i.selected = 0
			i.mu.Unlock()
			return true
		case 'i', 'I', ' ':
			i.interceptActive = !i.interceptActive
			return true
		case 'e', 'E':
			// Accept currently pending edit (dummy implementation for UI)
			select {
			case req := <-i.editChan:
				// Pass original payload by returning nil
				req.resp <- nil
			default:
			}
			return true
		}
	}
	return false
}

func (i *interceptScreen) render(width, height int) []string {
	i.mu.Lock()
	defer i.mu.Unlock()

	th := i.t.theme
	out := []string{}

	statusStr := th.Success + " [INTERCEPT: OFF]" + th.Reset
	if i.interceptActive {
		statusStr = th.Warning + " [INTERCEPT: ON]" + th.Reset
	}
	headerText := th.Bold + th.Primary + " \U0001f6e1\ufe0f LIVE MITM INTERCEPT" + th.Reset + statusStr
	out = append(out, centerText(headerText, width))
	out = append(out, th.Edge+strings.Repeat("─", width)+th.Reset)

	if len(i.packets) == 0 {
		out = append(out, "")
		out = append(out, centerText(th.Muted+"Waiting for game client connection..."+th.Reset, width))
		out = append(out, "")
		out = append(out, centerText(th.Muted+"Press Esc or Q to stop and return to Settings"+th.Reset, width))
		return out
	}

	// Split view: Top (List), Bottom (Details)
	listHeight := (height - 4) / 2
	if listHeight < 5 {
		listHeight = 5
	}

	// Adjust viewport
	if i.selected < i.vpStart {
		i.vpStart = i.selected
	}
	if i.selected >= i.vpStart+listHeight {
		i.vpStart = i.selected - listHeight + 1
	}

	// Render List
	out = append(out, fmt.Sprintf("  %s%-12s %-5s %-10s %-10s%s", th.Muted, "TIME", "DIR", "TYPE", "SIZE", th.Reset))
	for idx := i.vpStart; idx < i.vpStart+listHeight && idx < len(i.packets); idx++ {
		p := i.packets[idx]

		dirColor := th.Info
		if p.Direction == netproxy.DirectionServerToClient {
			dirColor = th.Warning
		}

		line := fmt.Sprintf("  %-12s %s%-5s%s %-10s %d bytes",
			p.Timestamp.Format("15:04:05.000"),
			dirColor, p.Direction, th.Reset,
			fmt.Sprintf("0x%04X", p.MessageType),
			p.Size,
		)

		if idx == i.selected {
			out = append(out, th.Highlight+th.Bold+line+th.Reset)
		} else {
			out = append(out, line)
		}
	}

	for pad := len(out); pad < listHeight+3; pad++ {
		out = append(out, "")
	}

	// Render Details
	out = append(out, th.Edge+strings.Repeat("─", width)+th.Reset)

	if i.selected >= 0 && i.selected < len(i.packets) {
		p := i.packets[i.selected]
		out = append(out, fmt.Sprintf("  %sPacket Details: 0x%04X%s", th.Bold+th.Primary, p.MessageType, th.Reset))

		dumpLines := strings.Split(p.HexDump(256), "\n")
		for _, l := range dumpLines {
			if l != "" {
				out = append(out, "  "+th.Muted+l+th.Reset)
			}
		}
	}

	// Pad bottom
	for len(out) < height-1 {
		out = append(out, "")
	}

	footerText := th.Muted + "[\u2191\u2193] Navigate   [C]lear   [Space] Toggle Intercept"
	if i.interceptActive {
		footerText += "   [E] Accept Packet"
	}
	footerText += "   [Esc/Q] Return to Menu" + th.Reset
	out = append(out, centerText(footerText, width))

	return out
}
