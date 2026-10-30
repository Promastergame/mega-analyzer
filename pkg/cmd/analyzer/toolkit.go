package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/deobfuscation"
	"mega-analyzer/pkg/internal/jspatcher"
	"mega-analyzer/pkg/internal/labdns"
	"mega-analyzer/pkg/internal/netflow"
	"mega-analyzer/pkg/internal/netproxy"
	"mega-analyzer/pkg/internal/protocol"
	"mega-analyzer/pkg/internal/servgen"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/vulnscan"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PRIVATE SERVER TOOLKIT COMMANDS
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) handleJSDeobfuscate() error {
	a.output.Info("🧹 Mega-Analyzer JS/React Native Deobfuscator")
	a.output.Info("Target Bundle: %s", a.opts.Target)

	ctx, stop := a.setupContext()
	defer stop()
	data, err := apkloader.ReadBundleFile(ctx, a.opts.Target)
	if err != nil {
		return fmt.Errorf("failed to read JS bundle: %w", err)
	}

	if apkloader.IsHermesBytecode(data) {
		out := a.opts.Output
		if out == "" {
			out = "analysis_output"
		}
		coverage, err := apkloader.ExportBundle(ctx, a.opts.Target, filepath.Join(out, "bundle_export"))
		a.output.Info("Hermes %d: %s. Exported disassembly/metadata; not recovered JavaScript. See %s", coverage.Version, coverage.Status, out)
		return err
	}
	if !apkloader.IsJavaScriptBundle(data) {
		return fmt.Errorf("input is not a supported text JavaScript bundle")
	}
	code := string(data)
	originalLen := len(code)

	a.output.Info("Analyzing %d bytes...", originalLen)

	engine := deobfuscation.NewJSDeobfuscator(deobfuscation.DefaultJSOptions())
	deobfuscated := engine.Deobfuscate(code)

	if a.opts.JSDeobfuscateOut == "" {
		out := a.opts.Output
		if out == "" {
			out = "analysis_output"
		}
		a.opts.JSDeobfuscateOut = filepath.Join(out, "deobfuscated.js")
	}

	if err := os.MkdirAll(filepath.Dir(a.opts.JSDeobfuscateOut), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(a.opts.JSDeobfuscateOut, []byte(deobfuscated), 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	a.output.Success("Deobfuscation complete!")
	a.output.Success("Saved to: %s", a.opts.JSDeobfuscateOut)

	// Print Bridges if found
	bridges := deobfuscation.MapRNBridge(code)
	if len(bridges) > 0 {
		a.output.Info("Found %d React Native Bridges (NativeModules):", len(bridges))
		for _, b := range bridges {
			a.output.Info("  - %s", b)
		}
	}

	return nil
}

// handleJSPatch runs the smart JS bundle patcher.
// It supports React Native JS bundles and Hermes bytecode targets (scan-only for Hermes).
func (a *App) handleJSPatch() error {
	a.output.Info("JS Bundle Patcher — mega-analyzer")
	a.output.Info("Target: %s", a.opts.Target)

	// Build config from CLI options.
	cfg := jspatcher.DefaultConfig()
	cfg.NewServerIP = a.opts.JSPatchServerIP
	cfg.Backup = a.opts.JSPatchBackup
	cfg.MinConfidence = a.opts.JSPatchMinConf
	if cfg.MinConfidence == 0 {
		cfg.MinConfidence = 40
	}

	switch a.opts.JSPatchApply {
	case "write":
		cfg.Apply = jspatcher.ApplyWrite
	default:
		cfg.Apply = jspatcher.ApplyDryRun
	}

	// Category whitelist.
	if a.opts.JSPatchCategories != "" {
		for _, c := range strings.Split(a.opts.JSPatchCategories, ",") {
			cat := jspatcher.JSPatchCategory(strings.TrimSpace(c))
			if _, ok := jspatcher.AllCategoryMeta[cat]; ok {
				cfg.Categories = append(cfg.Categories, cat)
			} else {
				a.output.Warning("Unknown JS patch category: %q — ignored", c)
			}
		}
	}

	// Output directory.
	outputDir := a.opts.JSPatchOutput
	if outputDir == "" {
		outputDir = a.opts.Output
	}
	if outputDir == "" {
		outputDir = "analysis_output"
	}
	outputDir = filepath.Join(outputDir, "js_patch")
	cfg.OutputDir = outputDir

	p := jspatcher.NewPatcher(cfg)

	// Determine if target is a file or directory.
	info, err := os.Stat(a.opts.Target)
	if err != nil {
		return fmt.Errorf("cannot access target: %w", err)
	}

	var result *jspatcher.JSPatchResult
	if info.IsDir() {
		a.output.Info("Scanning directory recursively for JS bundles...")
		result, err = p.PatchDirectory(a.opts.Target)
	} else {
		a.output.Info("Scanning bundle file...")
		result, err = p.PatchFile(a.opts.Target)
	}
	if err != nil {
		return fmt.Errorf("js-patch failed: %w", err)
	}

	// Print summary.
	a.output.Info("")
	a.output.Info("Bundle type  : %s", result.BundleType)
	if result.IsHermes {
		a.output.Warning("Hermes bytecode — patching not available. Use hermes-dec to decompile first.")
	}
	a.output.Info("Symbols found: %d  |  Occurrences: %d  |  Patches: %d",
		result.GroupCount, result.MatchCount, result.PatchCount)

	if result.SkippedCount > 0 {
		a.output.Info("Skipped      : %d matches below confidence threshold (%d%%)",
			result.SkippedCount, cfg.MinConfidence)
	}

	// Print grouped findings.
	if len(result.Groups) > 0 {
		a.output.Info("")
		a.output.Info("─── Findings ────────────────────────────────────────────")
		currentCat := jspatcher.JSPatchCategory("")
		for _, g := range result.Groups {
			if g.Category != currentCat {
				currentCat = g.Category
				meta := jspatcher.AllCategoryMeta[currentCat]
				a.output.Info("  [%s] %s", strings.ToUpper(string(currentCat)), meta.Name)
			}
			bm := g.BestMatch
			patchDesc := "(no patch)"
			strategy := ""
			if bm.ProposedPatch != nil {
				patchDesc = bm.ProposedPatch.Description
				strategy = string(bm.ProposedPatch.Strategy)
			} else if bm.Context.IsAlreadyPatched {
				patchDesc = "already patched"
			}
			refs := ""
			if g.TotalRefs > 1 {
				refs = fmt.Sprintf(" [%d refs]", g.TotalRefs)
			}
			a.output.Info("    %-40s  conf:%3d%%  %s%s  → %s",
				g.Symbol+refs, bm.Confidence, strategy, "", patchDesc)
		}
		a.output.Info("")
	}

	// Applied patches.
	if len(result.Applied) > 0 {
		a.output.Success("%d patches applied to disk.", len(result.Applied))
		if len(result.BackedUp) > 0 {
			a.output.Info("Originals backed up to .orig files.")
		}
	} else if cfg.Apply == jspatcher.ApplyDryRun && result.PatchCount > 0 {
		a.output.Info("DRY-RUN: %d patches proposed. Use --js-patch-apply write to apply.", result.PatchCount)
	}

	// Errors.
	for _, e := range result.Errors {
		a.output.Warning("  %s", e)
	}

	// Generate reports.
	if err := os.MkdirAll(outputDir, 0755); err == nil {
		mdPath, err := jspatcher.GenerateMarkdownReport(result, outputDir)
		if err != nil {
			a.output.Warning("Failed to write JSPATCH.md: %v", err)
		} else {
			a.output.Success("Report: %s", mdPath)
		}

		jsonPath, err := jspatcher.GenerateJSONReport(result, outputDir)
		if err != nil {
			a.output.Warning("Failed to write jspatch.json: %v", err)
		} else {
			a.output.Info("JSON  : %s", jsonPath)
		}
	}

	return nil
}

func (a *App) handleLabDNS() error {
	fmt.Println("📡 Mega-Analyzer Lab DNS Server")
	fmt.Printf("Listening on: %s\n", a.opts.DNSAddr)
	fmt.Printf("Upstream:     %s\n", a.opts.DNSUpstream)
	fmt.Printf("Sinkhole IP:  %s\n", a.opts.DNSSinkholeIP)

	config := &labdns.Config{
		ListenAddr: a.opts.DNSAddr,
		Upstream:   a.opts.DNSUpstream,
		Rules:      labdns.NewSinkholeRulesWithSafetyNet(false, nil), // default to safety net, don't block all
		SinkIP:     a.opts.DNSSinkholeIP,
	}

	server := labdns.NewDNSServer(config)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		fmt.Println("\nStopping DNS server...")
		cancel()
	}()

	if err := server.Start(ctx); err != nil && err != context.Canceled {
		return fmt.Errorf("failed to start DNS server: %w", err)
	}

	stats := server.Stats()
	fmt.Printf("\nDNS Session Stats:\n")
	fmt.Printf("  Total Queries: %d\n", stats.TotalQueries)
	fmt.Printf("  Forwarded:     %d\n", stats.ForwardedCount)
	fmt.Printf("  Sinkholed:     %d\n", stats.SinkholeCount)

	if len(stats.TopDomains) > 0 {
		fmt.Println("\nTop Domains:")
		for i, d := range stats.TopDomains {
			if i >= 5 {
				break
			}
			fmt.Printf("  %d. %s (%d)\n", i+1, d.Name, d.Count)
		}
	}

	return nil
}

func (a *App) handleIntercept() error {
	fmt.Println("🎮 Mega-Analyzer MITM Proxy")
	fmt.Printf("Listening on: :%d\n", a.opts.InterceptPort)

	if a.opts.InterceptRecord != "" {
		fmt.Printf("Recording session to: %s\n", a.opts.InterceptRecord)
	}
	fmt.Println("Waiting for game client connection...")

	// -net-filter / -net-flows wire the netflow engine into the proxy path so
	// interception gets port-independent protocol classification (HTTP/1,
	// HTTP/2, WebSocket, TLS+SNI, DNS, SSH) instead of raw byte previews.
	var netFilter *netflow.Filter
	if a.opts.NetFilter != "" {
		compiled, err := netflow.Compile(a.opts.NetFilter)
		if err != nil {
			return fmt.Errorf("-net-filter: %w", err)
		}
		netFilter = compiled
		fmt.Printf("Display filter: %s\n", netFilter.String())
	}

	var flowTable *netflow.FlowTable
	if a.opts.NetFlows {
		flowTable = netflow.NewFlowTable()
		fmt.Println("Flow reassembly: on (classified summary printed on exit)")
	}

	config := netproxy.ProxyConfig{
		ListenAddr:   fmt.Sprintf(":%d", a.opts.InterceptPort),
		UpstreamAddr: a.opts.InterceptUpstream,
		RecordPath:   a.opts.InterceptRecord,
		OnPacket: func(p netproxy.Packet) {
			if flowTable != nil || netFilter != nil {
				rec := observeInterceptPacket(flowTable, p)

				// A filtered-out packet is still forwarded untouched; the filter
				// only decides what the operator is shown.
				if netFilter != nil && !netFilter.Match(rec) {
					return
				}
			}
			if a.opts.NetJSONEvents {
				emitNetEvent(netproxy.NewNetEvent("packet", p, p.PayloadOffset))
				return
			}
			if !a.opts.InterceptInteractive {
				fmt.Printf("\r%s", p.Summary())
			}
		},
		Interactive: a.opts.InterceptInteractive,
	}

	// -net-remote-edit (M3, see DEVMEGA_TODO.md) will set config.InterceptEdit to a
	// stdio-based async handler here instead of the terminal PacketEditor prompt.

	if a.opts.InterceptFrame != "" {
		framer, desc, err := buildFramer(a.opts.InterceptFrame)
		if err != nil {
			return fmt.Errorf("invalid -frame spec: %w", err)
		}
		config.Framer = framer
		fmt.Printf("Frame reassembly: %s\n", desc)
	}

	proxy := netproxy.NewTCPProxy(config)
	if err := proxy.Start(); err != nil {
		return fmt.Errorf("failed to start proxy: %w", err)
	}
	defer proxy.Stop()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)
	var inputClosed <-chan struct{}
	if a.opts.InterceptStopOnEOF {
		closed := make(chan struct{})
		inputClosed = closed
		go func() {
			_, _ = io.Copy(io.Discard, os.Stdin)
			close(closed)
		}()
	}
	select {
	case <-sig:
	case <-inputClosed:
	}

	fmt.Println("\nStopping proxy...")
	proxy.Stop()

	fmt.Printf("Intercepted %d packets across %d connections.\n", proxy.Stats(), proxy.Connections())
	if a.opts.InterceptRecord != "" {
		fmt.Printf("Capture: %d dropped record(s), %d write error(s).\n", proxy.DroppedRecords(), proxy.RecordWriteErrors())
	}
	if flowTable != nil {
		printFlowTable(flowTable, netFilter)
	}
	if proxy.DroppedRecords() > 0 || proxy.RecordWriteErrors() > 0 {
		return fmt.Errorf("capture incomplete: %d dropped record(s), %d write error(s)", proxy.DroppedRecords(), proxy.RecordWriteErrors())
	}
	return nil
}

// printFlowTable renders the reassembled flow table. When a -net-filter is
// active the table is narrowed to matching flows so the summary agrees with
// what was shown live during the session.
func printFlowTable(t *netflow.FlowTable, f *netflow.Filter) {
	list := t.Flows()
	if f != nil {
		list = t.Select(f)
	}
	if len(list) == 0 {
		fmt.Println("\nNo flows matched.")
		return
	}

	fmt.Printf("\nFlows (%d of %d):\n", len(list), t.Len())
	fmt.Printf("  %-44s  %-9s  %9s  %9s  %6s  %s\n", "FLOW", "PROTO", "C2S", "S2C", "PKTS", "SNI")
	for _, fl := range list {
		fmt.Printf("  %-44s  %-9s  %9d  %9d  %6d  %s\n",
			fl.Key.String(), string(fl.Protocol), fl.BytesC2S, fl.BytesS2C, fl.Packets, fl.SNI)
	}
}

// buildFramer parses a -frame spec into a netproxy.Framer.
//
//	"supercell"                  → Supercell [2B type][3B len][2B ver] header
//	"len:HDR,OFF,SZ"             → length-prefixed, length counts payload only
//	"len:HDR,OFF,SZ,inclhdr"     → length field counts the header too
//
// HDR is the header size, OFF the length-field offset, SZ its width (1–4).
func buildFramer(spec string) (netproxy.Framer, string, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "supercell" {
		return netproxy.SupercellFramer(), "Supercell (7-byte header, 3-byte payload length)", nil
	}
	if !strings.HasPrefix(spec, "len:") {
		return nil, "", fmt.Errorf("unknown framer %q (want 'supercell' or 'len:HDR,OFF,SZ')", spec)
	}
	parts := strings.Split(strings.TrimPrefix(spec, "len:"), ",")
	if len(parts) < 3 || len(parts) > 4 {
		return nil, "", fmt.Errorf("len spec needs HDR,OFF,SZ[,inclhdr]")
	}
	atoi := func(s string) (int, error) { return strconv.Atoi(strings.TrimSpace(s)) }
	hdr, err := atoi(parts[0])
	if err != nil {
		return nil, "", fmt.Errorf("bad HDR: %w", err)
	}
	off, err := atoi(parts[1])
	if err != nil {
		return nil, "", fmt.Errorf("bad OFF: %w", err)
	}
	sz, err := atoi(parts[2])
	if err != nil {
		return nil, "", fmt.Errorf("bad SZ: %w", err)
	}
	inclHdr := len(parts) == 4 && (parts[3] == "inclhdr" || parts[3] == "true" || parts[3] == "1")
	desc := fmt.Sprintf("length-prefixed (header=%dB, len@%d width=%dB, incl-header=%v)", hdr, off, sz, inclHdr)
	return netproxy.LengthPrefixFramer(hdr, off, sz, inclHdr, 0), desc, nil
}

func (a *App) handleServgen() error {
	fmt.Println("🏗️ Mega-Analyzer Server Generator")

	// Preferred path: replay a real recorded capture into a spec with inferred
	// fields. Falls through to -protocol-spec / dummy otherwise.
	if a.opts.ServgenFromCapture != "" {
		fmt.Printf("Replaying capture: %s\n", a.opts.ServgenFromCapture)
		spec, err := protocol.BuildSpecFromCapture(a.opts.ServgenFromCapture, "Captured Game")
		if err != nil {
			return fmt.Errorf("build spec from capture: %w", err)
		}
		return a.generateServerFromSpec(spec)
	}

	if a.opts.ServgenProtocol == "" {
		return fmt.Errorf("--protocol-spec or --from-capture is required for servgen")
	}

	fmt.Printf("Loading protocol spec: %s\n", a.opts.ServgenProtocol)

	// Create a dummy spec for demonstration if real file isn't found
	spec, err := protocol.LoadFromFile(a.opts.ServgenProtocol)
	if err != nil {
		log.Printf("Warning: failed to load spec (%v). Creating dummy spec.", err)
		spec = protocol.NewProtocolSpec("Custom Game")
		spec.AddSample(10101, string(netproxy.DirectionClientToServer), make([]byte, 50))
		spec.AddSample(20104, string(netproxy.DirectionServerToClient), make([]byte, 100))
		spec.AnnotateSupercell()
	}

	return a.generateServerFromSpec(spec)
}

// generateServerFromSpec prints the spec summary and runs the server generator.
func (a *App) generateServerFromSpec(spec *protocol.ProtocolSpec) error {
	fmt.Println(spec.Summary())

	outDir := fmt.Sprintf("./server_%d", time.Now().Unix())
	config := servgen.DefaultConfig()
	config.OutputDir = outDir
	config.GameName = spec.GameName

	fmt.Printf("Generating server to %s...\n", outDir)

	gen := servgen.NewGenerator(config, spec)
	if err := gen.Generate(); err != nil {
		return fmt.Errorf("generation failed: %w", err)
	}

	fmt.Println("✅ Server stub generated successfully!")
	fmt.Printf("To run it:\n  cd %s\n  go run cmd/server/main.go\n", outDir)

	return nil
}

// buildFrameLayout parses a -frame spec into a protocol.FrameLayout. Empty spec
// defaults to the Supercell layout — the common case for these game protocols.
func buildFrameLayout(spec string) (protocol.FrameLayout, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" || spec == "supercell" {
		return protocol.SupercellLayout(), nil
	}
	if !strings.HasPrefix(spec, "len:") {
		return protocol.FrameLayout{}, fmt.Errorf("unknown frame layout %q (want 'supercell' or 'len:HDR,OFF,SZ[,inclhdr]')", spec)
	}
	parts := strings.Split(strings.TrimPrefix(spec, "len:"), ",")
	if len(parts) < 3 || len(parts) > 4 {
		return protocol.FrameLayout{}, fmt.Errorf("len spec needs HDR,OFF,SZ[,inclhdr]")
	}
	hdr, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	off, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	sz, err3 := strconv.Atoi(strings.TrimSpace(parts[2]))
	if err1 != nil || err2 != nil || err3 != nil {
		return protocol.FrameLayout{}, fmt.Errorf("HDR,OFF,SZ must be integers")
	}
	inclHdr := len(parts) == 4 && (parts[3] == "inclhdr" || parts[3] == "true" || parts[3] == "1")
	return protocol.FrameLayout{HeaderLen: hdr, LenOffset: off, LenSize: sz, LenInclHeader: inclHdr}, nil
}

// fuzzManifest is the JSON schema written by -fuzz-out.
type fuzzManifest struct {
	Capture  string               `json:"capture"`
	Layout   protocol.FrameLayout `json:"layout"`
	Messages []fuzzManifestMsg    `json:"messages"`
	Total    int                  `json:"total_mutations"`
}

type fuzzManifestMsg struct {
	ID        uint16              `json:"id"`
	Name      string              `json:"name"`
	Mutations []protocol.Mutation `json:"mutations"`
}

// handleFuzz builds a protocol spec from a recorded capture, generates a
// protocol-aware mutation corpus from the inferred field layout, and optionally
// replays it against a loopback/private target to flag anomalous reactions.
func (a *App) handleFuzz() error {
	fmt.Println("🧪 Mega-Analyzer Protocol Frame Fuzzer")

	if a.opts.FuzzCapture == "" {
		return fmt.Errorf("--fuzz-capture <recorded.jsonl> is required for fuzz")
	}
	layout, err := buildFrameLayout(a.opts.InterceptFrame)
	if err != nil {
		return fmt.Errorf("invalid -frame layout: %w", err)
	}

	fmt.Printf("Replaying capture for inference: %s\n", a.opts.FuzzCapture)
	spec, err := protocol.BuildSpecFromCapture(a.opts.FuzzCapture, "Fuzz Target")
	if err != nil {
		return fmt.Errorf("build spec from capture: %w", err)
	}
	fmt.Println(spec.Summary())

	corpus := spec.MutateSpec(layout)
	if len(corpus) == 0 {
		return fmt.Errorf("no messages with samples to mutate in %s", a.opts.FuzzCapture)
	}

	// Stable ordering by message ID for reproducible output.
	ids := make([]uint16, 0, len(corpus))
	for id := range corpus {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	total := 0
	manifest := fuzzManifest{Capture: a.opts.FuzzCapture, Layout: layout}
	fmt.Println("\nMutation corpus:")
	for _, id := range ids {
		muts := corpus[id]
		total += len(muts)
		name := spec.Messages[id].Name
		fmt.Printf("  0x%04X %-20s %d mutations\n", id, name, len(muts))
		manifest.Messages = append(manifest.Messages, fuzzManifestMsg{ID: id, Name: name, Mutations: muts})
	}
	manifest.Total = total
	fmt.Printf("Total: %d mutations across %d message types\n", total, len(ids))

	if a.opts.FuzzOut != "" {
		data, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal manifest: %w", err)
		}
		if err := os.WriteFile(a.opts.FuzzOut, data, 0644); err != nil {
			return fmt.Errorf("write manifest %s: %w", a.opts.FuzzOut, err)
		}
		fmt.Printf("📄 Wrote mutation manifest → %s\n", a.opts.FuzzOut)
	}

	if a.opts.FuzzTarget != "" {
		return a.replayFuzz(spec, layout, corpus, ids)
	}

	fmt.Println("\n(no -fuzz-target given — corpus generated offline; add -fuzz-target host:port to replay)")
	return nil
}

// replayFuzz drives the generated corpus against a live loopback/private target
// and reports mutations that triggered an anomalous server reaction.
func (a *App) replayFuzz(spec *protocol.ProtocolSpec, layout protocol.FrameLayout, corpus map[uint16][]protocol.Mutation, ids []uint16) error {
	replayer := &netproxy.Replayer{Target: a.opts.FuzzTarget}
	fmt.Printf("\n🎯 Replaying against %s …\n", a.opts.FuzzTarget)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; cancel() }()

	totalInteresting := 0
	for _, id := range ids {
		baseline, ok := spec.SeedFrame(id, layout)
		if !ok {
			continue
		}
		cases := make([]netproxy.ReplayCase, 0, len(corpus[id]))
		for _, m := range corpus[id] {
			cases = append(cases, netproxy.ReplayCase{Name: m.Name, Frame: m.Data})
		}
		results, err := replayer.Run(ctx, baseline, cases)
		if err != nil {
			return err
		}
		for _, r := range results {
			if r.Interesting {
				totalInteresting++
				fmt.Printf("  ⚠️  0x%04X %-22s → %-11s %s %s\n",
					id, r.Name, r.Outcome, r.Note, r.RespHex)
			}
		}
		if ctx.Err() != nil {
			break
		}
	}
	fmt.Printf("\nDone. %d anomalous reaction(s) flagged.\n", totalInteresting)
	return nil
}

func (a *App) handleActiveWebScanOnly() error {
	a.output.Info("══════ Standalone Active Web Security Scan ══════")
	a.output.Info("Target URL: %s", a.opts.WebScanTarget)

	scanner, err := vulnscan.NewScanner(a.opts.WebScanTarget)
	if err != nil {
		return fmt.Errorf("failed to initialize web scanner: %w", err)
	}

	scanner.Config.IOwnThisTarget = a.opts.WebScanIOwnThisTarget
	scanner.Config.LabMode = a.opts.WebScanLabMode
	scanner.Config.MaxWorkers = a.opts.Workers // reuse global workers flag
	if a.opts.WebScanAllowlist != "" {
		scanner.Config.TargetAllowlist = strings.Split(a.opts.WebScanAllowlist, ",")
	}
	scanner.Config.FSMConfigPath = a.opts.WebScanFSMConfig

	vulns, err := scanner.Scan()
	if err != nil {
		return fmt.Errorf("web vulnerability scan failed: %w", err)
	}

	a.output.Success("Scan complete. Detected %d security findings.", len(vulns))

	outputDir := a.opts.Output
	if outputDir == "" {
		outputDir = "analysis_output"
	}
	reportDir := filepath.Join(outputDir, "web_scan")
	reportPath := vulnscan.GenerateMarkdownReport(vulns, a.opts.WebScanTarget, reportDir)
	a.output.Success("Sleek HTML/Markdown report saved to: %s", reportPath)

	a.output.Info("\n================ Scan Results Matrix ================")
	for i, v := range vulns {
		a.output.Info(" [%d] %-8s | %-12s | %s", i+1, v.Severity, v.ID, v.Name)
		if v.Parameter != "" {
			a.output.Info("     Parameter: %s | Payload: %s", v.Parameter, v.Payload)
		}
	}
	a.output.Info("=====================================================")
	return nil
}

// handleWebScanOnly is the unified website-analysis entry point. The old
// handleActiveWebScanOnly method remains as the active-mode implementation so
// existing integrations keep their safety-gate behaviour.
func (a *App) handleWebScanOnly() error {
	if a.opts.HTMLBody != "" {
		info, err := os.Stat(a.opts.HTMLBody)
		if err != nil {
			return fmt.Errorf("failed to access HTML body path: %w", err)
		}
		scanner, _ := vulnscan.NewScanner("http://localhost")
		scanner.Config.IOwnThisTarget = true
		sourceURL := "file://" + a.opts.HTMLBody

		var vulns []vulnscan.Vulnerability
		if info.IsDir() {
			vulns, err = scanner.ScanHTMLDirectory(a.opts.HTMLBody)
			if err != nil {
				return fmt.Errorf("failed to scan directory: %w", err)
			}
		} else {
			data, err := os.ReadFile(a.opts.HTMLBody)
			if err != nil {
				return fmt.Errorf("failed to read HTML body file: %w", err)
			}
			vulns = scanner.ScanFileContent(a.opts.HTMLBody, string(data), sourceURL)
		}

		a.output.Info("[+] Passive HTML/directory scan complete. %d finding(s).", len(vulns))
		if a.opts.JSON {
			b, _ := json.MarshalIndent(vulns, "", "  ")
			fmt.Println(string(b))
		}
		return nil
	}

	mode, err := a.configuredWebScanMode()
	if err != nil {
		return err
	}
	if mode == vulnscan.ScanModeActive {
		return a.handleActiveWebScanOnly()
	}

	result, err := a.runSafeWebScan(mode)
	if err != nil {
		return fmt.Errorf("web %s scan failed: %w", mode, err)
	}
	return a.renderSafeWebScan(result, "")
}

func (a *App) handleActiveWebScan(result *types.AnalysisResult, outputDir string) error {
	a.output.Info("══════ Integrated Active Web Security Scan ══════")
	a.output.Info("Target URL: %s", a.opts.WebScanTarget)

	scanner, err := vulnscan.NewScanner(a.opts.WebScanTarget)
	if err != nil {
		return fmt.Errorf("failed to initialize web scanner: %w", err)
	}

	scanner.Config.IOwnThisTarget = a.opts.WebScanIOwnThisTarget
	scanner.Config.LabMode = a.opts.WebScanLabMode
	scanner.Config.MaxWorkers = a.opts.Workers
	if a.opts.WebScanAllowlist != "" {
		scanner.Config.TargetAllowlist = strings.Split(a.opts.WebScanAllowlist, ",")
	}
	scanner.Config.FSMConfigPath = a.opts.WebScanFSMConfig

	vulns, err := scanner.Scan()
	if err != nil {
		return fmt.Errorf("web vulnerability scan failed: %w", err)
	}

	a.output.Success("Scan complete. Detected %d security findings.", len(vulns))

	reportDir := filepath.Join(outputDir, "web_scan")
	reportPath := vulnscan.GenerateMarkdownReport(vulns, a.opts.WebScanTarget, reportDir)
	a.output.Success("Integrated report saved to: %s", reportPath)

	// Inject web scan findings as sidecar/artifact findings into the main analysis result
	for _, v := range vulns {
		reason := v.Name
		if v.Parameter != "" {
			reason += fmt.Sprintf(" on parameter '%s'", v.Parameter)
		}
		if v.Payload != "" {
			reason += fmt.Sprintf(" (Payload: %s)", v.Payload)
		}

		result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
			Path:     "web_scan/WEB_SCAN_REPORT.md",
			Severity: typesSeverity(v.Severity),
			Reason:   reason,
			Stages:   []string{"module: active-web-scan", "target: " + a.opts.WebScanTarget},
		})
	}

	return nil
}

// handleWebScan integrates the selected website mode into a regular analysis.
// Status/passive remain bounded to one GET; only active mode can reach the
// crawler/fuzzer implementation.
func (a *App) handleWebScan(result *types.AnalysisResult, outputDir string) error {
	mode, err := a.configuredWebScanMode()
	if err != nil {
		return err
	}
	if mode == vulnscan.ScanModeActive {
		return a.handleActiveWebScan(result, outputDir)
	}

	scanResult, err := a.runSafeWebScan(mode)
	if err != nil {
		return fmt.Errorf("web %s scan failed: %w", mode, err)
	}
	if err := a.renderSafeWebScan(scanResult, outputDir); err != nil {
		return err
	}

	if result != nil {
		for _, v := range scanResult.Findings {
			result.ArtifactFindings = append(result.ArtifactFindings, types.ArtifactFinding{
				Path:     "web_scan/WEB_SCAN_REPORT.md",
				Severity: typesSeverity(v.Severity),
				Reason:   v.Name,
				Stages:   []string{"module: passive-web-scan", "target: " + a.opts.WebScanTarget},
			})
		}
	}
	return nil
}

func (a *App) configuredWebScanMode() (vulnscan.ScanMode, error) {
	raw := a.opts.WebScanMode
	if strings.TrimSpace(raw) == "" {
		raw = string(vulnscan.ScanModeActive)
	}
	return vulnscan.ParseScanMode(raw)
}

func (a *App) runSafeWebScan(mode vulnscan.ScanMode) (*vulnscan.ModeResult, error) {
	scanner, err := vulnscan.NewScanner(a.opts.WebScanTarget)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize web scanner: %w", err)
	}
	scanner.Config.MaxWorkers = a.opts.Workers
	if scanner.Config.MaxWorkers < 1 {
		scanner.Config.MaxWorkers = 1
	}
	if a.opts.WebScanAllowlist != "" {
		scanner.Config.TargetAllowlist = strings.Split(a.opts.WebScanAllowlist, ",")
	}
	scanner.LogFunc = func(msg string) { a.output.Info("%s", strings.TrimSpace(msg)) }
	return scanner.ScanWithMode(context.Background(), mode)
}

func (a *App) renderSafeWebScan(result *vulnscan.ModeResult, outputDir string) error {
	if result == nil {
		return fmt.Errorf("web scan returned no result")
	}
	if result.Status != nil {
		if result.Status.OK {
			a.output.Success("Website is reachable: HTTP %d (%s)", result.Status.StatusCode, result.Status.Duration.Round(time.Millisecond))
		} else {
			a.output.Warning("Website responded but health check is not HTTP 200: %s", result.Status.Status)
		}
	}
	if result.Mode == vulnscan.ScanModeStatus {
		return nil
	}

	a.output.Success("Passive scan complete. Detected %d security finding(s); no fuzzing or endpoint probes were sent.", len(result.Findings))
	if outputDir == "" {
		outputDir = a.opts.Output
		if outputDir == "" {
			outputDir = "analysis_output"
		}
	}
	reportDir := filepath.Join(outputDir, "web_scan")
	reportPath := vulnscan.GenerateMarkdownReport(result.Findings, a.opts.WebScanTarget, reportDir)
	a.output.Success("Passive report saved to: %s", reportPath)
	return nil
}

func typesSeverity(sev vulnscan.Severity) types.Severity {
	switch sev {
	case vulnscan.SeverityCritical:
		return types.SeverityCritical
	case vulnscan.SeverityHigh:
		return types.SeverityHigh
	case vulnscan.SeverityMedium:
		return types.SeverityMedium
	case vulnscan.SeverityLow:
		return types.SeverityLow
	default:
		return types.SeverityInfo
	}
}
