package cfg

import (
	"testing"
)

// helper: build a minimal ControlFlowGraph with one node
func newTestCFGWithNode(instructions []Instruction) *ControlFlowGraph {
	node := &CFGNode{
		ID:           1,
		Instructions: make([]InstructionRef, len(instructions)),
	}
	for i, ins := range instructions {
		node.Instructions[i] = InstructionRef{
			Index:  ins.Index,
			Opcode: ins.Opcode,
			Line:   ins.Line,
			Raw:    ins.Raw,
		}
	}
	return &ControlFlowGraph{
		Nodes: []*CFGNode{node},
	}
}

func newTestAnalyzer(instructions []Instruction) *PatternAnalyzer {
	cfg := newTestCFGWithNode(instructions)
	return NewPatternAnalyzer(cfg)
}

// ─── inferEmulatorCheckType ───────────────────────────────────────────────

func TestInferEmulatorCheckType_Generic(t *testing.T) {
	p := newTestAnalyzer(nil)
	result := p.inferEmulatorCheckType("generic.model")
	if result != EmulatorCheckBuild {
		t.Errorf("expected EmulatorCheckBuild, got %v", result)
	}
}

func TestInferEmulatorCheckType_SDK(t *testing.T) {
	p := newTestAnalyzer(nil)
	result := p.inferEmulatorCheckType("sdk.version")
	if result != EmulatorCheckBuild {
		t.Errorf("expected EmulatorCheckBuild, got %v", result)
	}
}

func TestInferEmulatorCheckType_Dev(t *testing.T) {
	p := newTestAnalyzer(nil)
	result := p.inferEmulatorCheckType("/dev/qemu_pipe")
	if result != EmulatorCheckFiles {
		t.Errorf("expected EmulatorCheckFiles, got %v", result)
	}
}

func TestInferEmulatorCheckType_System(t *testing.T) {
	p := newTestAnalyzer(nil)
	result := p.inferEmulatorCheckType("/system/lib/emugl")
	if result != EmulatorCheckFiles {
		t.Errorf("expected EmulatorCheckFiles, got %v", result)
	}
}

func TestInferEmulatorCheckType_Goldfish(t *testing.T) {
	p := newTestAnalyzer(nil)
	result := p.inferEmulatorCheckType("goldfish_cpu")
	if result != EmulatorCheckCPU {
		t.Errorf("expected EmulatorCheckCPU, got %v", result)
	}
}

func TestInferEmulatorCheckType_Ranchu(t *testing.T) {
	p := newTestAnalyzer(nil)
	result := p.inferEmulatorCheckType("ranchu_arm")
	if result != EmulatorCheckCPU {
		t.Errorf("expected EmulatorCheckCPU, got %v", result)
	}
}

func TestInferEmulatorCheckType_Default(t *testing.T) {
	p := newTestAnalyzer(nil)
	result := p.inferEmulatorCheckType("something_else")
	if result != EmulatorCheckBuild {
		t.Errorf("expected EmulatorCheckBuild for default, got %v", result)
	}
}

// ─── extractCryptoAlgorithm ───────────────────────────────────────────────

func TestExtractCryptoAlgorithm_Found(t *testing.T) {
	p := newTestAnalyzer([]Instruction{
		{Opcode: "const-string", Raw: `const-string v0, "AES/CBC/PKCS5Padding"`},
	})
	node := p.cfg.Nodes[0]
	result := p.extractCryptoAlgorithm(node)
	if result != "AES/CBC/PKCS5Padding" {
		t.Errorf("expected AES/CBC/PKCS5Padding, got %q", result)
	}
}

func TestExtractCryptoAlgorithm_NotFound(t *testing.T) {
	p := newTestAnalyzer([]Instruction{
		{Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}"},
	})
	node := p.cfg.Nodes[0]
	result := p.extractCryptoAlgorithm(node)
	if result != "unknown" {
		t.Errorf("expected 'unknown', got %q", result)
	}
}

// ─── checkCryptoWeaknesses ────────────────────────────────────────────────

func TestCheckCryptoWeaknesses_WeakDES(t *testing.T) {
	p := newTestAnalyzer(nil)
	weaknesses := p.checkCryptoWeaknesses("DES")
	if len(weaknesses) == 0 {
		t.Error("expected weaknesses for DES")
	}
}

func TestCheckCryptoWeaknesses_WeakMD5(t *testing.T) {
	p := newTestAnalyzer(nil)
	weaknesses := p.checkCryptoWeaknesses("MD5")
	if len(weaknesses) == 0 {
		t.Error("expected weaknesses for MD5")
	}
}

func TestCheckCryptoWeaknesses_StrongAES(t *testing.T) {
	p := newTestAnalyzer(nil)
	weaknesses := p.checkCryptoWeaknesses("AES")
	if len(weaknesses) != 0 {
		t.Errorf("expected no weaknesses for AES, got %v", weaknesses)
	}
}

// ─── extractLibraryName ───────────────────────────────────────────────────

func TestExtractLibraryName_Found(t *testing.T) {
	p := newTestAnalyzer([]Instruction{
		{Opcode: "const-string", Raw: `const-string v0, "libssl.so"`},
	})
	node := p.cfg.Nodes[0]
	result := p.extractLibraryName(node)
	if result != "libssl.so" {
		t.Errorf("expected 'libssl.so', got %q", result)
	}
}

func TestExtractLibraryName_NotFound(t *testing.T) {
	p := newTestAnalyzer([]Instruction{
		{Opcode: "invoke-virtual", Raw: "invoke-virtual {v0}"},
	})
	node := p.cfg.Nodes[0]
	result := p.extractLibraryName(node)
	if result != "unknown" {
		t.Errorf("expected 'unknown', got %q", result)
	}
}

// ─── isReflectionSuspicious ───────────────────────────────────────────────

func TestIsReflectionSuspicious_True(t *testing.T) {
	p := newTestAnalyzer([]Instruction{
		{Opcode: "invoke-virtual", Raw: "android.os.ServiceManager.getService"},
	})
	node := p.cfg.Nodes[0]
	if !p.isReflectionSuspicious(node) {
		t.Error("expected suspicious=true for ServiceManager")
	}
}

func TestIsReflectionSuspicious_False(t *testing.T) {
	p := newTestAnalyzer([]Instruction{
		{Opcode: "invoke-virtual", Raw: "java.lang.String.valueOf"},
	})
	node := p.cfg.Nodes[0]
	if p.isReflectionSuspicious(node) {
		t.Error("expected suspicious=false for normal call")
	}
}

// ─── hasSSLContext ────────────────────────────────────────────────────────

func TestHasSSLContext_True(t *testing.T) {
	p := newTestAnalyzer([]Instruction{
		{Opcode: "invoke-virtual", Raw: "SSLContext.getInstance"},
	})
	node := p.cfg.Nodes[0]
	if !p.hasSSLContext(node) {
		t.Error("expected hasSSLContext=true")
	}
}

func TestHasSSLContext_HTTPS(t *testing.T) {
	p := newTestAnalyzer([]Instruction{
		{Opcode: "const-string", Raw: `const-string v0, "https://api.example.com"`},
	})
	node := p.cfg.Nodes[0]
	if !p.hasSSLContext(node) {
		t.Error("expected hasSSLContext=true for https")
	}
}

func TestHasSSLContext_False(t *testing.T) {
	p := newTestAnalyzer([]Instruction{
		{Opcode: "const-string", Raw: `const-string v0, "http://api.example.com"`},
	})
	node := p.cfg.Nodes[0]
	if p.hasSSLContext(node) {
		t.Error("expected hasSSLContext=false for plain http")
	}
}

// ─── isNetworkSuspicious ──────────────────────────────────────────────────

func TestIsNetworkSuspicious_PrivateIP(t *testing.T) {
	p := newTestAnalyzer([]Instruction{
		{Opcode: "const-string", Raw: `const-string v0, "192.168.1.100:8080"`},
	})
	node := p.cfg.Nodes[0]
	if !p.isNetworkSuspicious(node) {
		t.Error("expected suspicious=true for private IP")
	}
}

func TestIsNetworkSuspicious_TorProxy(t *testing.T) {
	p := newTestAnalyzer([]Instruction{
		{Opcode: "const-string", Raw: `const-string v0, "foobar.onion"`},
	})
	node := p.cfg.Nodes[0]
	if !p.isNetworkSuspicious(node) {
		t.Error("expected suspicious=true for .onion")
	}
}

func TestIsNetworkSuspicious_False(t *testing.T) {
	p := newTestAnalyzer([]Instruction{
		{Opcode: "const-string", Raw: `const-string v0, "https://api.example.com"`},
	})
	node := p.cfg.Nodes[0]
	if p.isNetworkSuspicious(node) {
		t.Error("expected suspicious=false for normal URL")
	}
}

// ─── containsAny ─────────────────────────────────────────────────────────

func TestContainsAny_Match(t *testing.T) {
	if !containsAny("Hello World", "world") {
		t.Error("expected match (case-insensitive)")
	}
}

func TestContainsAny_NoMatch(t *testing.T) {
	if containsAny("Hello World", "golang") {
		t.Error("expected no match")
	}
}

func TestContainsAny_CaseInsensitive(t *testing.T) {
	if !containsAny("ANDROID", "android") {
		t.Error("expected case-insensitive match")
	}
}

// ─── canReachNode ─────────────────────────────────────────────────────────

func TestCanReachNode_NilNodes(t *testing.T) {
	cfg2 := &ControlFlowGraph{}
	p := NewPatternAnalyzer(cfg2)
	if p.canReachNode(nil, nil, 5) {
		t.Error("expected false for nil nodes")
	}
}

func TestCanReachNode_SameNode(t *testing.T) {
	cfg2 := &ControlFlowGraph{}
	p := NewPatternAnalyzer(cfg2)
	node := &CFGNode{ID: 1}
	if !p.canReachNode(node, node, 5) {
		t.Error("expected true when start == target")
	}
}

func TestCanReachNode_ZeroDepth(t *testing.T) {
	cfg2 := &ControlFlowGraph{}
	p := NewPatternAnalyzer(cfg2)
	a := &CFGNode{ID: 1}
	b := &CFGNode{ID: 2}
	if p.canReachNode(a, b, 0) {
		t.Error("expected false with maxDepth=0")
	}
}

func TestCanReachNode_DirectSuccessor(t *testing.T) {
	cfg2 := &ControlFlowGraph{}
	p := NewPatternAnalyzer(cfg2)
	b := &CFGNode{ID: 2}
	a := &CFGNode{ID: 1, Successors: []*CFGNode{b}}
	if !p.canReachNode(a, b, 5) {
		t.Error("expected true for direct successor")
	}
}

func TestCanReachNode_NotReachable(t *testing.T) {
	cfg2 := &ControlFlowGraph{}
	p := NewPatternAnalyzer(cfg2)
	a := &CFGNode{ID: 1}
	c := &CFGNode{ID: 3}
	b := &CFGNode{ID: 2, Successors: []*CFGNode{}}
	a.Successors = []*CFGNode{b}
	if p.canReachNode(a, c, 5) {
		t.Error("expected false for unreachable node")
	}
}
