package apkloader

import (
	"fmt"
	"strings"
)

// MethodProfile is the result of pre-patch analysis.
type MethodProfile struct {
	ReturnCount    int
	InvokeCount    int
	HasTryCatch    bool
	HasSwitch      bool
	IsComplex      bool
	Complexity     string
	ReturnType     string
	ReturnPCs      []uint32
	TryCatchRanges [][2]uint32

	// Semantic hints detected from invoke targets
	LikelyPayment      bool
	LikelyRegistration bool
	LikelyAntiTamper   bool
	LikelySSLPinning   bool
	LikelyEmulator     bool
	LikelyNetworking   bool
	LikelyCrypto       bool
	LikelyReflection   bool
	LikelyFileIO       bool
	LikelyShell        bool
	LikelyDatabase     bool
	ServerURLRefs      []uint32 // PCs of const-string instructions referencing URLs
}

// Analyze inspects a RawInsn stream and returns a MethodProfile.
func Analyze(insns []RawInsn, code *CodeItem) MethodProfile {
	p := MethodProfile{}

	for i := range insns {
		insn := &insns[i]
		switch {
		case insn.IsReturn():
			p.ReturnCount++
			p.ReturnPCs = append(p.ReturnPCs, insn.Offset)
			if p.ReturnType == "" {
				p.ReturnType = returnType(insn.Op)
			}
		case insn.IsInvoke():
			p.InvokeCount++
		case insn.IsSwitch():
			p.HasSwitch = true
		case insn.IsConst():
			// track const-string for URL detection (caller resolves string table)
			p.ServerURLRefs = append(p.ServerURLRefs, insn.Offset)
		}
	}

	if code != nil && len(code.Tries) > 0 {
		p.HasTryCatch = true
		for _, t := range code.Tries {
			p.TryCatchRanges = append(p.TryCatchRanges, [2]uint32{t.StartAddr, t.StartAddr + uint32(t.InsnCount)})
		}
	}

	switch {
	case p.ReturnCount == 0:
		p.IsComplex = true
		p.Complexity = "no_return_found"
	case p.HasTryCatch && p.InvokeCount > 3:
		p.IsComplex = true
		p.Complexity = fmt.Sprintf("try_catch+%d_invokes", p.InvokeCount)
	case p.ReturnCount > 4:
		p.IsComplex = true
		p.Complexity = fmt.Sprintf("%d_return_sites", p.ReturnCount)
	case p.HasSwitch:
		p.IsComplex = true
		p.Complexity = "switch_statement"
	}

	return p
}

// AnalyzeWithNames performs semantic analysis using method/string names.
// Pass the method name and a resolver that maps string index → string value.
func AnalyzeWithNames(insns []RawInsn, code *CodeItem, methodName string, stringAt func(uint32) string) MethodProfile {
	p := Analyze(insns, code)

	name := strings.ToLower(methodName)

	paymentKW := []string{"purchase", "billing", "payment", "iap", "subscribe", "premium", "buy", "order"}
	regKW := []string{"register", "activate", "license", "serial", "auth", "login", "signup", "trial", "verify"}
	tamperKW := []string{"integrity", "tamper", "signature", "cert", "checksum", "hash"}
	sslKW := []string{"pinning", "checkservertrusted", "verify", "pinnedcert", "getpinnedcerts"}
	emuKW := []string{"emulator", "isemulator", "genymotion", "bluestacks", "nox", "qemu"}
	netKW := []string{"http", "url", "connect", "request", "download", "upload", "socket", "proxy", "webview"}
	cryptoKW := []string{"crypto", "cipher", "encrypt", "decrypt", "digest", "aes", "rsa", "md5", "sha"}
	reflKW := []string{"reflect", "getmethod", "getfield", "invoke", "classforname", "declared"}
	fileKW := []string{"file", "path", "open", "read", "write", "stream", "asset", "cache"}
	shellKW := []string{"exec", "runtime", "command", "process", "shell", "su", "/system/bin/"}
	dbKW := []string{"database", "sql", "query", "insert", "update", "delete", "cursor", "contentresolver"}

	for _, kw := range paymentKW {
		if strings.Contains(name, kw) {
			p.LikelyPayment = true
			break
		}
	}
	for _, kw := range regKW {
		if strings.Contains(name, kw) {
			p.LikelyRegistration = true
			break
		}
	}
	for _, kw := range tamperKW {
		if strings.Contains(name, kw) {
			p.LikelyAntiTamper = true
			break
		}
	}
	for _, kw := range sslKW {
		if strings.Contains(name, kw) {
			p.LikelySSLPinning = true
			break
		}
	}
	for _, kw := range emuKW {
		if strings.Contains(name, kw) {
			p.LikelyEmulator = true
			break
		}
	}
	for _, kw := range netKW {
		if strings.Contains(name, kw) {
			p.LikelyNetworking = true
			break
		}
	}
	for _, kw := range cryptoKW {
		if strings.Contains(name, kw) {
			p.LikelyCrypto = true
			break
		}
	}
	for _, kw := range reflKW {
		if strings.Contains(name, kw) {
			p.LikelyReflection = true
			break
		}
	}
	for _, kw := range fileKW {
		if strings.Contains(name, kw) {
			p.LikelyFileIO = true
			break
		}
	}
	for _, kw := range shellKW {
		if strings.Contains(name, kw) {
			p.LikelyShell = true
			break
		}
	}
	for _, kw := range dbKW {
		if strings.Contains(name, kw) {
			p.LikelyDatabase = true
			break
		}
	}

	// Scan const-string refs for URL patterns and semantic keywords
	if stringAt != nil {
		urlRefs := p.ServerURLRefs[:0]
		for _, pc := range p.ServerURLRefs {
			idx := p.findConstStringIdx(insns, pc)
			if idx == ^uint32(0) {
				continue
			}
			s := strings.ToLower(stringAt(idx))
			if strings.HasPrefix(s, "http") || strings.HasPrefix(s, "ws") {
				urlRefs = append(urlRefs, pc)
			}
			for _, kw := range paymentKW {
				if strings.Contains(s, kw) {
					p.LikelyPayment = true
				}
			}
			for _, kw := range sslKW {
				if strings.Contains(s, kw) {
					p.LikelySSLPinning = true
				}
			}
			for _, kw := range cryptoKW {
				if strings.Contains(s, kw) {
					p.LikelyCrypto = true
				}
			}
			for _, kw := range shellKW {
				if strings.Contains(s, kw) {
					p.LikelyShell = true
				}
			}
		}
		p.ServerURLRefs = urlRefs
	}

	return p
}

func (p *MethodProfile) findConstStringIdx(insns []RawInsn, pc uint32) uint32 {
	for i, insn := range insns {
		if insn.Offset != pc {
			continue
		}
		if insn.Op == 0x1a && i+1 < len(insns) {
			return insn.RefIdx
		}
		if insn.Op == 0x1b {
			return insn.RefIdx
		}
	}
	return ^uint32(0)
}

// RecommendPatchType suggests the most appropriate PatchType for a method.
func RecommendPatchType(p MethodProfile) PatchType {
	switch {
	case p.LikelySSLPinning:
		return PatchBypassSSLAt
	case p.LikelyAntiTamper:
		return PatchBypassAntiTamper
	case p.LikelyEmulator:
		return PatchBypassEmulator
	case p.LikelyPayment:
		return PatchBypassPayment
	case p.LikelyRegistration:
		return PatchBypassRegistration
	case p.LikelyShell || p.LikelyCrypto:
		return PatchReturnTrue // Common for check methods
	case p.ReturnType == "void":
		return PatchReturnVoid
	case p.ReturnType == "bool" || p.ReturnType == "int":
		return PatchReturnTrue
	default:
		return PatchReturnTrue
	}
}

// SafePatchStrategy recommends a patch approach based on the profile.
type SafePatchStrategy int

const (
	StrategyHardReplace SafePatchStrategy = iota
	StrategySoftGuard
	StrategyCondInvert
	StrategyUnsafe
)

// RecommendStrategy returns the safest patch strategy for a boolean method.
func RecommendStrategy(p MethodProfile) SafePatchStrategy {
	if p.ReturnCount == 0 {
		return StrategyUnsafe
	}
	if p.IsComplex {
		return StrategySoftGuard
	}
	if p.ReturnCount == 1 && !p.HasTryCatch {
		return StrategyHardReplace
	}
	return StrategySoftGuard
}

func returnType(op uint8) string {
	switch op {
	case 0x0E:
		return "void"
	case 0x0F:
		return "int"
	case 0x10:
		return "wide"
	case 0x11:
		return "object"
	default:
		return "unknown"
	}
}
