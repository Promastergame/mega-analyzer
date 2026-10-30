// Package arbiter wires the pure-Go HDC (hyperdimensional computing) layer in
// pkg/ml/arbiter/hdc into a "precedent similarity" ML signal: cheap,
// explainable, CPU-only, no retraining. It extracts a handful of
// string-bucketed features from a CFG basic block / function, encodes them
// into a hypervector, and compares that vector against a small seeded anchor
// store of known-bad signatures (see arbiter.go).
package arbiter

import (
	"math"
	"regexp"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/matcher"
	"mega-analyzer/pkg/internal/types"
)

// callTargetRE extracts the "Lcom/Foo;->method" call target out of a smali
// invoke instruction's raw text, e.g.
//
//	invoke-virtual {v0}, Lcom/Foo;->isPremium()Z  ->  Lcom/Foo;->isPremium
var callTargetRE = regexp.MustCompile(`L[\w/$]+;->[\w$<>]+`)

// maxAPIBigrams caps how many api2:X→Y feature keys a single block
// contributes, so one large block can't drown out the rest of the signature.
const maxAPIBigrams = 6

// maxTaintBFSDepth bounds the sink-search BFS so pathological/huge CFGs
// (large switch/loop-heavy methods) can't make feature extraction slow.
const maxTaintBFSDepth = 6

// cryptoKeywords / networkKeywords / sinkKeywords are derived once from the
// existing curated pattern set in pkg/internal/matcher (used by the regular
// detector pipeline) instead of hand-rolling a second copy of the same
// literals here.
var (
	cryptoKeywords  = keywordsForCategories(types.CategoryCrypto, types.CategoryWeakCrypto)
	networkKeywords = keywordsForCategories(types.CategoryNetworkCall)
	sinkKeywords    = buildSinkKeywords()
)

// keywordsForCategories pulls the literal (non-regex) Pattern strings out of
// matcher.GetAllPatterns() for the given categories, lowercased for
// case-insensitive substring matching.
func keywordsForCategories(cats ...types.Category) []string {
	want := make(map[types.Category]bool, len(cats))
	for _, c := range cats {
		want[c] = true
	}
	var out []string
	for _, p := range matcher.GetAllPatterns() {
		if !want[p.Category] || p.IsRegex || p.Pattern == "" {
			continue
		}
		out = append(out, strings.ToLower(p.Pattern))
	}
	return out
}

// buildSinkKeywords combines the "sensitive sink" categories already curated
// for the regular detectors (dynamic code loading, native library loading,
// outbound network) with a small, fixed list of well-known dangerous Java/JNI
// sinks that don't have a dedicated matcher category. This backs the taint
// distance feature: "how many CFG hops from here to something dangerous".
func buildSinkKeywords() []string {
	out := keywordsForCategories(types.CategoryDynamicLoad, types.CategoryNetworkCall, types.CategoryNative)
	out = append(out,
		"ljava/lang/runtime;->exec",
		"ljava/lang/processbuilder;",
		"ljava/io/fileoutputstream;",
		"system;->loadlibrary",
		"runtime;->load",
	)
	return out
}

// BlockFeatures extracts a role->value feature map for a single CFG basic
// block, ready to be passed to hdc.EncodeFeatures. Every value is a small,
// bucketed string (never a raw float) since HDC atoms are seeded from
// strings, not numbers.
func BlockFeatures(node *cfg.CFGNode) map[string]string {
	feats := map[string]string{}
	if node == nil || len(node.Instructions) == 0 {
		return feats
	}

	raw := joinRaw(node)
	feats["entropy"] = bucketEntropy(shannonEntropy(raw))
	feats["crypto_ratio"] = bucketRatio(opcodeRatio(node, cryptoKeywords))
	feats["network_ratio"] = bucketRatio(opcodeRatio(node, networkKeywords))
	feats["taint_dist"] = bucketDistance(taintDistanceToSink(node))

	for i, bigram := range apiBigrams(node) {
		if i >= maxAPIBigrams {
			break
		}
		feats["api2:"+bigram] = "1"
	}

	return feats
}

func joinRaw(node *cfg.CFGNode) string {
	var b strings.Builder
	for _, instr := range node.Instructions {
		b.WriteString(instr.Raw)
		b.WriteByte('\n')
	}
	return b.String()
}

// shannonEntropy computes the byte-level Shannon entropy (bits/byte) of s.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

func bucketEntropy(h float64) string {
	switch {
	case h < 3.0:
		return "low"
	case h < 5.0:
		return "medium"
	default:
		return "high"
	}
}

// opcodeRatio returns the fraction of instructions in node whose raw text
// contains any of the given (already-lowercased) keywords.
func opcodeRatio(node *cfg.CFGNode, keywords []string) float64 {
	if len(node.Instructions) == 0 || len(keywords) == 0 {
		return 0
	}
	matched := 0
	for _, instr := range node.Instructions {
		lower := strings.ToLower(instr.Raw)
		for _, kw := range keywords {
			if strings.Contains(lower, kw) {
				matched++
				break
			}
		}
	}
	return float64(matched) / float64(len(node.Instructions))
}

func bucketRatio(r float64) string {
	switch {
	case r < 0.15:
		return "low"
	case r < 0.4:
		return "medium"
	default:
		return "high"
	}
}

// apiBigrams returns "TargetA→TargetB" tokens for consecutive invoke
// instructions within the block, in order, deduplicated.
func apiBigrams(node *cfg.CFGNode) []string {
	var targets []string
	for _, instr := range node.Instructions {
		if !strings.HasPrefix(instr.Opcode, "invoke") {
			continue
		}
		t := callTargetRE.FindString(instr.Raw)
		if t == "" {
			continue
		}
		targets = append(targets, t)
	}
	if len(targets) < 2 {
		return nil
	}

	seen := map[string]bool{}
	var bigrams []string
	for i := 0; i+1 < len(targets); i++ {
		bg := targets[i] + "→" + targets[i+1] // "→"
		if seen[bg] {
			continue
		}
		seen[bg] = true
		bigrams = append(bigrams, bg)
	}
	sort.Strings(bigrams) // deterministic order
	return bigrams
}

// taintDistanceToSink runs a bounded BFS over the CFG successors starting at
// node, looking for the nearest block (including node itself) whose
// instructions contain a sensitive-sink keyword. Returns -1 if none is found
// within maxTaintBFSDepth hops.
func taintDistanceToSink(node *cfg.CFGNode) int {
	if node == nil {
		return -1
	}
	visited := map[int]bool{node.ID: true}
	queue := []*cfg.CFGNode{node}
	depth := 0

	for len(queue) > 0 && depth <= maxTaintBFSDepth {
		next := make([]*cfg.CFGNode, 0, len(queue))
		for _, n := range queue {
			if blockHasSink(n) {
				return depth
			}
			for _, succ := range n.Successors {
				if succ == nil || visited[succ.ID] {
					continue
				}
				visited[succ.ID] = true
				next = append(next, succ)
			}
		}
		queue = next
		depth++
	}
	return -1
}

func blockHasSink(node *cfg.CFGNode) bool {
	for _, instr := range node.Instructions {
		lower := strings.ToLower(instr.Raw)
		for _, kw := range sinkKeywords {
			if strings.Contains(lower, kw) {
				return true
			}
		}
	}
	return false
}

func bucketDistance(d int) string {
	switch {
	case d < 0:
		return "none"
	case d == 0:
		return "0"
	case d == 1:
		return "1"
	case d == 2:
		return "2"
	default:
		return "3+"
	}
}
