// Package gnngraph converts analyzer control-flow graphs into the CSR graph
// tensors consumed by the GNN vulnerability classifier.
//
// It lives in its own internal package (rather than pkg/cmd/analyzer) so the
// scan hot path can be unit-tested and benchmarked in isolation, without
// pulling in the analyzer's externally-dependent build graph.
package gnngraph

import (
	"slices"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml/gnn"
)

// FeatureDim is the per-node feature vector width expected by the model.
const FeatureDim = 36

// Feature slots 0-27 are structural (see extractInto); 28-35 are semantic
// API/string signals added in v3 so structurally identical methods with
// different call targets (a license stub vs a benign lambda) stop colliding.
const (
	featAPILicense    = 28 // invoke -> *licens* / *billing* (LVL, Play Billing, DRM license clients)
	featAPIReflection = 29 // invoke -> java/lang/reflect, forName, newInstance, getDeclared*
	featAPIDynLoad    = 30 // invoke -> *ClassLoader, DexFile, loadDex/defineClass/loadClass
	featAPICrypto     = 31 // invoke -> javax/crypto, java/security (Cipher, Digest, Signature, Mac)
	featAPIPkgSig     = 32 // invoke getPackageInfo/getPackageArchiveInfo/SigningInfo, field signatures
	featAPINative     = 33 // System/Runtime.loadLibrary/load
	featStrURL        = 34 // const-string with a URI scheme (http/https/content/file/ftp)
	featStrLicenseKw  = 35 // const-string with licens/premium/subscri/trial/activat
)

// FeatureSchemaID identifies the MEANING of the node features, not just
// their count. Bump it whenever extractInto changes what a slot measures
// (normalization, opcode bucketing, operand/branch semantics) — a model
// trained on a different schema reads valid-looking numbers that mean
// something else.
//
// v1: feature 16 counts commas in the raw instruction text; if-* does not set
//     the comparison flag (feature 20).
// v2: feature 16 counts typed operands; if-* sets the comparison flag.
//
// v3: 8 semantic slots appended (28-35: API buckets + string signals, see
//     above). Width changes 28 -> 36, so v1/v2 tensors are rejected by
//     dimension check as well as by schema id.
//
// Records without this field are legacy (pre-v2) and must not be mixed into a
// v2 training set; the Rust loader skips foreign schemas and reports legacy
// ones.
const FeatureSchemaID = "smali-cfg-v3"

// Builder turns control-flow graphs into deterministic CSR tensors while
// reusing scratch buffers between calls: converting the tens of thousands of
// small graphs in a typical APK scan allocates the node-index map and the
// successor scratch slice once per worker instead of once per graph (and the
// old per-node `seen` map plus per-node feature slice are gone entirely).
//
// A Builder is NOT safe for concurrent use; create one per worker goroutine.
// The zero value is ready to use.
type Builder struct {
	nodeToIndex map[*cfg.CFGNode]int
	succScratch []int
}

// Build converts a control-flow graph into a deterministic CSR tensor.
// Every row receives an explicit self-loop and EdgeTypes stays aligned with
// ColIndices. Supplying a complete tensor here avoids FFI-side CSR mutation.
//
// The output is bit-for-bit identical to the historical builder in
// pkg/cmd/analyzer, so run-local memo keys and persistent GNN cache keys
// derived from these tensors remain valid.
func (b *Builder) Build(gCFG *cfg.ControlFlowGraph) *gnn.Graph {
	if gCFG == nil || len(gCFG.Nodes) == 0 {
		return nil
	}
	numNodes := len(gCFG.Nodes)
	if b.nodeToIndex == nil {
		b.nodeToIndex = make(map[*cfg.CFGNode]int, numNodes)
	} else {
		clear(b.nodeToIndex)
	}
	nodeToIndex := b.nodeToIndex
	for idx, node := range gCFG.Nodes {
		if node != nil {
			nodeToIndex[node] = idx
		}
	}

	rowPtrs := make([]uint64, numNodes+1)
	colIndices := make([]uint64, 0, numNodes*2)
	edgeTypes := make([]uint32, 0, numNodes*2)
	// One zeroed allocation for the whole feature matrix; rows are filled in
	// place instead of allocating a FeatureDim-float slice per node and
	// copying it over with append.
	flatFeatures := make([]float32, numNodes*FeatureDim)

	for i, node := range gCFG.Nodes {
		rowPtrs[i] = uint64(len(colIndices))
		if node == nil {
			// Features stay all-zero; the row still gets its self-loop.
			colIndices = append(colIndices, uint64(i))
			edgeTypes = append(edgeTypes, gnn.EdgeSelfLoop)
			continue
		}

		// Collect known successor indices into the reusable scratch and
		// sort them; skipping adjacent duplicates below replaces the old
		// per-node `seen` map allocation.
		succs := b.succScratch[:0]
		for _, succ := range node.Successors {
			if succ == nil {
				continue
			}
			if succIdx, ok := nodeToIndex[succ]; ok {
				succs = append(succs, succIdx)
			}
		}
		slices.Sort(succs)
		b.succScratch = succs

		// Emit unique successors in ascending order with the explicit
		// self-loop placed exactly where the old (index, edgeType) sort put
		// it: EdgeControlFlow(0) sorts before EdgeSelfLoop(4) on the same
		// column, so a real self-edge precedes the identity loop.
		selfEmitted := false
		prev := -1
		for _, succIdx := range succs {
			if succIdx == prev {
				continue // duplicate successor
			}
			prev = succIdx
			if !selfEmitted && succIdx > i {
				colIndices = append(colIndices, uint64(i))
				edgeTypes = append(edgeTypes, gnn.EdgeSelfLoop)
				selfEmitted = true
			}
			colIndices = append(colIndices, uint64(succIdx))
			edgeTypes = append(edgeTypes, gnn.EdgeControlFlow)
			if succIdx == i {
				colIndices = append(colIndices, uint64(i))
				edgeTypes = append(edgeTypes, gnn.EdgeSelfLoop)
				selfEmitted = true
			}
		}
		if !selfEmitted {
			colIndices = append(colIndices, uint64(i))
			edgeTypes = append(edgeTypes, gnn.EdgeSelfLoop)
		}

		extractInto(flatFeatures[i*FeatureDim:(i+1)*FeatureDim], node, numNodes)
	}
	rowPtrs[numNodes] = uint64(len(colIndices))

	return &gnn.Graph{
		RowPtrs: rowPtrs, ColIndices: colIndices, EdgeTypes: edgeTypes,
		Features: flatFeatures, NumNodes: uint64(numNodes), FeatureDim: FeatureDim,
	}
}

// Build converts a CFG using a throwaway Builder. Hot loops should hold one
// Builder per worker and call its method instead to reuse scratch buffers.
func Build(gCFG *cfg.ControlFlowGraph) *gnn.Graph {
	var b Builder
	return b.Build(gCFG)
}

// ExtractFeatures mirrors Rust FeatureExtractor exactly. Keeping training
// and serving normalization identical is part of the on-disk model contract.
func ExtractFeatures(node *cfg.CFGNode, numNodes int) []float32 {
	features := make([]float32, FeatureDim)
	extractInto(features, node, numNodes)
	return features
}

// extractInto fills dst (length FeatureDim, all zeros) with node features.
func extractInto(dst []float32, node *cfg.CFGNode, numNodes int) {
	if node == nil {
		return
	}

	var opcodeHistogram [16]uint32
	var operandCount uint32
	isBranch, isCall, isMemory, isComparison := false, false, false, false
	var apiFlags uint32
	for _, inst := range node.Instructions {
		op := inst.Opcode
		switch {
		case hasPrefixFold(op, "monitor-"):
			opcodeHistogram[9]++
		case hasPrefixFold(op, "throw") || hasPrefixFold(op, "move-exception"):
			opcodeHistogram[10]++
		case hasPrefixFold(op, "return"):
			opcodeHistogram[11]++
		case hasPrefixFold(op, "const") || hasPrefixFold(op, "iget") || hasPrefixFold(op, "sget") || hasPrefixFold(op, "aget"):
			opcodeHistogram[0]++
			isMemory = isMemory || hasPrefixFold(op, "iget") || hasPrefixFold(op, "sget") || hasPrefixFold(op, "aget")
		case hasPrefixFold(op, "iput") || hasPrefixFold(op, "sput") || hasPrefixFold(op, "aput"):
			opcodeHistogram[1]++
			isMemory = true
		case hasPrefixFold(op, "if-") || hasPrefixFold(op, "goto") || hasPrefixFold(op, "packed-switch") || hasPrefixFold(op, "sparse-switch"):
			opcodeHistogram[3]++
			isBranch = true
			// if-* is a conditional comparison against zero or another
			// register; only cmp* used to set this flag, so the model saw
			// every guarded branch as "not a comparison".
			if hasPrefixFold(op, "if-") {
				isComparison = true
			}
		case hasPrefixFold(op, "invoke-"):
			opcodeHistogram[4]++
			isCall = true
		case hasPrefixFold(op, "move"):
			opcodeHistogram[5]++
		case hasPrefixFold(op, "cmp"):
			opcodeHistogram[6]++
			isComparison = true
		case containsFold(op, "array") || hasPrefixFold(op, "fill-"):
			opcodeHistogram[7]++
		case hasPrefixFold(op, "new-instance") || hasPrefixFold(op, "check-cast") || hasPrefixFold(op, "instance-of"):
			opcodeHistogram[8]++
		case containsFold(op, "-to-"):
			opcodeHistogram[12]++
		case hasPrefixFold(op, "neg-") || hasPrefixFold(op, "not-"):
			opcodeHistogram[13]++
		case hasPrefixFold(op, "nop"):
			opcodeHistogram[14]++
		case containsFold(op, "add") || containsFold(op, "sub") || containsFold(op, "mul") || containsFold(op, "div") ||
			containsFold(op, "rem") || containsFold(op, "and") || containsFold(op, "or") || containsFold(op, "xor") ||
			containsFold(op, "shl") || containsFold(op, "shr") || containsFold(op, "ushr"):
			opcodeHistogram[2]++
		default:
			opcodeHistogram[15]++
		}
		operandCount += uint32(inst.OperandCount())
		apiFlags |= apiFlagsFor(inst)
	}

	totalOpcodes := uint32(0)
	for _, count := range opcodeHistogram {
		totalOpcodes += count
	}
	if totalOpcodes > 0 {
		for i := range opcodeHistogram {
			dst[i] = float32(opcodeHistogram[i]) / float32(totalOpcodes)
		}
	}
	if operandCount > 10 {
		operandCount = 10
	}
	dst[16] = float32(operandCount) / 10.0
	dst[17] = boolFeature(isBranch)
	dst[18] = boolFeature(isCall)
	dst[19] = boolFeature(isMemory)
	dst[20] = boolFeature(isComparison)
	dst[21] = float32(minInt(len(node.Predecessors), 20)) / 20.0
	dst[22] = float32(minInt(len(node.Successors), 20)) / 20.0
	dst[23] = float32(minInt(len(node.Instructions), 100)) / 100.0
	dst[24] = float32(minInt(node.LoopDepth, 10)) / 10.0
	if numNodes > 1 {
		dst[25] = minFloat32(float32(len(node.Dominators))/float32(numNodes), 1)
	} else {
		dst[25] = 1
	}
	dst[26] = boolFeature(node.Type == cfg.NodeTypeCatch || node.Type == cfg.NodeTypeThrow)
	dst[27] = boolFeature(node.Type == cfg.NodeTypeEntry)
	for i := 0; i < 8; i++ {
		dst[28+i] = boolFeature(apiFlags&(1<<uint(i)) != 0)
	}
}

// apiFlag bits align with feature slots 28-35 (bit 0 -> slot 28).
const (
	apiLicenseBit    uint32 = 1 << 0
	apiReflectionBit uint32 = 1 << 1
	apiDynLoadBit    uint32 = 1 << 2
	apiCryptoBit     uint32 = 1 << 3
	apiPkgSigBit     uint32 = 1 << 4
	apiNativeBit     uint32 = 1 << 5
	strURLBit        uint32 = 1 << 6
	strLicenseKwBit  uint32 = 1 << 7
)

// apiFlagsFor classifies one instruction's semantic signals: the invoke
// target bucket (licensing, reflection, dynamic loading, crypto, package
// signatures, native loading) and const-string content (URLs, license
// keywords). Typed IR is preferred; raw text is the fallback for hand-built
// graphs without IR, so serving and tests agree.
func apiFlagsFor(inst cfg.InstructionRef) uint32 {
	var flags uint32
	if hasPrefixFold(inst.Opcode, "invoke-") {
		class, name, ok := invokeTarget(inst)
		if ok {
			target := class + "->" + name
			switch {
			case containsFold(target, "licens") || containsFold(target, "billing"):
				flags |= apiLicenseBit
			case containsFold(class, "java/lang/reflect") || apiName(name, "forName", "newInstance", "getDeclaredMethod", "getMethod", "getDeclaredField", "getDeclaredConstructor"):
				flags |= apiReflectionBit
			case containsFold(class, "ClassLoader") || containsFold(class, "DexFile") || containsFold(class, "dalvik/system") || apiName(name, "loadDex", "defineClass", "loadClass"):
				flags |= apiDynLoadBit
			case containsFold(class, "javax/crypto") || containsFold(class, "java/security"):
				flags |= apiCryptoBit
			case name == "getPackageInfo" || name == "getPackageArchiveInfo" || containsFold(target, "SigningInfo"):
				flags |= apiPkgSigBit
			case name == "loadLibrary" || (name == "load" && (containsFold(class, "lang/System") || containsFold(class, "lang/Runtime"))):
				flags |= apiNativeBit
			}
		}
	} else if hasPrefixFold(inst.Opcode, "const-string") {
		if s, ok := constString(inst); ok {
			switch {
			case containsFold(s, "http://") || containsFold(s, "https://") || containsFold(s, "content://") || containsFold(s, "file://") || containsFold(s, "ftp://"):
				flags |= strURLBit
			case containsFold(s, "licens") || containsFold(s, "premium") || containsFold(s, "subscri") || containsFold(s, "trial") || containsFold(s, "activat"):
				flags |= strLicenseKwBit
			}
		}
	} else if hasPrefixFold(inst.Opcode, "iget") || hasPrefixFold(inst.Opcode, "sget") ||
		hasPrefixFold(inst.Opcode, "iput") || hasPrefixFold(inst.Opcode, "sput") {
		if field, ok := invokeField(inst); ok {
			if field == "signatures" || containsFold(field, "SigningInfo") {
				flags |= apiPkgSigBit
			}
		}
	}
	return flags
}

// apiName reports whether name equals one of the candidates (exact,
// case-sensitive: Dalvik method names are case-significant).
func apiName(name string, candidates ...string) bool {
	for _, c := range candidates {
		if name == c {
			return true
		}
	}
	return false
}

// invokeTarget returns the (class, method) of an invoke instruction from
// typed IR, falling back to the raw method token ("Lcls;->name(proto)ret").
func invokeTarget(inst cfg.InstructionRef) (string, string, bool) {
	if inst.IR != nil && inst.IR.Method != nil {
		return inst.IR.Method.Class, inst.IR.Method.Name, true
	}
	raw := inst.Raw
	arrow := indexOf(raw, "->")
	if arrow < 0 {
		return "", "", false
	}
	class := lastTokenBefore(raw[:arrow])
	rest := raw[arrow+2:]
	name := rest
	if open := indexByte(rest, '('); open >= 0 {
		name = rest[:open]
	}
	name = trimSpace(name)
	if class == "" || name == "" {
		return "", "", false
	}
	return class, name, true
}

// invokeField returns the field name of a field-access instruction from
// typed IR, falling back to the raw field token ("Lcls;->name:type").
func invokeField(inst cfg.InstructionRef) (string, bool) {
	if inst.IR != nil && inst.IR.Field != nil {
		return inst.IR.Field.Name, true
	}
	raw := inst.Raw
	arrow := indexOf(raw, "->")
	if arrow < 0 {
		return "", false
	}
	rest := raw[arrow+2:]
	name := rest
	if colon := indexByte(rest, ':'); colon >= 0 {
		name = rest[:colon]
	}
	name = trimSpace(name)
	if name == "" {
		return "", false
	}
	return name, true
}

// constString returns the const-string literal from typed IR, falling back
// to the quoted span of the raw text.
func constString(inst cfg.InstructionRef) (string, bool) {
	if inst.IR != nil && inst.IR.HasStr {
		return inst.IR.Str, true
	}
	raw := inst.Raw
	first := indexByte(raw, '"')
	last := lastIndexByte(raw, '"')
	if first < 0 || last <= first {
		return "", false
	}
	return raw[first+1 : last], true
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if s[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// lastTokenBefore returns the last whitespace-separated token of s (the
// method/field reference in "invoke-X {regs}, Lcls;->name...").
func lastTokenBefore(s string) string {
	end := len(s)
	for end > 0 && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	start := end
	for start > 0 && s[start-1] != ' ' && s[start-1] != '\t' && s[start-1] != ',' {
		start--
	}
	return s[start:end]
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r' || s[0] == '\n') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r' || s[len(s)-1] == '\n') {
		s = s[:len(s)-1]
	}
	return s
}

func boolFeature(v bool) float32 {
	if v {
		return 1
	}
	return 0
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minFloat32(a, b float32) float32 {
	if a < b {
		return a
	}
	return b
}

// hasPrefixFold reports whether s starts with the all-lowercase ASCII
// prefix, ignoring ASCII case in s. Equivalent to
// strings.HasPrefix(strings.ToLower(s), prefix) for the pure-ASCII smali
// opcodes handled here, without allocating a lowered copy of every opcode on
// the feature-extraction hot path.
func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != prefix[i] {
			return false
		}
	}
	return true
}

// containsFold reports whether s contains the all-lowercase ASCII substr,
// ignoring ASCII case in s. Allocation-free counterpart of
// strings.Contains(strings.ToLower(s), substr).
func containsFold(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if hasPrefixFold(s[i:], substr) {
			return true
		}
	}
	return false
}

// BuildMethodCFG builds a control-flow graph for a single smali method from its
// raw body lines. Returns nil when the method has no analyzable instructions.
func BuildMethodCFG(builder *cfg.CFGBuilder, className string, m *types.SmaliMethod) *cfg.ControlFlowGraph {
	if m == nil || len(m.Body) == 0 {
		return nil
	}
	input := cfg.BuildInputFromLines(className, m.Name, m.Params+m.ReturnType, m.Body)
	if len(input.Instructions) == 0 {
		return nil
	}
	if builder == nil {
		builder = cfg.NewCFGBuilder()
	}
	return builder.Build(input)
}

// MinChainInstructions is the smallest straight-line body that gets a
// chain-fallback graph: one node per instruction, so fewer instructions
// cannot reach the 3-node minimum the classifier needs for message passing.
const MinChainInstructions = 3

// BuildChainCFG builds a linear instruction-chain CFG for straight-line
// methods whose real CFG collapses to fewer than 3 blocks (the dominant
// cfg-less cause: ~70% of methods in game APKs are a single basic block).
//
// Each instruction becomes one node chained to the next. The result flows
// through the same Builder.Build as block CFGs, so CSR layout, self-loops
// and the 28-dim features stay comparable — but the provenance differs
// (per-instruction one-hot histograms vs per-block averages), so callers
// must mark graphs built from it (dataset notes, fallback counters) and
// must NOT mix them into training sets silently.
//
// Returns nil when the body has fewer than MinChainInstructions executable
// instructions. Graphs that exceed the serving tensor budget are returned
// as-is; callers apply the usual gnnGraphWithinBudget check.
func BuildChainCFG(className string, m *types.SmaliMethod) *cfg.ControlFlowGraph {
	if m == nil || len(m.Body) == 0 {
		return nil
	}
	input := cfg.BuildInputFromLines(className, m.Name, m.Params+m.ReturnType, m.Body)
	if len(input.Instructions) < MinChainInstructions {
		return nil
	}
	n := len(input.Instructions)
	nodes := make([]*cfg.CFGNode, n)
	for i, ins := range input.Instructions {
		nodeType := cfg.NodeTypeBasic
		if i == 0 {
			nodeType = cfg.NodeTypeEntry
		}
		nodes[i] = &cfg.CFGNode{
			ID:       i,
			Type:     nodeType,
			StartIdx: i,
			EndIdx:   i,
			Instructions: []cfg.InstructionRef{{
				Index: i, Opcode: ins.Opcode, Line: ins.Line, Raw: ins.Raw, IR: ins.IR,
			}},
		}
	}
	for i := range nodes {
		if i > 0 {
			nodes[i].Predecessors = []*cfg.CFGNode{nodes[i-1]}
		}
		if i+1 < n {
			nodes[i].Successors = []*cfg.CFGNode{nodes[i+1]}
		}
	}
	signature := m.Params + m.ReturnType
	return &cfg.ControlFlowGraph{
		MethodName: m.Name,
		ClassName:  className,
		Signature:  signature,
		// Same rendering as cfg.buildFullName (Class->methodSignature).
		FullName: className + "->" + m.Name + signature,
		Nodes:    nodes,
		Entry:    nodes[0],
	}
}
