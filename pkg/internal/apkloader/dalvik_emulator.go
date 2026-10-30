package apkloader

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// DalvikEmulationStatus describes a deterministic bounded execution outcome.
type DalvikEmulationStatus string

const (
	DalvikEmulationRecovered       DalvikEmulationStatus = "recovered"
	DalvikEmulationNoOutput        DalvikEmulationStatus = "no_output"
	DalvikEmulationAbstained       DalvikEmulationStatus = "abstained"
	DalvikEmulationBudgetExhausted DalvikEmulationStatus = "budget_exhausted"
	DalvikEmulationCancelled       DalvikEmulationStatus = "cancelled"
)

// DalvikEmulatorConfig bounds every resource controlled by bytecode.
type DalvikEmulatorConfig struct {
	MaxSteps                  int
	MaxVisitsPerOffset        int
	MaxBranches               int
	MaxSwitchEntries          int
	MaxAllocations            int
	MaxArrayElements          int
	MaxAllocatedBytes         int
	MaxStringBytes            int
	MaxTraceEntries           int
	MaxRecoveredValues        int
	MaxCallDepth              int
	MaxInterproceduralMethods int
	MaxCacheEntries           int
	MaxProofEntries           int
}

func DefaultDalvikEmulatorConfig() DalvikEmulatorConfig {
	return DalvikEmulatorConfig{
		MaxSteps: 10000, MaxVisitsPerOffset: 256, MaxBranches: 2048,
		MaxSwitchEntries: 512, MaxAllocations: 128, MaxArrayElements: 65536,
		MaxAllocatedBytes: 1 << 20, MaxStringBytes: 1 << 16,
		MaxTraceEntries: 64, MaxRecoveredValues: 8,
		MaxCallDepth: 3, MaxInterproceduralMethods: 64, MaxCacheEntries: 128,
		MaxProofEntries: 128,
	}
}

// DalvikRecoveredValue is accepted only for a concrete transformed string.
type DalvikRecoveredValue struct {
	Value      string   `json:"value"`
	Offset     uint32   `json:"offset"`
	Source     string   `json:"source"`
	Proof      string   `json:"proof"`
	Operations []string `json:"operations,omitempty"`
}

// DalvikCallProof is deterministic interprocedural provenance.
type DalvikCallProof struct {
	Caller          string   `json:"caller"`
	Callee          string   `json:"callee"`
	Offset          uint32   `json:"offset"`
	Depth           int      `json:"depth"`
	Digest          string   `json:"digest,omitempty"`
	ArgumentSummary []string `json:"argument_summary,omitempty"`
	Status          string   `json:"status"`
	Reason          string   `json:"reason,omitempty"`
	CacheHit        bool     `json:"cache_hit,omitempty"`
}

// DalvikStaticProof records immutable reads and transactional writes.
type DalvikStaticProof struct {
	ClassName string `json:"class,omitempty"`
	Field     string `json:"field"`
	Operation string `json:"operation"`
	Offset    uint32 `json:"offset,omitempty"`
	State     string `json:"state,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// DalvikCallMetrics summarizes bounded app-defined calls.
type DalvikCallMetrics struct {
	Attempts   int `json:"attempts,omitempty"`
	Completed  int `json:"completed,omitempty"`
	CacheHits  int `json:"cache_hits,omitempty"`
	Recursions int `json:"recursions,omitempty"`
	Impure     int `json:"impure,omitempty"`
	Unresolved int `json:"unresolved,omitempty"`
	Budgeted   int `json:"budgeted,omitempty"`
}

// DalvikEmulationResult is separate from Hyperion's transformation journal.
type DalvikEmulationResult struct {
	Status          DalvikEmulationStatus  `json:"status"`
	StopReason      string                 `json:"stop_reason,omitempty"`
	Steps           int                    `json:"steps,omitempty"`
	Branches        int                    `json:"branches,omitempty"`
	Allocations     int                    `json:"allocations,omitempty"`
	RecoveredValues []DalvikRecoveredValue `json:"recovered_values,omitempty"`
	CallProofs      []DalvikCallProof      `json:"call_proofs,omitempty"`
	StaticProofs    []DalvikStaticProof    `json:"static_proofs,omitempty"`
	CallMetrics     DalvikCallMetrics      `json:"call_metrics,omitempty"`
	Trace           []string               `json:"trace,omitempty"`
	TraceTruncated  bool                   `json:"trace_truncated,omitempty"`
	ProofsTruncated bool                   `json:"proofs_truncated,omitempty"`
}

type emuValueKind uint8

const (
	emuUnknown emuValueKind = iota
	emuInt
	emuLong
	emuNull
	emuString
	emuArrayValue
	emuObject
)

type emuArray struct {
	typeName string
	elements []emuValue
}

type emuObjectValue struct {
	typeName string
	builder  *strings.Builder
}

type emuValue struct {
	kind         emuValueKind
	i            int64
	s            string
	array        *emuArray
	object       *emuObjectValue
	transformed  bool
	ops          []string
	staticOrigin string
	wideHigh     bool
}

func intValue(v int64, long bool, op string, transformed bool) emuValue {
	kind := emuInt
	if long {
		kind = emuLong
		v = normalizeMIRInt(v, TypeLong)
	} else {
		v = normalizeMIRInt(v, TypeInt)
	}
	out := emuValue{kind: kind, i: v, transformed: transformed}
	if op != "" {
		out.ops = []string{op}
	}
	return out
}

func stringValue(v, op string, transformed bool) emuValue {
	out := emuValue{kind: emuString, s: v, transformed: transformed}
	if op != "" {
		out.ops = []string{op}
	}
	return out
}

func combineOps(values ...emuValue) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, value := range values {
		for _, op := range value.ops {
			if _, ok := seen[op]; ok {
				continue
			}
			seen[op] = struct{}{}
			out = append(out, op)
			if len(out) == 16 {
				return out
			}
		}
	}
	return out
}

type methodEligibility struct {
	Eligible bool
	Reason   string
}

type dalvikEmulationSession struct {
	resolver        *OwnedMethodResolver
	statics         *OwnedStaticResolver
	active          map[string]struct{}
	cache           map[string]emuValue
	eligibility     map[string]methodEligibility
	calls           int
	proofs          []DalvikCallProof
	staticProofs    []DalvikStaticProof
	metrics         DalvikCallMetrics
	proofsTruncated bool
}

type dalvikExecution struct {
	ctx               context.Context
	method            OwnedDEXMethod
	config            DalvikEmulatorConfig
	mir               []MIRInsn
	offsets           map[uint32]int
	registers         []emuValue
	pending           emuValue
	visits            map[uint32]int
	result            DalvikEmulationResult
	allocatedBytes    int
	session           *dalvikEmulationSession
	depth             int
	root              bool
	returnValue       emuValue
	returned          bool
	staticTxn         map[string]OwnedStaticValue
	allowStaticWrites bool
}

// EmulateOwnedMethod executes one parser-detached method without reparsing DEX.
func EmulateOwnedMethod(ctx context.Context, method OwnedDEXMethod, config DalvikEmulatorConfig) DalvikEmulationResult {
	return EmulateOwnedMethodWithResolver(ctx, method, nil, config)
}

// EmulateOwnedMethodWithResolver executes a root method and may summarize
// concrete invoke-static targets from an immutable parser-detached resolver.
func EmulateOwnedMethodWithResolver(ctx context.Context, method OwnedDEXMethod, resolver *OwnedMethodResolver, config DalvikEmulatorConfig) DalvikEmulationResult {
	return EmulateOwnedMethodWithEnvironment(ctx, method, resolver, nil, config)
}

// EmulateOwnedMethodWithEnvironment adds immutable DEX static values to the
// bounded root session without giving ordinary methods write access.
func EmulateOwnedMethodWithEnvironment(ctx context.Context, method OwnedDEXMethod, resolver *OwnedMethodResolver, statics *OwnedStaticResolver, config DalvikEmulatorConfig) DalvikEmulationResult {
	if ctx == nil {
		ctx = context.Background()
	}
	config = normalizeDalvikEmulatorConfig(config)
	if err := ctx.Err(); err != nil {
		return DalvikEmulationResult{Status: DalvikEmulationCancelled, StopReason: err.Error()}
	}
	if method.RegistersSize == 0 || len(method.RawInsns) == 0 {
		return DalvikEmulationResult{Status: DalvikEmulationNoOutput, StopReason: "empty method"}
	}
	mir := LowerToMIR(method.RawInsns)
	for i := range mir {
		if args := method.InvokeArgs[mir[i].Offset]; len(args) > 0 {
			if n := len(args); n <= len(mir[i].ArgsData) {
				mir[i].ArgsLen = uint8(n)
				copy(mir[i].ArgsData[:], args)
			}
		}
	}
	e := &dalvikExecution{
		ctx: ctx, method: method, config: config, mir: mir,
		offsets:   make(map[uint32]int, len(mir)),
		registers: make([]emuValue, int(method.RegistersSize)),
		visits:    make(map[uint32]int),
		result:    DalvikEmulationResult{Status: DalvikEmulationNoOutput},
		session: &dalvikEmulationSession{
			resolver:    resolver,
			statics:     statics,
			active:      make(map[string]struct{}),
			cache:       make(map[string]emuValue),
			eligibility: make(map[string]methodEligibility),
		},
		root: true,
	}
	for i := range mir {
		e.offsets[mir[i].Offset] = i
	}
	e.run()
	e.result.CallProofs = append([]DalvikCallProof(nil), e.session.proofs...)
	e.result.StaticProofs = append([]DalvikStaticProof(nil), e.session.staticProofs...)
	e.result.CallMetrics = e.session.metrics
	e.result.ProofsTruncated = e.session.proofsTruncated
	return e.result
}

// ReconstructStaticFields executes owned class initializers transactionally.
// A class commits only after its <clinit>()V returns normally.
func ReconstructStaticFields(ctx context.Context, resolver *OwnedMethodResolver, initial *OwnedStaticResolver, config DalvikEmulatorConfig) *OwnedStaticResolver {
	if resolver == nil {
		return NewOwnedStaticResolver(initial.Values())
	}
	classes := make([]OwnedClassInit, 0)
	for _, descriptor := range resolver.Descriptors() {
		if strings.HasSuffix(descriptor, "-><clinit>()V") {
			classes = append(classes, OwnedClassInit{ClassName: classNameFromMemberDescriptor(descriptor), Initializer: descriptor})
		}
	}
	return ReconstructStaticFieldsWithClasses(ctx, resolver, NewOwnedClassInitResolver(classes), initial, config).Resolver
}

func normalizeDalvikEmulatorConfig(c DalvikEmulatorConfig) DalvikEmulatorConfig {
	d := DefaultDalvikEmulatorConfig()
	if c.MaxSteps <= 0 {
		c.MaxSteps = d.MaxSteps
	}
	if c.MaxVisitsPerOffset <= 0 {
		c.MaxVisitsPerOffset = d.MaxVisitsPerOffset
	}
	if c.MaxBranches <= 0 {
		c.MaxBranches = d.MaxBranches
	}
	if c.MaxSwitchEntries <= 0 {
		c.MaxSwitchEntries = d.MaxSwitchEntries
	}
	if c.MaxAllocations <= 0 {
		c.MaxAllocations = d.MaxAllocations
	}
	if c.MaxArrayElements <= 0 {
		c.MaxArrayElements = d.MaxArrayElements
	}
	if c.MaxAllocatedBytes <= 0 {
		c.MaxAllocatedBytes = d.MaxAllocatedBytes
	}
	if c.MaxStringBytes <= 0 {
		c.MaxStringBytes = d.MaxStringBytes
	}
	if c.MaxTraceEntries <= 0 {
		c.MaxTraceEntries = d.MaxTraceEntries
	}
	if c.MaxRecoveredValues <= 0 {
		c.MaxRecoveredValues = d.MaxRecoveredValues
	}
	if c.MaxCallDepth <= 0 {
		c.MaxCallDepth = d.MaxCallDepth
	}
	if c.MaxInterproceduralMethods <= 0 {
		c.MaxInterproceduralMethods = d.MaxInterproceduralMethods
	}
	if c.MaxCacheEntries <= 0 {
		c.MaxCacheEntries = d.MaxCacheEntries
	}
	if c.MaxProofEntries <= 0 {
		c.MaxProofEntries = d.MaxProofEntries
	}
	return c
}

func (e *dalvikExecution) run() {
	pc := 0
	for pc >= 0 && pc < len(e.mir) {
		if e.result.Steps >= e.config.MaxSteps {
			e.stop(DalvikEmulationBudgetExhausted, "instruction budget exhausted")
			return
		}
		if e.result.Steps&63 == 0 {
			if err := e.ctx.Err(); err != nil {
				e.stop(DalvikEmulationCancelled, err.Error())
				return
			}
		}
		insn := e.mir[pc]
		e.result.Steps++
		e.visits[insn.Offset]++
		if e.visits[insn.Offset] > e.config.MaxVisitsPerOffset {
			e.stop(DalvikEmulationBudgetExhausted, "loop visit budget exhausted")
			return
		}
		next, done := e.step(pc, insn)
		if done {
			return
		}
		pc = next
	}
	if e.result.Status == "" {
		e.result.Status = DalvikEmulationNoOutput
	}
	if e.result.StopReason == "" {
		e.result.StopReason = "method completed without concrete transformed string"
	}
}

func (e *dalvikExecution) step(pc int, insn MIRInsn) (int, bool) {
	next := pc + 1
	switch insn.Kind {
	case MIR_NOP, MIR_PAYLOAD:
		return next, false
	case MIR_CONST:
		if insn.ConstKind == ConstString {
			value, ok := e.method.References.Strings[insn.RefIdx]
			if !ok {
				return e.abstain("missing string reference")
			}
			return e.setAndContinue(insn.Dst, stringValue(value, "const-string", false), next)
		}
		if insn.ConstKind == ConstClass {
			return e.abstain("class constants are unsupported")
		}
		if insn.DataType == TypeObject && insn.Imm == 0 {
			return e.setAndContinue(insn.Dst, emuValue{kind: emuNull}, next)
		}
		return e.setAndContinue(insn.Dst, intValue(insn.Imm, insn.DataType == TypeLong, "const", false), next)
	case MIR_MOVE:
		value, ok := e.reg(insn.Src1)
		if !ok {
			return e.abstain("invalid move register")
		}
		return e.setAndContinue(insn.Dst, value, next)
	case MIR_MOVE_RESULT:
		if e.pending.kind == emuUnknown {
			return e.abstain("move-result without concrete result")
		}
		value := e.pending
		e.pending = emuValue{}
		return e.setAndContinue(insn.Dst, value, next)
	case MIR_ADD, MIR_SUB, MIR_RSUB, MIR_MUL, MIR_DIV, MIR_REM, MIR_AND, MIR_OR, MIR_XOR, MIR_SHL, MIR_SHR, MIR_USHR:
		a, ok := e.integral(insn.Src1)
		if !ok {
			return e.abstain("unknown arithmetic operand")
		}
		b := insn.Imm
		var bv emuValue
		if insn.Src2 >= 0 {
			bv, ok = e.reg(insn.Src2)
			if !ok || !isIntegral(bv) {
				return e.abstain("unknown arithmetic operand")
			}
			b = bv.i
		}
		kind := insn.Kind
		if kind == MIR_RSUB {
			a, b, kind = b, a, MIR_SUB
		}
		v, ok := evalMIRBinary(kind, insn.DataType, a, b)
		if !ok {
			return e.abstain("invalid arithmetic operation")
		}
		out := intValue(v, insn.DataType == TypeLong, mirOpName(insn.Kind), true)
		av, _ := e.reg(insn.Src1)
		out.ops = append(combineOps(av, bv), mirOpName(insn.Kind))
		return e.setAndContinue(insn.Dst, out, next)
	case MIR_NEG, MIR_NOT:
		v, ok := e.integral(insn.Src1)
		if !ok {
			return e.abstain("unknown unary operand")
		}
		if insn.Kind == MIR_NEG {
			v = -v
		} else {
			v = ^v
		}
		out := intValue(v, insn.DataType == TypeLong, mirOpName(insn.Kind), true)
		return e.setAndContinue(insn.Dst, out, next)
	case MIR_CONVERT:
		v, ok := e.integral(insn.Src1)
		if !ok {
			return e.abstain("unsupported conversion")
		}
		return e.setAndContinue(insn.Dst, intValue(v, insn.DataType == TypeLong, "convert", true), next)
	case MIR_CMP:
		a, ok := e.integral(insn.Src1)
		if !ok {
			return e.abstain("unknown compare operand")
		}
		b, ok := e.integral(insn.Src2)
		if !ok {
			return e.abstain("unknown compare operand")
		}
		v := int64(0)
		if a < b {
			v = -1
		} else if a > b {
			v = 1
		}
		return e.setAndContinue(insn.Dst, intValue(v, false, "compare", true), next)
	case MIR_IF:
		a, ok := e.integralOrNull(insn.Src1)
		if !ok {
			return e.abstain("unknown branch condition")
		}
		b := int64(0)
		if insn.Src2 >= 0 {
			b, ok = e.integralOrNull(insn.Src2)
			if !ok {
				return e.abstain("unknown branch condition")
			}
		}
		e.result.Branches++
		if e.result.Branches > e.config.MaxBranches {
			e.stop(DalvikEmulationBudgetExhausted, "branch budget exhausted")
			return 0, true
		}
		if evalMIRCondition(insn.Cond, a, b) {
			return e.branchTarget(insn)
		}
		return next, false
	case MIR_GOTO:
		e.result.Branches++
		if e.result.Branches > e.config.MaxBranches {
			e.stop(DalvikEmulationBudgetExhausted, "branch budget exhausted")
			return 0, true
		}
		return e.branchTarget(insn)
	case MIR_SWITCH:
		selector, ok := e.integral(insn.Src1)
		if !ok {
			return e.abstain("unknown switch selector")
		}
		target, found, err := decodeOwnedSwitchTarget(e.method.CodeUnits, insn.Offset, insn.Imm, int32(selector), e.config.MaxSwitchEntries)
		if err != nil {
			return e.abstain(err.Error())
		}
		if !found {
			return next, false
		}
		e.result.Branches++
		return e.absoluteTarget(target)
	case MIR_NEW_ARRAY:
		return e.newArray(insn, next)
	case MIR_ARRAY_LENGTH:
		array, ok := e.array(insn.Src1)
		if !ok {
			return e.abstain("array-length on unknown array")
		}
		return e.setAndContinue(insn.Dst, intValue(int64(len(array.elements)), false, "array-length", arrayTransformed(array)), next)
	case MIR_ARRAY_GET:
		array, ok := e.array(insn.Src1)
		if !ok {
			return e.abstain("aget on unknown array")
		}
		index, ok := e.integral(insn.Src2)
		if !ok || index < 0 || index >= int64(len(array.elements)) {
			return e.abstain("array index out of bounds")
		}
		return e.setAndContinue(insn.Dst, array.elements[index], next)
	case MIR_ARRAY_PUT:
		arrayValue, ok := e.reg(insn.Src1)
		if !ok || arrayValue.kind != emuArrayValue || arrayValue.array == nil {
			return e.abstain("aput on unknown array")
		}
		index, ok := e.integral(insn.Src2)
		if !ok || index < 0 || index >= int64(len(arrayValue.array.elements)) {
			return e.abstain("array index out of bounds")
		}
		value, ok := e.reg(insn.Src3)
		if !ok || value.kind == emuUnknown {
			return e.abstain("unknown array value")
		}
		value.transformed = true
		value.ops = append(value.ops, "array-put")
		arrayValue.array.elements[index] = value
		arrayValue.transformed = true
		arrayValue.ops = append(arrayValue.ops, "array-put")
		if arrayValue.staticOrigin != "" && e.allowStaticWrites {
			owned, convertible := ownedStaticFromEmuValue(arrayValue, arrayValue.array.typeName)
			if !convertible {
				return e.abstain("unsupported static array transaction " + arrayValue.staticOrigin)
			}
			owned.Transformed = true
			owned.Operations = append(owned.Operations, fmt.Sprintf("clinit-array-write:%s@%d", arrayValue.staticOrigin, insn.Offset))
			e.staticTxn[arrayValue.staticOrigin] = owned
		}
		if !e.setReg(insn.Src1, arrayValue) {
			return e.abstain("invalid array register")
		}
		e.tracef("array-put@%d", insn.Offset)
		return next, false
	case MIR_FILL_ARRAY:
		arrayValue, ok := e.reg(insn.Src1)
		if !ok || arrayValue.kind != emuArrayValue || arrayValue.array == nil {
			return e.abstain("fill-array on unknown array")
		}
		values, err := decodeOwnedFillArray(e.method.CodeUnits, insn.Offset, insn.Imm, e.config.MaxArrayElements)
		if err != nil || len(values) != len(arrayValue.array.elements) {
			if err == nil {
				err = fmt.Errorf("fill-array size mismatch")
			}
			return e.abstain(err.Error())
		}
		for i, v := range values {
			arrayValue.array.elements[i] = intValue(v, false, "fill-array-data", true)
		}
		arrayValue.transformed = true
		arrayValue.ops = append(arrayValue.ops, "fill-array-data")
		if arrayValue.staticOrigin != "" && e.allowStaticWrites {
			owned, convertible := ownedStaticFromEmuValue(arrayValue, arrayValue.array.typeName)
			if !convertible {
				return e.abstain("unsupported static array transaction " + arrayValue.staticOrigin)
			}
			owned.Transformed = true
			owned.Operations = append(owned.Operations, fmt.Sprintf("clinit-array-write:%s@%d", arrayValue.staticOrigin, insn.Offset))
			e.staticTxn[arrayValue.staticOrigin] = owned
		}
		if !e.setReg(insn.Src1, arrayValue) {
			return e.abstain("invalid array register")
		}
		e.tracef("fill-array-data@%d", insn.Offset)
		return next, false
	case MIR_NEW_INSTANCE:
		typeName := e.method.References.Types[insn.RefIdx]
		if typeName != "Ljava/lang/StringBuilder;" && typeName != "Ljava/lang/String;" {
			return e.abstain("unsupported object allocation")
		}
		if !e.reserve(1, 64) {
			return 0, true
		}
		obj := &emuObjectValue{typeName: typeName}
		if typeName == "Ljava/lang/StringBuilder;" {
			obj.builder = &strings.Builder{}
		}
		return e.setAndContinue(insn.Dst, emuValue{kind: emuObject, object: obj}, next)
	case MIR_CHECK_CAST:
		value, ok := e.reg(insn.Src1)
		if !ok || (value.kind != emuNull && value.kind != emuString && value.kind != emuObject && value.kind != emuArrayValue) {
			return e.abstain("unsupported check-cast")
		}
		return e.setAndContinue(insn.Dst, value, next)
	case MIR_FIELD_GET:
		if insn.FieldKind != FieldStatic {
			return e.abstain("instance field read is unsupported")
		}
		field, ok := e.method.References.Fields[insn.RefIdx]
		if !ok || e.session == nil || e.session.statics == nil {
			return e.abstain("missing static field snapshot")
		}
		descriptor := field.Descriptor()
		owned, ok := e.staticTxn[descriptor]
		if !ok {
			owned, ok = e.session.statics.Resolve(descriptor)
		}
		if !ok {
			return e.abstain("unknown static field " + descriptor)
		}
		value, ok := emuValueFromOwnedStatic(owned)
		if !ok {
			return e.abstain("unsupported static field value " + descriptor)
		}
		value.staticOrigin = descriptor
		value.ops = append(value.ops, "static-read:"+descriptor)
		e.appendStaticProof(DalvikStaticProof{ClassName: field.ClassName, Field: descriptor, Operation: "read", Offset: insn.Offset, State: "resolved"})
		return e.setAndContinue(insn.Dst, value, next)
	case MIR_FIELD_PUT:
		if !e.allowStaticWrites || insn.FieldKind != FieldStatic {
			return e.abstain("static field writes require bounded <clinit> transaction")
		}
		field, ok := e.method.References.Fields[insn.RefIdx]
		value, valid := e.reg(insn.Src1)
		if !ok || !valid {
			return e.abstain("invalid <clinit> static write")
		}
		owned, ok := ownedStaticFromEmuValue(value, field.TypeName)
		if !ok {
			return e.abstain("unsupported <clinit> static value " + field.Descriptor())
		}
		owned.Transformed = true
		owned.Operations = append(owned.Operations, fmt.Sprintf("clinit-write:%s@%d", field.Descriptor(), insn.Offset))
		e.staticTxn[field.Descriptor()] = owned
		e.appendStaticProof(DalvikStaticProof{ClassName: field.ClassName, Field: field.Descriptor(), Operation: "write", Offset: insn.Offset, State: "staged"})
		return next, false
	case MIR_INVOKE:
		return e.invoke(insn, next)
	case MIR_RETURN:
		if insn.Src1 < 0 {
			e.returned = true
			e.stop(DalvikEmulationNoOutput, "void return")
			return 0, true
		}
		value, ok := e.reg(insn.Src1)
		if !ok || value.kind == emuUnknown {
			return e.abstain("unknown return value")
		}
		e.returnValue, e.returned = value, true
		if !e.root {
			e.stop(DalvikEmulationNoOutput, "concrete callee return")
			return 0, true
		}
		if value.kind == emuString && e.acceptString(value.s, value.transformed) {
			e.result.RecoveredValues = append(e.result.RecoveredValues, DalvikRecoveredValue{Value: value.s, Offset: insn.Offset, Source: "return", Proof: "deterministic bounded Dalvik execution", Operations: append([]string(nil), value.ops...)})
			e.result.Status = DalvikEmulationRecovered
			e.result.StopReason = "concrete transformed string returned"
			return 0, true
		}
		e.stop(DalvikEmulationNoOutput, "return value is not an accepted transformed string")
		return 0, true
	default:
		return e.abstain(fmt.Sprintf("unsupported MIR operation %d", insn.Kind))
	}
}

func (e *dalvikExecution) newArray(insn MIRInsn, next int) (int, bool) {
	var count int64
	if len(insn.Args()) > 0 {
		count = int64(len(insn.Args()))
	} else {
		var ok bool
		count, ok = e.integral(insn.Src1)
		if !ok {
			return e.abstain("unknown array size")
		}
	}
	if count < 0 || count > int64(e.config.MaxArrayElements) {
		e.stop(DalvikEmulationBudgetExhausted, "array element budget exhausted")
		return 0, true
	}
	if !e.reserve(1, int(count)*8) {
		return 0, true
	}
	typeName := e.method.References.Types[insn.RefIdx]
	array := &emuArray{typeName: typeName, elements: make([]emuValue, int(count))}
	for i, reg := range insn.Args() {
		value, ok := e.reg(int16(reg))
		if !ok {
			return e.abstain("invalid filled-array argument")
		}
		value.transformed = true
		value.ops = append(value.ops, "filled-new-array")
		array.elements[i] = value
	}
	value := emuValue{kind: emuArrayValue, array: array, transformed: len(insn.Args()) > 0, ops: []string{"new-array"}}
	if insn.Dst >= 0 {
		return e.setAndContinue(insn.Dst, value, next)
	}
	e.pending = value
	return next, false
}

func (e *dalvikExecution) invoke(insn MIRInsn, next int) (int, bool) {
	method, ok := e.method.References.Methods[insn.RefIdx]
	if !ok {
		return e.abstain("missing invoked method descriptor")
	}
	args := make([]emuValue, len(insn.Args()))
	for i, reg := range insn.Args() {
		value, valid := e.reg(int16(reg))
		if !valid || value.kind == emuUnknown {
			return e.abstain("unknown invoke argument")
		}
		args[i] = value
	}
	desc := method.Descriptor()
	result, mutatesReceiver, supported := e.summarizeCall(desc, args)
	if !supported {
		if insn.InvokeKind != InvokeStatic {
			return e.abstain("unsupported app invoke kind " + desc)
		}
		var reason string
		result, reason, supported = e.summarizeAppCall(desc, args, insn.Offset)
		if !supported {
			if e.result.Status == DalvikEmulationBudgetExhausted || e.result.Status == DalvikEmulationCancelled {
				return 0, true
			}
			return e.abstain(reason)
		}
	}
	if mutatesReceiver && len(args) > 0 {
		receiverReg := int16(insn.Args()[0])
		_ = e.setReg(receiverReg, args[0])
	}
	if result.kind != emuUnknown {
		e.pending = result
	}
	e.tracef("pure-call %s@%d", desc, insn.Offset)
	return next, false
}

func (e *dalvikExecution) summarizeAppCall(desc string, args []emuValue, offset uint32) (emuValue, string, bool) {
	if e.session == nil || e.session.resolver == nil {
		return emuValue{}, "unsupported invoke " + desc, false
	}
	e.session.metrics.Attempts++
	proof := DalvikCallProof{Caller: e.method.Descriptor(), Callee: desc, Offset: offset, Depth: e.depth + 1, ArgumentSummary: summarizeEmuArguments(args)}
	callee, ok := e.session.resolver.Resolve(desc)
	if !ok {
		e.session.metrics.Unresolved++
		proof.Status, proof.Reason = "unresolved", "unresolved app invoke"
		e.appendCallProof(proof)
		return emuValue{}, "unresolved app invoke " + desc, false
	}
	if !callee.IsStatic() {
		e.session.metrics.Impure++
		proof.Status, proof.Reason = "impure", "non-static app invoke"
		e.appendCallProof(proof)
		return emuValue{}, "non-static app invoke " + desc, false
	}
	eligibility := e.methodEligibility(callee, false, make(map[string]struct{}))
	if !eligibility.Eligible {
		e.session.metrics.Impure++
		proof.Status, proof.Reason = "impure", eligibility.Reason
		e.appendCallProof(proof)
		return emuValue{}, "impure app invoke " + desc + ": " + eligibility.Reason, false
	}
	if e.depth+1 > e.config.MaxCallDepth {
		e.session.metrics.Budgeted++
		proof.Status, proof.Reason = "budget", "call depth budget exhausted"
		e.appendCallProof(proof)
		e.stop(DalvikEmulationBudgetExhausted, proof.Reason)
		return emuValue{}, e.result.StopReason, false
	}
	if e.session.calls >= e.config.MaxInterproceduralMethods {
		e.session.metrics.Budgeted++
		proof.Status, proof.Reason = "budget", "interprocedural method budget exhausted"
		e.appendCallProof(proof)
		e.stop(DalvikEmulationBudgetExhausted, proof.Reason)
		return emuValue{}, e.result.StopReason, false
	}
	key, digest, ok := canonicalEmuCallKey(desc, args, e.session.statics)
	proof.Digest = digest
	if !ok {
		proof.Status, proof.Reason = "unsupported", "unsupported app call arguments"
		e.appendCallProof(proof)
		return emuValue{}, "unsupported app call arguments " + desc, false
	}
	if value, cached := e.session.cache[key]; cached {
		e.session.metrics.CacheHits++
		proof.Status, proof.CacheHit = "completed", true
		e.appendCallProof(proof)
		value.ops = append(value.ops, "app-call-cache:"+desc)
		e.tracef("app-call-cache %s@%d", desc, offset)
		return value, "", true
	}
	if _, recursive := e.session.active[key]; recursive {
		e.session.metrics.Recursions++
		proof.Status, proof.Reason = "recursion", "recursive app invoke"
		e.appendCallProof(proof)
		return emuValue{}, "recursive app invoke " + desc, false
	}
	registers, reason, ok := bindStaticArguments(callee, args)
	if !ok {
		proof.Status, proof.Reason = "invalid_arguments", reason
		e.appendCallProof(proof)
		return emuValue{}, reason, false
	}
	mir := LowerToMIR(callee.RawInsns)
	for i := range mir {
		if invokeArgs := callee.InvokeArgs[mir[i].Offset]; len(invokeArgs) > 0 {
			if n := len(invokeArgs); n <= len(mir[i].ArgsData) {
				mir[i].ArgsLen = uint8(n)
				copy(mir[i].ArgsData[:], invokeArgs)
			}
		}
	}
	frame := &dalvikExecution{
		ctx: e.ctx, method: callee, config: e.config, mir: mir,
		offsets: make(map[uint32]int, len(mir)), registers: registers,
		visits: make(map[uint32]int), result: DalvikEmulationResult{Status: DalvikEmulationNoOutput},
		session: e.session, depth: e.depth + 1,
	}
	for i := range mir {
		frame.offsets[mir[i].Offset] = i
	}
	e.session.active[key] = struct{}{}
	e.session.calls++
	frame.run()
	delete(e.session.active, key)
	e.result.Steps += frame.result.Steps
	e.result.Branches += frame.result.Branches
	e.result.Allocations += frame.result.Allocations
	e.allocatedBytes += frame.allocatedBytes
	if e.result.Steps > e.config.MaxSteps || e.result.Branches > e.config.MaxBranches || e.result.Allocations > e.config.MaxAllocations || e.allocatedBytes > e.config.MaxAllocatedBytes {
		e.session.metrics.Budgeted++
		proof.Status, proof.Reason = "budget", "cumulative interprocedural budget exhausted"
		e.appendCallProof(proof)
		e.stop(DalvikEmulationBudgetExhausted, proof.Reason)
		return emuValue{}, e.result.StopReason, false
	}
	for _, trace := range frame.result.Trace {
		e.tracef("call[%s] %s", desc, trace)
	}
	if frame.result.Status == DalvikEmulationCancelled || frame.result.Status == DalvikEmulationBudgetExhausted || frame.result.Status == DalvikEmulationAbstained {
		proof.Status, proof.Reason = string(frame.result.Status), frame.result.StopReason
		e.appendCallProof(proof)
		e.stop(frame.result.Status, desc+": "+frame.result.StopReason)
		return emuValue{}, e.result.StopReason, false
	}
	if !frame.returned {
		proof.Status, proof.Reason = "no_output", "app invoke returned no concrete value"
		e.appendCallProof(proof)
		return emuValue{}, "app invoke returned no concrete value " + desc, false
	}
	value := cloneEmuValue(frame.returnValue)
	value.transformed = true
	value.ops = append(combineOps(value), fmt.Sprintf("app-call:%s@%d", desc, offset))
	if len(e.session.cache) < e.config.MaxCacheEntries {
		e.session.cache[key] = cloneEmuValue(value)
	}
	e.session.metrics.Completed++
	proof.Status = "completed"
	e.appendCallProof(proof)
	e.tracef("app-call %s@%d", desc, offset)
	return value, "", true
}

func bindStaticArguments(method OwnedDEXMethod, args []emuValue) ([]emuValue, string, bool) {
	if method.RegistersSize < method.InsSize {
		return nil, "invalid callee register window " + method.Descriptor(), false
	}
	words := 0
	for _, parameter := range method.Parameters {
		words += descriptorWordWidth(parameter)
	}
	if words != int(method.InsSize) || len(args) != words {
		return nil, "callee argument width mismatch " + method.Descriptor(), false
	}
	registers := make([]emuValue, int(method.RegistersSize))
	first := int(method.RegistersSize - method.InsSize)
	argWord := 0
	for _, parameter := range method.Parameters {
		value := args[argWord]
		if value.kind == emuUnknown || value.kind == emuObject || value.wideHigh {
			return nil, "unsupported mutable/unknown callee argument " + method.Descriptor(), false
		}
		width := descriptorWordWidth(parameter)
		if width == 2 {
			if argWord+1 >= len(args) || (!args[argWord+1].wideHigh && args[argWord+1].i != value.i) {
				return nil, "invalid wide argument pair " + method.Descriptor(), false
			}
			low := cloneEmuValue(value)
			high := cloneEmuValue(value)
			high.wideHigh = true
			registers[first+argWord], registers[first+argWord+1] = low, high
		} else {
			if value.kind == emuLong {
				return nil, "narrow descriptor bound to wide value " + method.Descriptor(), false
			}
			registers[first+argWord] = cloneEmuValue(value)
		}
		argWord += width
	}
	return registers, "", true
}

func descriptorWordWidth(descriptor string) int {
	if descriptor == "J" || descriptor == "D" {
		return 2
	}
	return 1
}

func canonicalEmuCallKey(desc string, args []emuValue, statics *OwnedStaticResolver) (string, string, bool) {
	h := sha256.New()
	writeDigestBytes(h, []byte(desc))
	for _, value := range args {
		if !writeEmuDigestValue(h, value, 0) {
			return "", "", false
		}
	}
	if statics != nil {
		for _, descriptor := range statics.Descriptors() {
			value, ok := statics.Resolve(descriptor)
			if !ok {
				continue
			}
			writeDigestBytes(h, []byte(descriptor))
			if !writeOwnedStaticDigestValue(h, value, 0) {
				return "", "", false
			}
		}
	}
	digest := h.Sum(nil)
	full := hex.EncodeToString(digest)
	return desc + "#" + full, full[:16], true
}

func writeDigestBytes(h interface{ Write([]byte) (int, error) }, data []byte) {
	var size [8]byte
	binary.LittleEndian.PutUint64(size[:], uint64(len(data)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(data)
}

func writeEmuDigestValue(h interface{ Write([]byte) (int, error) }, value emuValue, depth int) bool {
	if depth > 8 {
		return false
	}
	_, _ = h.Write([]byte{byte(value.kind)})
	var integer [8]byte
	switch value.kind {
	case emuInt, emuLong:
		binary.LittleEndian.PutUint64(integer[:], uint64(value.i))
		_, _ = h.Write(integer[:])
	case emuNull:
	case emuString:
		writeDigestBytes(h, []byte(value.s))
	case emuArrayValue:
		if value.array == nil || len(value.array.elements) > 65536 {
			return false
		}
		writeDigestBytes(h, []byte(value.array.typeName))
		binary.LittleEndian.PutUint64(integer[:], uint64(len(value.array.elements)))
		_, _ = h.Write(integer[:])
		for _, element := range value.array.elements {
			if !writeEmuDigestValue(h, element, depth+1) {
				return false
			}
		}
	default:
		return false
	}
	return true
}

func writeOwnedStaticDigestValue(h interface{ Write([]byte) (int, error) }, value OwnedStaticValue, depth int) bool {
	emu, ok := emuValueFromOwnedStatic(value)
	return ok && writeEmuDigestValue(h, emu, depth)
}

func summarizeEmuArguments(args []emuValue) []string {
	out := make([]string, 0, len(args))
	for _, value := range args {
		switch value.kind {
		case emuInt:
			out = append(out, fmt.Sprintf("int:%d", value.i))
		case emuLong:
			if value.wideHigh {
				out = append(out, "wide:high")
			} else {
				out = append(out, fmt.Sprintf("long:%d", value.i))
			}
		case emuNull:
			out = append(out, "null")
		case emuString:
			out = append(out, fmt.Sprintf("string:%dB", len(value.s)))
		case emuArrayValue:
			if value.array == nil {
				out = append(out, "array:nil")
			} else {
				out = append(out, fmt.Sprintf("array:%s[%d]", value.array.typeName, len(value.array.elements)))
			}
		default:
			out = append(out, "unsupported")
		}
	}
	return out
}

func ownedStaticFromEmuValue(value emuValue, typeName string) (OwnedStaticValue, bool) {
	out := OwnedStaticValue{TypeName: typeName, Transformed: value.transformed, Operations: append([]string(nil), value.ops...)}
	switch value.kind {
	case emuInt, emuLong:
		out.Kind, out.Int64 = StaticIntegral, value.i
	case emuNull:
		out.Kind = StaticNull
	case emuString:
		out.Kind, out.String = StaticString, value.s
	case emuArrayValue:
		if value.array == nil {
			return OwnedStaticValue{}, false
		}
		out.Kind = StaticArray
		out.Elements = make([]OwnedStaticValue, len(value.array.elements))
		for i := range value.array.elements {
			element, ok := ownedStaticFromEmuValue(value.array.elements[i], "")
			if !ok {
				return OwnedStaticValue{}, false
			}
			out.Elements[i] = element
		}
	default:
		return OwnedStaticValue{}, false
	}
	return out, true
}

func emuValueFromOwnedStatic(value OwnedStaticValue) (emuValue, bool) {
	var out emuValue
	switch value.Kind {
	case StaticIntegral:
		out = intValue(value.Int64, value.TypeName == "J", "", value.Transformed)
	case StaticNull:
		out = emuValue{kind: emuNull, transformed: value.Transformed}
	case StaticString:
		out = stringValue(value.String, "", value.Transformed)
	case StaticArray:
		array := &emuArray{typeName: value.TypeName, elements: make([]emuValue, len(value.Elements))}
		for i := range value.Elements {
			element, ok := emuValueFromOwnedStatic(value.Elements[i])
			if !ok {
				return emuValue{}, false
			}
			array.elements[i] = element
		}
		out = emuValue{kind: emuArrayValue, array: array, transformed: value.Transformed}
	default:
		return emuValue{}, false
	}
	out.ops = append([]string(nil), value.Operations...)
	return out, true
}

func cloneEmuValue(value emuValue) emuValue {
	out := value
	out.ops = append([]string(nil), value.ops...)
	if value.array != nil {
		out.array = &emuArray{typeName: value.array.typeName, elements: make([]emuValue, len(value.array.elements))}
		for i := range value.array.elements {
			out.array.elements[i] = cloneEmuValue(value.array.elements[i])
		}
	}
	return out
}

func (e *dalvikExecution) summarizeCall(desc string, args []emuValue) (emuValue, bool, bool) {
	op := "pure-call:" + desc
	switch desc {
	case "Ljava/lang/String;->length()I":
		if len(args) == 1 && args[0].kind == emuString {
			return intValue(int64(len([]rune(args[0].s))), false, op, args[0].transformed), false, true
		}
	case "Ljava/lang/String;->charAt(I)C":
		if len(args) == 2 && args[0].kind == emuString && isIntegral(args[1]) {
			r := []rune(args[0].s)
			i := args[1].i
			if i >= 0 && i < int64(len(r)) {
				return intValue(int64(r[i]), false, op, true), false, true
			}
		}
	case "Ljava/lang/String;->substring(I)Ljava/lang/String;":
		if len(args) == 2 && args[0].kind == emuString && isIntegral(args[1]) {
			r := []rune(args[0].s)
			i := args[1].i
			if i >= 0 && i <= int64(len(r)) {
				return e.boundedString(string(r[i:]), op, args...), false, true
			}
		}
	case "Ljava/lang/String;->substring(II)Ljava/lang/String;":
		if len(args) == 3 && args[0].kind == emuString && isIntegral(args[1]) && isIntegral(args[2]) {
			r := []rune(args[0].s)
			a, b := args[1].i, args[2].i
			if a >= 0 && b >= a && b <= int64(len(r)) {
				return e.boundedString(string(r[a:b]), op, args...), false, true
			}
		}
	case "Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;":
		if len(args) == 2 && args[0].kind == emuString && args[1].kind == emuString {
			return e.boundedString(args[0].s+args[1].s, op, args...), false, true
		}
	case "Ljava/lang/String;->toCharArray()[C":
		if len(args) == 1 && args[0].kind == emuString {
			r := []rune(args[0].s)
			if !e.reserve(1, len(r)*4) {
				return emuValue{}, false, true
			}
			array := &emuArray{typeName: "[C", elements: make([]emuValue, len(r))}
			for i, c := range r {
				array.elements[i] = intValue(int64(c), false, op, true)
			}
			return emuValue{kind: emuArrayValue, array: array, transformed: true, ops: []string{op}}, false, true
		}
	case "Ljava/lang/String;-><init>([B)V", "Ljava/lang/String;-><init>([C)V":
		if len(args) == 2 && args[0].kind == emuObject && args[1].kind == emuArrayValue {
			s, ok := arrayToString(args[1].array)
			if ok && len(s) <= e.config.MaxStringBytes {
				args[0].kind, args[0].s, args[0].transformed = emuString, s, true
				args[0].ops = append(combineOps(args[1]), op)
				return emuValue{}, true, true
			}
		}
	case "Ljava/lang/StringBuilder;-><init>()V":
		if len(args) == 1 && args[0].kind == emuObject && args[0].object != nil && args[0].object.builder != nil {
			return emuValue{}, true, true
		}
	case "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;":
		if len(args) == 2 && builderValue(args[0]) && args[1].kind == emuString && args[0].object.builder.Len()+len(args[1].s) <= e.config.MaxStringBytes {
			args[0].object.builder.WriteString(args[1].s)
			args[0].transformed = true
			args[0].ops = append(combineOps(args...), op)
			return args[0], true, true
		}
	case "Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;":
		if len(args) == 2 && builderValue(args[0]) && isIntegral(args[1]) {
			args[0].object.builder.WriteRune(rune(args[1].i))
			args[0].transformed = true
			args[0].ops = append(combineOps(args...), op)
			return args[0], true, true
		}
	case "Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;":
		if len(args) == 2 && builderValue(args[0]) && isIntegral(args[1]) {
			args[0].object.builder.WriteString(strconv.FormatInt(args[1].i, 10))
			args[0].transformed = true
			args[0].ops = append(combineOps(args...), op)
			return args[0], true, true
		}
	case "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;":
		if len(args) == 1 && builderValue(args[0]) {
			return e.boundedString(args[0].object.builder.String(), op, args...), false, true
		}
	case "Landroid/util/Base64;->decode(Ljava/lang/String;I)[B":
		if len(args) == 2 && args[0].kind == emuString && isIntegral(args[1]) {
			decoded, err := decodeAndroidBase64(args[0].s, args[1].i)
			if err == nil && len(decoded) <= e.config.MaxAllocatedBytes && e.reserve(1, len(decoded)) {
				array := &emuArray{typeName: "[B", elements: make([]emuValue, len(decoded))}
				for i, b := range decoded {
					array.elements[i] = intValue(int64(int8(b)), false, op, true)
				}
				return emuValue{kind: emuArrayValue, array: array, transformed: true, ops: []string{op}}, false, true
			}
		}
	}
	return emuValue{}, false, false
}

func (e *dalvikExecution) boundedString(s, op string, inputs ...emuValue) emuValue {
	if len(s) > e.config.MaxStringBytes {
		return emuValue{}
	}
	out := stringValue(s, op, true)
	out.ops = append(combineOps(inputs...), op)
	return out
}

func (e *dalvikExecution) acceptString(s string, transformed bool) bool {
	return transformed && s != "" && len(s) <= e.config.MaxStringBytes && utf8.ValidString(s) && len(e.result.RecoveredValues) < e.config.MaxRecoveredValues
}

func (e *dalvikExecution) branchTarget(insn MIRInsn) (int, bool) {
	return e.absoluteTarget(int64(insn.Offset) + insn.Imm)
}
func (e *dalvikExecution) absoluteTarget(target int64) (int, bool) {
	if target < 0 || target > int64(^uint32(0)) {
		return e.abstain("invalid branch target")
	}
	index, ok := e.offsets[uint32(target)]
	if !ok {
		return e.abstain("branch target is not an instruction")
	}
	return index, false
}
func (e *dalvikExecution) reg(index int16) (emuValue, bool) {
	if index < 0 || int(index) >= len(e.registers) {
		return emuValue{}, false
	}
	return e.registers[index], true
}
func (e *dalvikExecution) setReg(index int16, value emuValue) bool {
	if index < 0 || int(index) >= len(e.registers) {
		return false
	}
	e.registers[index] = value
	return true
}
func (e *dalvikExecution) setAndContinue(index int16, value emuValue, next int) (int, bool) {
	if !e.setReg(index, value) {
		return e.abstain("invalid destination register")
	}
	return next, false
}
func (e *dalvikExecution) integral(index int16) (int64, bool) {
	value, ok := e.reg(index)
	if !ok || !isIntegral(value) {
		return 0, false
	}
	return value.i, true
}
func (e *dalvikExecution) integralOrNull(index int16) (int64, bool) {
	value, ok := e.reg(index)
	if !ok {
		return 0, false
	}
	if value.kind == emuNull {
		return 0, true
	}
	if !isIntegral(value) {
		return 0, false
	}
	return value.i, true
}
func (e *dalvikExecution) array(index int16) (*emuArray, bool) {
	value, ok := e.reg(index)
	return value.array, ok && value.kind == emuArrayValue && value.array != nil
}
func (e *dalvikExecution) abstain(reason string) (int, bool) {
	e.stop(DalvikEmulationAbstained, reason)
	return 0, true
}
func (e *dalvikExecution) stop(status DalvikEmulationStatus, reason string) {
	e.result.Status, e.result.StopReason = status, reason
}
func (e *dalvikExecution) reserve(allocations, bytes int) bool {
	e.result.Allocations += allocations
	e.allocatedBytes += bytes
	if e.result.Allocations > e.config.MaxAllocations || e.allocatedBytes > e.config.MaxAllocatedBytes {
		e.stop(DalvikEmulationBudgetExhausted, "allocation budget exhausted")
		return false
	}
	return true
}
func (e *dalvikExecution) appendCallProof(proof DalvikCallProof) {
	if e.session == nil {
		return
	}
	if len(e.session.proofs) >= e.config.MaxProofEntries {
		e.session.proofsTruncated = true
		return
	}
	e.session.proofs = append(e.session.proofs, proof)
}

func (e *dalvikExecution) appendStaticProof(proof DalvikStaticProof) {
	if e.session == nil {
		return
	}
	if len(e.session.staticProofs) >= e.config.MaxProofEntries {
		e.session.proofsTruncated = true
		return
	}
	e.session.staticProofs = append(e.session.staticProofs, proof)
}

func (e *dalvikExecution) methodEligibility(method OwnedDEXMethod, allowStaticWrites bool, visiting map[string]struct{}) methodEligibility {
	descriptor := method.Descriptor()
	cacheKey := descriptor
	if allowStaticWrites {
		cacheKey += "#clinit"
	}
	if e.session != nil {
		if cached, ok := e.session.eligibility[cacheKey]; ok {
			return cached
		}
	}
	if _, recursive := visiting[cacheKey]; recursive {
		return methodEligibility{Reason: "eligibility cycle"}
	}
	visiting[cacheKey] = struct{}{}
	defer delete(visiting, cacheKey)
	result := methodEligibility{Eligible: true}
	for _, insn := range LowerToMIR(method.RawInsns) {
		switch insn.Kind {
		case MIR_UNKNOWN, MIR_THROW, MIR_MONITOR_ENTER, MIR_MONITOR_EXIT, MIR_MOVE_EXCEPTION:
			result = methodEligibility{Reason: fmt.Sprintf("unsupported side effect %d", insn.Kind)}
		case MIR_FIELD_GET:
			if insn.FieldKind != FieldStatic {
				result = methodEligibility{Reason: "instance field read"}
			}
		case MIR_FIELD_PUT:
			if !allowStaticWrites || insn.FieldKind != FieldStatic {
				result = methodEligibility{Reason: "static/instance write outside initializer"}
			}
		case MIR_INVOKE:
			ref, ok := method.References.Methods[insn.RefIdx]
			if !ok {
				result = methodEligibility{Reason: "missing invoke descriptor"}
				break
			}
			desc := ref.Descriptor()
			if isAllowlistedPureDescriptor(desc) {
				break
			}
			if insn.InvokeKind != InvokeStatic || e.session == nil || e.session.resolver == nil {
				result = methodEligibility{Reason: "non-pure invoke " + desc}
				break
			}
			callee, found := e.session.resolver.Resolve(desc)
			if !found || !callee.IsStatic() {
				result = methodEligibility{Reason: "unresolved app invoke " + desc}
				break
			}
			child := e.methodEligibility(callee, false, visiting)
			if !child.Eligible {
				result = methodEligibility{Reason: desc + ": " + child.Reason}
			}
		}
		if !result.Eligible {
			break
		}
	}
	if e.session != nil {
		e.session.eligibility[cacheKey] = result
	}
	return result
}

func isAllowlistedPureDescriptor(desc string) bool {
	switch desc {
	case "Ljava/lang/String;->length()I",
		"Ljava/lang/String;->charAt(I)C",
		"Ljava/lang/String;->substring(I)Ljava/lang/String;",
		"Ljava/lang/String;->substring(II)Ljava/lang/String;",
		"Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;",
		"Ljava/lang/String;->toCharArray()[C",
		"Ljava/lang/String;-><init>([B)V",
		"Ljava/lang/String;-><init>([C)V",
		"Ljava/lang/StringBuilder;-><init>()V",
		"Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
		"Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;",
		"Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;",
		"Ljava/lang/StringBuilder;->toString()Ljava/lang/String;",
		"Landroid/util/Base64;->decode(Ljava/lang/String;I)[B":
		return true
	default:
		return false
	}
}

func (e *dalvikExecution) tracef(format string, args ...any) {
	if len(e.result.Trace) >= e.config.MaxTraceEntries {
		e.result.TraceTruncated = true
		return
	}
	e.result.Trace = append(e.result.Trace, fmt.Sprintf(format, args...))
}

func isIntegral(v emuValue) bool { return v.kind == emuInt || v.kind == emuLong }
func builderValue(v emuValue) bool {
	return v.kind == emuObject && v.object != nil && v.object.builder != nil
}
func arrayTransformed(a *emuArray) bool {
	for _, value := range a.elements {
		if value.transformed {
			return true
		}
	}
	return false
}
func arrayToString(a *emuArray) (string, bool) {
	if a == nil {
		return "", false
	}
	var b strings.Builder
	for _, value := range a.elements {
		if !isIntegral(value) {
			return "", false
		}
		if a.typeName == "[B" {
			b.WriteByte(byte(value.i))
		} else {
			b.WriteRune(rune(value.i))
		}
	}
	return b.String(), true
}

func decodeAndroidBase64(s string, flags int64) ([]byte, error) {
	if flags&^int64(2|8|16) != 0 {
		return nil, fmt.Errorf("unsupported Base64 flags")
	}
	encoding := base64.StdEncoding
	if flags&8 != 0 {
		encoding = base64.URLEncoding
	}
	if flags&16 != 0 {
		encoding = encoding.WithPadding(base64.NoPadding)
	}
	return encoding.DecodeString(strings.TrimSpace(s))
}

func mirOpName(kind MIROpKind) string { return fmt.Sprintf("mir-%d", kind) }

func decodeOwnedFillArray(code []uint16, insnOffset uint32, relative int64, maxElements int) ([]int64, error) {
	payload, err := relativePayloadOffset(code, insnOffset, relative)
	if err != nil {
		return nil, err
	}
	if payload+4 > uint32(len(code)) || code[payload] != 0x0300 {
		return nil, fmt.Errorf("invalid fill-array payload")
	}
	width := uint32(code[payload+1])
	if width != 1 && width != 2 && width != 4 && width != 8 {
		return nil, fmt.Errorf("unsupported fill-array element width %d", width)
	}
	count := uint32(code[payload+2]) | uint32(code[payload+3])<<16
	if count > uint32(maxElements) {
		return nil, fmt.Errorf("fill-array element budget exhausted")
	}
	bytesNeeded := uint64(count) * uint64(width)
	words := (bytesNeeded + 1) / 2
	if uint64(payload)+4+words > uint64(len(code)) {
		return nil, fmt.Errorf("truncated fill-array payload")
	}
	out := make([]int64, count)
	start := payload + 4
	for i := uint32(0); i < count; i++ {
		var raw uint64
		for j := uint32(0); j < width; j++ {
			bytePos := i*width + j
			word := code[start+bytePos/2]
			value := byte(word)
			if bytePos%2 != 0 {
				value = byte(word >> 8)
			}
			raw |= uint64(value) << (8 * j)
		}
		switch width {
		case 1:
			out[i] = int64(int8(raw))
		case 2:
			out[i] = int64(int16(raw))
		case 4:
			out[i] = int64(int32(raw))
		case 8:
			out[i] = int64(raw)
		}
	}
	return out, nil
}

func decodeOwnedSwitchTarget(code []uint16, insnOffset uint32, relative int64, selector int32, maxEntries int) (int64, bool, error) {
	payload, err := relativePayloadOffset(code, insnOffset, relative)
	if err != nil {
		return 0, false, err
	}
	if payload+2 > uint32(len(code)) {
		return 0, false, fmt.Errorf("truncated switch payload")
	}
	count := uint32(code[payload+1])
	if count > uint32(maxEntries) {
		return 0, false, fmt.Errorf("switch entry budget exhausted")
	}
	switch code[payload] {
	case 0x0100:
		if uint64(payload)+4+uint64(count)*2 > uint64(len(code)) {
			return 0, false, fmt.Errorf("truncated packed-switch payload")
		}
		first := int32(uint32(code[payload+2]) | uint32(code[payload+3])<<16)
		index := int64(selector) - int64(first)
		if index < 0 || index >= int64(count) {
			return 0, false, nil
		}
		pos := payload + 4 + uint32(index)*2
		rel := int32(uint32(code[pos]) | uint32(code[pos+1])<<16)
		return int64(insnOffset) + int64(rel), true, nil
	case 0x0200:
		if uint64(payload)+2+uint64(count)*4 > uint64(len(code)) {
			return 0, false, fmt.Errorf("truncated sparse-switch payload")
		}
		keys := payload + 2
		targets := keys + count*2
		for i := uint32(0); i < count; i++ {
			pos := keys + i*2
			key := int32(uint32(code[pos]) | uint32(code[pos+1])<<16)
			if key == selector {
				t := targets + i*2
				rel := int32(uint32(code[t]) | uint32(code[t+1])<<16)
				return int64(insnOffset) + int64(rel), true, nil
			}
		}
		return 0, false, nil
	default:
		return 0, false, fmt.Errorf("invalid switch payload")
	}
}

func relativePayloadOffset(code []uint16, insnOffset uint32, relative int64) (uint32, error) {
	target := int64(insnOffset) + relative
	if target < 0 || target >= int64(len(code)) {
		return 0, fmt.Errorf("payload target out of bounds")
	}
	return uint32(target), nil
}
