package apkloader

// Native Smali→DEX assembler: SmaliFile model → Dalvik code units.
//
// Two passes per method: label collection with branch-size fixpoint, then
// encoding. Reference pools (strings/types/protos/fields/methods/handles/
// call sites) are shared per DEX job so indices stay consistent. No external
// processes are used at any stage.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// smaliMnemonics maps mnemonic → candidate opcodes (reverse of opcodeTable).
var smaliMnemonics = map[string][]uint8{}

func init() {
	for op := 0; op < 256; op++ {
		info := opcodeTable[op]
		if info.Format == FmtUnknown {
			continue
		}
		smaliMnemonics[info.Name] = append(smaliMnemonics[info.Name], uint8(op))
	}
}

// ── Pools ────────────────────────────────────────────────────────────────────

// asmPools accumulates deduplicated references for one DEX output.
type asmPools struct {
	strings     []string
	strIndex    map[string]uint32
	types       []string
	typeIndex   map[string]uint32
	protos      []*asmProto
	protoIndex  map[string]uint32
	fields      []*asmField
	fieldIndex  map[string]uint32
	methods     []*asmMethod
	methodIndex map[string]uint32
	handles     []DEXMethodHandle
	handleIndex map[string]uint32
	callSites   [][]DEXValue
	callIndex   map[string]uint32
	frozen      bool
}

type asmProto struct {
	shorty string
	ret    string
	params []string
}

type asmField struct {
	cls  string
	name string
	typ  string
}

type asmMethod struct {
	cls    string
	name   string
	params []string
	ret    string
}

func newAsmPools() *asmPools {
	return &asmPools{
		strIndex: map[string]uint32{}, typeIndex: map[string]uint32{},
		protoIndex: map[string]uint32{}, fieldIndex: map[string]uint32{},
		methodIndex: map[string]uint32{}, handleIndex: map[string]uint32{},
		callIndex: map[string]uint32{},
	}
}

func (p *asmPools) str(s string) uint32 {
	if i, ok := p.strIndex[s]; ok {
		return i
	}
	i := uint32(len(p.strings))
	p.strings = append(p.strings, s)
	p.strIndex[s] = i
	return i
}

func (p *asmPools) typ(desc string) uint32 {
	if i, ok := p.typeIndex[desc]; ok {
		return i
	}
	p.str(desc)
	i := uint32(len(p.types))
	p.types = append(p.types, desc)
	p.typeIndex[desc] = i
	return i
}

func protoKey(ret string, params []string) string {
	return ret + "\x00" + strings.Join(params, "\x00")
}

func (p *asmPools) proto(ret string, params []string) uint32 {
	k := protoKey(ret, params)
	if i, ok := p.protoIndex[k]; ok {
		return i
	}
	p.str(shortyFor(ret, params))
	p.typ(ret)
	for _, t := range params {
		p.typ(t)
	}
	i := uint32(len(p.protos))
	p.protos = append(p.protos, &asmProto{shorty: shortyFor(ret, params), ret: ret, params: append([]string(nil), params...)})
	p.protoIndex[k] = i
	return i
}

func (p *asmPools) field(cls, name, typ string) uint32 {
	k := cls + "\x00" + name + "\x00" + typ
	if i, ok := p.fieldIndex[k]; ok {
		return i
	}
	p.typ(cls)
	p.typ(typ)
	p.str(name)
	i := uint32(len(p.fields))
	p.fields = append(p.fields, &asmField{cls: cls, name: name, typ: typ})
	p.fieldIndex[k] = i
	return i
}

func (p *asmPools) method(cls, name string, params []string, ret string) uint32 {
	k := cls + "\x00" + name + "\x00" + protoKey(ret, params)
	if i, ok := p.methodIndex[k]; ok {
		return i
	}
	p.typ(cls)
	p.str(name)
	p.proto(ret, params)
	i := uint32(len(p.methods))
	p.methods = append(p.methods, &asmMethod{cls: cls, name: name, params: append([]string(nil), params...), ret: ret})
	p.methodIndex[k] = i
	return i
}

var dexHandleKindByName = map[string]uint16{
	"static-put": 0, "static-get": 1, "instance-put": 2, "instance-get": 3,
	"invoke-static": 4, "invoke-instance": 5, "invoke-constructor": 6,
	"invoke-direct": 7, "invoke-interface": 8,
}

// handle resolves a method-handle text, interning field/method targets.
func (p *asmPools) handle(text string) (uint32, error) {
	if i, ok := p.handleIndex[text]; ok {
		return i, nil
	}
	at := strings.Index(text, "@")
	if at < 0 {
		return 0, fmt.Errorf("bad method handle %q", text)
	}
	kind, ok := dexHandleKindByName[text[:at]]
	if !ok {
		return 0, fmt.Errorf("bad method handle kind in %q", text)
	}
	ref := text[at+1:]
	var target uint32
	if kind < 4 {
		c, n, t2, err := splitFieldRef(ref)
		if err != nil {
			return 0, err
		}
		target = p.field(c, n, t2)
	} else {
		c, n, ps, r, err := splitMethodRef(ref)
		if err != nil {
			return 0, err
		}
		target = p.method(c, n, ps, r)
	}
	i := uint32(len(p.handles))
	p.handles = append(p.handles, DEXMethodHandle{Kind: kind, Target: uint16(target)})
	p.handleIndex[text] = i
	return i, nil
}

// ── Operand helpers ──────────────────────────────────────────────────────────

func parseReg(s string) (uint16, error) {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "v") {
		return 0, fmt.Errorf("bad register %q", s)
	}
	n, err := strconv.Atoi(t[1:])
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("bad register %q", s)
	}
	return uint16(n), nil
}

func parseRegList(s string) ([]uint16, bool, error) {
	return parseRegListWith(s, parseReg)
}

func parseRegListWith(s string, reg func(string) (uint16, error)) ([]uint16, bool, error) {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "{") || !strings.HasSuffix(t, "}") {
		return nil, false, fmt.Errorf("bad register set %q", s)
	}
	inner := strings.TrimSpace(t[1 : len(t)-1])
	if inner == "" {
		return nil, false, nil
	}
	if strings.Contains(inner, "..") {
		parts := strings.SplitN(inner, "..", 2)
		lo, err := reg(parts[0])
		if err != nil {
			return nil, false, err
		}
		hi, err := reg(parts[1])
		if err != nil {
			return nil, false, err
		}
		if hi < lo {
			return nil, false, fmt.Errorf("bad register range %q", s)
		}
		var out []uint16
		for r := lo; ; r++ {
			out = append(out, r)
			if r == hi {
				break
			}
		}
		return out, true, nil
	}
	var out []uint16
	for _, part := range splitTopLevel(inner, ',') {
		r, err := reg(part)
		if err != nil {
			return nil, false, err
		}
		out = append(out, r)
	}
	return out, false, nil
}

// smaliRegisterWindow maps pN aliases to the high registers occupied by the
// receiver and arguments. Wide arguments consume two register slots.
func smaliRegisterWindow(m *SmaliMethod) (registers, paramSlots int, err error) {
	if m.Access&0x0008 == 0 {
		paramSlots++
	}
	for _, typ := range m.Params {
		paramSlots++
		if typ == "J" || typ == "D" {
			paramSlots++
		}
	}
	registers = m.Registers
	if registers < 0 {
		return 0, 0, fmt.Errorf("method %s: missing .registers/.locals", m.Name)
	}
	if m.UsesLocals {
		registers += paramSlots
	}
	if registers > 65535 || registers < paramSlots {
		return 0, 0, fmt.Errorf("method %s: %d registers cannot hold %d parameter slots", m.Name, registers, paramSlots)
	}
	return registers, paramSlots, nil
}

func parseMethodInsnOperands(ln *SmaliLine, m *SmaliMethod) (*asmInsn, error) {
	registers, paramSlots, err := smaliRegisterWindow(m)
	if err != nil {
		return nil, err
	}
	return parseInsnOperandsWith(ln, func(s string) (uint16, error) {
		t := strings.TrimSpace(s)
		if strings.HasPrefix(t, "p") {
			n, err := strconv.Atoi(t[1:])
			if err != nil || n < 0 || n >= paramSlots {
				return 0, fmt.Errorf("parameter register %q outside %d parameter slots", s, paramSlots)
			}
			return uint16(registers - paramSlots + n), nil
		}
		r, err := parseReg(t)
		if err == nil && int(r) >= registers {
			return 0, fmt.Errorf("register %s outside .registers %d", t, registers)
		}
		return r, err
	})
}

// parseBranchTarget parses a numeric offset or :label reference.
func parseBranchTarget(s string) (int64, string, error) {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, ":") {
		return 0, strings.Fields(t)[0], nil
	}
	v, err := parseSmaliInt(t)
	if err != nil {
		return 0, "", fmt.Errorf("bad branch target %q", s)
	}
	return v, "", nil
}

// ── Method assembly ──────────────────────────────────────────────────────────

// asmItem is one layout unit: label marker, instruction or payload.
type asmItem struct {
	label   string
	insn    *asmInsn
	payload *SmaliPayload
}

// asmInsn is one parsed instruction awaiting encoding.
type asmInsn struct {
	op     uint8
	kind   int // flex kind (flexFixed/flexGoto/flexConst/flexMove/flexConstString)
	regs   []uint16
	lit    int64
	hasLit bool
	ref    string // resolved reference text (string/type/field/method/proto/handle/callsite)
	ref2   string // second ref (proto for polymorphic)
	line   *SmaliLine
	size   uint32 // current encoded size (fixpoint)
	pos    uint32 // current position (fixpoint)
}

// asmMethodCode is the assembled result for one method.
type asmMethodCode struct {
	units      []uint16
	registers  uint16
	insSize    uint16
	outsSize   uint16
	tries      []*asmTry
	payloadPos map[uint32]bool
}

type asmTry struct {
	start    uint32
	count    uint32
	handlers []*asmHandler
}

type asmHandler struct {
	typeName string
	addr     uint32
	catchAll bool
}

// assembleMethod encodes one method body.
func assembleMethod(pools *asmPools, m *SmaliMethod, cls string) (*asmMethodCode, error) {
	registers, paramSlots, err := smaliRegisterWindow(m)
	if err != nil {
		return nil, err
	}
	// Expand lines: attach labels, expand payloads into items.
	var items []*asmItem
	labelPos := map[string]int{} // label → item index
	for _, ln := range m.Lines {
		switch ln.Kind {
		case LineLabel:
			if _, dup := labelPos[ln.Label]; dup {
				return nil, fmt.Errorf("duplicate label %s", ln.Label)
			}
			labelPos[ln.Label] = len(items)
			items = append(items, &asmItem{label: ln.Label})
		case LineInsn:
			ai := ln.parsed
			if ai == nil {
				var err error
				ai, err = parseMethodInsnOperands(ln, m)
				if err != nil {
					return nil, fmt.Errorf("%s: %v", ln.Raw, err)
				}
				ln.parsed = ai
			}
			items = append(items, &asmItem{insn: ai})
		case LinePayload:
			for _, l := range ln.Payload.Labels {
				if _, dup := labelPos[l]; dup {
					return nil, fmt.Errorf("duplicate label %s", l)
				}
				labelPos[l] = len(items)
				items = append(items, &asmItem{label: l})
			}
			items = append(items, &asmItem{payload: ln.Payload})
		case LineCatch:
			// handled after layout
		case LineRaw:
			// .param informational lines
		}
	}
	// Fixpoint for branch sizes.
	for _, it := range items {
		if it.insn != nil {
			it.insn.size = minInsnSizeFor(it.insn)
		}
	}
	labelAddr := map[string]uint32{}
	for iter := 0; iter < 8; iter++ {
		changed := layoutItems(items, labelPos, labelAddr)
		grew := false
		for _, it := range items {
			if it.insn == nil {
				continue
			}
			need, err := insnSizeFor(pools, it.insn, labelAddr)
			if err != nil {
				return nil, err
			}
			if need > it.insn.size {
				it.insn.size = need
				grew = true
			}
		}
		if !changed && !grew {
			break
		}
		if iter == 7 {
			return nil, fmt.Errorf("method %s: branch layout did not converge", m.Name)
		}
	}
	// Encode: recompute final addresses (payloads 4-byte aligned). Nothing
	// is emitted in this pass; the write cursor below reproduces it exactly.
	var units []uint16
	payloadPos := map[uint32]bool{}
	addrOfItem := map[int]uint32{}
	var pos uint32
	for idx, it := range items {
		if it.payload != nil && pos%2 == 1 {
			pos++ // alignment padding, emitted by the write cursor
		}
		addrOfItem[idx] = pos
		switch {
		case it.insn != nil:
			pos += it.insn.size
		case it.payload != nil:
			payloadPos[pos] = true
			n, err := payloadSize(it.payload)
			if err != nil {
				return nil, err
			}
			pos += n
		}
	}
	// label → address (markers before a payload address the payload itself).
	labelAddress := map[string]uint32{}
	for l, idx := range labelPos {
		a := addrOfItem[idx]
		next := idx
		for next < len(items) && items[next].label != "" {
			next++
		}
		if next < len(items) && items[next].payload != nil {
			a = addrOfItem[next]
		}
		labelAddress[l] = a
	}
	// Map payload labels → referencing switch instruction base so :label
	// entries inside payloads resolve to switch-relative offsets.
	payloadOwner := map[*SmaliPayload]uint32{}
	labelToPayload := map[string]*SmaliPayload{}
	for _, it := range items {
		if it.payload != nil {
			for _, l := range it.payload.Labels {
				labelToPayload[l] = it.payload
			}
		}
	}
	for idx, it := range items {
		if it.insn == nil {
			continue
		}
		switch it.insn.op {
		case 0x26, 0x2B, 0x2C:
			if lbl := it.insn.ref; strings.HasPrefix(lbl, ":") {
				if pl, ok := labelToPayload[lbl]; ok {
					payloadOwner[pl] = addrOfItem[idx]
				}
			}
		}
	}
	for idx, it := range items {
		base := addrOfItem[idx]
		if it.payload != nil && base%2 == 1 {
			base++ // payloads start after alignment padding
		}
		// Keep the write cursor in sync with layout (payload padding).
		for uint32(len(units)) < base {
			units = append(units, 0x0000)
		}
		switch {
		case it.insn != nil:
			words, err := encodeInsn(pools, it.insn, base, labelAddress)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", it.insn.line.Raw, err)
			}
			// Pad if fixpoint reserved more (shouldn't happen post-convergence).
			for uint32(len(words)) < it.insn.size {
				words = append(words, 0x0000)
			}
			units = append(units, words...)
		case it.payload != nil:
			words, err := encodePayload(pools, it.payload, payloadOwner[it.payload], labelAddress)
			if err != nil {
				return nil, err
			}
			units = append(units, words...)
		case it.label != "":
			// zero-size marker
		}
	}
	// Tries from catch directives.
	var tries []*asmTry
	for _, ln := range m.Lines {
		if ln.Kind != LineCatch || ln.Catch == nil {
			continue
		}
		c := ln.Catch
		from, ok1 := labelAddress[c.TryFrom]
		to, ok2 := labelAddress[c.TryTo]
		ha, ok3 := labelAddress[c.Handler]
		if !ok1 || !ok2 || !ok3 {
			return nil, fmt.Errorf("dangling try label in %q", ln.Raw)
		}
		if to < from {
			return nil, fmt.Errorf("inverted try range in %q", ln.Raw)
		}
		// Merge handlers sharing the same range.
		var t *asmTry
		for _, e := range tries {
			if e.start == from && e.count == to-from {
				t = e
				break
			}
		}
		if t == nil {
			t = &asmTry{start: from, count: to - from}
			tries = append(tries, t)
		}
		t.handlers = append(t.handlers, &asmHandler{typeName: c.Type, addr: ha, catchAll: c.Type == ""})
	}
	sort.Slice(tries, func(i, j int) bool { return tries[i].start < tries[j].start })
	// outs = max invoke/filled-new-array arg slots.
	var outs uint16
	for _, it := range items {
		if it.insn == nil {
			continue
		}
		if isInvokeOp(it.insn.op) || it.insn.op == 0x24 || it.insn.op == 0x25 {
			if n := uint16(len(it.insn.regs)); n > outs {
				outs = n
			}
		}
	}
	return &asmMethodCode{
		units: units, registers: uint16(registers),
		insSize: uint16(paramSlots), outsSize: outs,
		tries: tries, payloadPos: payloadPos,
	}, nil
}

func layoutItems(items []*asmItem, labelPos map[string]int, labelAddr map[string]uint32) bool {
	_ = labelPos
	var pos uint32
	changed := false
	addrOf := map[int]uint32{}
	for idx, it := range items {
		addrOf[idx] = pos
		switch {
		case it.insn != nil:
			pos += it.insn.size
		case it.payload != nil:
			if pos%2 == 1 {
				pos++
			}
			n, err := payloadSize(it.payload)
			if err == nil {
				pos += n
			}
		}
	}
	for l, idx := range labelPos {
		a := addrOf[idx]
		next := idx
		for next < len(items) && items[next].label != "" {
			next++
		}
		if next < len(items) && items[next].payload != nil {
			// All aliases before a payload address its aligned start.
			pa := addrOf[next]
			if pa%2 == 1 {
				pa++
			}
			a = pa
		}
		if old, ok := labelAddr[l]; !ok || old != a {
			labelAddr[l] = a
			changed = true
		}
	}
	for idx, it := range items {
		if it.insn != nil {
			it.insn.pos = addrOf[idx]
		}
	}
	return changed
}

// minInsnSize returns the smallest encoding size for an instruction.
func minInsnSizeFor(in *asmInsn) uint32 {
	switch in.kind {
	case flexGoto, flexConst, flexMove:
		return 1
	case flexConstString:
		return 2
	}
	return opcodeTable[in.op].Size
}

// insnSizeFor returns the required size given label addresses.
func insnSizeFor(pools *asmPools, in *asmInsn, labels map[string]uint32) (uint32, error) {
	name := opcodeTable[in.op].Name
	if name == "goto" {
		off, err := branchOffset(in, labels)
		if err != nil {
			return 0, err
		}
		switch {
		case off >= -128 && off <= 127:
			return 1, nil
		case off >= -32768 && off <= 32767:
			return 2, nil
		default:
			return 3, nil
		}
	}
	if isBranchMnemonic(name) {
		// if-*: 22t fixed; goto-*: fixed by mnemonic.
		return opcodeTable[in.op].Size, nil
	}
	if in.kind == flexConst {
		v := in.lit
		switch {
		case v >= -8 && v <= 7:
			return 1, nil
		case v >= -32768 && v <= 32767:
			return 2, nil
		default:
			return 3, nil
		}
	}
	if in.kind == flexConstString {
		s, err := unquoteSmaliString(in.ref)
		if err != nil {
			return 0, err
		}
		if pools.strIndex[s] > 0xFFFF {
			return 3, nil
		}
		return 2, nil
	}
	if in.kind == flexMove {
		hi := in.regs[0] > 15 || in.regs[1] > 15
		if !hi {
			return 1, nil
		}
		if in.regs[0] <= 255 && in.regs[1] <= 65535 {
			return 2, nil
		}
		return 3, nil
	}
	return opcodeTable[in.op].Size, nil
}

func isBranchMnemonic(name string) bool {
	if strings.HasPrefix(name, "if-") {
		return true
	}
	switch name {
	case "goto", "goto/16", "goto/32", "packed-switch", "sparse-switch", "fill-array-data":
		return true
	}
	return false
}

func isInvokeOp(op uint8) bool { return op >= 0x6E && op <= 0x78 || op >= 0xFA && op <= 0xFD }

// branchOffset computes the relative offset for a branch insn.
func branchOffset(in *asmInsn, labels map[string]uint32) (int64, error) {
	if in.ref != "" && strings.HasPrefix(in.ref, ":") {
		a, ok := labels[in.ref]
		if !ok {
			return 0, fmt.Errorf("unknown label %s", in.ref)
		}
		return int64(a) - int64(in.pos), nil
	}
	return in.lit, nil
}
