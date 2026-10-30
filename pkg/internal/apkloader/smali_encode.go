package apkloader

// Smali instruction parsing (mnemonic+operands → asmInsn) and binary encoding.

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// flex kinds for size-variable mnemonics.
const (
	flexFixed = iota
	flexGoto
	flexConst
	flexMove
	flexConstString
)

// parseInsnOperands resolves mnemonic + operand text into an asmInsn.
func parseInsnOperands(ln *SmaliLine) (*asmInsn, error) {
	return parseInsnOperandsWith(ln, parseReg)
}

func parseInsnOperandsWith(ln *SmaliLine, reg func(string) (uint16, error)) (*asmInsn, error) {
	mn := ln.Mnemonic
	ops := strings.TrimSpace(ln.Operands)
	comma := func() []string {
		if ops == "" {
			return nil
		}
		return splitTopLevel(ops, ',')
	}
	in := &asmInsn{line: ln}

	single := func() (uint8, error) {
		cand := smaliMnemonics[mn]
		if len(cand) != 1 {
			return 0, fmt.Errorf("ambiguous mnemonic %q", mn)
		}
		return cand[0], nil
	}

	switch mn {
	// No operands.
	case "nop", "return-void":
		if ops != "" {
			return nil, fmt.Errorf("%s takes no operands", mn)
		}
		op, err := single()
		if err != nil {
			return nil, err
		}
		in.op = op
		return in, nil
	// Single register.
	case "move-result", "move-result-wide", "move-result-object", "move-exception",
		"return", "return-wide", "return-object",
		"monitor-enter", "monitor-exit", "throw":
		parts := comma()
		if len(parts) != 1 {
			return nil, fmt.Errorf("%s takes one register", mn)
		}
		r, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		op, err := single()
		if err != nil {
			return nil, err
		}
		in.op = op
		in.regs = []uint16{r}
		return in, nil
	// Size-flexible moves.
	case "move", "move-wide", "move-object":
		parts := comma()
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s takes two registers", mn)
		}
		a, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		b, err := reg(parts[1])
		if err != nil {
			return nil, err
		}
		in.regs = []uint16{a, b}
		in.flexKind(mn)
		return in, nil
	case "move/from16", "move-wide/from16", "move-object/from16",
		"move/16", "move-wide/16", "move-object/16":
		parts := comma()
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s takes two registers", mn)
		}
		a, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		b, err := reg(parts[1])
		if err != nil {
			return nil, err
		}
		op, err := single()
		if err != nil {
			return nil, err
		}
		in.op = op
		in.regs = []uint16{a, b}
		return in, nil
	// const family.
	case "const/4", "const/16", "const/high16":
		parts := comma()
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s takes register and literal", mn)
		}
		r, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		v, err := parseSmaliInt(parts[1])
		if err != nil {
			return nil, err
		}
		op, err := single()
		if err != nil {
			return nil, err
		}
		in.op = op
		in.regs = []uint16{r}
		in.lit, in.hasLit = v, true
		return in, nil
	case "const":
		parts := comma()
		if len(parts) != 2 {
			return nil, fmt.Errorf("const takes register and literal")
		}
		r, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		v, err := parseSmaliInt(parts[1])
		if err != nil {
			return nil, err
		}
		in.regs = []uint16{r}
		in.lit, in.hasLit = v, true
		in.kind = flexConst
		in.op = 0x12
		return in, nil
	case "const-wide/16", "const-wide/32", "const-wide/high16":
		parts := comma()
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s takes register and literal", mn)
		}
		r, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		v, err := parseSmaliInt(parts[1])
		if err != nil {
			return nil, err
		}
		op, err := single()
		if err != nil {
			return nil, err
		}
		in.op = op
		in.regs = []uint16{r}
		in.lit, in.hasLit = v, true
		return in, nil
	case "const-wide":
		parts := comma()
		if len(parts) != 2 {
			return nil, fmt.Errorf("const-wide takes register and literal")
		}
		r, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		v, err := parseSmaliInt(parts[1])
		if err != nil {
			return nil, err
		}
		in.op = 0x18
		in.regs = []uint16{r}
		in.lit, in.hasLit = v, true
		return in, nil
	case "const-string", "const-string/jumbo", "const-class",
		"check-cast", "new-instance":
		parts := comma()
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s takes register and reference", mn)
		}
		r, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		in.regs = []uint16{r}
		in.ref = strings.TrimSpace(parts[1])
		if mn == "const-string" {
			in.kind = flexConstString
			in.op = 0x1A
		} else {
			op, err := single()
			if err != nil {
				return nil, err
			}
			in.op = op
		}
		return in, nil
	case "sget", "sget-wide", "sget-object", "sget-boolean", "sget-byte",
		"sget-char", "sget-short",
		"sput", "sput-wide", "sput-object", "sput-boolean", "sput-byte",
		"sput-char", "sput-short":
		parts := comma()
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s takes register and field", mn)
		}
		r, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		op, err := single()
		if err != nil {
			return nil, err
		}
		in.op = op
		in.regs = []uint16{r}
		in.ref = strings.TrimSpace(parts[1])
		return in, nil
	// 12x two-register.
	case "array-length", "neg-int", "not-int", "neg-long", "not-long",
		"neg-float", "neg-double", "int-to-long", "int-to-float",
		"int-to-double", "long-to-int", "long-to-float", "long-to-double",
		"float-to-int", "float-to-long", "float-to-double",
		"double-to-int", "double-to-long", "double-to-float",
		"int-to-byte", "int-to-char", "int-to-short",
		"add-int/2addr", "sub-int/2addr", "mul-int/2addr", "div-int/2addr",
		"rem-int/2addr", "and-int/2addr", "or-int/2addr", "xor-int/2addr",
		"shl-int/2addr", "shr-int/2addr", "ushr-int/2addr",
		"add-long/2addr", "sub-long/2addr", "mul-long/2addr", "div-long/2addr",
		"rem-long/2addr", "and-long/2addr", "or-long/2addr", "xor-long/2addr",
		"shl-long/2addr", "shr-long/2addr", "ushr-long/2addr",
		"add-float/2addr", "sub-float/2addr", "mul-float/2addr",
		"div-float/2addr", "rem-float/2addr",
		"add-double/2addr", "sub-double/2addr", "mul-double/2addr",
		"div-double/2addr", "rem-double/2addr":
		parts := comma()
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s takes two registers", mn)
		}
		a, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		b, err := reg(parts[1])
		if err != nil {
			return nil, err
		}
		op, err := single()
		if err != nil {
			return nil, err
		}
		in.op = op
		in.regs = []uint16{a, b}
		return in, nil
	// 23x three-register.
	case "cmpl-float", "cmpg-float", "cmpl-double", "cmpg-double", "cmp-long",
		"aget", "aget-wide", "aget-object", "aget-boolean", "aget-byte",
		"aget-char", "aget-short",
		"aput", "aput-wide", "aput-object", "aput-boolean", "aput-byte",
		"aput-char", "aput-short",
		"add-int", "sub-int", "mul-int", "div-int", "rem-int",
		"and-int", "or-int", "xor-int", "shl-int", "shr-int", "ushr-int",
		"add-long", "sub-long", "mul-long", "div-long", "rem-long",
		"and-long", "or-long", "xor-long", "shl-long", "shr-long", "ushr-long",
		"add-float", "sub-float", "mul-float", "div-float", "rem-float",
		"add-double", "sub-double", "mul-double", "div-double", "rem-double":
		parts := comma()
		if len(parts) != 3 {
			return nil, fmt.Errorf("%s takes three registers", mn)
		}
		var regs []uint16
		for _, ps := range parts {
			r, err := reg(ps)
			if err != nil {
				return nil, err
			}
			regs = append(regs, r)
		}
		op, err := single()
		if err != nil {
			return nil, err
		}
		in.op = op
		in.regs = regs
		return in, nil
	// 22b / 22s: two regs + literal.
	case "add-int/lit8", "rsub-int/lit8", "mul-int/lit8", "div-int/lit8",
		"rem-int/lit8", "and-int/lit8", "or-int/lit8", "xor-int/lit8",
		"shl-int/lit8", "shr-int/lit8", "ushr-int/lit8",
		"add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16",
		"rem-int/lit16", "and-int/lit16", "or-int/lit16", "xor-int/lit16":
		parts := comma()
		if len(parts) != 3 {
			return nil, fmt.Errorf("%s takes two registers and a literal", mn)
		}
		a, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		b, err := reg(parts[1])
		if err != nil {
			return nil, err
		}
		v, err := parseSmaliInt(parts[2])
		if err != nil {
			return nil, err
		}
		op, err := single()
		if err != nil {
			return nil, err
		}
		in.op = op
		in.regs = []uint16{a, b}
		in.lit, in.hasLit = v, true
		return in, nil
	// 22c: two regs + ref.
	case "instance-of", "new-array",
		"iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte",
		"iget-char", "iget-short",
		"iput", "iput-wide", "iput-object", "iput-boolean", "iput-byte",
		"iput-char", "iput-short":
		parts := comma()
		if len(parts) != 3 {
			return nil, fmt.Errorf("%s takes two registers and a reference", mn)
		}
		a, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		b, err := reg(parts[1])
		if err != nil {
			return nil, err
		}
		op, err := single()
		if err != nil {
			return nil, err
		}
		in.op = op
		in.regs = []uint16{a, b}
		in.ref = strings.TrimSpace(parts[2])
		return in, nil
	// Branches.
	case "goto", "goto/16", "goto/32":
		parts := comma()
		if len(parts) != 1 {
			return nil, fmt.Errorf("%s takes one target", mn)
		}
		off, label, err := parseBranchTarget(parts[0])
		if err != nil {
			return nil, err
		}
		if mn == "goto" {
			in.kind = flexGoto
			in.op = 0x28
		} else {
			op, err := single()
			if err != nil {
				return nil, err
			}
			in.op = op
		}
		in.lit, in.hasLit = off, label == ""
		in.ref = label
		return in, nil
	}
	// if-* (22t).
	if strings.HasPrefix(mn, "if-") && !strings.HasSuffix(mn, "z") {
		parts := comma()
		if len(parts) != 3 {
			return nil, fmt.Errorf("%s takes two registers and a target", mn)
		}
		a, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		b, err := reg(parts[1])
		if err != nil {
			return nil, err
		}
		off, label, err := parseBranchTarget(parts[2])
		if err != nil {
			return nil, err
		}
		op, err := single()
		if err != nil {
			return nil, err
		}
		in.op = op
		in.regs = []uint16{a, b}
		in.lit, in.hasLit = off, label == ""
		in.ref = label
		return in, nil
	}
	// if-*z (21t).
	if strings.HasPrefix(mn, "if-") {
		parts := comma()
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s takes a register and a target", mn)
		}
		a, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		off, label, err := parseBranchTarget(parts[1])
		if err != nil {
			return nil, err
		}
		op, err := single()
		if err != nil {
			return nil, err
		}
		in.op = op
		in.regs = []uint16{a}
		in.lit, in.hasLit = off, label == ""
		in.ref = label
		return in, nil
	}
	switch mn {
	// 31i/t: register + literal-or-target.
	case "packed-switch", "sparse-switch", "fill-array-data":
		parts := comma()
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s takes a register and a target", mn)
		}
		r, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		off, label, err := parseBranchTarget(parts[1])
		if err != nil {
			return nil, err
		}
		op, err := single()
		if err != nil {
			return nil, err
		}
		in.op = op
		in.regs = []uint16{r}
		in.lit, in.hasLit = off, label == ""
		in.ref = label
		return in, nil
	case "const-wide/32":
		// handled above
	}
	// const with 31i shape printed as hex (const-wide/32 handled above).
	// invoke kinds.
	if strings.HasPrefix(mn, "invoke-") || strings.HasPrefix(mn, "filled-new-array") {
		return parseInvokeOperands(mn, ops, ln, reg)
	}
	if mn == "const-method-handle" || mn == "const-method-type" {
		parts := comma()
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s takes a register and a reference", mn)
		}
		r, err := reg(parts[0])
		if err != nil {
			return nil, err
		}
		op, err := single()
		if err != nil {
			return nil, err
		}
		in.op = op
		in.regs = []uint16{r}
		in.ref = strings.TrimSpace(parts[1])
		return in, nil
	}
	return nil, fmt.Errorf("unsupported instruction %q", mn)
}

// flexKind assigns the move triple for bare move mnemonics.
func (in *asmInsn) flexKind(mn string) {
	in.kind = flexMove
	switch mn {
	case "move":
		in.op = 0x01
	case "move-wide":
		in.op = 0x04
	case "move-object":
		in.op = 0x07
	}
}

// parseInvokeOperands handles invoke-*, filled-new-array and polymorphic/custom.
func parseInvokeOperands(mn, ops string, ln *SmaliLine, reg func(string) (uint16, error)) (*asmInsn, error) {
	in := &asmInsn{line: ln}
	parts := splitTopLevel(ops, ',')
	if len(parts) < 1 {
		return nil, fmt.Errorf("%s needs operands", mn)
	}
	regs, isRange, err := parseRegListWith(parts[0], reg)
	if err != nil {
		return nil, err
	}
	wantRange := strings.HasSuffix(mn, "/range")
	base := strings.TrimSuffix(mn, "/range")
	_ = base
	if wantRange && !isRange && len(regs) > 1 {
		return nil, fmt.Errorf("%s/range needs {vX .. vY}", mn)
	}
	if !wantRange && isRange {
		if len(regs) > 5 {
			return nil, fmt.Errorf("%s needs /range for %d registers", mn, len(regs))
		}
		// Accept range syntax for the plain form when it fits.
	}
	op, err := func() (uint8, error) {
		cand := smaliMnemonics[mn]
		if len(cand) != 1 {
			// plain form with range syntax: map to /range variant.
			if isRange {
				cand = smaliMnemonics[mn+"/range"]
			}
			if len(cand) != 1 {
				return 0, fmt.Errorf("ambiguous mnemonic %q", mn)
			}
		}
		return cand[0], nil
	}()
	if err != nil {
		return nil, err
	}
	in.op = op
	in.regs = regs
	rest := parts[1:]
	switch op {
	case 0xFA, 0xFB: // invoke-polymorphic: method, proto
		if len(rest) != 2 {
			return nil, fmt.Errorf("invoke-polymorphic needs method and proto")
		}
		in.ref = strings.TrimSpace(rest[0])
		in.ref2 = strings.TrimSpace(rest[1])
	case 0xFC, 0xFD: // invoke-custom: call site [, proto printed? no]
		if len(rest) < 1 {
			return nil, fmt.Errorf("invoke-custom needs a call site")
		}
		in.ref = strings.TrimSpace(strings.Join(rest, ", "))
	default:
		if len(rest) != 1 {
			return nil, fmt.Errorf("%s needs one reference", mn)
		}
		in.ref = strings.TrimSpace(rest[0])
	}
	return in, nil
}

// parseProto parses "(params)ret".
func parseProto(s string) ([]string, string, error) {
	t := strings.TrimSpace(s)
	if !strings.HasPrefix(t, "(") {
		return nil, "", fmt.Errorf("bad proto %q", s)
	}
	rp := strings.Index(t, ")")
	if rp < 0 {
		return nil, "", fmt.Errorf("bad proto %q", s)
	}
	params, err := splitParams(t[1:rp])
	if err != nil {
		return nil, "", err
	}
	ret := t[rp+1:]
	if ret == "" {
		return nil, "", fmt.Errorf("bad proto %q", s)
	}
	return params, ret, nil
}

// ── Encoding ─────────────────────────────────────────────────────────────────

// internInsnRefs pre-interns every pool reference of a parsed instruction so
// later layout passes observe final indices (const-string/jumbo sizing).
func internInsnRefs(pools *asmPools, in *asmInsn) error {
	op := in.op
	if in.kind == flexConstString {
		s, err := unquoteSmaliString(in.ref)
		if err != nil {
			return err
		}
		pools.str(s)
		return nil
	}
	switch opcodeTable[op].Format {
	case Fmt21c:
		_, err := encode21cRef(pools, op, in.ref)
		return err
	case Fmt22c:
		_, err := encode22cRef(pools, op, in.ref)
		return err
	case Fmt31c:
		s, err := unquoteSmaliString(in.ref)
		if err != nil {
			return err
		}
		pools.str(s)
		return nil
	case Fmt35c, Fmt3rc, Fmt45cc, Fmt4rcc:
		if _, err := encodeInvokeRef(pools, op, in.ref); err != nil {
			return err
		}
		if op == 0xFA || op == 0xFB {
			params, ret, err := parseProto(in.ref2)
			if err != nil {
				return err
			}
			pools.proto(ret, params)
		}
		return nil
	}
	return nil
}

// encodeInsn writes one instruction; base is its address for branches.
func encodeInsn(pools *asmPools, in *asmInsn, base uint32, labels map[string]uint32) ([]uint16, error) {
	op := in.op
	if in.kind == flexConstString {
		s, err := unquoteSmaliString(in.ref)
		if err != nil {
			return nil, err
		}
		if pools.strIndex[s] > 0xFFFF {
			op = 0x1B
		} else {
			op = 0x1A
		}
	}
	name := ""
	if in.kind == flexGoto {
		switch in.size {
		case 1:
			op = 0x28
		case 2:
			op = 0x29
		default:
			op = 0x2A
		}
		name = opcodeTable[op].Name
	} else if in.kind == flexConst {
		switch in.size {
		case 1:
			op = 0x12
		case 2:
			op = 0x13
		default:
			op = 0x14
		}
		name = opcodeTable[op].Name
	} else if in.kind == flexMove {
		switch in.size {
		case 1:
			// keep base
		case 2:
			op += 1
		default:
			op += 2
		}
		name = opcodeTable[op].Name
	} else if in.kind == flexConstString {
		name = "const-string"
	} else {
		name = opcodeTable[op].Name
	}
	format := opcodeTable[op].Format
	for i, r := range in.regs {
		limit := uint16(65535)
		switch format {
		case Fmt12x, Fmt11n, Fmt22t, Fmt22s, Fmt22c, Fmt35c, Fmt45cc:
			limit = 15
		case Fmt11x, Fmt21t, Fmt21s, Fmt21h, Fmt21c, Fmt23x, Fmt22b, Fmt31i, Fmt31t, Fmt31c, Fmt51l:
			limit = 255
		case Fmt22x:
			if i == 0 {
				limit = 255
			}
		}
		if r > limit {
			return nil, fmt.Errorf("register v%d does not fit %s (maximum v%d)", r, name, limit)
		}
	}
	if (format == Fmt35c || format == Fmt45cc) && len(in.regs) > 5 {
		return nil, fmt.Errorf("%s accepts at most 5 register slots; use /range", name)
	}
	if (format == Fmt3rc || format == Fmt4rcc) && len(in.regs) > 255 {
		return nil, fmt.Errorf("%s accepts at most 255 register slots", name)
	}
	if format == Fmt11n && (in.lit < -8 || in.lit > 7) {
		return nil, fmt.Errorf("literal %d out of range for %s", in.lit, name)
	}
	if (format == Fmt21s || format == Fmt22s) && (in.lit < -32768 || in.lit > 32767) {
		return nil, fmt.Errorf("literal %d out of range for %s", in.lit, name)
	}
	off := func() int64 {
		if in.ref != "" && strings.HasPrefix(in.ref, ":") {
			a, ok := labels[in.ref]
			if !ok {
				return 0
			}
			return int64(a) - int64(base)
		}
		return in.lit
	}
	u16 := func(v int64) uint16 { return uint16(v) }

	switch opcodeTable[op].Format {
	case Fmt10x:
		return []uint16{uint16(op)}, nil
	case Fmt12x:
		a, b := in.regs[0], in.regs[1]
		return []uint16{uint16(op) | (b&0xF)<<12 | (a&0xF)<<8}, nil
	case Fmt11n:
		return []uint16{uint16(op) | (uint16(in.lit)&0xF)<<12 | (in.regs[0]&0xF)<<8}, nil
	case Fmt11x:
		return []uint16{uint16(op) | (in.regs[0]&0xFF)<<8}, nil
	case Fmt10t:
		o := off()
		if o < -128 || o > 127 {
			return nil, fmt.Errorf("goto offset %d out of range", o)
		}
		return []uint16{uint16(op) | uint16(uint8(int8(o)))<<8}, nil
	case Fmt20t:
		o := off()
		if o < -32768 || o > 32767 {
			return nil, fmt.Errorf("goto/16 offset %d out of range", o)
		}
		return []uint16{uint16(op), u16(o)}, nil
	case Fmt30t:
		return []uint16{uint16(op), u16(off()), u16(off() >> 16)}, nil
	case Fmt22x:
		return []uint16{uint16(op) | (in.regs[0]&0xFF)<<8, in.regs[1]}, nil
	case Fmt21t:
		o := off()
		if o < -32768 || o > 32767 {
			return nil, fmt.Errorf("branch offset %d out of range", o)
		}
		return []uint16{uint16(op) | (in.regs[0]&0xFF)<<8, u16(o)}, nil
	case Fmt21s:
		return []uint16{uint16(op) | (in.regs[0]&0xFF)<<8, u16(in.lit)}, nil
	case Fmt21h:
		return []uint16{uint16(op) | (in.regs[0]&0xFF)<<8, u16(in.lit >> 16)}, nil
	case Fmt21c:
		{
			idx, err := encode21cRef(pools, op, in.ref)
			if err != nil {
				return nil, err
			}
			if idx > 0xFFFF {
				return nil, fmt.Errorf("reference index overflow for %s", name)
			}
			return []uint16{uint16(op) | (in.regs[0]&0xFF)<<8, uint16(idx)}, nil
		}
	case Fmt23x:
		a, b, c := in.regs[0], in.regs[1], in.regs[2]
		return []uint16{uint16(op) | (a&0xFF)<<8, (b & 0xFF) | (c&0xFF)<<8}, nil
	case Fmt22b:
		{
			if in.regs[0] > 0xFF || in.regs[1] > 0xFF {
				return nil, fmt.Errorf("register overflow for %s", name)
			}
			if in.lit < -128 || in.lit > 127 {
				return nil, fmt.Errorf("literal %d out of range for %s", in.lit, name)
			}
			w0 := uint16(op) | (in.regs[0]&0xFF)<<8
			w1 := (in.regs[1] & 0xFF) | (uint16(uint8(int8(in.lit))) << 8)
			return []uint16{w0, w1}, nil
		}
	case Fmt22t:
		{
			o := off()
			if o < -32768 || o > 32767 {
				return nil, fmt.Errorf("branch offset %d out of range", o)
			}
			w := uint16(op) | (in.regs[0]&0xF)<<8 | (in.regs[1]&0xF)<<12
			return []uint16{w, u16(o)}, nil
		}
	case Fmt22s:
		{
			w := uint16(op) | (in.regs[0]&0xF)<<8 | (in.regs[1]&0xF)<<12
			return []uint16{w, u16(in.lit)}, nil
		}
	case Fmt22c:
		{
			idx, err := encode22cRef(pools, op, in.ref)
			if err != nil {
				return nil, err
			}
			w := uint16(op) | (in.regs[0]&0xF)<<8 | (in.regs[1]&0xF)<<12
			return []uint16{w, uint16(idx)}, nil
		}
	case Fmt32x:
		return []uint16{uint16(op), in.regs[0], in.regs[1]}, nil
	case Fmt31i, Fmt31t:
		{
			o := in.lit
			if in.ref != "" && strings.HasPrefix(in.ref, ":") {
				a, ok := labels[in.ref]
				if !ok {
					return nil, fmt.Errorf("unknown label %s", in.ref)
				}
				o = int64(a) - int64(base)
			}
			return []uint16{uint16(op) | (in.regs[0]&0xFF)<<8, u16(o), u16(o >> 16)}, nil
		}
	case Fmt31c:
		{
			s, err := unquoteSmaliString(in.ref)
			if err != nil {
				return nil, err
			}
			idx := pools.str(s)
			return []uint16{uint16(op) | (in.regs[0]&0xFF)<<8, uint16(idx), uint16(idx >> 16)}, nil
		}
	case Fmt35c:
		{
			regs := in.regs
			if len(regs) > 5 {
				return nil, fmt.Errorf("too many registers for %s", name)
			}
			idx, err := encodeInvokeRef(pools, op, in.ref)
			if err != nil {
				return nil, err
			}
			var g uint16
			if len(regs) == 5 {
				g = regs[4]
			}
			w := uint16(op) | (g&0xF)<<8 | (uint16(len(regs))&0xF)<<12
			var rc uint16
			get := func(i int) uint16 {
				if i < len(regs) {
					return regs[i] & 0xF
				}
				return 0
			}
			rc = get(0) | get(1)<<4 | get(2)<<8 | get(3)<<12
			return []uint16{w, uint16(idx), rc}, nil
		}
	case Fmt3rc:
		{
			idx, err := encodeInvokeRef(pools, op, in.ref)
			if err != nil {
				return nil, err
			}
			var start uint16
			if len(in.regs) > 0 {
				start = in.regs[0]
			}
			w := uint16(op) | (uint16(len(in.regs))&0xFF)<<8
			return []uint16{w, uint16(idx), start}, nil
		}
	case Fmt45cc:
		{
			regs := in.regs
			midx, err := encodeInvokeRef(pools, op, in.ref)
			if err != nil {
				return nil, err
			}
			params, ret, err := parseProto(in.ref2)
			if err != nil {
				return nil, err
			}
			pidx := pools.proto(ret, params)
			var g uint16
			if len(regs) == 5 {
				g = regs[4]
			}
			w := uint16(op) | (g&0xF)<<8 | (uint16(len(regs))&0xF)<<12
			var rc uint16
			get := func(i int) uint16 {
				if i < len(regs) {
					return regs[i] & 0xF
				}
				return 0
			}
			rc = get(0) | get(1)<<4 | get(2)<<8 | get(3)<<12
			return []uint16{w, uint16(midx), rc, uint16(pidx)}, nil
		}
	case Fmt4rcc:
		{
			midx, err := encodeInvokeRef(pools, op, in.ref)
			if err != nil {
				return nil, err
			}
			params, ret, err := parseProto(in.ref2)
			if err != nil {
				return nil, err
			}
			pidx := pools.proto(ret, params)
			var start uint16
			if len(in.regs) > 0 {
				start = in.regs[0]
			}
			w := uint16(op) | (uint16(len(in.regs))&0xFF)<<8
			return []uint16{w, uint16(midx), start, uint16(pidx)}, nil
		}
	case Fmt51l:
		return []uint16{uint16(op) | (in.regs[0]&0xFF)<<8,
			u16(in.lit), u16(in.lit >> 16), u16(in.lit >> 32), u16(in.lit >> 48)}, nil
	}
	_ = name
	_ = strconv.Itoa
	return nil, fmt.Errorf("cannot encode opcode 0x%02x", op)
}

// encode21cRef resolves a 21c reference operand to an index.
func encode21cRef(pools *asmPools, op uint8, ref string) (uint32, error) {
	switch {
	case op == 0x1A:
		s, err := unquoteSmaliString(ref)
		if err != nil {
			return 0, err
		}
		return pools.str(s), nil
	case op == 0x1C:
		return pools.typ(ref), nil
	case op == 0x1F || op == 0x22:
		return pools.typ(ref), nil
	case op == 0xFE:
		return pools.handle(ref)
	case op == 0xFF:
		params, ret, err := parseProto(ref)
		if err != nil {
			return 0, err
		}
		return pools.proto(ret, params), nil
	default: // sget/sput field
		c, n, t, err := splitFieldRef(ref)
		if err != nil {
			return 0, err
		}
		return pools.field(c, n, t), nil
	}
}

func encode22cRef(pools *asmPools, op uint8, ref string) (uint32, error) {
	if op == 0x20 || op == 0x23 {
		return pools.typ(ref), nil
	}
	c, n, t, err := splitFieldRef(ref)
	if err != nil {
		return 0, err
	}
	return pools.field(c, n, t), nil
}

// encodeInvokeRef resolves invoke/filled-new-array references.
func encodeInvokeRef(pools *asmPools, op uint8, ref string) (uint32, error) {
	switch op {
	case 0x24, 0x25:
		return pools.typ(ref), nil
	case 0xFA, 0xFB:
		{
			c, n, ps, r, err := splitMethodRef(ref)
			if err != nil {
				return 0, err
			}
			return pools.method(c, n, ps, r), nil
		}
	case 0xFC, 0xFD:
		return pools.callSite(ref)
	default:
		{
			c, n, ps, r, err := splitMethodRef(ref)
			if err != nil {
				return 0, err
			}
			return pools.method(c, n, ps, r), nil
		}
	}
}

// callSite parses call_site_N(args)@handle text into an interned array.
func (p *asmPools) callSite(text string) (uint32, error) {
	if i, ok := p.callIndex[text]; ok {
		return i, nil
	}
	t := strings.TrimSpace(text)
	at := strings.LastIndex(t, "@")
	if at < 0 {
		return 0, fmt.Errorf("bad call site %q", text)
	}
	handleText := t[strings.Index(t, "@")+1:]
	head := t[:strings.Index(t, "@")]
	lp := strings.Index(head, "(")
	if lp < 0 || !strings.HasSuffix(head, ")") {
		return 0, fmt.Errorf("bad call site %q", text)
	}
	_ = lp
	argsText := head[strings.Index(head, "(")+1 : len(head)-1]
	var args []string
	if strings.TrimSpace(argsText) != "" {
		args = splitTopLevel(argsText, ',')
	}
	if len(args) < 2 {
		return 0, fmt.Errorf("bad call site %q: need name and proto", text)
	}
	// v[0] = method handle.
	hidx, err := p.handle(handleText)
	if err != nil {
		return 0, err
	}
	_ = at
	_ = hidx
	// v[1] = method name string.
	nameVal, err := parseSmaliValue(strings.TrimSpace(args[0]))
	if err != nil || nameVal.Kind != "string" {
		return 0, fmt.Errorf("bad call site %q: first arg must be the method name string", text)
	}
	// v[2] = method type proto.
	protoParams, protoRet, err := parseProto(strings.TrimSpace(args[1]))
	if err != nil {
		return 0, fmt.Errorf("bad call site %q: second arg must be a proto: %v", text, err)
	}
	protoStr := "(" + strings.Join(protoParams, "") + ")" + protoRet
	arr := []DEXValue{
		{Kind: 0x16, Bits: uint64(len(p.handles) - 1), Text: handleText},
		{Kind: 0x17, Bits: uint64(p.str(nameVal.Str)), Text: nameVal.Str},
		{Kind: 0x15, Bits: uint64(p.proto(protoRet, protoParams)), Text: protoStr},
	}
	for _, a := range args[2:] {
		v, err := parseSmaliValue(strings.TrimSpace(a))
		if err != nil {
			return 0, fmt.Errorf("bad call site arg %q: %v", a, err)
		}
		dv, err := p.internDEXValue(v)
		if err != nil {
			return 0, err
		}
		arr = append(arr, dv)
	}
	i := uint32(len(p.callSites))
	p.callSites = append(p.callSites, arr)
	p.callIndex[text] = i
	return i, nil
}

// internDEXValue converts a SmaliValue, interning pool refs.
func (p *asmPools) internDEXValue(v *SmaliValue) (DEXValue, error) {
	switch v.Kind {
	case "null":
		return DEXValue{Kind: 0x1e}, nil
	case "boolean":
		return DEXValue{Kind: 0x1f, Bits: uint64(v.Int & 1)}, nil
	case "string":
		return DEXValue{Kind: 0x17, Bits: uint64(p.str(v.Str)), Text: v.Str}, nil
	case "type":
		return DEXValue{Kind: 0x18, Bits: uint64(p.typ(v.Str)), Text: v.Str}, nil
	case "field":
		{
			c, n, t, err := splitFieldRef(v.Str)
			if err != nil {
				return DEXValue{}, err
			}
			return DEXValue{Kind: 0x19, Bits: uint64(p.field(c, n, t)), Text: v.Str}, nil
		}
	case "method":
		{
			c, n, ps, r, err := splitMethodRef(v.Str)
			if err != nil {
				return DEXValue{}, err
			}
			return DEXValue{Kind: 0x1a, Bits: uint64(p.method(c, n, ps, r)), Text: v.Str}, nil
		}
	case "enum":
		{
			c, n, t, err := splitFieldRef(v.Str)
			if err != nil {
				return DEXValue{}, err
			}
			return DEXValue{Kind: 0x1b, Bits: uint64(p.field(c, n, t)), Text: v.Str}, nil
		}
	case "int":
		return DEXValue{Kind: 0x04, Bits: uint64(uint32(v.Int))}, nil
	case "byte":
		return DEXValue{Kind: 0x00, Bits: uint64(v.Int)}, nil
	case "short":
		return DEXValue{Kind: 0x02, Bits: uint64(v.Int)}, nil
	case "long":
		return DEXValue{Kind: 0x06, Bits: uint64(v.Int)}, nil
	case "char":
		return DEXValue{Kind: 0x03, Bits: uint64(v.Int)}, nil
	case "float":
		return DEXValue{Kind: 0x10, Bits: uint64(math.Float32bits(float32(v.Float)))}, nil
	case "double":
		return DEXValue{Kind: 0x11, Bits: math.Float64bits(v.Float)}, nil
	case "array":
		{
			var els []DEXValue
			for _, e := range v.Elements {
				dv, err := p.internDEXValue(e)
				if err != nil {
					return DEXValue{}, err
				}
				els = append(els, dv)
			}
			return DEXValue{Kind: 0x1c, Elements: els}, nil
		}
	case "subannotation":
		{
			if v.Sub == nil {
				return DEXValue{}, fmt.Errorf("empty subannotation")
			}
			a, err := p.internAnnotation(v.Sub)
			if err != nil {
				return DEXValue{}, err
			}
			return DEXValue{Kind: 0x1d, Annotation: &a}, nil
		}
	}
	return DEXValue{}, fmt.Errorf("unsupported encoded value kind %q", v.Kind)
}

// internAnnotation interns an annotation's type, returning DEXAnnotation.
func (p *asmPools) internAnnotation(a *SmaliAnnotation) (DEXAnnotation, error) {
	p.typ(a.Type)
	out := DEXAnnotation{Type: a.Type}
	switch a.Visibility {
	case "build":
		out.Visibility = 0
	case "runtime":
		out.Visibility = 1
	case "system":
		out.Visibility = 2
	default:
		return out, fmt.Errorf("bad visibility %q", a.Visibility)
	}
	for _, e := range a.Elements {
		p.str(e.Name)
		dv, err := p.internDEXValue(e.Value)
		if err != nil {
			return out, err
		}
		out.Elements = append(out.Elements, DEXAnnotationElement{Name: e.Name, Value: dv})
	}
	return out, nil
}

// ── Payloads ─────────────────────────────────────────────────────────────────

func payloadSize(pl *SmaliPayload) (uint32, error) {
	switch pl.Kind {
	case "packed-switch":
		n := 0
		for _, it := range pl.Items {
			t := strings.TrimSpace(it)
			if t == "" {
				continue
			}
			n++
		}
		return uint32(4 + n*2), nil
	case "sparse-switch":
		n := 0
		for _, it := range pl.Items {
			if strings.TrimSpace(it) == "" {
				continue
			}
			n++
		}
		return uint32(2 + n*4), nil
	case "array-data":
		w, err := strconv.Atoi(strings.TrimSpace(pl.Arg))
		if err != nil || (w != 1 && w != 2 && w != 4 && w != 8) {
			return 0, fmt.Errorf("bad .array-data width %q", pl.Arg)
		}
		n := 0
		for _, it := range pl.Items {
			if strings.TrimSpace(it) == "" {
				continue
			}
			n++
		}
		units := uint32(4) + uint32((uint64(n)*uint64(w)+1)/2)
		return units, nil
	}
	return 0, fmt.Errorf("unknown payload %q", pl.Kind)
}

func encodePayload(pools *asmPools, pl *SmaliPayload, base uint32, labels map[string]uint32) ([]uint16, error) {
	_ = pools
	// resolve turns a numeric offset or :label into a switch-relative target.
	resolve := func(t string) (int64, error) {
		t = strings.TrimSpace(t)
		if strings.HasPrefix(t, ":") {
			a, ok := labels[strings.Fields(t)[0]]
			if !ok {
				return 0, fmt.Errorf("unknown label %s", t)
			}
			return int64(a) - int64(base), nil
		}
		return parseSmaliInt(t)
	}
	switch pl.Kind {
	case "packed-switch":
		{
			var targets []int64
			for _, it := range pl.Items {
				t := strings.TrimSpace(it)
				if t == "" {
					continue
				}
				v, err := resolve(t)
				if err != nil {
					return nil, err
				}
				targets = append(targets, v)
			}
			var first int64
			if pl.Arg != "" {
				f, err := parseSmaliInt(pl.Arg)
				if err != nil {
					return nil, fmt.Errorf("bad packed-switch key %q", pl.Arg)
				}
				first = f
			}
			out := []uint16{0x0100, uint16(len(targets)), uint16(first), uint16(first >> 16)}
			for _, t := range targets {
				out = append(out, uint16(t), uint16(t>>16))
			}
			return out, nil
		}
	case "sparse-switch":
		{
			type kv struct {
				k int64
				v int64
			}
			var pairs []kv
			for _, it := range pl.Items {
				t := strings.TrimSpace(it)
				if t == "" {
					continue
				}
				arrow := strings.Index(t, "->")
				if arrow < 0 {
					return nil, fmt.Errorf("bad sparse-switch entry %q", it)
				}
				k, err := parseSmaliInt(strings.TrimSpace(t[:arrow]))
				if err != nil {
					return nil, err
				}
				v, err := resolve(strings.TrimSpace(t[arrow+2:]))
				if err != nil {
					return nil, err
				}
				pairs = append(pairs, kv{k, v})
			}
			out := []uint16{0x0200, uint16(len(pairs))}
			for _, pr := range pairs {
				out = append(out, uint16(pr.k), uint16(pr.k>>16))
			}
			for _, pr := range pairs {
				out = append(out, uint16(pr.v), uint16(pr.v>>16))
			}
			return out, nil
		}
	case "array-data":
		{
			w, _ := strconv.Atoi(strings.TrimSpace(pl.Arg))
			var vals []uint64
			for _, it := range pl.Items {
				t := strings.TrimSpace(it)
				if t == "" {
					continue
				}
				v, err := parseSmaliInt(t)
				if err != nil {
					return nil, err
				}
				vals = append(vals, uint64(v))
			}
			out := []uint16{0x0300, uint16(w), uint16(len(vals)), uint16(len(vals) >> 16)}
			var cur uint16
			bits := 0
			flush := func() {
				out = append(out, cur)
				cur = 0
				bits = 0
			}
			push := func(v uint64, nbytes int) {
				for i := 0; i < nbytes; i++ {
					b := byte(v >> (8 * i))
					if bits == 0 {
						cur = uint16(b)
						bits = 8
					} else {
						cur |= uint16(b) << 8
						flush()
					}
				}
			}
			for _, v := range vals {
				push(v, w)
			}
			if bits != 0 {
				flush()
			}
			_ = math.Pi
			return out, nil
		}
	}
	return nil, fmt.Errorf("unknown payload %q", pl.Kind)
}
