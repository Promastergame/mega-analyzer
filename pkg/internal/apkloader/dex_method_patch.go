package apkloader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// PatchDEXMethod applies the reviewed method bodies using the input DEX's
// reference indices. It returns changed=false only when the complete target
// body is already present. It never changes data on failure. Changes requiring
// new references, code relocation or a different exception layout must use a
// full Smali rebuild rather than silently applying a different patch.
func PatchDEXMethod(data []byte, descriptor, original, patched string) ([]byte, bool, error) {
	if err := verifyDEXIntegrity(data); err != nil {
		return nil, false, err
	}
	parser, err := ParseDEXBytes(data)
	if err != nil {
		return nil, false, fmt.Errorf("parse DEX: %w", err)
	}
	className, signature, ok := strings.Cut(descriptor, "->")
	if !ok || !strings.HasPrefix(className, "L") || !strings.HasSuffix(className, ";") || !strings.Contains(signature, "(") {
		return nil, false, fmt.Errorf("an exact class and method descriptor is required: %q", descriptor)
	}
	method, err := findPatchMethod(parser, descriptor)
	if err != nil {
		return nil, false, err
	}
	if err := validatePatchCodeItem(method, len(data)); err != nil {
		return nil, false, err
	}
	from, err := parsePatchMethod(className, original)
	if err != nil {
		return nil, false, fmt.Errorf("original method: %w", err)
	}
	to, err := parsePatchMethod(className, patched)
	if err != nil {
		return nil, false, fmt.Errorf("patched method: %w", err)
	}
	for _, m := range []*SmaliMethod{from, to} {
		if MethodDescriptor(className, m.Name, m.Params, m.Return) != descriptor || m.Access != method.AccessFlags {
			return nil, false, fmt.Errorf("artifact method identity or access flags do not match %s", descriptor)
		}
	}
	if !reflect.DeepEqual(from.Annotations, to.Annotations) || !reflect.DeepEqual(from.ParamAnnots, to.ParamAnnots) {
		return nil, false, fmt.Errorf("changing method annotations requires a full Smali rebuild")
	}

	pools := patchPoolsFromDEX(parser)
	expected, err := assemblePatchMethod(pools, parser, className, from)
	if err != nil {
		return nil, false, fmt.Errorf("assemble original method: %w", err)
	}
	replacement, err := assemblePatchMethod(pools, parser, className, to)
	if err != nil {
		return nil, false, fmt.Errorf("assemble patched method: %w", err)
	}
	if len(replacement.units) == 0 || len(replacement.units) > len(method.Code.Insns) {
		return nil, false, fmt.Errorf("patched method needs %d code units; DEX slot holds %d; use a full Smali rebuild", len(replacement.units), len(method.Code.Insns))
	}
	if !patchTriesMatch(replacement.tries, method.Code.Tries) {
		return nil, false, fmt.Errorf("changing DEX exception layout requires a full Smali rebuild")
	}
	// Assemble the current method too: textual whitespace, parameter aliases
	// and equivalent const/goto widths must not create false source drift.
	var currentText bytes.Buffer
	writeSmaliMethodBuf(&currentText, method, parser)
	currentMethod, err := parsePatchMethod(className, currentText.String())
	if err != nil {
		return nil, false, fmt.Errorf("read current method: %w", err)
	}
	if !reflect.DeepEqual(to.Annotations, currentMethod.Annotations) || !reflect.DeepEqual(to.ParamAnnots, currentMethod.ParamAnnots) {
		return nil, false, fmt.Errorf("DEX source annotations drifted in %s", descriptor)
	}
	if patchedCodeMatches(method.Code, replacement) {
		return data, false, nil
	}
	current, err := assemblePatchMethod(pools, parser, className, currentMethod)
	if err != nil {
		return nil, false, fmt.Errorf("assemble current method: %w", err)
	}
	if !samePatchCode(expected, current) {
		return nil, false, fmt.Errorf("DEX source drift in %s", descriptor)
	}

	out := bytes.Clone(data)
	off := uint64(method.CodeOff)
	if off+16+uint64(len(method.Code.Insns))*2 > uint64(len(out)) {
		return nil, false, fmt.Errorf("DEX code item extends beyond the image")
	}
	putU16(out, method.CodeOff, replacement.registers)
	putU16(out, method.CodeOff+2, replacement.insSize)
	putU16(out, method.CodeOff+4, replacement.outsSize)
	// The old debug program describes old instruction addresses/registers.
	// Keep the code_item's physical size and catch table, but detach stale debug.
	binary.LittleEndian.PutUint32(out[off+8:off+12], 0)
	for i := range method.Code.Insns {
		word := uint16(0)
		if i < len(replacement.units) {
			word = replacement.units[i]
		}
		putU16(out, method.CodeOff+16+uint32(i*2), word)
	}
	if err := finalizeDEX(out); err != nil {
		return nil, false, err
	}
	if err := verifyDEXIntegrity(out); err != nil {
		return nil, false, err
	}
	verified, err := ParseDEXBytes(out)
	if err != nil {
		return nil, false, fmt.Errorf("patched DEX validation: %w", err)
	}
	result, err := findPatchMethod(verified, descriptor)
	if err != nil || !patchedCodeMatches(result.Code, replacement) {
		return nil, false, fmt.Errorf("patched DEX does not match the reviewed method")
	}
	return out, true, nil
}

func findPatchMethod(parser *DEXParser, descriptor string) (*EncodedMethod, error) {
	var found *EncodedMethod
	for _, cls := range parser.GetClasses() {
		for _, methods := range [][]*EncodedMethod{cls.DirectMethods, cls.VirtualMethods} {
			for _, method := range methods {
				if buildDescriptor(cls.ClassName, method) != descriptor {
					continue
				}
				if found != nil {
					return nil, fmt.Errorf("ambiguous DEX method descriptor: %s", descriptor)
				}
				found = method
			}
		}
	}
	if found == nil || found.Code == nil || found.CodeOff == 0 {
		return nil, fmt.Errorf("concrete DEX method not found: %s", descriptor)
	}
	for _, cls := range parser.GetClasses() {
		for _, methods := range [][]*EncodedMethod{cls.DirectMethods, cls.VirtualMethods} {
			for _, method := range methods {
				if method != found && method.CodeOff == found.CodeOff {
					return nil, fmt.Errorf("DEX code item is shared with %s; use a full Smali rebuild", buildDescriptor(cls.ClassName, method))
				}
			}
		}
	}
	return found, nil
}

func validatePatchCodeItem(method *EncodedMethod, imageSize int) error {
	code := method.Code
	if method.CodeOff%4 != 0 || code.InsnsSize == 0 || uint64(code.InsnsSize) != uint64(len(code.Insns)) ||
		uint64(method.CodeOff)+16+uint64(code.InsnsSize)*2 > uint64(imageSize) {
		return fmt.Errorf("invalid DEX code item bounds for %s", method.Name)
	}
	if int(code.InsSize) != paramRegisterCount(method) || code.RegistersSize < code.InsSize {
		return fmt.Errorf("DEX register frame does not match the method parameters in %s", method.Name)
	}
	if int(code.TriesSize) != len(code.Tries) {
		return fmt.Errorf("incomplete DEX exception table in %s", method.Name)
	}
	return nil
}

func parsePatchMethod(className, body string) (*SmaliMethod, error) {
	file, _, err := ParseSmaliFile("patch.smali", ".class public "+className+"\n.super Ljava/lang/Object;\n"+body)
	if err != nil {
		return nil, err
	}
	if file.Class != className || len(file.Methods) != 1 || len(file.Fields) != 0 {
		return nil, fmt.Errorf("artifact must contain exactly one method")
	}
	return file.Methods[0], nil
}

func patchPoolsFromDEX(p *DEXParser) *asmPools {
	pool := newAsmPools()
	pool.strings = slices.Clone(p.strings)
	for i, value := range p.strings {
		pool.strIndex[value] = uint32(i)
	}
	pool.types = slices.Clone(p.types)
	for i, value := range p.types {
		pool.typeIndex[value] = uint32(i)
	}
	for i, value := range p.protos {
		pool.protos = append(pool.protos, &asmProto{shorty: value.Shorty, ret: value.ReturnType, params: slices.Clone(value.Parameters)})
		pool.protoIndex[protoKey(value.ReturnType, value.Parameters)] = uint32(i)
	}
	for i, value := range p.fields {
		pool.fields = append(pool.fields, &asmField{cls: value.ClassName, name: value.FieldName, typ: value.TypeName})
		pool.fieldIndex[value.ClassName+"\x00"+value.FieldName+"\x00"+value.TypeName] = uint32(i)
	}
	for i, value := range p.methods {
		pool.methods = append(pool.methods, &asmMethod{cls: value.ClassName, name: value.MethodName, params: slices.Clone(value.Parameters), ret: value.ReturnType})
		pool.methodIndex[value.ClassName+"\x00"+value.MethodName+"\x00"+protoKey(value.ReturnType, value.Parameters)] = uint32(i)
	}
	pool.handles = slices.Clone(p.methodHandles)
	for i := range p.methodHandles {
		pool.handleIndex[p.methodHandleText(uint32(i))] = uint32(i)
	}
	pool.callSites = slices.Clone(p.callSites)
	for i := range p.callSites {
		pool.callIndex[p.callSiteText(uint32(i))] = uint32(i)
	}
	return pool
}

func assemblePatchMethod(pool *asmPools, p *DEXParser, cls string, method *SmaliMethod) (*asmMethodCode, error) {
	if err := prescanMethod(pool, cls, method); err != nil {
		return nil, err
	}
	code, err := assembleMethod(pool, method, cls)
	if err != nil {
		return nil, err
	}
	if len(pool.strings) != len(p.strings) || len(pool.types) != len(p.types) || len(pool.protos) != len(p.protos) || len(pool.fields) != len(p.fields) || len(pool.methods) != len(p.methods) || len(pool.handles) != len(p.methodHandles) || len(pool.callSites) != len(p.callSites) {
		return nil, fmt.Errorf("method introduces new DEX references; use a full Smali rebuild")
	}
	return code, nil
}

func samePatchCode(a, b *asmMethodCode) bool {
	return a.registers == b.registers && a.insSize == b.insSize && a.outsSize == b.outsSize && slices.Equal(a.units, b.units) && reflect.DeepEqual(a.tries, b.tries)
}

func patchedCodeMatches(code *CodeItem, patch *asmMethodCode) bool {
	if code.RegistersSize != patch.registers || code.InsSize != patch.insSize || code.OutsSize != patch.outsSize || len(patch.units) > len(code.Insns) || !patchTriesMatch(patch.tries, code.Tries) {
		return false
	}
	if !slices.Equal(code.Insns[:len(patch.units)], patch.units) {
		return false
	}
	for _, word := range code.Insns[len(patch.units):] {
		if word != 0 {
			return false
		}
	}
	return true
}

func patchTriesMatch(tries []*asmTry, current []*TryItem) bool {
	if len(tries) != len(current) {
		return false
	}
	for i, want := range tries {
		got := current[i]
		if want == nil || got == nil || want.start != got.StartAddr || want.count != uint32(got.InsnCount) {
			return false
		}
		var handlers []*asmHandler
		for _, h := range got.CatchHandlers {
			if h == nil {
				return false
			}
			if h.TypeIdx >= 0 {
				handlers = append(handlers, &asmHandler{typeName: h.TypeName, addr: h.HandlerAddr})
			}
			if h.HasCatchAll {
				handlers = append(handlers, &asmHandler{addr: h.CatchAllAddr, catchAll: true})
			}
		}
		if !reflect.DeepEqual(want.handlers, handlers) {
			return false
		}
	}
	return true
}
