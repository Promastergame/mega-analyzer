package apkloader

// Java view: structural pseudocode per class, emitted next to smali during
// decode so any editor (including the external apk-editor) can show method
// bodies as Java instead of a bare skeleton. Smali stays authoritative:
// the header says so, and unrecoverable sections keep explicit markers.

import (
	"fmt"
	"strings"
)

// GenerateJavaClass renders one class as Java-like pseudocode.
func GenerateJavaClass(class *ClassDef, parser *DEXParser) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// Decompiled by Mega-Analyzer (structural pseudocode).\n")
	fmt.Fprintf(&b, "// Smali is authoritative; words like /* missing */ mark uncertainty.\n")
	if pkg := javaPackage(class.ClassName); pkg != "" {
		fmt.Fprintf(&b, "package %s;\n\n", pkg)
	}
	fmt.Fprintf(&b, "public class %s {\n", javaSimpleName(class.ClassName))
	for _, f := range class.StaticFields {
		fmt.Fprintf(&b, "    %s %s;\n", javaType(f.TypeName), f.Name)
	}
	for _, f := range class.InstanceFields {
		fmt.Fprintf(&b, "    %s %s;\n", javaType(f.TypeName), f.Name)
	}
	if len(class.StaticFields)+len(class.InstanceFields) > 0 {
		b.WriteByte('\n')
	}
	for _, m := range class.DirectMethods {
		b.WriteString(indentJavaMethod(generateJavaMethod(class, m, parser)))
	}
	for _, m := range class.VirtualMethods {
		b.WriteString(indentJavaMethod(generateJavaMethod(class, m, parser)))
	}
	b.WriteString("}\n")
	return b.String()
}

func indentJavaMethod(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			b.WriteByte('\n')
			continue
		}
		b.WriteString("    ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func generateJavaMethod(class *ClassDef, m *EncodedMethod, parser *DEXParser) string {
	sig := javaMethodSignature(class, m)
	code := parser.GetMethodCode(m)
	if code == nil {
		return "// abstract or native\n" + sig + ";\n"
	}
	raw := DecodeMethodIR(code.Insns, nil)
	mir := LowerToMIR(raw)
	cfg := BuildCFGWithHandlers(mir, code)
	cfg.ComputeDominance()
	cfg.DetectLoops()
	psig := &MethodSignature{
		ClassName:  class.ClassName,
		MethodName: m.Name,
		ReturnType: TypeInfo{BaseType: javaType(m.ReturnType)},
		IsStatic:   m.AccessFlags&0x0008 != 0,
	}
	for _, p := range m.Parameters {
		psig.ParameterTypes = append(psig.ParameterTypes, TypeInfo{BaseType: javaType(p)})
	}
	for i := range m.Parameters {
		psig.ParameterNames = append(psig.ParameterNames, fmt.Sprintf("arg%d", i))
	}
	gen := NewPseudocodeGenerator(cfg, nil, nil, nil, nil, psig)
	body := gen.Generate()
	// Rewrite the synthetic method name into the real one.
	lines := strings.Split(body, "\n")
	if len(lines) > 0 {
		lines[0] = sig + " {"
	}
	return strings.Join(lines, "\n")
}

func javaMethodSignature(class *ClassDef, m *EncodedMethod) string {
	var b strings.Builder
	if m.AccessFlags&0x0008 != 0 {
		b.WriteString("static ")
	}
	if m.Name == "<init>" {
		b.WriteString(javaSimpleName(class.ClassName))
	} else if m.Name == "<clinit>" {
		b.WriteString("static")
	} else {
		b.WriteString(javaType(m.ReturnType))
		b.WriteByte(' ')
		b.WriteString(m.Name)
	}
	b.WriteByte('(')
	for i, p := range m.Parameters {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s arg%d", javaType(p), i)
	}
	b.WriteByte(')')
	return b.String()
}

// javaPackage extracts the dotted package from a descriptor.
func javaPackage(desc string) string {
	t := strings.TrimPrefix(desc, "L")
	t = strings.TrimSuffix(t, ";")
	if i := strings.LastIndex(t, "/"); i >= 0 {
		return strings.ReplaceAll(t[:i], "/", ".")
	}
	return ""
}

// javaSimpleName extracts the class short name ($ kept, idiomatic for Java).
func javaSimpleName(desc string) string {
	t := strings.TrimPrefix(desc, "L")
	t = strings.TrimSuffix(t, ";")
	if i := strings.LastIndex(t, "/"); i >= 0 {
		t = t[i+1:]
	}
	return t
}

// javaType maps a type descriptor to a Java-ish type name.
func javaType(desc string) string {
	depth := 0
	for depth < len(desc) && desc[depth] == '[' {
		depth++
	}
	base := desc[depth:]
	var name string
	switch base {
	case "V":
		name = "void"
	case "Z":
		name = "boolean"
	case "B":
		name = "byte"
	case "S":
		name = "short"
	case "C":
		name = "char"
	case "I":
		name = "int"
	case "J":
		name = "long"
	case "F":
		name = "float"
	case "D":
		name = "double"
	default:
		name = javaSimpleName(base)
		if name == "" {
			name = "Object"
		}
	}
	for i := 0; i < depth; i++ {
		name += "[]"
	}
	return name
}
