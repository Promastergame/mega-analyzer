package deobfuscation

import (
	"fmt"
	"os"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PROGUARD / R8 MAPPING PARSER
// ═══════════════════════════════════════════════════════════════════════════════

// ProGuardMap holds an inverted mapping: obfuscated -> original.
type ProGuardMap struct {
	classMap  map[string]string // obf class -> original class
	methodMap map[string]string // obfClass->obfMethod -> original signature
	fieldMap  map[string]string // obfClass.obfField -> original field name
}

// LoadProGuardMap reads a ProGuard / R8 mapping.txt and builds lookup tables.
func LoadProGuardMap(path string) (*ProGuardMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read mapping: %w", err)
	}

	m := &ProGuardMap{
		classMap:  make(map[string]string),
		methodMap: make(map[string]string),
		fieldMap:  make(map[string]string),
	}

	var currentObfClass string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Class declaration lines are NOT indented and end with ':'
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			parts := strings.Split(line, " -> ")
			if len(parts) == 2 {
				original := strings.TrimSpace(parts[0])
				obf := strings.TrimSuffix(strings.TrimSpace(parts[1]), ":")
				m.classMap[obf] = original
				currentObfClass = obf
			}
			continue
		}

		// Member lines (indented)
		line = strings.TrimSpace(line)
		parts := strings.Split(line, " -> ")
		if len(parts) != 2 || currentObfClass == "" {
			continue
		}
		left := strings.TrimSpace(parts[0])
		obfName := strings.TrimSpace(parts[1])

		if strings.Contains(left, "(") {
			// Method
			sig := stripLineNumbers(left)
			m.methodMap[currentObfClass+"->"+obfName] = sig
		} else {
			// Field: "type originalName"
			spaceIdx := strings.LastIndex(left, " ")
			originalField := left
			if spaceIdx >= 0 {
				originalField = left[spaceIdx+1:]
			}
			m.fieldMap[currentObfClass+"."+obfName] = originalField
		}
	}

	return m, nil
}

// NormalizeClassName converts a smali type descriptor to the dotted form used
// as a key in a ProGuard mapping file: `Lcom/example/Foo;` -> `com.example.Foo`.
// Input that is already dotted is returned unchanged.
//
// Every lookup has to go through this. mapping.txt is written in dotted form,
// while class names inside the analyzer are smali descriptors, so the two never
// matched and --proguard-map resolved nothing — while still reporting "N
// classes resolved" from the map's size, which made it look like it worked.
func NormalizeClassName(name string) string {
	if name == "" {
		return name
	}
	if strings.HasPrefix(name, "L") && strings.HasSuffix(name, ";") {
		name = name[1 : len(name)-1]
	}
	return strings.ReplaceAll(name, "/", ".")
}

// ResolveClass returns the original class name or the obfuscated one if unknown.
func (m *ProGuardMap) ResolveClass(obf string) string {
	if orig, ok := m.classMap[NormalizeClassName(obf)]; ok {
		return orig
	}
	return obf
}

// ResolveMethod returns the original method signature or obfMethod if unknown.
func (m *ProGuardMap) ResolveMethod(obfClass, obfMethod string) string {
	if orig, ok := m.methodMap[NormalizeClassName(obfClass)+"->"+obfMethod]; ok {
		return orig
	}
	return obfMethod
}

// ResolveField returns the original field name or obfField if unknown.
func (m *ProGuardMap) ResolveField(obfClass, obfField string) string {
	if orig, ok := m.fieldMap[NormalizeClassName(obfClass)+"."+obfField]; ok {
		return orig
	}
	return obfField
}

// ClassMapLen returns the size of the class mapping.
func (m *ProGuardMap) ClassMapLen() int {
	if m == nil {
		return 0
	}
	return len(m.classMap)
}

// MethodMapLen returns the size of the method mapping.
func (m *ProGuardMap) MethodMapLen() int {
	if m == nil {
		return 0
	}
	return len(m.methodMap)
}

// FieldMapLen returns the size of the field mapping.
func (m *ProGuardMap) FieldMapLen() int {
	if m == nil {
		return 0
	}
	return len(m.fieldMap)
}

// stripLineNumbers removes ProGuard line-number prefixes/suffixes.
//
//	"1:1:void onCreate(Bundle):42:42" -> "void onCreate(Bundle)"
//	"void onCreate(Bundle)"           -> "void onCreate(Bundle)"
func stripLineNumbers(s string) string {
	// Strip leading N:N: where N are digits
	for {
		c1 := strings.Index(s, ":")
		if c1 < 0 {
			break
		}
		c2 := strings.Index(s[c1+1:], ":")
		if c2 < 0 {
			break
		}
		c2 += c1 + 1
		if isDigits(s[:c1]) && isDigits(s[c1+1:c2]) {
			s = s[c2+1:]
			continue
		}
		break
	}
	// Strip trailing :N:N where N are digits
	for {
		last := strings.LastIndex(s, ":")
		if last < 0 {
			break
		}
		prev := strings.LastIndex(s[:last], ":")
		if prev < 0 {
			break
		}
		if isDigits(s[prev+1:last]) && isDigits(s[last+1:]) {
			s = s[:prev]
			continue
		}
		break
	}
	return strings.TrimSpace(s)
}

func isDigits(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
