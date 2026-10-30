package main

import (
	"fmt"
	"os"

	"mega-analyzer/pkg/internal/il2cpp"
)

func main() {
	md, _ := os.ReadFile(os.Args[1])
	m, err := il2cpp.ParseMetadata(md, "")
	if err != nil { panic(err) }
	targets := map[string]bool{"DayOfWeek": true, "AttributeTargets": true, "BindingFlags": true, "StringComparison": true}
	for i := range m.TypeDefs {
		td := &m.TypeDefs[i]
		name := m.Str.Get(td.NameIdx)
		if !targets[name] || !td.IsEnum() || td.FieldCount < 4 { continue }
		under := "int"
		fmt.Printf("=== %s (typedef %d, %d fields)\n", name, i, td.FieldCount)
		for k := int64(0); k < int64(td.FieldCount) && k < 12; k++ {
			fi := td.FirstField + k
			f := m.Fields[fi]
			dv, ok := m.FieldDefaultByIdx[fi]
			if !ok { continue }
			raw := m.DefaultDataRaw(dv.DataIdx)
			n := 6; if len(raw) < n { n = len(raw) }
			fmt.Printf("  %-28s off=%-6d bytes=%d\n", m.Str.Get(f.NameIdx), dv.DataIdx, raw[:n])
		}
		_ = under
	}
}
