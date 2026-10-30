package dataflow

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestArrayFlow(t *testing.T) {
	cases := []struct {
		name string
		body []string
		want bool
	}{
		{"filled_command", []string{
			`filled-new-array {v1, v2, v0}, [Ljava/lang/String;`, `move-result-object v3`,
			`invoke-virtual {v8, v3}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;`,
		}, true},
		{"filled_range_command", []string{
			`filled-new-array/range {v0 .. v2}, [Ljava/lang/String;`, `move-result-object v3`,
			`invoke-direct {v9, v3}, Ljava/lang/ProcessBuilder;-><init>([Ljava/lang/String;)V`,
		}, true},
		{"constant_command", []string{
			`filled-new-array {v1, v2}, [Ljava/lang/String;`, `move-result-object v3`,
			`invoke-virtual {v8, v3}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;`,
		}, false},
		{"aput_command", []string{
			`aput-object v0, v3, v4`,
			`invoke-virtual {v8, v3}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;`,
		}, true},
		{"overwritten_element", []string{
			`aput-object v0, v3, v4`, `aput-object v1, v3, v4`,
			`invoke-virtual {v8, v3}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;`,
		}, false},
		{"different_element_survives", []string{
			`aput-object v0, v3, v4`, `aput-object v1, v3, v5`,
			`invoke-virtual {v8, v3}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;`,
		}, true},
		{"read_clean_index", []string{
			`aput-object v0, v3, v4`, `aput-object v1, v3, v5`,
			`aget-object v6, v3, v5`,
			`invoke-virtual {v8, v6}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`,
		}, false},
		{"read_filled_index", []string{
			`filled-new-array {v1, v0}, [Ljava/lang/String;`, `move-result-object v3`,
			`aget-object v6, v3, v5`,
			`invoke-virtual {v8, v6}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`,
		}, true},
		{"read_filled_clean_index", []string{
			`filled-new-array {v1, v0}, [Ljava/lang/String;`, `move-result-object v3`,
			`aget-object v6, v3, v4`,
			`invoke-virtual {v8, v6}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`,
		}, false},
		{"branch_retains_dangerous_write", []string{
			`if-eqz p1, :safe`, `aput-object v0, v3, v4`, `goto :join`,
			`:safe`, `aput-object v1, v3, v4`, `:join`, `aget-object v6, v3, v4`,
			`invoke-virtual {v8, v6}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`,
		}, true},
		{"unreachable_write", []string{
			`goto :join`, `aput-object v0, v3, v4`, `:join`, `aget-object v6, v3, v4`,
			`invoke-virtual {v8, v6}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`,
		}, false},
		{"write_through_alias", []string{
			`move-object v7, v3`, `aput-object v0, v7, v4`, `aget-object v6, v3, v4`,
			`invoke-virtual {v8, v6}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`,
		}, true},
		{"read_through_alias", []string{
			`move-object v7, v3`, `aput-object v0, v3, v4`, `aget-object v6, v7, v4`,
			`invoke-virtual {v8, v6}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`,
		}, true},
		{"alias_overwrite", []string{
			`move-object v7, v3`, `aput-object v0, v3, v4`, `aput-object v1, v7, v4`,
			`aget-object v6, v3, v4`,
			`invoke-virtual {v8, v6}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`,
		}, false},
		{"reallocated_array", []string{
			`aput-object v0, v3, v4`, `new-array v3, v5, [Ljava/lang/String;`,
			`aget-object v6, v3, v4`,
			`invoke-virtual {v8, v6}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`,
		}, false},
		{"branch_index_is_not_constant", []string{
			`aput-object v0, v3, v4`, `aput-object v1, v3, v5`,
			`if-eqz p1, :one`, `const/4 v7, 0x0`, `goto :join`, `:one`, `const/4 v7, 0x1`,
			`:join`, `aget-object v6, v3, v7`,
			`invoke-virtual {v8, v6}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`,
		}, true},
		{"equivalent_index_literals", []string{
			`aput-object v0, v3, v5`, `const/16 v7, 1`, `aput-object v1, v3, v7`,
			`aget-object v6, v3, v5`,
			`invoke-virtual {v8, v6}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`,
		}, false},
		{"bound_sql_parameters", []string{
			`filled-new-array {v0}, [Ljava/lang/String;`, `move-result-object v3`,
			`const-string v6, "SELECT id FROM items WHERE name = ?"`,
			`invoke-virtual {p2, v6, v3}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;`,
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := NewProgram(DefaultConfig())
			body := []string{
				`.locals 10`, `const-string v1, "sh"`, `const-string v2, "-c"`,
				`invoke-virtual {p0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;`,
				`move-result-object v0`, `const/4 v4, 0x0`, `const/4 v5, 0x1`, `const/4 v6, 0x3`,
				`new-array v3, v6, [Ljava/lang/String;`,
				`invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;`, `move-result-object v8`,
				`new-instance v9, Ljava/lang/ProcessBuilder;`,
			}
			body = append(body, tc.body...)
			body = append(body, "return-void")
			addMethod(p, "Lapp/Arrays;", "run", "Landroid/content/Intent;ZLandroid/database/sqlite/SQLiteDatabase;", "V", true, body...)
			result := p.Analyze(context.Background())
			if got := len(result.Findings) > 0; got != tc.want {
				t.Fatalf("dangerous=%v, detected=%v: %+v", tc.want, got, result.Findings)
			}
			if result.Stats.LimitReached {
				t.Fatalf("small fixture exhausted analysis: %+v", result.Stats)
			}
			for _, f := range result.Findings {
				if f.Category != "command_injection" || !strings.Contains(f.Source, "getStringExtra") ||
					len(f.Path) < 3 || f.Path[0].Type != "source" || f.Path[len(f.Path)-1].Type != "sink" {
					t.Fatalf("missing source-to-sink evidence: %+v", f)
				}
			}
		})
	}
}

func TestArrayFlowAcrossCalls(t *testing.T) {
	for _, tc := range []struct {
		name string
		read int
		want bool
	}{
		{"returned_array", -1, true},
		{"safe_element_from_helper", 0, false},
		{"tainted_element_from_helper", 1, true},
		{"overwritten_element_from_helper", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NewProgram(DefaultConfig())
			addMethod(p, "Lapp/Factory;", "make", "Ljava/lang/String;", "[Ljava/lang/String;", true,
				`.locals 2`, `const-string v0, "fixed"`, `filled-new-array {v0, p0}, [Ljava/lang/String;`,
				`move-result-object v1`, `return-object v1`)
			addMethod(p, "Lapp/Helper;", "identity", "[Ljava/lang/String;", "[Ljava/lang/String;", true, `return-object p0`)
			addMethod(p, "Lapp/Helper;", "clean", "[Ljava/lang/String;", "[Ljava/lang/String;", true,
				`.locals 2`, `const/4 v0, 0x1`, `const-string v1, "fixed"`, `aput-object v1, p0, v0`, `return-object p0`)
			read := tc.read
			if read < 0 {
				read = 0
			}
			if read == 2 {
				read = 1
			}
			addMethod(p, "Lapp/Helper;", "read", "[Ljava/lang/String;", "Ljava/lang/String;", true,
				`.locals 2`, fmt.Sprintf("const/4 v0, 0x%x", read), `aget-object v1, p0, v0`, `return-object v1`)
			body := []string{`.locals 4`, `const-string v1, "command"`,
				`invoke-virtual {p0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`,
				`invoke-static {v0}, Lapp/Factory;->make(Ljava/lang/String;)[Ljava/lang/String;`, `move-result-object v1`,
				`invoke-static {v1}, Lapp/Helper;->identity([Ljava/lang/String;)[Ljava/lang/String;`, `move-result-object v1`,
			}
			if tc.read == 2 {
				body = append(body, `invoke-static {v1}, Lapp/Helper;->clean([Ljava/lang/String;)[Ljava/lang/String;`, `move-result-object v1`)
			}
			if tc.read < 0 {
				body = append(body, `invoke-virtual {v3, v1}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;`)
			} else {
				body = append(body, `invoke-static {v1}, Lapp/Helper;->read([Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v2`,
					`invoke-virtual {v3, v2}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`)
			}
			body = append(body, `return-void`)
			addMethod(p, "Lapp/Entry;", "run", "Landroid/content/Intent;", "V", true, body...)
			r := p.Analyze(context.Background())
			if hasCategory(r, "command_injection") != tc.want || r.Stats.LimitReached {
				t.Fatalf("want danger=%v, got %+v", tc.want, r)
			}
		})
	}
}

func TestArrayRangeSupports255Registers(t *testing.T) {
	p := NewProgram(DefaultConfig())
	body := []string{`.locals 258`}
	for i := 0; i < 254; i++ {
		body = append(body, fmt.Sprintf("const-string v%d, \"fixed\"", i))
	}
	body = append(body,
		`invoke-virtual {p0, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v254`,
		`filled-new-array/range {v0 .. v254}, [Ljava/lang/String;`, `move-result-object v255`,
		`const/16 v256, 0xfe`, `aget-object v257, v255, v256`,
		`invoke-virtual {p1, v257}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`, `return-void`)
	addMethod(p, "Lapp/LargeArray;", "run", "Landroid/content/Intent;Ljava/lang/Runtime;", "V", true, body...)
	r := p.Analyze(context.Background())
	if !hasCategory(r, "command_injection") || r.Stats.LimitReached {
		t.Fatalf("valid maximum-size range lost its last element: %+v", r)
	}
	for _, invalid := range []string{"v0 .. v255", "v-1 .. v1", "v65535 .. v65536", "v9 .. v2", "v0 .. v999999999999999999"} {
		if regs := parseRegisterList(invalid); len(regs) != 0 {
			t.Errorf("invalid range expanded: %q => %v", invalid, regs)
		}
	}
}

func TestArraySourceAndParameterSink(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Lapp/Helper;", "execute", "[Ljava/lang/String;", "V", true,
		`.locals 1`, `invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;`, `move-result-object v0`,
		`invoke-virtual {v0, p0}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;`, `return-void`)
	addMethod(p, "Lapp/Entry;", "run", "Landroid/content/Intent;", "V", true,
		`.locals 2`, `const-string v1, "command"`,
		`invoke-virtual {p0, v1}, Landroid/content/Intent;->getStringArrayExtra(Ljava/lang/String;)[Ljava/lang/String;`, `move-result-object v0`,
		`invoke-static {v0}, Lapp/Helper;->execute([Ljava/lang/String;)V`, `return-void`)
	r := p.Analyze(context.Background())
	if len(r.Findings) != 1 || !strings.Contains(r.Findings[0].Source, "getStringArrayExtra") ||
		r.Findings[0].Location.Method != "Lapp/Helper;->execute([Ljava/lang/String;)V" || r.Stats.LimitReached {
		t.Fatalf("lost caller array contents at callee sink: %+v", r)
	}
}

func TestArrayBudgetDoesNotStarveScalarSink(t *testing.T) {
	config := DefaultConfig()
	config.MaxSliceStepsPerSink = 80
	p := NewProgram(config)
	body := []string{`.locals 4`, `const/4 v0, 0x0`, `const/4 v1, 0x1`, `new-array v2, v1, [Ljava/lang/String;`, `const-string v3, "fixed"`}
	for i := 0; i < 60; i++ {
		body = append(body, `aput-object v3, v2, v0`)
	}
	body = append(body, `invoke-virtual {p0, v2}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;`, `return-void`)
	addMethod(p, "Lapp/A;", "arrays", "Ljava/lang/Runtime;", "V", true, body...)
	addMethod(p, "Lapp/Z;", "simple", "Landroid/content/Intent;Ljava/lang/Runtime;", "V", true,
		`.locals 2`, `const-string v1, "command"`,
		`invoke-virtual {p0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`,
		`invoke-virtual {p1, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`, `return-void`)
	r := p.Analyze(context.Background())
	if !r.Stats.LimitReached || r.Stats.SlicesTruncated != 1 || len(r.Findings) != 1 ||
		!strings.HasPrefix(r.Findings[0].Location.Method, "Lapp/Z;") {
		t.Fatalf("array budget must be explicit and leave other sinks usable: %+v", r)
	}
}

func TestHelperSanitizerOnOnlyOneBranch(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Lapp/Helper;", "maybeEscape", "Ljava/lang/String;Z", "Ljava/lang/String;", true,
		`.locals 1`, `if-eqz p1, :raw`,
		`invoke-static {p0}, Landroid/database/DatabaseUtils;->sqlEscapeString(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`,
		`return-object v0`, `:raw`, `return-object p0`)
	addMethod(p, "Lapp/Entry;", "run", "Landroid/content/Intent;Landroid/database/sqlite/SQLiteDatabase;Z", "V", true,
		`.locals 2`, `const-string v1, "query"`,
		`invoke-virtual {p0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`,
		`invoke-static {v0, p2}, Lapp/Helper;->maybeEscape(Ljava/lang/String;Z)Ljava/lang/String;`, `move-result-object v0`,
		`const/4 v1, 0x0`, `invoke-virtual {p1, v0, v1}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;`, `return-void`)
	if r := p.Analyze(context.Background()); !hasCategory(r, "sql_injection") {
		t.Fatalf("escaping one branch must not sanitize the other: %+v", r)
	}
}

func TestCallReturnPreservesSanitizerAndEvidence(t *testing.T) {
	for _, sanitize := range []bool{false, true} {
		t.Run(map[bool]string{false: "unsafe", true: "escaped"}[sanitize], func(t *testing.T) {
			p := NewProgram(DefaultConfig())
			body := []string{`.locals 1`, `move-object v0, p0`}
			if sanitize {
				body = append(body, `invoke-static {v0}, Landroid/database/DatabaseUtils;->sqlEscapeString(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`)
			}
			body = append(body, `return-object v0`)
			addMethod(p, "Lapp/Helper;", "value", "Ljava/lang/String;", "Ljava/lang/String;", true, body...)
			addMethod(p, "Lapp/Entry;", "run", "Landroid/content/Intent;Landroid/database/sqlite/SQLiteDatabase;", "V", true,
				`.locals 3`, `const-string v1, "name"`,
				`invoke-virtual {p0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`,
				`invoke-static {v0}, Lapp/Helper;->value(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`,
				`const-string v1, "SELECT id FROM items WHERE name = "`,
				`invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`,
				`const/4 v2, 0x0`,
				`invoke-virtual {p1, v0, v2}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;`, `return-void`)
			r := p.Analyze(context.Background())
			if got := hasCategory(r, "sql_injection"); got == sanitize {
				t.Fatalf("sanitizer lost across helper: sanitized=%v findings=%+v", sanitize, r.Findings)
			}
			if !sanitize {
				foundHelper := false
				for _, step := range r.Findings[0].Path {
					foundHelper = foundHelper || strings.HasPrefix(step.Method, "Lapp/Helper;->value(")
				}
				if !foundHelper {
					t.Fatalf("helper disappeared from evidence: %+v", r.Findings[0].Path)
				}
			}
		})
	}
}
