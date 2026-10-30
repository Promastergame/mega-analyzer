package dataflow

import (
	"context"
	"strings"
	"testing"
)

// These are detector assertions, not application exploitability assertions.
// Every case specifies an actual sensitive sink; constructor-only warnings do
// not satisfy a FileInputStream target. Inputs are never executed as bytecode.
func precisionPrefix() []string {
	return []string{
		`.locals 4`, `const-string v1, "input"`,
		`invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;`, `move-result-object v2`,
	}
}
func precisionSource() []string {
	return []string{
		`invoke-virtual {p1, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`,
	}
}

const precisionExec = `invoke-virtual {v2, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;`
const precisionOpen = `invoke-direct {v2, v0}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V`

func precisionBody(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestPrecisionV2Cases(t *testing.T) {
	cases := []struct {
		name   string
		danger bool
		target string
		body   []string
	}{
		{"branch_merge_tainted_arm", true, "Ljava/lang/Runtime;->exec", precisionBody([]string{`if-eqz p0, :safe`}, precisionSource(), []string{`goto :join`, `:safe`, `const-string v0, "fixed"`, `:join`, precisionExec, `return-void`})},
		{"unreachable_sink", false, "Ljava/lang/Runtime;->exec", precisionBody([]string{`goto :exit`}, precisionSource(), []string{precisionExec, `:exit`, `return-void`})},
		{"dead_definition_before_join", false, "Ljava/lang/Runtime;->exec", precisionBody([]string{`const-string v0, "fixed"`, `goto :join`}, precisionSource(), []string{`:join`, precisionExec, `return-void`})},
		{"backedge_reaches_next_iteration", true, "Ljava/lang/Runtime;->exec", precisionBody([]string{`const-string v0, "fixed"`, `:loop`, precisionExec}, precisionSource(), []string{`if-nez p0, :loop`, `return-void`})},
		// Numeric relative offsets are Dalvik code units, NOT source line counts.
		{"numeric_branch_merge", true, "Ljava/lang/Runtime;->exec", precisionBody([]string{`if-eqz p0, +7`}, precisionSource(), []string{`goto +3`, `const-string v0, "fixed"`, precisionExec, `return-void`})},
		{"switch_tainted_arm", true, "Ljava/lang/Runtime;->exec", precisionBody([]string{`packed-switch p0, :table`, `goto :safe`, `:tainted`}, precisionSource(), []string{`goto :join`, `:safe`, `const-string v0, "fixed"`, `:join`, precisionExec, `return-void`, `:table`, `.packed-switch 0x0`, `:tainted`, `.end packed-switch`})},
		{"exception_merge_preserves_normal_taint", true, "Ljava/lang/Runtime;->exec", precisionBody([]string{`:try_start`}, precisionSource(), []string{`:try_end`, `goto :join`, `:catch`, `move-exception v3`, `const-string v0, "fixed"`, `:join`, precisionExec, `return-void`, `.catch Ljava/lang/Exception; {:try_start .. :try_end} :catch`})},
		{"canonicalization_is_not_containment", true, "Ljava/io/FileInputStream;-><init>", []string{
			`invoke-virtual {p1, v1}, Landroid/content/Intent;->getSerializableExtra(Ljava/lang/String;)Ljava/io/Serializable;`, `move-result-object v0`, `check-cast v0, Ljava/io/File;`,
			`invoke-virtual {v0}, Ljava/io/File;->getCanonicalPath()Ljava/lang/String;`, `move-result-object v0`,
			`new-instance v2, Ljava/io/FileInputStream;`, precisionOpen, `return-void`,
		}},
		{"ignored_canonical_return_not_mutation", true, "Ljava/io/FileInputStream;-><init>", []string{
			`invoke-virtual {p1, v1}, Landroid/content/Intent;->getSerializableExtra(Ljava/lang/String;)Ljava/io/Serializable;`, `move-result-object v0`, `check-cast v0, Ljava/io/File;`,
			`invoke-virtual {v0}, Ljava/io/File;->getCanonicalPath()Ljava/lang/String;`,
			`new-instance v2, Ljava/io/FileInputStream;`, `invoke-direct {v2, v0}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V`, `return-void`,
		}},
		{"encoded_dotdot_is_not_containment", true, "Ljava/io/FileInputStream;-><init>", precisionBody(precisionSource(), []string{
			`const-string v1, "UTF-8"`, `invoke-static {v0, v1}, Ljava/net/URLEncoder;->encode(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`,
			`const-string v1, "/target.dat"`, `invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`,
			`const-string v1, "/app/base/"`, `invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`,
			`new-instance v2, Ljava/io/FileInputStream;`, precisionOpen, `return-void`,
		})},
		{"constructor_receiver_carries_path", true, "Ljava/io/FileInputStream;-><init>", precisionBody(precisionSource(), []string{
			`new-instance v3, Ljava/io/File;`, `invoke-direct {v3, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V`,
			`new-instance v2, Ljava/io/FileInputStream;`, `invoke-direct {v2, v3}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V`, `return-void`,
		})},
		{"constant_path_control", false, "Ljava/io/FileInputStream;-><init>", []string{`const-string v0, "/app/base/fixed.txt"`, `new-instance v2, Ljava/io/FileInputStream;`, precisionOpen, `return-void`}},
		{"overwritten_input_control", false, "Ljava/lang/Runtime;->exec", precisionBody(precisionSource(), []string{`const-string v0, "fixed"`, precisionExec, `return-void`})},
		{"straight_source_control", true, "Ljava/lang/Runtime;->exec", precisionBody(precisionSource(), []string{precisionExec, `return-void`})},
		{"sql_bound_parameter_control", false, "Landroid/database/sqlite/SQLiteDatabase;->rawQuery", precisionBody(precisionSource(), []string{
			`const-string v1, "SELECT id FROM items WHERE name = ?"`, `const/4 v3, 0x1`, `new-array v2, v3, [Ljava/lang/String;`, `const/4 v3, 0x0`, `aput-object v0, v2, v3`,
			`invoke-virtual {p2, v1, v2}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;`, `return-void`,
		})},
		{"sql_raw_concat_control", true, "Landroid/database/sqlite/SQLiteDatabase;->rawQuery", precisionBody(precisionSource(), []string{
			`const-string v1, "SELECT id FROM items WHERE name = "`, `invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`, `const/4 v3, 0x0`,
			`invoke-virtual {p2, v0, v3}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;`, `return-void`,
		})},
		{"ordinary_input_log_not_secret_leak", false, "Landroid/util/Log;->d", precisionBody(precisionSource(), []string{`invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I`, `return-void`})},
		{"location_log_sensitive_control", true, "Landroid/util/Log;->d", []string{
			`invoke-virtual {p3, v1}, Landroid/location/LocationManager;->getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;`, `move-result-object v0`,
			`invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;`, `move-result-object v0`,
			`invoke-static {v1, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I`, `return-void`,
		}},
		{"exception_before_write_keeps_prior_value", true, "Ljava/lang/Runtime;->exec", precisionBody(precisionSource(), []string{
			`:try_start`, `invoke-static {p0}, Lfixture/Helper;->maybeRead(Z)Ljava/lang/String;`, `move-result-object v0`, `:try_end`, `return-void`,
			`:caught`, `move-exception v3`, precisionExec, `return-void`, `.catch Ljava/lang/Exception; {:try_start .. :try_end} :caught`,
		})},
		{"parcelable_cannot_be_cast_to_string", false, "Ljava/io/FileInputStream;-><init>", []string{
			`invoke-virtual {p1, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;`, `move-result-object v0`, `check-cast v0, Ljava/lang/String;`,
			`new-instance v2, Ljava/io/FileInputStream;`, precisionOpen, `return-void`,
		}},
		{"parcelable_string_conversion_preserves_flow", true, "Ljava/io/FileInputStream;-><init>", []string{
			`invoke-virtual {p1, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;`, `move-result-object v0`,
			`invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;`, `move-result-object v0`, `check-cast v0, Ljava/lang/String;`,
			`new-instance v2, Ljava/io/FileInputStream;`, precisionOpen, `return-void`,
		}},
		{"serializable_may_be_a_string", true, "Ljava/io/FileInputStream;-><init>", []string{
			`invoke-virtual {p1, v1}, Landroid/content/Intent;->getSerializableExtra(Ljava/lang/String;)Ljava/io/Serializable;`, `move-result-object v0`, `check-cast v0, Ljava/lang/String;`,
			`new-instance v2, Ljava/io/FileInputStream;`, precisionOpen, `return-void`,
		}},
		{"type_merge_keeps_converted_arm", true, "Ljava/io/FileInputStream;-><init>", []string{
			`invoke-virtual {p1, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;`, `move-result-object v0`, `if-eqz p0, :typed_join`,
			`invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;`, `move-result-object v0`, `:typed_join`, `check-cast v0, Ljava/lang/String;`,
			`new-instance v2, Ljava/io/FileInputStream;`, precisionOpen, `return-void`,
		}},
		{"parcelable_cannot_be_cast_via_byte_array", false, "Ljava/io/FileInputStream;-><init>", []string{
			`invoke-virtual {p1, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;`, `move-result-object v0`, `check-cast v0, [B`, `check-cast v0, Ljava/lang/String;`,
			`new-instance v2, Ljava/io/FileInputStream;`, precisionOpen, `return-void`,
		}},
		{"array_string_conversion_preserves_flow", true, "Ljava/io/FileInputStream;-><init>", []string{
			`invoke-virtual {p1, v1}, Landroid/content/Intent;->getSerializableExtra(Ljava/lang/String;)Ljava/io/Serializable;`, `move-result-object v0`, `check-cast v0, [B`,
			`invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;`, `move-result-object v0`, `check-cast v0, Ljava/lang/String;`,
			`new-instance v2, Ljava/io/FileInputStream;`, precisionOpen, `return-void`,
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := NewProgram(DefaultConfig())
			if c.name == "exception_before_write_keeps_prior_value" {
				addMethod(p, "Lfixture/Helper;", "maybeRead", "Z", "Ljava/lang/String;", true,
					`.locals 1`, `if-eqz p0, :failure`, `const-string v0, "fixed"`, `return-object v0`,
					`:failure`, `new-instance v0, Ljava/lang/RuntimeException;`, `invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V`, `throw v0`)
			}
			addMethod(p, "Lfixture/Precision;", "run", "ZLandroid/content/Intent;Landroid/database/sqlite/SQLiteDatabase;Landroid/location/LocationManager;", "V", true, precisionBody(precisionPrefix(), c.body)...)
			r := p.Analyze(context.Background())
			detected := false
			for _, f := range r.Findings {
				if strings.HasPrefix(f.Sink, c.target) {
					detected = true
				}
			}
			t.Logf("EXPECTED=%t DETECTED=%t TARGET=%s FINDINGS=%d", c.danger, detected, c.target, len(r.Findings))
			if detected != c.danger {
				t.Errorf("detector decision differs from fixture property: expected=%t detected=%t", c.danger, detected)
			}
		})
	}
}
func TestPrecisionV2UnreachableReturnDoesNotTaintCaller(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Lfixture/Helper;", "read", "Landroid/content/Intent;", "Ljava/lang/String;", true,
		`.locals 2`, `const-string v0, "fixed"`, `return-object v0`,
		`const-string v1, "input"`, `invoke-virtual {p0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;`, `move-result-object v0`, `return-object v0`)
	addMethod(p, "Lfixture/Precision;", "run", "ZLandroid/content/Intent;Landroid/database/sqlite/SQLiteDatabase;Landroid/location/LocationManager;", "V", true, precisionBody(precisionPrefix(), []string{
		`invoke-static {p1}, Lfixture/Helper;->read(Landroid/content/Intent;)Ljava/lang/String;`, `move-result-object v0`, precisionExec, `return-void`,
	})...)
	r := p.Analyze(context.Background())
	t.Logf("EXPECTED=false DETECTED=%t TARGET=unreachable_return FINDINGS=%d", len(r.Findings) != 0, len(r.Findings))
	if len(r.Findings) != 0 {
		t.Fatalf("unreachable callee return imported a source: %+v", r.Findings)
	}
}
