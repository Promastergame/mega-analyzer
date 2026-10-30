package dataflow

import (
	"context"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func addMethod(program *Program, className, name, params, returnType string, isStatic bool, body ...string) {
	access := types.AccessPublic
	if isStatic {
		access |= types.AccessStatic
	}
	program.AddClass("smali/app/Test.smali", &types.SmaliClass{
		Name: className,
		Methods: []types.SmaliMethod{{
			Name: name, Params: params, ReturnType: returnType, Access: access,
			SourceRange: types.SourceRange{LineStart: 1, LineEnd: len(body)}, Body: body,
		}},
	})
}

func TestProgramSourceReturnPropagatesIntoCallerSink(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Flow;", "read", "Landroid/content/Intent;Ljava/lang/String;", "Ljava/lang/String;", true,
		".method public static read(Landroid/content/Intent;Ljava/lang/String;)Ljava/lang/String;",
		"invoke-virtual {p0, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v0", "return-object v0", ".end method")
	addMethod(program, "Lapp/Flow;", "run", "Landroid/content/Intent;Ljava/lang/String;", "V", true,
		".method public static run(Landroid/content/Intent;Ljava/lang/String;)V",
		"invoke-static {p0, p1}, Lapp/Flow;->read(Landroid/content/Intent;Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v0",
		"invoke-virtual {v9, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if len(result.Findings) == 0 {
		t.Fatalf("source return did not propagate to caller sink: %+v", result.Stats)
	}
	if result.Findings[0].Category != "command_injection" {
		t.Fatalf("unexpected finding: %+v", result.Findings[0])
	}
}

func TestProgramCanonicalizesParserClassNameForDirectCalls(t *testing.T) {
	// The production parser emits app.Flow for the declaration and invoke-* is
	// necessarily Lapp/Flow;. Direct calls must still join their definition.
	class := &types.SmaliClass{Name: "app.Flow", Methods: []types.SmaliMethod{
		{Name: "read", Params: "Landroid/content/Intent;Ljava/lang/String;", ReturnType: "Ljava/lang/String;", Access: types.AccessStatic,
			Body: []string{"invoke-virtual {p0, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v0", "return-object v0"}},
		{Name: "run", Params: "Landroid/content/Intent;Ljava/lang/String;", ReturnType: "V", Access: types.AccessStatic,
			Body: []string{"invoke-static {p0, p1}, Lapp/Flow;->read(Landroid/content/Intent;Ljava/lang/String;)Ljava/lang/String;", "move-result-object v0", "invoke-virtual {v9, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;", "return-void"}},
	}}
	program := NewProgram(DefaultConfig())
	program.AddClass("Flow.smali", class)
	if findings := program.Analyze(context.Background()).Findings; len(findings) != 1 || findings[0].Category != "command_injection" {
		t.Fatalf("direct parsed-smali flow missed: %+v", findings)
	}
}

func TestProgramResolvesInterfaceImplementationForSink(t *testing.T) {
	program := NewProgram(DefaultConfig())
	program.AddClass("Command.smali", &types.SmaliClass{
		Name:    "app.Command",
		Methods: []types.SmaliMethod{{Name: "execute", Params: "Ljava/lang/String;", ReturnType: "V"}},
	})
	program.AddClass("CommandImpl.smali", &types.SmaliClass{
		Name: "app.CommandImpl", Interfaces: []string{"app.Command"},
		Methods: []types.SmaliMethod{{
			Name: "execute", Params: "Ljava/lang/String;", ReturnType: "V", Access: types.AccessPublic,
			Body: []string{"invoke-virtual {v9, p1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;", "return-void"},
		}},
	})
	program.AddClass("Entry.smali", &types.SmaliClass{
		Name: "app.Entry",
		Methods: []types.SmaliMethod{{
			Name: "run", Params: "Landroid/content/Intent;Ljava/lang/String;", ReturnType: "V", Access: types.AccessStatic,
			Body: []string{
				"invoke-virtual {p0, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
				"move-result-object v0",
				"invoke-interface {v8, v0}, Lapp/Command;->execute(Ljava/lang/String;)V",
				"return-void",
			},
		}},
	})

	findings := program.Analyze(context.Background()).Findings
	if len(findings) != 1 || findings[0].Category != "command_injection" {
		t.Fatalf("interface dispatch chain missed: %+v", findings)
	}
}

func TestProgramSubstitutesCallerFactIntoCalleeSink(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Flow;", "execute", "Ljava/lang/String;", "V", true,
		".method public static execute(Ljava/lang/String;)V",
		"invoke-virtual {v9, p0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
		"return-void", ".end method")
	addMethod(program, "Lapp/Flow;", "entry", "Landroid/content/Intent;Ljava/lang/String;", "V", true,
		".method public static entry(Landroid/content/Intent;Ljava/lang/String;)V",
		"invoke-virtual {p0, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v0",
		"invoke-static {v0}, Lapp/Flow;->execute(Ljava/lang/String;)V",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if len(result.Findings) == 0 {
		t.Fatalf("callee param-to-sink summary was not substituted: %+v", result.Stats)
	}
}

func TestProgramSQLSanitizerSuppressesOnlySQLSink(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Flow;", "query", "Landroid/content/Intent;Ljava/lang/String;", "V", true,
		".method public static query(Landroid/content/Intent;Ljava/lang/String;)V",
		"invoke-virtual {p0, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v0",
		"invoke-static {v0}, Landroid/database/DatabaseUtils;->sqlEscapeString(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v1",
		"invoke-virtual {v9, v1, v8}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if len(result.Findings) != 0 {
		t.Fatalf("SQL-escaped value produced a SQL injection finding: %+v", result.Findings)
	}
}

func TestProgramIntentPutExtraCarriesSensitiveFactToIPC(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Flow;", "broadcast", "Landroid/content/Context;", "V", true,
		".method public static broadcast(Landroid/content/Context;)V",
		"new-instance v0, Landroid/content/Intent;",
		"invoke-virtual {v8}, Landroid/accounts/AccountManager;->getAccounts()[Landroid/accounts/Account;",
		"move-result-object v1",
		"invoke-virtual {v0, v7, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;",
		"move-result-object v0",
		"invoke-virtual {p0, v0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if len(result.Findings) == 0 || result.Findings[0].Category != "ipc_data_exposure" {
		t.Fatalf("Intent/Bundle lifecycle flow not found: %+v", result.Findings)
	}
}

type memorySummaryCache struct{ entries map[string][]byte }

func (c *memorySummaryCache) Get(signature string, _ []string) ([]byte, bool) {
	data, ok := c.entries[signature]
	return data, ok
}
func (c *memorySummaryCache) Put(signature string, _ []string, data []byte) {
	c.entries[signature] = append([]byte(nil), data...)
}

func TestProgramReusesLeafSummaryCache(t *testing.T) {
	cache := &memorySummaryCache{entries: make(map[string][]byte)}
	first := NewProgram(DefaultConfig())
	first.SetCache(cache)
	addMethod(first, "Lapp/Flow;", "read", "Landroid/content/Intent;Ljava/lang/String;", "Ljava/lang/String;", true,
		".method public static read(Landroid/content/Intent;Ljava/lang/String;)Ljava/lang/String;",
		"invoke-virtual {p0, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v0", "return-object v0", ".end method")
	first.Analyze(context.Background())
	if len(cache.entries) == 0 {
		t.Fatal("first run did not store a leaf summary")
	}

	second := NewProgram(DefaultConfig())
	second.SetCache(cache)
	addMethod(second, "Lapp/Flow;", "read", "Landroid/content/Intent;Ljava/lang/String;", "Ljava/lang/String;", true,
		".method public static read(Landroid/content/Intent;Ljava/lang/String;)Ljava/lang/String;",
		"invoke-virtual {p0, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v0", "return-object v0", ".end method")
	result := second.Analyze(context.Background())
	if result.Stats.CacheHits != 1 {
		t.Fatalf("cache hits = %d, want 1", result.Stats.CacheHits)
	}
}
