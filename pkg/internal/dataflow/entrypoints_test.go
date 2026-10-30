// entrypoints_test.go — IPC entry-point parameter tainting (audit P1-7 / C2).
package dataflow

import (
	"context"
	"testing"
)

func TestEntryPoint_BroadcastReceiverIntentToBroadcast(t *testing.T) {
	program := NewProgram(DefaultConfig())
	// Re-emits the received Intent without filtering: interception chain
	// that starts INSIDE the callback, with no explicit source call.
	addMethod(program, "Lapp/Forwarder;", "onReceive", "Landroid/content/Context;Landroid/content/Intent;", "V", false,
		".method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V",
		"invoke-virtual {p1, p2}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if !hasCategory(result, "broadcast_interception") {
		t.Fatalf("expected broadcast_interception from onReceive entry taint, got %v", findingCategories(result))
	}
	// Heuristic origin must lower confidence below the concrete-source level.
	for _, f := range result.Findings {
		if f.Category == "broadcast_interception" && f.Confidence >= 0.98 {
			t.Errorf("entry-point finding should carry a depth penalty, confidence=%v", f.Confidence)
		}
	}
}

func TestEntryPoint_ContentProviderSelectionToSQL(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Provider;", "query", "Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;", "Landroid/database/Cursor;", false,
		".method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;",
		"invoke-virtual {v9, p3, v8}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;",
		"move-result-object v0", "return-object v0", ".end method")

	result := program.Analyze(context.Background())
	if !hasCategory(result, "sql_injection") {
		t.Fatalf("expected sql_injection via provider selection param, got %v", findingCategories(result))
	}
}

func TestEntryPoint_ServiceStartIntentRedirection(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Worker;", "onStartCommand", "Landroid/content/Intent;II", "I", false,
		".method public onStartCommand(Landroid/content/Intent;II)I",
		"invoke-virtual {p0, p1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V",
		"const/4 v0, 0x2", "return v0", ".end method")

	result := program.Analyze(context.Background())
	if !hasCategory(result, "intent_redirection") {
		t.Fatalf("expected intent_redirection from onStartCommand, got %v", findingCategories(result))
	}
}

func TestEntryPoint_NonLifecycleSameNameNotTainted(t *testing.T) {
	program := NewProgram(DefaultConfig())
	// Static helper named like a callback / wrong signature shape: entry
	// taint must NOT apply (heuristic precision guard).
	addMethod(program, "Lapp/Util;", "onReceive", "Landroid/content/Intent;", "V", true,
		".method public static onReceive(Landroid/content/Intent;)V",
		"invoke-virtual {v9, p0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if hasCategory(result, "broadcast_interception") {
		t.Fatalf("static/wrong-shape method must not be entry-tainted, got %v", findingCategories(result))
	}
}
