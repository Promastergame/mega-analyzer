// program_catalog_test.go — coverage for the expanded source/sink/sanitizer
// catalogs (audit P1-6 / C1+C4).
package dataflow

import (
	"context"
	"testing"
)

func findingCategories(result Result) []string {
	out := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		out = append(out, f.Category)
	}
	return out
}

func hasCategory(result Result, category string) bool {
	for _, f := range result.Findings {
		if f.Category == category {
			return true
		}
	}
	return false
}

func TestCatalog_DexClassLoaderFromIntentExtra(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Flow;", "load", "Landroid/content/Intent;Ljava/lang/String;", "V", true,
		".method public static load(Landroid/content/Intent;Ljava/lang/String;)V",
		"invoke-virtual {p0, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v0",
		"new-instance v1, Ldalvik/system/DexClassLoader;",
		"invoke-direct {v1, v0, v2, v3, v4}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if !hasCategory(result, "dynamic_code_loading") {
		t.Fatalf("expected dynamic_code_loading, got %v", findingCategories(result))
	}
}

func TestCatalog_UriQueryParameterToFileTraversal(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Flow;", "open", "Landroid/content/Intent;", "V", true,
		".method public static open(Landroid/content/Intent;)V",
		"invoke-virtual {p0}, Landroid/content/Intent;->getData()Landroid/net/Uri;",
		"move-result-object v0",
		"invoke-virtual {v0, v7}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v1",
		"new-instance v2, Ljava/io/File;",
		"invoke-direct {v2, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if !hasCategory(result, "path_traversal") {
		t.Fatalf("expected path_traversal, got %v", findingCategories(result))
	}
}

func TestCatalog_UriEncodeDoesNotProveFilesystemContainment(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Flow;", "openSafe", "Landroid/content/Intent;", "V", true,
		".method public static openSafe(Landroid/content/Intent;)V",
		"invoke-virtual {p0}, Landroid/content/Intent;->getData()Landroid/net/Uri;",
		"move-result-object v0",
		"invoke-virtual {v0, v7}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v1",
		"invoke-static {v1}, Landroid/net/Uri;->encode(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v2",
		"new-instance v3, Ljava/io/File;",
		"invoke-direct {v3, v2}, Ljava/io/File;-><init>(Ljava/lang/String;)V",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if !hasCategory(result, "path_traversal") {
		t.Fatalf("Uri.encode alone must not suppress path traversal: encoded dot-dot can still escape a composed path; got %v", findingCategories(result))
	}
}

func TestCatalog_OkHTTPBytesToInMemoryDexIsExploitChain(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Loader;", "load", "Lokhttp3/ResponseBody;Ljava/lang/ClassLoader;", "V", true,
		".method public static load(Lokhttp3/ResponseBody;Ljava/lang/ClassLoader;)V",
		"invoke-virtual {p0}, Lokhttp3/ResponseBody;->bytes()[B",
		"move-result-object v0",
		"invoke-static {v0}, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;",
		"move-result-object v1",
		"new-instance v2, Ldalvik/system/InMemoryDexClassLoader;",
		"invoke-direct {v2, v1, p1}, Ldalvik/system/InMemoryDexClassLoader;-><init>(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V",
		"return-void", ".end method")
	result := program.Analyze(context.Background())
	for _, finding := range result.Findings {
		if finding.Category == "dynamic_code_loading" && finding.ExploitChain == "network_response_to_code_execution" {
			return
		}
	}
	t.Fatalf("expected network-to-code-execution chain, got %+v", result.Findings)
}

func TestCatalog_ZipEntryNameToFileIsZipSlipChain(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Extractor;", "extract", "Ljava/util/zip/ZipEntry;Ljava/io/File;", "V", true,
		".method public static extract(Ljava/util/zip/ZipEntry;Ljava/io/File;)V",
		"invoke-virtual {p0}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;",
		"move-result-object v0",
		"new-instance v1, Ljava/io/File;",
		"invoke-direct {v1, p1, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V",
		"return-void", ".end method")
	result := program.Analyze(context.Background())
	for _, finding := range result.Findings {
		if finding.Category == "path_traversal" && finding.ExploitChain == "untrusted_file_to_filesystem_access" {
			return
		}
	}
	t.Fatalf("expected Zip-Slip chain, got %+v", result.Findings)
}

func TestCatalog_NestedIntentToPendingIntentIsChain(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Receiver;", "schedule", "Landroid/content/Context;Landroid/content/Intent;", "V", true,
		".method public static schedule(Landroid/content/Context;Landroid/content/Intent;)V",
		"invoke-virtual {p1, v0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;",
		"move-result-object v1",
		"check-cast v1, Landroid/content/Intent;",
		"const/4 v2, 0x0",
		"invoke-static {p0, v2, v1, v2}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;",
		"return-void", ".end method")
	result := program.Analyze(context.Background())
	for _, finding := range result.Findings {
		if finding.Category == "pending_intent_injection" && finding.ExploitChain == "ipc_or_deep_link_to_pending_intent" {
			return
		}
	}
	t.Fatalf("expected pending-intent injection chain, got %+v", result.Findings)
}

func TestCatalog_NumericParseDropsTaint(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Flow;", "asNumber", "Landroid/content/Intent;Ljava/lang/String;", "V", true,
		".method public static asNumber(Landroid/content/Intent;Ljava/lang/String;)V",
		"invoke-virtual {p0, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v0",
		"invoke-static {v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I",
		"move-result v1",
		"invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;",
		"move-result-object v2",
		"invoke-virtual {v9, v2}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if hasCategory(result, "command_injection") {
		t.Fatalf("parseInt must drop taint labels entirely, got %v", findingCategories(result))
	}
}

func TestCatalog_ReflectionForNameFromExtra(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Flow;", "reflect", "Landroid/content/Intent;Ljava/lang/String;", "V", true,
		".method public static reflect(Landroid/content/Intent;Ljava/lang/String;)V",
		"invoke-virtual {p0, p1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v0",
		"invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if !hasCategory(result, "dynamic_class_loading") {
		t.Fatalf("expected dynamic_class_loading, got %v", findingCategories(result))
	}
}

func TestCatalog_ObjectInputStreamFromSocket(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Flow;", "deser", "Ljava/net/Socket;", "V", true,
		".method public static deser(Ljava/net/Socket;)V",
		"invoke-virtual {p0}, Ljava/net/Socket;->getInputStream()Ljava/io/InputStream;",
		"move-result-object v0",
		"new-instance v1, Ljava/io/ObjectInputStream;",
		"invoke-direct {v1, v0}, Ljava/io/ObjectInputStream;-><init>(Ljava/io/InputStream;)V",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if !hasCategory(result, "insecure_deserialization") {
		t.Fatalf("expected insecure_deserialization, got %v", findingCategories(result))
	}
}

func TestCatalog_StartActivityWithAttackerIntent(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Flow;", "redirect", "Landroid/content/Context;Landroid/content/Intent;", "V", true,
		".method public static redirect(Landroid/content/Context;Landroid/content/Intent;)V",
		"invoke-virtual {p1, v7}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;",
		"move-result-object v0",
		"check-cast v0, Landroid/content/Intent;",
		"invoke-virtual {p0, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if !hasCategory(result, "intent_redirection") {
		t.Fatalf("expected intent_redirection, got %v", findingCategories(result))
	}
}
