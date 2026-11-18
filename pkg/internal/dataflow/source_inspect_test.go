package dataflow

import (
	"context"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/sourceevidence"
	"mega-analyzer/pkg/internal/types"
)

func sourceCheckOf(t *testing.T, report sourceevidence.Report, kind string) sourceevidence.Check {
	t.Helper()
	for _, check := range report.Checks {
		if check.Kind == kind {
			return check
		}
	}
	t.Fatalf("missing %s check: %+v", kind, report)
	return sourceevidence.Check{}
}

func TestSourceOutputTracksArgumentInsteadOfNearbyEntryName(t *testing.T) {
	for _, name := range []string{"payload.bin", "archive-copy.dat", "abc.so"} {
		t.Run(name, func(t *testing.T) {
			p := NewProgram(DefaultConfig())
			addMethod(p, "Lunrelated/Writer;", "save", "Ljava/util/zip/ZipEntry;", "V", true,
				"invoke-virtual {p0}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;",
				"move-result-object v8", // selection/logging is unrelated to the output
				"const-string v1, \"/somewhere\"",
				"const-string v2, \""+name+"\"",
				"move-object v4, v2",
				"new-instance v3, Ljava/io/File;",
				"invoke-direct {v3, v1, v4}, Ljava/io/File;-><init>(Ljava/lang/String;Ljava/lang/String;)V",
				"invoke-direct {v9, v3}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V", "return-void")
			check := sourceCheckOf(t, p.InspectSource(context.Background()), "output_name")
			if check.Status != "supported" || check.Choice != "constant_filename" || !strings.Contains(check.Summary, name) {
				t.Fatalf("nearby getName contaminated actual output: %+v", check)
			}
		})
	}
}

func TestSourceOutputEntryDerivedAndAmbiguousBranches(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		p := NewProgram(DefaultConfig())
		body := []string{"invoke-virtual {p0}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;", "move-result-object v1"}
		if mixed {
			body = append(body, "if-eqz p1, :out", "const-string v1, \"fixed.bin\"", ":out")
		}
		body = append(body, "invoke-direct {v9, v1}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V", "return-void")
		addMethod(p, "Ltest/Random;", "write", "Ljava/util/zip/ZipEntry;Z", "V", true, body...)
		check := sourceCheckOf(t, p.InspectSource(context.Background()), "output_name")
		want := "archive_entry_name"
		if mixed {
			want = "unresolved"
		}
		if check.Choice != want {
			t.Fatalf("mixed=%v: choice=%s, want %s; %+v", mixed, check.Choice, want, check)
		}
	}
}

func TestSourceFlowKillsOverwrittenRegistersAndUnknownReturns(t *testing.T) {
	for _, overwrite := range []string{
		"invoke-static {}, Lunknown/Native;->path()Ljava/lang/String;\nmove-result-object v0",
		"const/4 v0, 0",
	} {
		p := NewProgram(DefaultConfig())
		body := []string{"const-string v0, \"/known/file.so\""}
		body = append(body, strings.Split(overwrite, "\n")...)
		body = append(body, "invoke-static {v0}, Ljava/lang/System;->load(Ljava/lang/String;)V", "return-void")
		addMethod(p, "Ltest/Reassign;", "run", "", "V", true, body...)
		check := sourceCheckOf(t, p.InspectSource(context.Background()), "path_origin")
		if check.Choice != "unresolved" {
			t.Fatalf("stale constant survived overwrite: %+v", check)
		}
	}
}

func TestSourceNativeLoadDistinguishesDeadCodeAndIncompleteCFG(t *testing.T) {
	for _, target := range []string{":exit", ":missing"} {
		p := NewProgram(DefaultConfig())
		addMethod(p, "Ltest/Dead;", "run", "", "V", true, "goto "+target,
			"const-string v0, \"/unused.so\"", "invoke-static {v0}, Ljava/lang/System;->load(Ljava/lang/String;)V", ":exit", "return-void")
		check := sourceCheckOf(t, p.InspectSource(context.Background()), "native_load")
		want := "unreachable_call"
		if target == ":missing" {
			want = "unresolved"
		}
		if check.Choice != want {
			t.Fatalf("target=%s: %+v", target, check)
		}
	}
}

func TestSourceContextBindsCallerParametersAndRegisterAliases(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Lsample/Renamed;", "load", "Ljava/lang/String;", "V", true,
		".registers 2", // v1 aliases p0
		"invoke-static {v1}, Ljava/lang/System;->load(Ljava/lang/String;)V", "return-void")
	addMethod(p, "Lsample/Entry;", "run", "Landroid/content/pm/ApplicationInfo;", "V", true,
		"iget-object v0, p0, Landroid/content/pm/ApplicationInfo;->dataDir:Ljava/lang/String;",
		"invoke-static {v0}, Lsample/Renamed;->load(Ljava/lang/String;)V", "return-void")
	check := sourceCheckOf(t, p.InspectSource(context.Background()), "path_origin")
	if check.Choice != "application_data_dir" || check.Status != "supported" {
		t.Fatalf("exact caller argument not resolved: %+v", check)
	}
	files := map[string]bool{}
	for _, citation := range check.Citations {
		files[citation.Method] = true
	}
	if !files["Lsample/Entry;->run(Landroid/content/pm/ApplicationInfo;)V"] {
		t.Fatal("caller provenance lost")
	}
}

func TestSourceHelperReturnIsBoundAtThisCallSite(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Ltest/Identity;", "id", "Ljava/lang/String;", "Ljava/lang/String;", true, "return-object p0")
	// A separate call to the same helper must not contaminate the sink call.
	addMethod(p, "Ltest/Caller;", "other", "Ljava/util/zip/ZipEntry;", "V", true,
		"invoke-virtual {p0}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;", "move-result-object v0",
		"invoke-static {v0}, Ltest/Identity;->id(Ljava/lang/String;)Ljava/lang/String;", "return-void")
	addMethod(p, "Ltest/Caller;", "write", "", "V", true, "const-string v0, \"/fixed/result.bin\"",
		"invoke-static {v0}, Ltest/Identity;->id(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v1",
		"invoke-direct {v9, v1}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V", "return-void")
	if check := sourceCheckOf(t, p.InspectSource(context.Background()), "output_name"); check.Choice != "constant_filename" {
		t.Fatalf("unrelated helper caller polluted the result: %+v", check)
	}
}

func TestSourceBuilderAliasMutationRequiresReview(t *testing.T) {
	for _, mutate := range []string{
		"move-object v4, v0\ninvoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
		"invoke-static {v0}, Lunknown/Mutator;->edit(Ljava/lang/StringBuilder;)V",
	} {
		p := NewProgram(DefaultConfig())
		body := []string{"new-instance v0, Ljava/lang/StringBuilder;", "const-string v1, \"/fixed/out.so\"",
			"invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V"}
		body = append(body, strings.Split(mutate, "\n")...)
		body = append(body, "invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;", "move-result-object v2",
			"invoke-static {v2}, Ljava/lang/System;->load(Ljava/lang/String;)V", "return-void")
		addMethod(p, "Ltest/Alias;", "run", "Ljava/lang/String;", "V", true, body...)
		if check := sourceCheckOf(t, p.InspectSource(context.Background()), "path_origin"); check.Choice != "unresolved" {
			t.Fatalf("untracked mutable state became a source proof: %+v", check)
		}
	}
}

func TestSourceBuilderConcatHasFixedBasename(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Ltest/Build;", "write", "Ljava/lang/String;", "V", true,
		"new-instance v0, Ljava/lang/StringBuilder;",
		"invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V",
		"invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
		"const-string v1, \"/copy.dat\"",
		"invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
		"invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;", "move-result-object v2",
		"invoke-direct {v9, v2}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V", "return-void")
	if check := sourceCheckOf(t, p.InspectSource(context.Background()), "output_name"); check.Choice != "constant_filename" {
		t.Fatalf("fixed suffix not resolved: %+v", check)
	}
}

func TestSourceConstantSuffixWithoutSeparatorIsNotFixedBasename(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Ltest/Suffix;", "write", "Ljava/util/zip/ZipEntry;", "V", true,
		"invoke-virtual {p0}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;", "move-result-object v0",
		"const-string v1, \"fixed.so\"",
		"invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v2",
		"invoke-direct {v9, v2}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V", "return-void")
	if check := sourceCheckOf(t, p.InspectSource(context.Background()), "output_name"); check.Choice != "unresolved" {
		t.Fatalf("dynamic prefix discarded from filename: %+v", check)
	}
}

func TestSourceConflictingDefinitionsCannotProveValue(t *testing.T) {
	p := NewProgram(DefaultConfig())
	for _, name := range []string{"a.so", "b.so"} {
		p.AddClass(name+".smali", &types.SmaliClass{Name: "test.Conflict", Methods: []types.SmaliMethod{{
			Name: "run", ReturnType: "V", Access: types.AccessStatic, SourceRange: types.SourceRange{LineStart: 1},
			Body: []string{"const-string v0, \"" + name + "\"", "invoke-static {v0}, Ljava/lang/System;->load(Ljava/lang/String;)V", "return-void"},
		}}})
	}
	if check := sourceCheckOf(t, p.InspectSource(context.Background()), "path_origin"); check.Choice != "unresolved" {
		t.Fatalf("conflicting class definitions silently selected: %+v", check)
	}
}

func TestSourceCancelledAndDeterministicSnapshots(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Ltest/Cancel;", "run", "", "V", true, "const-string v0, \"/a.so\"",
		"invoke-static {v0}, Ljava/lang/System;->load(Ljava/lang/String;)V", "return-void")
	first, second := p.InspectSource(context.Background()), p.InspectSource(context.Background())
	if first.SHA256() != second.SHA256() {
		t.Fatal("static source snapshots are not deterministic")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report := p.InspectSource(ctx)
	if !report.Cancelled || report.Status != "partial" || len(report.Checks) != 0 {
		t.Fatalf("cancelled review ran: %+v", report)
	}
}

func TestSourceFilenameProjectionIgnoresUnresolvedDirectoryButNotName(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Ltest/Projected;", "write", "", "V", true,
		"invoke-static {}, Lopaque/Directory;->resolve()Ljava/lang/String;", "move-result-object v0",
		"const-string v1, \"retained-name.dat\"",
		"new-instance v2, Ljava/io/File;",
		"invoke-direct {v2, v0, v1}, Ljava/io/File;-><init>(Ljava/lang/String;Ljava/lang/String;)V",
		"invoke-direct {v9, v2}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V", "return-void")
	check := sourceCheckOf(t, p.InspectSource(context.Background()), "output_name")
	if check.Choice != "constant_filename" || check.Status != "supported" || len(check.Citations) > 4 {
		t.Fatalf("irrelevant directory contaminated basename proof: %+v", check)
	}
}

func TestSourceBuilderDirectoryDependencyIsNotAContainmentClaim(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Ltest/Dependency;", "load", "Landroid/content/pm/ApplicationInfo;Ljava/lang/String;", "V", true,
		"iget-object v0, p0, Landroid/content/pm/ApplicationInfo;->dataDir:Ljava/lang/String;",
		"new-instance v1, Ljava/lang/StringBuilder;", "invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V",
		"invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
		"invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
		"invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;", "move-result-object v2",
		"invoke-static {v2}, Ljava/lang/System;->load(Ljava/lang/String;)V", "return-void")
	check := sourceCheckOf(t, p.InspectSource(context.Background()), "path_origin")
	if check.Choice != "application_data_dir" || !strings.Contains(check.Summary, "Канонический путь") {
		t.Fatalf("dependency or scope lost: %+v", check)
	}
}

func TestSourceRelativeFileAbsolutePathIncludesRuntimeDirectory(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Ltest/Relative;", "load", "", "V", true,
		"const-string v0, \"relative.so\"", "new-instance v1, Ljava/io/File;",
		"invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V",
		"invoke-virtual {v1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;", "move-result-object v2",
		"invoke-static {v2}, Ljava/lang/System;->load(Ljava/lang/String;)V", "return-void")
	if check := sourceCheckOf(t, p.InspectSource(context.Background()), "path_origin"); check.Choice != "unresolved" {
		t.Fatalf("runtime cwd was silently treated as a constant: %+v", check)
	}
}

func TestSourceEmptyFileChildUsesParentBasename(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Ltest/EmptyChild;", "write", "", "V", true,
		"const-string v0, \"/parent.dat\"", "const-string v1, \"\"", "new-instance v2, Ljava/io/File;",
		"invoke-direct {v2, v0, v1}, Ljava/io/File;-><init>(Ljava/lang/String;Ljava/lang/String;)V",
		"invoke-direct {v9, v2}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V", "return-void")
	if check := sourceCheckOf(t, p.InspectSource(context.Background()), "output_name"); check.Choice != "constant_filename" || !strings.Contains(check.Summary, "parent.dat") {
		t.Fatalf("empty child erased parent filename: %+v", check)
	}
}

func TestSourceWideParameterAndReturnDescriptorResolution(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Ltest/Wide;", "load", "JLjava/lang/String;", "V", true,
		".registers 4", "invoke-static {v3}, Ljava/lang/System;->load(Ljava/lang/String;)V", "return-void")
	addMethod(p, "Ltest/Caller;", "run", "", "V", true, "const-wide/16 v0, 0", "const-string v2, \"/wide.so\"",
		"invoke-static {v0, v1, v2}, Ltest/Wide;->load(JLjava/lang/String;)V", "return-void")
	if check := sourceCheckOf(t, p.InspectSource(context.Background()), "path_origin"); check.Choice != "constant_path" {
		t.Fatalf("wide parameter words confused argument binding: %+v", check)
	}
	p = NewProgram(DefaultConfig())
	addMethod(p, "Ltest/Return;", "value", "", "Ljava/lang/Object;", true, "return-object p0")
	addMethod(p, "Ltest/Return;", "value", "", "Ljava/lang/String;", true, "const-string v0, \"/exact.bin\"", "return-object v0")
	addMethod(p, "Ltest/Return;", "write", "", "V", true, "invoke-static {}, Ltest/Return;->value()Ljava/lang/String;", "move-result-object v0",
		"invoke-direct {v9, v0}, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V", "return-void")
	if check := sourceCheckOf(t, p.InspectSource(context.Background()), "output_name"); check.Choice != "constant_filename" {
		t.Fatalf("return descriptor ignored: %+v", check)
	}
}
