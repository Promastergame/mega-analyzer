package dataflow

import (
	"context"
	"strings"
	"testing"
)

func TestReflectionChecksMethodSelectorNotTargetObject(t *testing.T) {
	for _, dynamic := range []bool{false, true} {
		p := NewProgram(DefaultConfig())
		body := []string{
			".method public run()V",
			"invoke-virtual {p0, v8}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
			"move-result-object v0",
			"const-class v1, Ljava/lang/Object;",
			"const-string v2, \"toString\"",
			"const/4 v3, 0x0",
		}
		if dynamic {
			body = append(body, "move-object v2, v0")
		}
		body = append(body,
			"invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
			"move-result-object v4",
			"invoke-virtual {v4, v0, v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
			"return-void", ".end method")
		addMethod(p, "Lapp/Example;", "run", "", "V", false, body...)
		result := p.Analyze(context.Background())
		if hasCategory(result, "reflection_invocation") != dynamic {
			t.Fatalf("dynamic selector=%v, findings=%+v", dynamic, result.Findings)
		}
	}
}

func TestContainerReadRetainsUnknownOriginAndTracesExternalOrigin(t *testing.T) {
	for _, external := range []bool{false, true} {
		p := NewProgram(DefaultConfig())
		body := []string{".method public run()V"}
		if external {
			body = append(body, "invoke-virtual {p0}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;", "move-result-object v0")
		} else {
			body = append(body, "new-instance v0, Landroid/os/Bundle;", "invoke-direct {v0}, Landroid/os/Bundle;-><init>()V")
		}
		body = append(body,
			"invoke-virtual {v0, v8}, Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v1",
			"invoke-static {v1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;", "return-void", ".end method")
		addMethod(p, "Lapp/Example;", "run", "", "V", false, body...)
		result := p.Analyze(context.Background())
		if len(result.Findings) != 1 {
			t.Fatalf("findings=%+v", result.Findings)
		}
		unknown := strings.HasPrefix(result.Findings[0].Source, "[unverified container origin]")
		if unknown == external {
			t.Fatalf("external=%v source=%s", external, result.Findings[0].Source)
		}
	}
}

func TestBinderParcelReadHasExternalOrigin(t *testing.T) {
	p := NewProgram(DefaultConfig())
	addMethod(p, "Lapp/Binder;", "onTransact", "ILandroid/os/Parcel;Landroid/os/Parcel;I", "Z", false,
		".method public onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z",
		"invoke-virtual {p2}, Landroid/os/Parcel;->readString()Ljava/lang/String;", "move-result-object v0",
		"invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;", "const/4 v1, 0x1", "return v1", ".end method")
	r := p.Analyze(context.Background())
	if len(r.Findings) != 1 || strings.HasPrefix(r.Findings[0].Source, "[unverified") {
		t.Fatalf("Binder input origin lost: %+v", r.Findings)
	}
}
