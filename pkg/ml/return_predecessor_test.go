package ml

import (
	"strings"
	"testing"
)

func TestReturnPredecessorStopsAtBlockBoundaries(t *testing.T) {
	cases := []struct {
		name string
		body []string
		want int
	}{
		{"adjacent", []string{"const/4 v0, 0x1", "return v0"}, 0},
		{"debug", []string{"const/4 v0, 0x1", ".line 10", "# comment", "return v0"}, 0},
		{"label", []string{"const/4 v0, 0x1", ":join", "return v0"}, -1},
		{"branch", []string{"const/4 v0, 0x1", "if-eqz v1, :other", "return v0"}, -1},
		{"overwrite", []string{"const/4 v0, 0x1", "move v0, v1", "return v0"}, 1},
		{"numeric_entry", []string{"goto +2", "const/4 v0, 0x1", "return v0"}, -1},
		{"numeric_comment", []string{"goto +2 # branch", "const/4 v0, 0x1", "return v0"}, -1},
		{"numeric_const_entry", []string{"goto +1", "const/4 v0, 0x1", "return v0"}, 1},
		{"unknown_numeric_layout", []string{"goto +2", "unknown-op v0", "return v0"}, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pred := straightLinePredecessors(tc.body)
			if pred[len(pred)-1] != tc.want {
				t.Fatalf("predecessor=%d want %d", pred[len(pred)-1], tc.want)
			}
		})
	}
}

func TestReturnPredecessorNoFalseNoEditAtLabel(t *testing.T) {
	body := []string{".method public static value(I)I", ".locals 1", "move v0, p0",
		"if-eqz p0, :join", "const/4 v0, 0x1", ":join", "return v0", ".end method"}
	out, count, _ := overrideReturnsSafe(body, 1)
	if count != 1 || !strings.Contains(out, ":join\nconst/4 v0, 0x1\nreturn v0") {
		t.Fatalf("predecessor const bypassed by branch was treated as a proof: %s", out)
	}
}

func TestReturnPredecessorSingleDefNeedsDominance(t *testing.T) {
	if entryDefinitionDominates([]string{"if-eqz p0, :join", "const/4 v0, 0x1", ":join", "return v0"}, 1, 3) {
		t.Fatal("single textual definition accepted across join")
	}
	if !entryDefinitionDominates([]string{"const/4 v0, 0x1", "if-eqz p0, :join", ":join", "return v0"}, 0, 3) {
		t.Fatal("safe entry definition rejected")
	}
	body := []string{".method public static value()I", ".locals 1", "return v0", "const/4 v0, 0x1", ".end method"}
	out, _, _ := overrideReturnsSafe(body, 1)
	if !strings.Contains(out, "const/4 v0, 0x1\nreturn v0") {
		t.Fatal("definition after return used to claim no edit")
	}
}

func TestReturnPredecessorWideOverwriteNotCredited(t *testing.T) {
	body := []string{".method public static value()J", ".locals 4",
		"const-wide v0, 0x1L", "move-wide v0, v2", "return-wide v0",
		".catchall {:a .. :b} :c", ".end method"}
	out, count, _ := overrideWideReturnsSafe(body, 7)
	if count != 0 || strings.Contains(out, "0x7L") {
		t.Fatal("old wide definition behind overwrite was counted as handled")
	}
}

func TestReturnPredecessorObjectOverwriteNotCredited(t *testing.T) {
	body := []string{".method public static value()Ljava/lang/String;", ".locals 2",
		"const-string v0, \"old\"", "move-object v0, v1", "return-object v0",
		".catchall {:a .. :b} :c", ".end method"}
	out, count, _ := overrideObjectReturnsSafe(body, "Ljava/lang/String;")
	if count != 0 || !strings.Contains(out, "\"old\"") {
		t.Fatal("old object definition behind overwrite was counted as handled")
	}
}

func TestReturnPredecessorObjectSwapKeepsTypeAndWidth(t *testing.T) {
	out, ok := tryObjectSwap("    const-string/jumbo v0, \"old\"", "v0", "Ljava/lang/String;")
	if !ok || out != "    const-string/jumbo v0, \"\"" {
		t.Fatalf("jumbo instruction width lost: %q", out)
	}
	if _, ok := tryObjectSwap("const-string v0, \"old\"", "v0", "Ljava/lang/Boolean;"); ok {
		t.Fatal("string rewrite accepted for Boolean contract")
	}
	if _, ok := tryObjectSwap("sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;", "v0", "Ljava/lang/String;"); ok {
		t.Fatal("Boolean rewrite accepted for String contract")
	}
}
