package jarloader

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestParseTelegramLink(t *testing.T) {
	cases := []struct {
		in     string
		ok     bool
		kind   string
		target string
	}{
		{"https://t.me/durov", true, TGUserChat, "durov"},
		{"https://t.me/MyCoolBot", true, TGBotChat, "MyCoolBot"},
		{"https://t.me/MyCoolBot?start=payload123", true, TGBotChat, "MyCoolBot"},
		{"https://t.me/durov?start=x", true, TGBotChat, "durov"},
		{"https://t.me/+AbCdEfGhIjK", true, TGInvite, "AbCdEfGhIjK"},
		{"https://t.me/joinchat/AAAAAFghi", true, TGInvite, "AAAAAFghi"},
		{"https://t.me/c/1234567890/5", true, TGChannel, "1234567890"},
		{"https://t.me/proxy?server=x&port=443", true, TGProxy, ""},
		{"https://telegram.me/durov", true, TGUserChat, "durov"},
		{"https://telegram.dog/s/durov", true, TGUserChat, "durov"},
		{"https://t.me", true, TGUnknown, ""},
		{"tg://resolve?domain=durov", true, TGUserChat, "durov"},
		{"tg://resolve?domain=MyBot", true, TGBotChat, "MyBot"},
		{"tg://join?invite=AbCdEfGhIjK", true, TGInvite, "AbCdEfGhIjK"},
		{"tg://proxy?server=x&port=443", true, TGProxy, ""},
		{"https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/sendMessage", true, TGBotAPI, "sendMessage"},
		{"https://api.telegram.org/bot123456:ABC/getMe", true, TGBotAPI, "getMe"},
		{"https://example.com/x", false, "", ""},
		{"https://web.telegram.org/a/", false, "", ""},
		{"not a url", false, "", ""},
		{"", false, "", ""},
	}
	for _, c := range cases {
		got, ok := ParseTelegramLink(c.in)
		if ok != c.ok {
			t.Errorf("ParseTelegramLink(%q) ok=%v, want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.Kind != c.kind || got.Target != c.target {
			t.Errorf("ParseTelegramLink(%q) = %+v, want kind=%q target=%q", c.in, got, c.kind, c.target)
		}
	}
}

func TestParseTelegramLinkDropsToken(t *testing.T) {
	got, ok := ParseTelegramLink("https://api.telegram.org/bot123456:SECRET-TOKEN-XYZ/sendMessage")
	if !ok || got.Kind != TGBotAPI {
		t.Fatalf("bot api not recognized: %+v %v", got, ok)
	}
	if got.Target != "sendMessage" {
		t.Errorf("target = %q, want the method, never the token", got.Target)
	}
	if contains(got.Target, "SECRET") || contains(got.Detail, "SECRET") {
		t.Errorf("token leaked into finding fields: %+v", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestTelegramURLInventoryRow(t *testing.T) {
	// t.me link + HttpClient ref in one class: INFO row with tg_* metadata
	// and the sink correlation note.
	cf := &ClassFile{
		ThisClass:       "com.example.Sender",
		StringConstants: []string{"https://t.me/durov"},
		MethodRefs:      []MethodRef{{Class: "java.net.http.HttpClient", Name: "send"}},
	}
	var rows []types.Match
	for _, m := range analyzeClass(cf, "Sender.class") {
		if m.Category == types.CategoryNetworkEndpoint && m.Severity == types.SeverityInfo {
			rows = append(rows, m)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 telegram inventory row, got %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.Metadata["tg_kind"] != TGUserChat || r.Metadata["tg_target"] != "durov" {
		t.Errorf("bad tg metadata: %+v", r.Metadata)
	}
	if r.Metadata["net_sink"] != "java.net.http.HttpClient.send" {
		t.Errorf("missing sink correlation: %+v", r.Metadata)
	}
}

func TestTelegramURLInventoryNoSink(t *testing.T) {
	// Bot API link in a class with no network refs: still an INFO row with
	// the method as target, but no sink note.
	cf := &ClassFile{
		ThisClass:       "com.example.Cfg",
		StringConstants: []string{"https://api.telegram.org/botTOKEN/sendMessage"},
	}
	var rows []types.Match
	for _, m := range analyzeClass(cf, "Cfg.class") {
		if m.Category == types.CategoryNetworkEndpoint && m.Severity == types.SeverityInfo {
			rows = append(rows, m)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d: %+v", len(rows), rows)
	}
	if rows[0].Metadata["tg_kind"] != TGBotAPI || rows[0].Metadata["tg_target"] != "sendMessage" {
		t.Errorf("bad bot-api metadata: %+v", rows[0].Metadata)
	}
	if _, has := rows[0].Metadata["net_sink"]; has {
		t.Errorf("sink note must be absent without sink refs: %+v", rows[0].Metadata)
	}
}

func TestTelegramLinkEndToEndAnalyze(t *testing.T) {
	// Real class bytes: t.me literal in the pool + HttpClient pool ref.
	// Analyze must surface one INFO row with tg_* metadata and sink note.
	cls := buildFlowClass(t, "com.example.Sender",
		"java.net.http.HttpClient", "send", "(Lreq;)Lresp;",
		[]string{"https://t.me/durov"}, []byte{0xb1})
	p := writeJar(t, t.TempDir(), "tg.jar", map[string][]byte{
		"com/example/Sender.class": cls,
	})
	rep, err := Analyze(p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range rep.Findings {
		if m.Category != types.CategoryNetworkEndpoint || m.Severity != types.SeverityInfo {
			continue
		}
		if m.Metadata["tg_kind"] == TGUserChat && m.Metadata["tg_target"] == "durov" {
			found = true
			if m.Metadata["net_sink"] == "" {
				t.Errorf("missing sink correlation: %+v", m.Metadata)
			}
		}
	}
	if !found {
		t.Fatalf("missing telegram inventory row: %+v", rep.Findings)
	}
}
