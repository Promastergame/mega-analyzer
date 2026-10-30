package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestPrivilegedServerDefaults(t *testing.T) {
	t.Setenv("MEGA_ANALYZER_HOST", "")
	s, e := New(Options{Port: 7474, Exe: "analyzer", Privileged: true, OpenBrowser: true})
	if e != nil {
		t.Fatal(e)
	}
	if s.host != "127.0.0.1" || !validPrivilegedToken(s.token) || s.opts.OpenBrowser {
		t.Fatal("unsafe admin defaults")
	}
	for _, h := range []string{"0.0.0.0", "::", "192.168.1.5", "evil.example"} {
		if _, e := New(Options{Port: 7474, Exe: "analyzer", Host: h, Privileged: true}); e == nil {
			t.Errorf("accepted %s", h)
		}
	}
	for _, h := range []string{"127.0.0.1", "::1", "LOCALHOST"} {
		if _, e := New(Options{Port: 7474, Exe: "analyzer", Host: h, Privileged: true}); e != nil {
			t.Error(e)
		}
	}
	t.Setenv("MEGA_ANALYZER_HOST", "0.0.0.0")
	if _, e := New(Options{Port: 7474, Exe: "analyzer", Privileged: true}); e == nil {
		t.Fatal("unsafe environment accepted")
	}
	for _, v := range []string{"short", strings.Repeat("a", 31) + ";", strings.Repeat("Я", 32)} {
		if _, e := New(Options{Port: 7474, Exe: "analyzer", Host: "127.0.0.1", Privileged: true, Token: v}); e == nil {
			t.Fatal("bad token accepted")
		}
	}
}
func TestPrivilegedWebGuard(t *testing.T) {
	s, e := New(Options{Port: 7474, Host: "127.0.0.1", Exe: "analyzer", Privileged: true})
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name, token, host, origin, site string
		status                          int
	}{
		{"unauthenticated", "", "127.0.0.1:7474", "", "", 401}, {"valid", s.token, "127.0.0.1:7474", "http://127.0.0.1:7474", "same-origin", 200},
		{"wrong-token", "wrong", "127.0.0.1:7474", "", "", 401}, {"rebinding", s.token, "evil.example:7474", "", "", 403},
		{"cross-site", s.token, "127.0.0.1:7474", "http://127.0.0.1:7474", "cross-site", 403},
		{"wrong-port", s.token, "127.0.0.1:7474", "http://127.0.0.1:9999", "", 403}, {"wrong-scheme", s.token, "127.0.0.1:7474", "https://127.0.0.1:7474", "", 403},
		{"path", s.token, "127.0.0.1:7474", "http://127.0.0.1:7474/path", "", 403}, {"userinfo", s.token, "127.0.0.1:7474", "http://user@127.0.0.1:7474", "", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7474/api/test", nil)
			r.Host = tc.host
			r.Header.Set("X-MA-Token", tc.token)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Sec-Fetch-Site", tc.site)
			w := httptest.NewRecorder()
			s.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })).ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("%d != %d: %s", w.Code, tc.status, w.Body.String())
			}
		})
	}
}
func TestPrivilegedPairingAndUTF8(t *testing.T) {
	s, e := New(Options{Port: 7474, Host: "127.0.0.1", Exe: "analyzer", Privileged: true})
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7474/?"+url.Values{"t": {s.token}}.Encode(), nil)
	w := httptest.NewRecorder()
	s.middleware(http.HandlerFunc(s.serveApp)).ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "charset=utf-8") || !utf8.Valid(w.Body.Bytes()) {
		t.Fatal("not UTF-8 HTML")
	}
	cs := w.Result().Cookies()
	if len(cs) != 1 || !cs[0].HttpOnly || cs[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	api := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7474/api/test", nil)
	api.AddCookie(cs[0])
	out := httptest.NewRecorder()
	s.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"message":"Привет, UTF-8 🙂"}`))
	})).ServeHTTP(out, api)
	if out.Code != 200 || !utf8.Valid(out.Body.Bytes()) || !strings.Contains(out.Body.String(), "Привет") {
		t.Fatal("paired UTF-8 API failed")
	}
}
