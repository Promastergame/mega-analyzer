package purl

import "testing"

func TestCanonicalForms(t *testing.T) {
	cases := []struct{ in, want string }{
		{"pkg:maven/org.apache.commons/commons-lang3@3.12.0", "pkg:maven/org.apache.commons/commons-lang3@3.12.0"},
		{"PKG:Maven/org.x/y@1", ""}, // схема регистрозависима
		{"pkg:Maven/org.x/Y@1", "pkg:maven/org.x/Y@1"},
		{"pkg:pypi/Foo_Bar@1.0", "pkg:pypi/foo-bar@1.0"},
		{"pkg:npm/%40Angular/Core@15.0.0", "pkg:npm/%40angular/core@15.0.0"},
		{"pkg://npm/left-pad@1.3.0", "pkg:npm/left-pad@1.3.0"},
		{"pkg:golang/github.com/Google/UUID@v1.3.0", "pkg:golang/github.com/google/uuid@v1.3.0"},
		{"pkg:deb/Debian/curl@7.68?arch=amd64&distro=buster", "pkg:deb/debian/curl@7.68?arch=amd64&distro=buster"},
		{"pkg:deb/debian/curl@7.68?distro=buster&arch=amd64&empty=", "pkg:deb/debian/curl@7.68?arch=amd64&distro=buster"},
		{"pkg:generic/name@1.0+build%2Fx", "pkg:generic/name@1.0%2Bbuild%2Fx"},
		{"pkg:maven/g/a@1#src/../main//x", "pkg:maven/g/a@1#src/main/x"},
		{"pkg:maven/g/a", "pkg:maven/g/a"},
	}
	for _, c := range cases {
		got, ok := Normalize(c.in)
		if c.want == "" {
			if ok {
				t.Errorf("%q must be rejected, got %q", c.in, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Errorf("Normalize(%q) = %q,%v want %q", c.in, got, ok, c.want)
		}
	}
}

func TestNormalizeIsIdempotent(t *testing.T) {
	for _, in := range []string{
		"pkg:pypi/Foo_Bar@1.0", "pkg:npm/%40a/b@1", "pkg:maven/g/a@1?x=%20y#p/q", "pkg:generic/a@1%2B2",
	} {
		once, ok := Normalize(in)
		if !ok {
			t.Fatalf("%q rejected", in)
		}
		twice, _ := Normalize(once)
		if once != twice {
			t.Errorf("not idempotent: %q -> %q -> %q", in, once, twice)
		}
	}
}

func TestRejectsMalformed(t *testing.T) {
	for _, in := range []string{
		"", "npm/left-pad", "pkg:", "pkg:npm", "pkg:npm/", "pkg:1npm/x@1", "pkg:np m/x", "pkg:npm/x@1%zz",
		"pkg:npm/x@1%4", "pkg:npm/x?novalue", "pkg:npm/x?=v",
	} {
		if got, ok := Normalize(in); ok {
			t.Errorf("%q must be rejected, got %q", in, got)
		}
	}
}

func TestKeyIgnoresQualifiersAndSubpath(t *testing.T) {
	a, _ := KeyOf("pkg:maven/g/a@1.0?classifier=sources#x")
	b, _ := KeyOf("pkg:maven/g/a@1.0")
	if a != b || a != "pkg:maven/g/a@1.0" {
		t.Fatalf("keys differ: %q %q", a, b)
	}
	c, _ := KeyOf("pkg:maven/g/a@1.1")
	if c == a {
		t.Fatal("different versions must differ")
	}
}

func TestIdentityDropsVersion(t *testing.T) {
	p, err := Parse("pkg:pypi/Requests@2.0")
	if err != nil {
		t.Fatal(err)
	}
	if p.Identity() != "pkg:pypi/requests" {
		t.Fatalf("identity = %q", p.Identity())
	}
}

func TestSpellingsCollapseToOneKey(t *testing.T) {
	k1, _ := KeyOf("pkg:pypi/Foo_Bar@1")
	k2, _ := KeyOf("pkg:pypi/foo-bar@1")
	k3, _ := KeyOf("pkg:pypi/FOO-BAR@1")
	if k1 != k2 || k2 != k3 {
		t.Fatalf("%q %q %q", k1, k2, k3)
	}
}

func TestConstructors(t *testing.T) {
	p, err := Maven("androidx.fragment", "fragment", "1.3.6")
	if err != nil || p.String() != "pkg:maven/androidx.fragment/fragment@1.3.6" {
		t.Fatalf("%v %v", p, err)
	}
	g, err := Golang("github.com/google/uuid", "v1.3.0")
	if err != nil || g.String() != "pkg:golang/github.com/google/uuid@v1.3.0" {
		t.Fatalf("%v %v", g, err)
	}
	if _, err := New("Bad Type", "", "x", ""); err == nil {
		t.Fatal("invalid type must fail")
	}
	if _, err := Maven("g", "", "1"); err == nil {
		t.Fatal("empty name must fail")
	}
}
