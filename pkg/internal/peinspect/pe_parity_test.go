package peinspect

// Shared PE corpus contract: Go (peinspect) expectations per fixture variant.
// Mirrors rust/crates/omnisec-loader-pe arch mapping (0x14c→x86, 0x8664→x86_64,
// 0xaa64→arm64). Rust consumes the same variants via its own synthetic PEs;
// this table is the source of truth for arch/hardening/completeness parity.

import "testing"

func TestPECorpusParity(t *testing.T) {
	va := uint64(fixtureImageBase + fixtureTextRVA)
	cases := []struct {
		name       string
		opts       peFixtureOpts
		arch       string
		is64       bool
		wantCF     bool
		wantCookie bool
	}{
		{"pe32-x86-hardened", peFixtureOpts{machine: 0x14c, dllChars: 0x40 | 0x100, ndirs: true,
			loadCfg: x86LoadCfg(va, va), sehCount: 2}, "x86", false, true, true},
		{"pe32plus-x64-hardened", peFixtureOpts{machine: 0x8664, dllChars: 0x40 | 0x100, ndirs: true,
			loadCfg: x64LoadCfg(va)}, "x86_64", true, true, true},
		{"pe32plus-arm64-plain", peFixtureOpts{machine: 0xaa64, ndirs: false}, "arm64", true, false, false},
		{"pe32-x86-no-loadcfg", peFixtureOpts{machine: 0x14c, dllChars: 0x40 | 0x100, ndirs: true}, "x86", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Inspect(buildFixturePE(t, tc.opts))
			if err != nil {
				t.Fatalf("Inspect: %v", err)
			}
			if m.Architecture != tc.arch {
				t.Errorf("arch = %q, want %q", m.Architecture, tc.arch)
			}
			if m.Is64Bit != tc.is64 {
				t.Errorf("is64 = %v, want %v", m.Is64Bit, tc.is64)
			}
			if m.CFValid != tc.wantCF {
				t.Errorf("CFValid = %v, want %v", m.CFValid, tc.wantCF)
			}
			if (m.StackCookie != nil) != tc.wantCookie {
				t.Errorf("cookie present = %v, want %v", m.StackCookie != nil, tc.wantCookie)
			}
			// Completeness: section view + entropy always populated on success.
			// Fixture entry RVA is 0 (no entry set) → EntryPointSection empty is fine.
			if len(m.Sections) == 0 {
				t.Errorf("structural overview missing: no sections")
			}
			// Native images carry no CLI metadata — normal negative, not error.
			if dn, err := ParseDotNet(buildFixturePE(t, tc.opts)); err != nil || dn != nil {
				t.Errorf("ParseDotNet = %v, %v; want (nil, nil) for native fixtures", dn, err)
			}
		})
	}
}

func TestPECorruptFailsCleanly(t *testing.T) {
	full := buildFixturePE(t, peFixtureOpts{machine: 0x14c, ndirs: true,
		loadCfg: x86LoadCfg(uint64(fixtureImageBase+fixtureTextRVA), uint64(fixtureImageBase+fixtureTextRVA)), sehCount: 1})
	// Flip load-config size to exceed directory → invalid, not panic.
	bad := append([]byte(nil), full...)
	if len(bad) > 520 {
		bad[512] = 0xFF
		bad[513] = 0xFF
		bad[514] = 0xFF
		bad[515] = 0x7F
	}
	for name, data := range map[string][]byte{"valid": full, "corrupt-loadcfg": bad} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: panic: %v", name, r)
				}
			}()
			_, _ = Inspect(data)
			_, _ = ParseDotNet(data)
		}()
	}
}
