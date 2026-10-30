package profile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerate_SeededDeterministic(t *testing.T) {
	spec := GenSpec{Mode: ModeSeeded, Model: "Pixel 8", API: 35, Seed: 42}
	a, err := Generate(spec)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	b, err := Generate(spec)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if a != b {
		t.Fatalf("seeded generation not reproducible:\n a=%+v\n b=%+v", a, b)
	}
}

func TestGenerate_SeededDiffersBySeed(t *testing.T) {
	a, _ := Generate(GenSpec{Mode: ModeSeeded, Seed: 1})
	b, _ := Generate(GenSpec{Mode: ModeSeeded, Seed: 2})
	if a == b {
		t.Fatal("different seeds produced identical profiles")
	}
}

func TestGenerate_AllModesValidate(t *testing.T) {
	specs := []GenSpec{
		{Mode: ModeFixed, Model: "Pixel 7", API: 34},
		{Mode: ModeSeeded, Model: "Pixel 9", API: 36, Seed: 7},
		{Mode: ModeRandom},
	}
	for _, s := range specs {
		p, err := Generate(s)
		if err != nil {
			t.Fatalf("Generate(%+v): %v", s, err)
		}
		Normalize(&p)
		if res := Validate(p); !res.OK() {
			t.Errorf("generated profile (mode %d) invalid: %v", s.Mode, res.Err())
		}
	}
}

func TestGenerate_RandomVariety(t *testing.T) {
	models := map[string]bool{}
	for i := 0; i < 40; i++ {
		p, _ := Generate(GenSpec{Mode: ModeRandom})
		models[p.Model] = true
	}
	if len(models) < 2 {
		t.Errorf("random generation lacks variety: %v", models)
	}
}

func TestGenerate_FixedUnknownModel(t *testing.T) {
	_, err := Generate(GenSpec{Mode: ModeFixed, Model: "NoSuchPhone"})
	if err == nil {
		t.Error("expected error for unknown model in fixed mode")
	}
}

func TestGenerate_BadAPI(t *testing.T) {
	_, err := Generate(GenSpec{Mode: ModeSeeded, API: 99, Seed: 1})
	if err == nil {
		t.Error("expected error for unsupported API level")
	}
}

func TestValidIMEI(t *testing.T) {
	tests := []struct {
		imei string
		want bool
	}{
		{"490154203237518", true},
		{"490154203237510", false},
		{"12345", false},
		{"abcdefghijklmno", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidIMEI(tt.imei); got != tt.want {
			t.Errorf("ValidIMEI(%q) = %v, want %v", tt.imei, got, tt.want)
		}
	}
}

func TestGenIMEI_AlwaysValid(t *testing.T) {
	r := newSeededRNG(123)
	for i := 0; i < 100; i++ {
		if imei := genIMEI(r); !ValidIMEI(imei) {
			t.Fatalf("generated invalid IMEI: %q", imei)
		}
	}
}

func TestValidate_CatchesInconsistency(t *testing.T) {
	good, _ := Generate(GenSpec{Mode: ModeSeeded, Model: "Pixel 7", API: 34, Seed: 5})

	cases := []struct {
		name  string
		mut   func(*DeviceProfile)
		field string
	}{
		{"wrong device for model", func(p *DeviceProfile) { p.Device = "cheetah" }, "device"},
		{"version mismatch", func(p *DeviceProfile) { p.AndroidVersion = "13" }, "android_version"},
		{"build prefix mismatch", func(p *DeviceProfile) { p.BuildID = "ZZ9A.111.1" }, "build_id"},
		{"emulator fingerprint", func(p *DeviceProfile) {
			p.Fingerprint = "generic/sdk_gphone/emulator:14/UP1A.240901.191/1:userdebug/test-keys"
		}, "fingerprint"},
		{"bad abi", func(p *DeviceProfile) { p.ABI = "mips" }, "abi"},
		{"bad resolution", func(p *DeviceProfile) { p.Resolution = "huge" }, "resolution"},
		{"bad density", func(p *DeviceProfile) { p.Density = 5 }, "density"},
		{"bad imei", func(p *DeviceProfile) { p.Network.IMEI = "111111111111111" }, "network.imei"},
		{"battery out of range", func(p *DeviceProfile) { p.Battery.Level = 250 }, "battery.level"},
		{"operator numeric mismatch", func(p *DeviceProfile) { p.Operator.Numeric = "99999" }, "operator.numeric"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := good.Clone()
			tc.mut(&p)
			Normalize(&p)
			res := Validate(p)
			if res.OK() {
				t.Fatalf("expected validation error on %s", tc.field)
			}
			found := false
			for _, e := range res.Errors {
				if e.Field == tc.field {
					found = true
				}
			}
			if !found {
				t.Errorf("expected error on field %q, got %v", tc.field, res.Errors)
			}
		})
	}
}

func TestValidate_GoodProfilePasses(t *testing.T) {
	p, _ := Generate(GenSpec{Mode: ModeSeeded, Model: "Pixel 9", API: 36, Seed: 9})
	Normalize(&p)
	if res := Validate(p); !res.OK() {
		t.Errorf("valid profile rejected: %v", res.Err())
	}
}

func TestJSONRoundTrip(t *testing.T) {
	p, _ := Generate(GenSpec{Mode: ModeSeeded, Model: "SM-A546B", API: 35, Seed: 11})
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var back DeviceProfile
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back != p {
		t.Errorf("round trip mismatch:\n orig=%+v\n back=%+v", p, back)
	}
}

func TestNormalize_Idempotent(t *testing.T) {
	p := DeviceProfile{
		Model:   "  Pixel 7  ",
		Network: NetworkProfile{MACAddress: "3c:5a:b4:11:22:33"},
		Battery: BatteryProfile{Status: "DISCHARGING"},
	}
	Normalize(&p)
	once := p
	Normalize(&p)
	if p != once {
		t.Error("Normalize is not idempotent")
	}
	if p.Model != "Pixel 7" || !strings.HasPrefix(p.Network.MACAddress, "3C:5A:B4") || p.Battery.Status != "discharging" {
		t.Errorf("Normalize did not canonicalise: %+v", p)
	}
}

func TestMerge(t *testing.T) {
	base, _ := Generate(GenSpec{Mode: ModeSeeded, Model: "Pixel 7", API: 34, Seed: 1})
	over := DeviceProfile{Locale: "ru-RU", Density: 480}
	got := Merge(base, over)
	if got.Locale != "ru-RU" {
		t.Errorf("Locale not overridden: %q", got.Locale)
	}
	if got.Density != 480 {
		t.Errorf("Density not overridden: %d", got.Density)
	}
	if got.Model != base.Model {
		t.Errorf("Model should be unchanged: %q", got.Model)
	}
}
