package media3d

import (
	"encoding/json"
	"strings"
	"testing"
)

func texDoc(t *testing.T, body string) TextureMap {
	t.Helper()
	if !json.Valid([]byte(body)) {
		t.Fatalf("test JSON is invalid")
	}
	return MapTextures([]byte(body))
}

const pbrAsset = `{
  "asset": {"version": "2.0"},
  "meshes": [{"name": "Body", "primitives": [{"material": 0}, {"material": 0}]},
             {"name": "Visor", "primitives": [{"material": 1}]}],
  "materials": [
    {"name": "Skin",
     "pbrMetallicRoughness": {"baseColorTexture": {"index": 0},
                              "metallicRoughnessTexture": {"index": 1, "texCoord": 1}},
     "normalTexture": {"index": 2},
     "occlusionTexture": {"index": 1},
     "emissiveTexture": {"index": 3}},
    {"name": "Glass",
     "pbrMetallicRoughness": {"baseColorTexture": {"index": 0}}}
  ],
  "textures": [{"source": 0, "sampler": 0}, {"source": 1, "sampler": 1},
               {"source": 2}, {"source": 9}],
  "samplers": [{"wrapS": 33071, "wrapT": 33648, "minFilter": 9987, "magFilter": 9729},
               {}],
  "images": [{"uri": "skin.png"}, {"uri": "rough.png"},
             {"uri": "normal.png"}, {"uri": "unused.png"}]
}`

func TestMapTexturesResolvesCoreSlots(t *testing.T) {
	m := texDoc(t, pbrAsset)
	if m.Images != 4 || m.Textures != 4 || m.Materials != 2 || m.Samplers != 2 {
		t.Fatalf("counts: images %d textures %d materials %d samplers %d",
			m.Images, m.Textures, m.Materials, m.Samplers)
	}
	// Five slots on Skin, one on Glass.
	if len(m.Bindings) != 6 {
		t.Fatalf("got %d bindings, want 6", len(m.Bindings))
	}
	var base *TextureBinding
	for i := range m.Bindings {
		if m.Bindings[i].Material == 0 && m.Bindings[i].Slot == SlotBaseColor {
			base = &m.Bindings[i]
		}
	}
	if base == nil {
		t.Fatal("no base colour binding for material 0")
	}
	if base.Image != 0 || base.MaterialName != "Skin" {
		t.Fatalf("base colour resolved to image %d of %q", base.Image, base.MaterialName)
	}
	if base.WrapS != "clamp" || base.WrapT != "mirror" {
		t.Fatalf("wrap modes are %s/%s, want clamp/mirror", base.WrapS, base.WrapT)
	}
	if base.MinFilter != "linear-mip-linear" || base.MagFilter != "linear" {
		t.Fatalf("filters are %s/%s", base.MinFilter, base.MagFilter)
	}
	if base.Primitives != 2 {
		t.Fatalf("Primitives = %d, want 2", base.Primitives)
	}
	if len(base.Meshes) != 1 || base.Meshes[0] != "Body" {
		t.Fatalf("Meshes = %v, want [Body]", base.Meshes)
	}
}

func TestMapTexturesRecordsUVSetAndSamplerDefaults(t *testing.T) {
	m := texDoc(t, pbrAsset)
	var mr *TextureBinding
	for i := range m.Bindings {
		if m.Bindings[i].Slot == SlotMetallicRoughness {
			mr = &m.Bindings[i]
		}
	}
	if mr == nil {
		t.Fatal("no metallicRoughness binding")
	}
	if mr.TexCoord != 1 {
		t.Fatalf("TexCoord = %d, want 1", mr.TexCoord)
	}
	if m.UVSets != 2 {
		t.Fatalf("UVSets = %d, want 2", m.UVSets)
	}
	// Sampler 1 is an empty object, so every field falls back to the glTF
	// default. Repeat is the default, which is why a texture authored for
	// clamping tiles when its sampler is dropped.
	if mr.WrapS != "repeat" || mr.WrapT != "repeat" {
		t.Fatalf("empty sampler gave %s/%s, want repeat/repeat", mr.WrapS, mr.WrapT)
	}
	if mr.MinFilter != "unset" {
		t.Fatalf("MinFilter = %s, want unset", mr.MinFilter)
	}
}

func TestMapTexturesFlagsBrokenChain(t *testing.T) {
	m := texDoc(t, pbrAsset)
	// Texture 3 points at image 9, which does not exist.
	var emissive *TextureBinding
	for i := range m.Bindings {
		if m.Bindings[i].Slot == SlotEmissive {
			emissive = &m.Bindings[i]
		}
	}
	if emissive == nil {
		t.Fatal("no emissive binding")
	}
	if emissive.Image != -1 {
		t.Fatalf("Image = %d, want -1 for a dangling index", emissive.Image)
	}
	if !strings.Contains(emissive.Note, "out of range") {
		t.Fatalf("Note = %q", emissive.Note)
	}
}

func TestMapTexturesReportsUnboundImages(t *testing.T) {
	m := texDoc(t, pbrAsset)
	// Image 3 is only reachable through the broken texture, so nothing binds
	// it. That is worth surfacing: it is either dead weight or a packing bug.
	if len(m.Unbound) != 1 || m.Unbound[0] != 3 {
		t.Fatalf("Unbound = %v, want [3]", m.Unbound)
	}
}

func TestMapTexturesReadsBasisuExtensionSource(t *testing.T) {
	// The case that silently reports zero textures if only the core field is
	// read: a KHR_texture_basisu texture with no top-level source at all.
	m := texDoc(t, `{
	  "asset": {"version": "2.0"},
	  "extensionsUsed": ["KHR_texture_basisu"],
	  "materials": [{"name": "M", "pbrMetallicRoughness": {"baseColorTexture": {"index": 0}}}],
	  "textures": [{"extensions": {"KHR_texture_basisu": {"source": 0}}}],
	  "images": [{"mimeType": "image/ktx2", "bufferView": 0}]
	}`)
	if len(m.Bindings) != 1 {
		t.Fatalf("got %d bindings, want 1", len(m.Bindings))
	}
	b := m.Bindings[0]
	if b.Image != 0 {
		t.Fatalf("Image = %d, want 0", b.Image)
	}
	if b.Extension != "KHR_texture_basisu" {
		t.Fatalf("Extension = %q", b.Extension)
	}
	if len(m.Unbound) != 0 {
		t.Fatalf("Unbound = %v, want empty", m.Unbound)
	}
}

func TestMapTexturesDerivesExtensionSlots(t *testing.T) {
	// Slots contributed by material extensions are named after the field, so
	// no list needs maintaining as Khronos ratifies more of them.
	m := texDoc(t, `{
	  "asset": {"version": "2.0"},
	  "materials": [{"name": "Car", "extensions": {
	    "KHR_materials_clearcoat": {"clearcoatTexture": {"index": 0},
	                                "clearcoatRoughnessTexture": {"index": 1},
	                                "clearcoatFactor": 1},
	    "KHR_materials_sheen": {"sheenColorTexture": {"index": 1, "texCoord": 2}}
	  }}],
	  "textures": [{"source": 0}, {"source": 1}],
	  "images": [{"uri": "a.png"}, {"uri": "b.png"}]
	}`)
	if len(m.Bindings) != 3 {
		t.Fatalf("got %d bindings, want 3", len(m.Bindings))
	}
	slots := map[string]string{}
	for _, b := range m.Bindings {
		slots[string(b.Slot)] = b.Extension
	}
	for slot, ext := range map[string]string{
		"clearcoat":          "KHR_materials_clearcoat",
		"clearcoatRoughness": "KHR_materials_clearcoat",
		"sheenColor":         "KHR_materials_sheen",
	} {
		if slots[slot] != ext {
			t.Errorf("slot %q came from %q, want %q", slot, slots[slot], ext)
		}
	}
	// clearcoatFactor is not a texture reference and must not become a slot.
	if _, bad := slots["clearcoatFactor"]; bad {
		t.Error("a scalar factor was treated as a texture slot")
	}
	if m.UVSets != 3 {
		t.Fatalf("UVSets = %d, want 3", m.UVSets)
	}
}

func TestMapTexturesIsDeterministic(t *testing.T) {
	// Go randomises map iteration, so extension-derived slots would otherwise
	// come out in a different order on every run and churn the JSON report.
	first := texDoc(t, pbrAsset)
	for i := 0; i < 8; i++ {
		got := texDoc(t, pbrAsset)
		if len(got.Bindings) != len(first.Bindings) {
			t.Fatalf("binding count changed between runs")
		}
		for j := range got.Bindings {
			if got.Bindings[j].Slot != first.Bindings[j].Slot ||
				got.Bindings[j].Material != first.Bindings[j].Material {
				t.Fatalf("binding %d differs between runs", j)
			}
		}
	}
}

func TestMapTexturesHandlesMissingMaterials(t *testing.T) {
	m := texDoc(t, `{"asset": {"version": "2.0"}, "images": [{"uri": "lonely.png"}]}`)
	if len(m.Bindings) != 0 {
		t.Fatalf("got %d bindings, want none", len(m.Bindings))
	}
	if len(m.Unbound) != 1 {
		t.Fatalf("Unbound = %v, want one entry", m.Unbound)
	}
	joined := strings.Join(m.Notes, " | ")
	if !strings.Contains(joined, "no materials") {
		t.Fatalf("notes = %q", joined)
	}
	if got := m.Summary(); !strings.Contains(got, "none bound") {
		t.Fatalf("Summary = %q", got)
	}
}

func TestMapTexturesRejectsNonGLTF(t *testing.T) {
	for _, in := range [][]byte{nil, []byte("not json"), {0x89, 'P', 'N', 'G'}} {
		m := MapTextures(in)
		if len(m.Bindings) != 0 || len(m.Notes) == 0 {
			t.Fatalf("input %q gave %d bindings and %d notes", in, len(m.Bindings), len(m.Notes))
		}
	}
}

func TestMapTexturesWorksThroughGLB(t *testing.T) {
	// The same document delivered as a binary container must give the same
	// answer, including the mesh usage counts that come from the raw JSON.
	glb := buildGLB(2, rawChunk{tag: "JSON", data: pad4([]byte(pbrAsset), ' ')})
	m := MapTextures(glb)
	if len(m.Bindings) != 6 {
		t.Fatalf("got %d bindings through GLB, want 6", len(m.Bindings))
	}
	found := false
	for _, b := range m.Bindings {
		if b.Slot == SlotBaseColor && b.Primitives == 2 {
			found = true
		}
	}
	if !found {
		t.Fatal("mesh usage was lost when reading through a GLB container")
	}
}

func TestSlotsForAndDescribe(t *testing.T) {
	m := texDoc(t, pbrAsset)
	// Image 1 is both the roughness map and the occlusion map.
	slots := m.SlotsFor(1)
	if len(slots) != 2 {
		t.Fatalf("SlotsFor(1) = %v, want two slots", slots)
	}
	d := m.Describe(0)
	for _, want := range []string{"baseColor", "Skin", "UV0", "clamp"} {
		if !strings.Contains(d, want) {
			t.Errorf("Describe(0) = %q, missing %q", d, want)
		}
	}
	if m.Describe(99) != "" {
		t.Error("Describe of an unknown image should be empty")
	}
	if got := m.Summary(); !strings.Contains(got, "6 bindings") {
		t.Fatalf("Summary = %q", got)
	}
}

func TestWrapAndFilterNames(t *testing.T) {
	v := func(n int) *int { return &n }
	if wrapName(nil) != "repeat" {
		t.Error("absent wrap must default to repeat")
	}
	if got := wrapName(v(12345)); got != "mode12345" {
		t.Errorf("unknown wrap = %q", got)
	}
	if got := filterName(v(9986)); got != "nearest-mip-linear" {
		t.Errorf("filter 9986 = %q", got)
	}
	if got := filterName(v(7)); got != "filter7" {
		t.Errorf("unknown filter = %q", got)
	}
}
