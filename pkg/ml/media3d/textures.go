package media3d

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════
// WHERE DOES THIS TEXTURE ACTUALLY GO?
// ═══════════════════════════════════════════════════════════════════════════
//
// Extracting an image from a GLB tells you a PNG exists. It does not tell you
// whether it is the colour map, the normal map, or a roughness mask that will
// look like garbage when viewed as a picture. That distinction is the whole
// difference between "here are some images" and "here is how this model is
// textured".
//
// The chain is: mesh primitive -> material -> texture slot -> texture ->
// sampler + image. Every link is an integer index into a different top-level
// array, and any of them can be missing or out of range in a real asset.
//
// Two things make this harder than it sounds:
//
//  1. Compressed-texture extensions move the image reference. On a
//     KHR_texture_basisu asset the texture's core "source" is often absent and
//     the real index lives inside the extension object. Reading only the core
//     field reports zero textures on an asset full of them.
//
//  2. Material extensions add their own slots, and there are two dozen of
//     them. Rather than hardcode a list that goes stale, any extension field
//     whose name ends in "Texture" and parses as a texture reference is
//     treated as a slot named after the field. Clearcoat, sheen, transmission,
//     specular, anisotropy, iridescence and the archived spec-gloss set all
//     fall out of that rule, and so will whatever Khronos ratifies next.
//
// Nothing here touches document.go. Its typed mesh view deliberately omits the
// material index, so the mesh list is re-read from the raw JSON instead of
// changing a struct other tests already assert against.

// TextureSlot names the role an image plays in a material. The five core slots
// are named by the glTF specification; slots contributed by extensions are
// derived from the field name, so a KHR_materials_clearcoat clearcoatTexture
// becomes the slot "clearcoat".
type TextureSlot string

const (
	SlotBaseColor         TextureSlot = "baseColor"
	SlotMetallicRoughness TextureSlot = "metallicRoughness"
	SlotNormal            TextureSlot = "normal"
	SlotOcclusion         TextureSlot = "occlusion"
	SlotEmissive          TextureSlot = "emissive"
)

// ── wire structures ────────────────────────────────────────────────────────

type textureRef struct {
	Index      *int                       `json:"index"`
	TexCoord   *int                       `json:"texCoord"`
	Extensions map[string]json.RawMessage `json:"extensions"`
}

type pbrBlock struct {
	BaseColorTexture         *textureRef `json:"baseColorTexture"`
	MetallicRoughnessTexture *textureRef `json:"metallicRoughnessTexture"`
}

type materialBlock struct {
	Name         string                     `json:"name"`
	PBR          *pbrBlock                  `json:"pbrMetallicRoughness"`
	NormalTex    *textureRef                `json:"normalTexture"`
	OcclusionTex *textureRef                `json:"occlusionTexture"`
	EmissiveTex  *textureRef                `json:"emissiveTexture"`
	AlphaMode    string                     `json:"alphaMode"`
	Extensions   map[string]json.RawMessage `json:"extensions"`
}

type textureBlock struct {
	Name       string                     `json:"name"`
	Source     *int                       `json:"source"`
	Sampler    *int                       `json:"sampler"`
	Extensions map[string]json.RawMessage `json:"extensions"`
}

type samplerBlock struct {
	Name      string `json:"name"`
	MagFilter *int   `json:"magFilter"`
	MinFilter *int   `json:"minFilter"`
	WrapS     *int   `json:"wrapS"`
	WrapT     *int   `json:"wrapT"`
}

// meshesOnly re-reads the one field Document's typed mesh view leaves out.
type meshesOnly struct {
	Meshes []struct {
		Name       string `json:"name"`
		Primitives []struct {
			Material *int `json:"material"`
		} `json:"primitives"`
	} `json:"meshes"`
}

// ── results ────────────────────────────────────────────────────────────────

// TextureBinding is one image together with everything the asset says about
// how it is applied.
type TextureBinding struct {
	// Image indexes images[], or -1 when the chain is broken.
	Image int `json:"image"`
	// Texture indexes textures[].
	Texture int         `json:"texture"`
	Slot    TextureSlot `json:"slot"`
	// Extension names the material extension that owns this slot, empty for
	// the five core slots.
	Extension    string `json:"extension,omitempty"`
	Material     int    `json:"material"`
	MaterialName string `json:"materialName"`
	// TexCoord is which UV set the mesh must supply: 0 means TEXCOORD_0.
	TexCoord int `json:"texCoord"`
	// Sampler indexes samplers[], or -1 when the texture declares none, in
	// which case the viewer picks its own defaults.
	Sampler   int    `json:"sampler"`
	WrapS     string `json:"wrapS"`
	WrapT     string `json:"wrapT"`
	MinFilter string `json:"minFilter"`
	MagFilter string `json:"magFilter"`
	// Meshes are the mesh names whose primitives use this material.
	Meshes []string `json:"meshes,omitempty"`
	// Primitives counts how many primitives draw with this material.
	Primitives int    `json:"primitives"`
	Note       string `json:"note,omitempty"`
}

// TextureMap is the whole picture for one asset.
type TextureMap struct {
	Bindings  []TextureBinding `json:"bindings,omitempty"`
	Images    int              `json:"images"`
	Textures  int              `json:"textures"`
	Materials int              `json:"materials"`
	Samplers  int              `json:"samplers"`
	// Unbound lists images no material references. Those are dead weight, or
	// a sign the asset was assembled by a tool that left them behind.
	Unbound []int `json:"unbound,omitempty"`
	// UVSets is how many TEXCOORD_n sets the materials require.
	UVSets int      `json:"uvSets"`
	Notes  []string `json:"notes,omitempty"`
}

// MapTextures reads a GLB or a .gltf JSON document and works out where every
// image lands. It never fails: a broken asset comes back with notes instead of
// an error, because a scanner wants the partial answer.
func MapTextures(data []byte) TextureMap {
	var jsonPart []byte
	switch {
	case IsGLB(data):
		c, err := ReadContainer(data)
		if err != nil {
			return TextureMap{Notes: []string{"GLB container did not read: " + err.Error()}}
		}
		var ok bool
		if jsonPart, ok = c.JSON(); !ok {
			return TextureMap{Notes: []string{"GLB has no JSON chunk, so nothing describes its textures"}}
		}
	case looksLikeJSON(data):
		jsonPart = data
	default:
		return TextureMap{Notes: []string{"not a glTF asset"}}
	}

	doc, err := ParseDocument(jsonPart)
	if err != nil {
		return TextureMap{Notes: []string{"glTF JSON did not parse: " + err.Error()}}
	}
	return doc.MapTextures(jsonPart)
}

// MapTextures resolves the material-to-image chain. rawJSON is the same JSON
// the Document was parsed from; pass nil to skip mesh usage counts.
func (d *Document) MapTextures(rawJSON []byte) TextureMap {
	m := TextureMap{
		Images:    len(d.Images),
		Textures:  len(d.Textures),
		Materials: len(d.Materials),
		Samplers:  len(d.Samplers),
		UVSets:    1,
	}

	samplers := make([]samplerBlock, len(d.Samplers))
	for i, raw := range d.Samplers {
		if json.Unmarshal(raw, &samplers[i]) != nil {
			m.Notes = append(m.Notes, fmt.Sprintf("sampler %d did not parse", i))
		}
	}

	textures := make([]textureBlock, len(d.Textures))
	texSource := make([]int, len(d.Textures))
	texExt := make([]string, len(d.Textures))
	for i, raw := range d.Textures {
		texSource[i] = -1
		if json.Unmarshal(raw, &textures[i]) != nil {
			m.Notes = append(m.Notes, fmt.Sprintf("texture %d did not parse", i))
			continue
		}
		if textures[i].Source != nil {
			texSource[i] = *textures[i].Source
		}
		// Walk extension names in order so the result does not depend on Go's
		// randomised map iteration.
		names := sortedKeys(textures[i].Extensions)
		for _, name := range names {
			var alt struct {
				Source *int `json:"source"`
			}
			if json.Unmarshal(textures[i].Extensions[name], &alt) == nil && alt.Source != nil {
				texExt[i] = name
				if texSource[i] < 0 {
					// This is the case that matters: a Basis Universal or WebP
					// texture whose only image reference is inside the
					// extension.
					texSource[i] = *alt.Source
				}
			}
		}
	}

	// material index -> meshes and primitive counts that use it
	meshUse := map[int][]string{}
	primCount := map[int]int{}
	if len(rawJSON) > 0 {
		var only meshesOnly
		if json.Unmarshal(rawJSON, &only) == nil {
			for mi, mesh := range only.Meshes {
				name := mesh.Name
				if name == "" {
					name = fmt.Sprintf("mesh%d", mi)
				}
				for _, p := range mesh.Primitives {
					if p.Material == nil {
						continue
					}
					primCount[*p.Material]++
					if !hasName(meshUse[*p.Material], name) {
						meshUse[*p.Material] = append(meshUse[*p.Material], name)
					}
				}
			}
		} else {
			m.Notes = append(m.Notes, "mesh list did not parse; texture usage counts are omitted")
		}
	}

	used := make([]bool, len(d.Images))
	uvMax := 0

	add := func(mi int, matName, ext string, slot TextureSlot, ref *textureRef) {
		if ref == nil || ref.Index == nil {
			return
		}
		ti := *ref.Index
		b := TextureBinding{
			Image:        -1,
			Texture:      ti,
			Slot:         slot,
			Extension:    ext,
			Material:     mi,
			MaterialName: matName,
			Sampler:      -1,
			// glTF defaults when no sampler is named.
			WrapS:      "repeat",
			WrapT:      "repeat",
			MinFilter:  "unset",
			MagFilter:  "unset",
			Meshes:     meshUse[mi],
			Primitives: primCount[mi],
		}
		if ref.TexCoord != nil {
			b.TexCoord = *ref.TexCoord
		}
		if b.TexCoord > uvMax {
			uvMax = b.TexCoord
		}

		if ti < 0 || ti >= len(d.Textures) {
			b.Note = "texture index is out of range"
			m.Bindings = append(m.Bindings, b)
			return
		}
		if b.Extension == "" {
			b.Extension = texExt[ti]
		}
		switch src := texSource[ti]; {
		case src < 0:
			b.Note = "texture names no image source"
		case src >= len(d.Images):
			b.Note = "image index is out of range"
		default:
			b.Image = src
			used[src] = true
		}
		if s := textures[ti].Sampler; s != nil && *s >= 0 && *s < len(samplers) {
			b.Sampler = *s
			sm := samplers[*s]
			b.WrapS = wrapName(sm.WrapS)
			b.WrapT = wrapName(sm.WrapT)
			b.MinFilter = filterName(sm.MinFilter)
			b.MagFilter = filterName(sm.MagFilter)
		}
		m.Bindings = append(m.Bindings, b)
	}

	for mi, raw := range d.Materials {
		var mat materialBlock
		if json.Unmarshal(raw, &mat) != nil {
			m.Notes = append(m.Notes, fmt.Sprintf("material %d did not parse", mi))
			continue
		}
		name := mat.Name
		if name == "" {
			name = fmt.Sprintf("material%d", mi)
		}

		if mat.PBR != nil {
			add(mi, name, "", SlotBaseColor, mat.PBR.BaseColorTexture)
			add(mi, name, "", SlotMetallicRoughness, mat.PBR.MetallicRoughnessTexture)
		}
		add(mi, name, "", SlotNormal, mat.NormalTex)
		add(mi, name, "", SlotOcclusion, mat.OcclusionTex)
		add(mi, name, "", SlotEmissive, mat.EmissiveTex)

		for _, extName := range sortedKeys(mat.Extensions) {
			var fields map[string]json.RawMessage
			if json.Unmarshal(mat.Extensions[extName], &fields) != nil {
				continue
			}
			for _, k := range sortedKeys(fields) {
				if !strings.HasSuffix(k, "Texture") {
					continue
				}
				var ref textureRef
				if json.Unmarshal(fields[k], &ref) != nil || ref.Index == nil {
					continue
				}
				add(mi, name, extName, TextureSlot(strings.TrimSuffix(k, "Texture")), &ref)
			}
		}
	}

	sort.SliceStable(m.Bindings, func(i, j int) bool {
		if m.Bindings[i].Material != m.Bindings[j].Material {
			return m.Bindings[i].Material < m.Bindings[j].Material
		}
		if m.Bindings[i].Slot != m.Bindings[j].Slot {
			return m.Bindings[i].Slot < m.Bindings[j].Slot
		}
		return m.Bindings[i].Texture < m.Bindings[j].Texture
	})

	for i := range d.Images {
		if !used[i] {
			m.Unbound = append(m.Unbound, i)
		}
	}
	m.UVSets = uvMax + 1

	if len(d.Materials) == 0 && len(d.Images) > 0 {
		m.Notes = append(m.Notes,
			"asset carries images but declares no materials, so nothing says where they go")
	}
	return m
}

// SlotsFor lists the roles one image is used in, extension-qualified.
func (m TextureMap) SlotsFor(image int) []string {
	var out []string
	for _, b := range m.Bindings {
		if b.Image != image {
			continue
		}
		label := string(b.Slot)
		if b.Extension != "" {
			label = b.Extension + ":" + label
		}
		if !hasName(out, label) {
			out = append(out, label)
		}
	}
	sort.Strings(out)
	return out
}

// Describe is a one-line answer to "how does this texture lie on the model?",
// meant for a preview caption.
func (m TextureMap) Describe(image int) string {
	for _, b := range m.Bindings {
		if b.Image != image {
			continue
		}
		slot := string(b.Slot)
		if b.Extension != "" {
			slot = b.Extension + " " + slot
		}
		d := fmt.Sprintf("%s of %s, UV%d, wrap %s/%s", slot, b.MaterialName, b.TexCoord, b.WrapS, b.WrapT)
		if b.Primitives > 0 {
			d += fmt.Sprintf(", %d primitives", b.Primitives)
		}
		if b.Note != "" {
			d += " (" + b.Note + ")"
		}
		return d
	}
	return ""
}

// Summary is a single line for the text report.
func (m TextureMap) Summary() string {
	if len(m.Bindings) == 0 {
		if m.Images == 0 {
			return "no textures"
		}
		return fmt.Sprintf("%d images, none bound to a material", m.Images)
	}
	counts := map[TextureSlot]int{}
	for _, b := range m.Bindings {
		counts[b.Slot]++
	}
	names := make([]string, 0, len(counts))
	for s := range counts {
		names = append(names, string(s))
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s x%d", n, counts[TextureSlot(n)]))
	}
	out := fmt.Sprintf("%d bindings across %d images (%s)",
		len(m.Bindings), m.Images, strings.Join(parts, ", "))
	if m.UVSets > 1 {
		out += fmt.Sprintf(", %d UV sets", m.UVSets)
	}
	if len(m.Unbound) > 0 {
		out += fmt.Sprintf("; %d unbound", len(m.Unbound))
	}
	return out
}

// ── small helpers ──────────────────────────────────────────────────────────

func sortedKeys(m map[string]json.RawMessage) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func hasName(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// wrapName maps the GL wrap enums. Absent means REPEAT, which is the glTF
// default and the reason a texture authored for clamping tiles unexpectedly
// when the sampler is dropped.
func wrapName(v *int) string {
	if v == nil {
		return "repeat"
	}
	switch *v {
	case 33071:
		return "clamp"
	case 33648:
		return "mirror"
	case 10497:
		return "repeat"
	}
	return fmt.Sprintf("mode%d", *v)
}

func filterName(v *int) string {
	if v == nil {
		return "unset"
	}
	switch *v {
	case 9728:
		return "nearest"
	case 9729:
		return "linear"
	case 9984:
		return "nearest-mip-nearest"
	case 9985:
		return "linear-mip-nearest"
	case 9986:
		return "nearest-mip-linear"
	case 9987:
		return "linear-mip-linear"
	}
	return fmt.Sprintf("filter%d", *v)
}
