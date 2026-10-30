package media3d

// ═══════════════════════════════════════════════════════════════════════════════
// EXTENSION REGISTRY
//
// glTF 2.0 is a small core plus an open extension registry, and the registry is
// where the format actually moves. A file that a loader rejects today is almost
// never malformed - it usually names an extension in extensionsRequired that
// the loader has never heard of.
//
// The point of this table is NOT to implement extensions. It is to make the
// unknown visible: anything absent here is reported by name so the caller knows
// precisely which capability is missing, instead of getting a silent zero.
// That is the difference between "this model has no vertices" and "the vertex
// data is Draco-compressed and this build cannot decode it".
// ═══════════════════════════════════════════════════════════════════════════════

// ExtClass groups an extension by what it does to the payload.
type ExtClass uint8

const (
	ExtOther ExtClass = iota
	// ExtGeometryCompression means accessor data is not readable as plain
	// buffer bytes; vertex and index counts may describe a decoded mesh that
	// does not exist on disk.
	ExtGeometryCompression
	// ExtTextureCodec means image payloads are not PNG or JPEG.
	ExtTextureCodec
	ExtMaterial
	ExtLighting
	ExtInstancing
	ExtMetadata
	ExtAnimation
	ExtScene
	ExtPhysics
	ExtAudio
)

func (c ExtClass) String() string {
	switch c {
	case ExtGeometryCompression:
		return "geometry-compression"
	case ExtTextureCodec:
		return "texture-codec"
	case ExtMaterial:
		return "material"
	case ExtLighting:
		return "lighting"
	case ExtInstancing:
		return "instancing"
	case ExtMetadata:
		return "metadata"
	case ExtAnimation:
		return "animation"
	case ExtScene:
		return "scene"
	case ExtPhysics:
		return "physics"
	case ExtAudio:
		return "audio"
	default:
		return "other"
	}
}

// ExtensionInfo describes one registered glTF extension.
type ExtensionInfo struct {
	Name  string
	Class ExtClass
	// Ratified is true only for the Khronos-ratified list. Vendor and
	// multi-vendor extensions are widely used but carry no such guarantee,
	// and a conservative loader may refuse them.
	Ratified bool
	Note     string
}

// extensionRegistry is keyed by the exact extension name as it appears in
// extensionsUsed / extensionsRequired. Names are case-sensitive per the spec.
var extensionRegistry = map[string]ExtensionInfo{
	// ── Khronos, ratified ────────────────────────────────────────────────
	"KHR_animation_pointer": {"KHR_animation_pointer", ExtAnimation, true,
		"animation channels may target arbitrary properties, not just node TRS"},
	"KHR_draco_mesh_compression": {"KHR_draco_mesh_compression", ExtGeometryCompression, true,
		"mesh attributes are Draco-compressed inside bufferViews; raw buffer bytes are not vertex data"},
	"KHR_lights_punctual":  {"KHR_lights_punctual", ExtLighting, true, "point, spot and directional lights"},
	"KHR_materials_anisotropy": {"KHR_materials_anisotropy", ExtMaterial, true, ""},
	"KHR_materials_clearcoat":  {"KHR_materials_clearcoat", ExtMaterial, true, ""},
	"KHR_materials_dispersion": {"KHR_materials_dispersion", ExtMaterial, true, ""},
	"KHR_materials_emissive_strength": {"KHR_materials_emissive_strength", ExtMaterial, true, ""},
	"KHR_materials_ior":         {"KHR_materials_ior", ExtMaterial, true, ""},
	"KHR_materials_iridescence":  {"KHR_materials_iridescence", ExtMaterial, true, ""},
	"KHR_materials_sheen":        {"KHR_materials_sheen", ExtMaterial, true, ""},
	"KHR_materials_specular":     {"KHR_materials_specular", ExtMaterial, true, ""},
	"KHR_materials_transmission": {"KHR_materials_transmission", ExtMaterial, true, ""},
	"KHR_materials_unlit":        {"KHR_materials_unlit", ExtMaterial, true, ""},
	"KHR_materials_variants":     {"KHR_materials_variants", ExtMaterial, true, "one mesh carries several material sets"},
	"KHR_materials_volume":       {"KHR_materials_volume", ExtMaterial, true, ""},
	"KHR_mesh_quantization": {"KHR_mesh_quantization", ExtGeometryCompression, true,
		"attributes use narrow integer component types; positions need the node scale to be meaningful"},
	"KHR_node_visibility": {"KHR_node_visibility", ExtScene, true, ""},
	"KHR_texture_basisu": {"KHR_texture_basisu", ExtTextureCodec, true,
		"images are KTX2 containers holding Basis Universal data, not PNG or JPEG"},
	"KHR_texture_transform": {"KHR_texture_transform", ExtMaterial, true, "UV offset, rotation and scale for atlases"},
	"KHR_xmp_json_ld":       {"KHR_xmp_json_ld", ExtMetadata, true, "XMP metadata, a place authorship strings hide"},
	"EXT_mesh_gpu_instancing": {"EXT_mesh_gpu_instancing", ExtInstancing, true,
		"node transforms are replicated from an instance attribute buffer"},
	"EXT_meshopt_compression": {"EXT_meshopt_compression", ExtGeometryCompression, true,
		"bufferView payloads are meshoptimizer-encoded and must be decoded before use"},
	"EXT_texture_webp": {"EXT_texture_webp", ExtTextureCodec, true, "images are WebP"},

	// ── Widely deployed, not ratified ────────────────────────────────────
	"KHR_materials_pbrSpecularGlossiness": {"KHR_materials_pbrSpecularGlossiness", ExtMaterial, false,
		"archived; superseded by the core metallic-roughness model, still emitted by older exporters"},
	"KHR_binary_glTF": {"KHR_binary_glTF", ExtOther, false,
		"glTF 1.0 only; folded into the core GLB container in 2.0"},
	"KHR_lights_image_based": {"KHR_lights_image_based", ExtLighting, false, ""},
	"EXT_lights_image_based": {"EXT_lights_image_based", ExtLighting, false, ""},
	"EXT_texture_avif":       {"EXT_texture_avif", ExtTextureCodec, false, "images are AVIF"},
	"EXT_structural_metadata": {"EXT_structural_metadata", ExtMetadata, false, "3D Tiles property tables"},
	"EXT_mesh_features":       {"EXT_mesh_features", ExtMetadata, false, "3D Tiles per-feature ids"},
	"EXT_instance_features":   {"EXT_instance_features", ExtMetadata, false, ""},
	"MSFT_texture_dds":        {"MSFT_texture_dds", ExtTextureCodec, false, "images are DDS"},
	"MSFT_lod":                {"MSFT_lod", ExtScene, false, ""},
	"MSFT_packing_normalRoughnessMetallic": {"MSFT_packing_normalRoughnessMetallic", ExtMaterial, false, ""},
	"MSFT_packing_occlusionRoughnessMetallic": {"MSFT_packing_occlusionRoughnessMetallic", ExtMaterial, false, ""},
	"ADOBE_materials_thin_transparency": {"ADOBE_materials_thin_transparency", ExtMaterial, false, ""},
	"AGI_articulations":                 {"AGI_articulations", ExtScene, false, ""},
	"AGI_stk_metadata":                  {"AGI_stk_metadata", ExtMetadata, false, ""},
	"CESIUM_primitive_outline":          {"CESIUM_primitive_outline", ExtScene, false, ""},
	"FB_geometry_metadata":              {"FB_geometry_metadata", ExtMetadata, false, ""},
	"KHR_audio_emitter":                 {"KHR_audio_emitter", ExtAudio, false, ""},
	"KHR_implicit_shapes":               {"KHR_implicit_shapes", ExtPhysics, false, ""},
	"KHR_physics_rigid_bodies":          {"KHR_physics_rigid_bodies", ExtPhysics, false, ""},
	"KHR_materials_diffuse_transmission": {"KHR_materials_diffuse_transmission", ExtMaterial, false, ""},
	"KHR_texture_procedurals":            {"KHR_texture_procedurals", ExtMaterial, false, ""},
}

// LookupExtension resolves a name against the registry.
func LookupExtension(name string) (ExtensionInfo, bool) {
	info, ok := extensionRegistry[name]
	return info, ok
}

// KnownExtensionCount reports the registry size. Tests use it to catch an
// accidentally emptied table, which would silently turn every extension into
// an "unrecognized" finding.
func KnownExtensionCount() int { return len(extensionRegistry) }

// classifyExtensions splits a name list into recognized infos and unknown
// names, preserving input order and dropping duplicates.
func classifyExtensions(names []string) (known []ExtensionInfo, unknown []string) {
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		if info, ok := extensionRegistry[n]; ok {
			known = append(known, info)
		} else {
			unknown = append(unknown, n)
		}
	}
	return known, unknown
}
