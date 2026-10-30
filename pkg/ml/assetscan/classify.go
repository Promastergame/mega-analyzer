package assetscan

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"mega-analyzer/pkg/ml/imagedec"
	"mega-analyzer/pkg/ml/media3d"
	"mega-analyzer/pkg/ml/preview"
	"mega-analyzer/pkg/ml/zstd"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CLASSIFICATION AND PREVIEW RENDERING
// ═══════════════════════════════════════════════════════════════════════════════

// minConfident is the score below which a recovered candidate is a lead, not a
// result. It matches the threshold documented on imagedec.Candidate.Score.
const minConfident = 50

// maxTexturesPerModel is the default cap on how many embedded textures one
// model contributes. Options.MaxTextures overrides it; -assets-no-textures
// drops it to zero.
const maxTexturesPerModel = 4

// maxInflateMB is the hard ceiling on a single inflated payload, whatever the
// per-entry size cap says. A thirty byte zstd frame can legally claim a
// sixteen exabyte content size, so the limit is not negotiable.
const maxInflateMB = 1024

func classForFamily(f imagedec.Family) string {
	switch f {
	case imagedec.FamilyRaster, imagedec.FamilyVector:
		return ClassImage
	case imagedec.FamilyGPUTexture:
		return ClassTexture
	case imagedec.FamilyCompressed, imagedec.FamilyContainer:
		return ClassPacked
	}
	return ClassOther
}

func imageInfo(res imagedec.Result, best imagedec.Candidate, ok bool) *ImageInfo {
	info := &ImageInfo{Direct: res.Direct}
	if ok {
		info.Signature = best.Signature
		info.Family = best.Family.String()
		info.Base = best.Base
		info.Score = best.Score
		info.Evidence = best.Evidence
		if !best.Transform.IsIdentity() {
			info.Transform = best.Transform.String()
		}
	}
	for _, f := range res.Frames {
		info.Frames = append(info.Frames, FrameInfo{
			Format:       f.Format,
			Offset:       f.Offset,
			DeclaredSize: f.DeclaredSize,
			Decodable:    f.Decodable,
			Note:         f.Note,
		})
	}
	return info
}

func (s *scanner) imagedecOptions(n int) imagedec.Options {
	var o imagedec.Options
	if s.opts.Deep {
		o.MaxKeyLen = 32
		o.MaxCandidates = 16
		o.ScanWindow = 1 << 18
		return o
	}
	// The embedded-frame scan walks its window byte by byte. On a bulk pass
	// over an APK that cost dominates everything else, and the answer almost
	// always lives in the first few kilobytes, so the window shrinks for large
	// buffers unless the caller explicitly asked to go deep.
	if n > 1<<20 {
		o.ScanWindow = 1 << 14
	}
	return o
}

// classify decides what a buffer is. The second return value reports whether
// the item is interesting enough to keep when Options.All is false.
func (s *scanner) classify(name, container string, data []byte) (Item, bool) {
	it := Item{
		Path:      name,
		Container: container,
		Size:      int64(len(data)),
		Class:     ClassOther,
		Format:    "unknown",
		Verdict:   "unrecognised",
	}
	if len(data) == 0 {
		it.Verdict = "empty file"
		return it, false
	}

	ext := strings.ToLower(path.Ext(name))

	// ── 3D first ────────────────────────────────────────────────────────
	// A vendor .glb looks like high-entropy noise to a signature scanner, so
	// asking media3d first is what keeps FLA2-style files out of the
	// "encrypted" bucket where nobody would look for them.
	if media3d.IsGLB(data) || threeDExts[ext] {
		if r := media3d.Probe(data); r.Kind != "" {
			s.fill3D(&it, r, data)
			return it, true
		}
		it.Notes = append(it.Notes,
			"extension claims a 3D asset but the bytes are not glTF; trying recovery")
	}

	// ── images, GPU textures, obfuscated blobs ────────────────────────────
	res := imagedec.Analyze(data, s.imagedecOptions(len(data)))
	best, ok := res.Best()

	switch {
	case res.Direct && ok:
		it.Class = classForFamily(best.Family)
		it.Format = best.Signature
		it.Verdict = best.Signature + ", stored as-is"
		it.Image = imageInfo(res, best, true)
		// Quiet unless the file really is a block-compressed texture, in
		// which case the report gains its footprint and block make-up.
		s.describeASTC(&it, data)
		s.preview(&it, data, "file", best.Ext, !s.opts.NoBytemap)
		return it, true

	case ok && best.Score >= minConfident && !best.Transform.IsIdentity():
		base := best.Base
		if base < 0 || base > len(data) {
			base = 0
		}
		recovered := best.Transform.Apply(data[base:])
		it.Class = ClassEncrypted
		it.Format = best.Signature
		it.Verdict = fmt.Sprintf("%s recovered with %s", best.Signature, best.Transform)
		it.Image = imageInfo(res, best, true)
		s.preview(&it, recovered, "recovered", best.Ext, true)
		return it, true

	case ok && best.Score >= minConfident && best.Base > 0:
		// Identity transform but a non-zero base: a real image sitting behind
		// a proprietary header. Worth surfacing, and the payload previews.
		it.Class = classForFamily(best.Family)
		it.Format = best.Signature
		it.Verdict = fmt.Sprintf("%s embedded at +%d", best.Signature, best.Base)
		it.Image = imageInfo(res, best, true)
		// If the embedded payload is zstd (as in .sctx), inflate it and try
		// to decode the texture inside, rather than just showing the
		// compressed bytes as a byte map.
		if best.Signature == "zstd" && !s.opts.NoZstd {
			if s.inflateZstd(&it, data, imagedec.Frame{Offset: best.Base, Format: "zstd", Decodable: true, DeclaredSize: int64(len(data) - best.Base)}) {
				return it, true
			}
		}
		s.preview(&it, data[best.Base:], "recovered", best.Ext, !s.opts.NoBytemap)
		return it, true

	case len(res.Frames) > 0:
		f := res.Frames[0]
		it.Class = ClassPacked
		it.Format = f.Format
		it.Verdict = fmt.Sprintf("%s stream at +%d", f.Format, f.Offset)
		it.Image = imageInfo(res, best, ok)
		if f.Format == "zstd" && !s.opts.NoZstd {
			s.inflateZstd(&it, data, f)
		} else if !f.Decodable {
			it.Notes = append(it.Notes,
				"header parsed only; this build has no "+f.Format+" decompressor")
		}
		return it, true
	}

	// ── nothing recognised ─────────────────────────────────────────────
	if ok {
		it.Image = imageInfo(res, best, true)
		it.Verdict = fmt.Sprintf("possible %s, only %d%% confident", best.Signature, best.Score)
	}
	// One last chance before writing the file off. A headerless block
	// texture looks like noise to every signature in the table, but its
	// block modes are self-describing enough to identify it outright.
	if s.tryASTC(&it, data, "file") {
		return it, true
	}
	if s.opts.All {
		s.preview(&it, data, "file", "map", true)
	}
	return it, false
}

// inflateZstd expands a zstd payload and re-classifies whatever comes out.
// This is the step that turns "an encrypted texture container" into an actual
// picture: a .sctx file is a small FlatBuffers head followed by one zstd
// frame, and KTX2 supercompression is the same idea in a different wrapper.
// Until this repository had a zstd decoder, both stopped at the header.
func (s *scanner) inflateZstd(it *Item, data []byte, f imagedec.Frame) bool {
	off := f.Offset
	if off < 0 || off >= len(data) {
		return false
	}

	// Two independent ceilings: the caller's per-entry cap, and a hard one
	// that a forged header cannot talk its way past.
	limitMB := s.opts.MaxFileMB
	if limitMB <= 0 || limitMB > maxInflateMB {
		limitMB = maxInflateMB
	}
	raw, err := zstd.DecompressLimit(data[off:], limitMB<<20)
	if err != nil {
		it.Notes = append(it.Notes, "zstd payload did not inflate: "+err.Error())
		return false
	}
	if len(raw) == 0 {
		it.Notes = append(it.Notes, "zstd payload inflated to nothing")
		return false
	}
	it.Notes = append(it.Notes, fmt.Sprintf(
		"zstd inflated: %d bytes at +%d expand to %d", len(data)-off, off, len(raw)))

	// Whatever came out is treated exactly like a file found on disk, so a
	// texture that was XOR-obfuscated *and then* compressed still recovers.
	inner := imagedec.Analyze(raw, s.imagedecOptions(len(raw)))
	ib, iok := inner.Best()

	switch {
	case inner.Direct && iok:
		it.Class = classForFamily(ib.Family)
		it.Format = ib.Signature
		it.Verdict = fmt.Sprintf("%s inside a zstd frame", ib.Signature)
		it.Image = imageInfo(inner, ib, true)
		s.preview(it, raw, "recovered", ib.Ext, !s.opts.NoBytemap)

	case iok && ib.Score >= minConfident && !ib.Transform.IsIdentity():
		base := ib.Base
		if base < 0 || base > len(raw) {
			base = 0
		}
		it.Class = ClassEncrypted
		it.Format = ib.Signature
		it.Verdict = fmt.Sprintf("%s inside a zstd frame, recovered with %s",
			ib.Signature, ib.Transform)
		it.Image = imageInfo(inner, ib, true)
		s.preview(it, ib.Transform.Apply(raw[base:]), "recovered", ib.Ext, !s.opts.NoBytemap)

	default:
		// Inflated fine, but no signature matched. The usual reason is a
		// block-compressed texture: out of its container, ASTC has neither a
		// magic number nor a header, so nothing short of a real decoder can
		// tell it apart from noise. This is the .sctx case exactly.
		it.Verdict = fmt.Sprintf("zstd stream at +%d, inflates to %d bytes", off, len(raw))
		if len(inner.Frames) > 0 {
			it.Notes = append(it.Notes, fmt.Sprintf(
				"inflated payload holds a %s stream at +%d",
				inner.Frames[0].Format, inner.Frames[0].Offset))
		}
		if s.tryASTC(it, raw, "recovered") {
			return true
		}
		s.preview(it, raw, "recovered", "inflated", !s.opts.NoBytemap)
	}
	return true
}

// toBinds converts the material map into the report's wire shape.
func toBinds(m media3d.TextureMap) []TextureBind {
	if len(m.Bindings) == 0 {
		return nil
	}
	out := make([]TextureBind, 0, len(m.Bindings))
	for _, b := range m.Bindings {
		out = append(out, TextureBind{
			Image:      b.Image,
			Slot:       string(b.Slot),
			Extension:  b.Extension,
			Material:   b.MaterialName,
			TexCoord:   b.TexCoord,
			Wrap:       b.WrapS + "/" + b.WrapT,
			Filter:     b.MinFilter + "/" + b.MagFilter,
			Meshes:     b.Meshes,
			Primitives: b.Primitives,
			Note:       b.Note,
		})
	}
	return out
}

func (s *scanner) fill3D(it *Item, r media3d.Report, data []byte) {
	textures := media3d.ExtractImages(data)
	// Extracting the images says what exists. The material map says where each
	// one goes, which is the part that decides whether a texture can be
	// judged or replaced.
	tm := media3d.MapTextures(data)
	defer func() {
		if len(it.Previews) == 0 {
			s.preview(it, data, "file", "map", !s.opts.NoBytemap)
		}
	}()

	it.Class = ClassThreeD
	it.Format = r.Kind
	it.Verdict = r.Summary()
	it.ThreeD = &ThreeDInfo{
		Kind:               r.Kind,
		AssetVersion:       r.AssetVersion,
		Generator:          r.Generator,
		Vertices:           r.Vertices,
		Faces:              r.Faces,
		Compressed:         r.Compressed,
		VendorChunks:       r.VendorChunks,
		ExtensionsRequired: r.ExtensionsRequired,
		Unrecognized:       r.Unrecognized,
		StockLoadable:      r.StockLoadable,
		Blockers:           r.Blockers,
		Anomalies:          r.Anomalies,
		Textures:           len(textures),
	}

	it.ThreeD.UVSets = tm.UVSets
	it.ThreeD.UnboundImages = tm.Unbound
	it.ThreeD.Bindings = toBinds(tm)
	if tm.Materials > 0 || tm.Images > 0 {
		it.Verdict += "; " + tm.Summary()
	}
	for _, n := range tm.Notes {
		it.Notes = append(it.Notes, "textures: "+n)
	}

	if s.opts.NoTextures {
		if len(textures) > 0 {
			it.Notes = append(it.Notes, fmt.Sprintf(
				"%d embedded textures skipped by request; the material map above still applies",
				len(textures)))
		}
		return
	}

	rendered := 0
	for i := range textures {
		t := &textures[i]
		if len(t.Data) == 0 {
			if t.Note != "" {
				note := fmt.Sprintf("image %d: %s", t.Index, t.Note)
				// When a texture lives outside the file, say what it would
				// have been used for; that is what makes the note actionable.
				if d := tm.Describe(t.Index); d != "" {
					note += " [" + d + "]"
				}
				it.Notes = append(it.Notes, note)
			}
			continue
		}
		if rendered >= s.opts.MaxTextures {
			it.Notes = append(it.Notes, fmt.Sprintf(
				"%d more embedded textures not rendered (raise -assets-textures)",
				len(textures)-i))
			break
		}
		before := len(it.Previews)
		s.preview(it, t.Data, "texture", fmt.Sprintf("tex%d", t.Index), !s.opts.NoBytemap)
		if len(it.Previews) > before {
			p := &it.Previews[len(it.Previews)-1]
			p.Slot = strings.Join(tm.SlotsFor(t.Index), "+")
			p.Applied = tm.Describe(t.Index)
		}
		rendered++
	}
}

// slugify turns any name into a safe ASCII filename fragment. Asset paths
// routinely contain Cyrillic, CJK and spaces; a preview directory full of
// those is a portability problem on every platform involved here.
func slugify(s string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

// previewName builds a unique, collision-free file name for one preview.
func (s *scanner) previewName(it *Item, label string) string {
	stem := it.Display()
	stem = strings.TrimSuffix(stem, path.Ext(stem))
	name := slugify(stem)
	if len(name) > 60 {
		// Keep the tail: the leaf name identifies the asset, the leading
		// directories are shared by everything in the same folder.
		name = name[len(name)-60:]
		name = strings.TrimPrefix(name, "-")
	}
	if name == "" {
		name = "asset"
	}
	if l := slugify(label); l != "" {
		name += "-" + l
	}
	s.slugs[name]++
	if n := s.slugs[name]; n > 1 {
		name = fmt.Sprintf("%s-%d", name, n)
	}
	return name + ".png"
}

// preview renders data to a PNG on disk and records it on the item.
func (s *scanner) preview(it *Item, data []byte, source, label string, allowMap bool) {
	if s.opts.PreviewDir == "" || len(data) == 0 {
		return
	}
	if s.previews >= s.opts.MaxPreviews {
		return
	}

	res, err := preview.Render(data, preview.Options{
		MaxDim:     s.opts.MaxDim,
		NoFallback: !allowMap,
	})
	if err != nil {
		// NoFallback rejecting an undecodable buffer is the expected path, not
		// a failure worth reporting to the user.
		if allowMap {
			s.fail(it.Display(), err)
		}
		return
	}

	s.writePreview(it, res, source, label)
}

// writePreview saves an already-rendered preview and records it on the item.
//
// Split out of preview() because a block-compressed texture is rendered by a
// different call with its own options, and both paths must write the file,
// count it against the cap and describe it identically.
func (s *scanner) writePreview(it *Item, res preview.Result, source, label string) {
	outPath := filepath.Join(s.opts.PreviewDir, s.previewName(it, label))
	if err := os.WriteFile(outPath, res.PNG, 0o644); err != nil {
		s.fail(outPath, err)
		return
	}
	s.previews++
	it.Previews = append(it.Previews, PreviewInfo{
		Path:    outPath,
		Label:   label,
		Source:  source,
		Width:   res.Width,
		Height:  res.Height,
		Decoder: res.Decoder,
		Lossy:   res.Lossy,
		Note:    res.Note,
	})
}
