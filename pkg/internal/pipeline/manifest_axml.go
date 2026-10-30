package pipeline

import (
	"bytes"

	"mega-analyzer/pkg/internal/apkloader/axml"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/logger"
)

// decodeBinaryManifest returns a plaintext XML body for a binary
// AndroidManifest.xml and the untouched input for everything else.
//
// The decoded-tree path receives an AndroidManifest.xml that APK preparation
// already rendered to text, so every manifest detector works on it. The
// in-memory DEX path analyses the archive as extracted, where the manifest is
// still an AXML resource chunk. All manifest detectors are regex-based and
// silently found nothing on those bytes, which dropped package metadata,
// declared permissions and exported-component findings from the results
// instead of reporting them. Decoding here keeps both paths on one code route
// and one detector set.
//
// A manifest that cannot be decoded is left as-is: the scan keeps exactly the
// coverage it had before and the warning states what is missing.
func decodeBinaryManifest(relPath string, fileType types.FileType, content []byte) []byte {
	if fileType != types.FileTypeXML || !isAndroidManifestPath(relPath) {
		return content
	}
	// Some apps ship a plaintext manifest; those need no work.
	if !axml.IsBinaryXML(content) {
		return content
	}

	manifest, err := axml.Decode(content)
	if err == nil && manifest != nil && isPlausibleManifestXML(manifest.XMLBytes) {
		return manifest.XMLBytes
	}

	// A truncated or malformed chunk can still decode into a well-formed but
	// empty document. Substituting that for the original bytes would silently
	// destroy evidence, so the raw body is kept instead.
	logger.Warn("Binary AndroidManifest.xml could not be decoded; manifest findings will be missing",
		"file", relPath, "error", err)
	return content
}

// isPlausibleManifestXML rejects decoder output that carries no manifest root
// element, which is the marker of a chunk that failed to yield real content.
func isPlausibleManifestXML(xml []byte) bool {
	return bytes.Contains(xml, []byte("<manifest"))
}
