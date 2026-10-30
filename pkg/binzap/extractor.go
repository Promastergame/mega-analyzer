package binzap

import (
	"context"
	"mega-analyzer/pkg/internal/apkloader"
)

// UnpackAPK prepares and unpacks an APK file using the internal apkloader Extractor.
// Exposing this helper under pkg/binzap allows external commands (like cmd/binzap)
// to unpack APKs without violating Go's internal package import restrictions.
func UnpackAPK(ctx context.Context, apkPath string) (string, error) {
	extractor := apkloader.NewExtractor()
	return extractor.PrepareInputWithOptions(ctx, apkPath, apkloader.PrepareOptions{})
}
