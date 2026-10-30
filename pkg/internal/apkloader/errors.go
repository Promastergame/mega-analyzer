package apkloader

import "errors"

var (
	// DEX / runtime format errors.
	errDexTooSmall   = errors.New("dex: file too small")
	errDexBadMagic   = errors.New("dex: unrecognized magic bytes")
	errOutOfBounds   = errors.New("dex: offset out of bounds")
	errBadULEB128    = errors.New("dex: malformed ULEB128 sequence")
	errBadSLEB128    = errors.New("dex: malformed SLEB128 sequence")
	errDexNotFound   = errors.New("dex: no DEX files found in APK")
	errNoSmali       = errors.New("loader: directory contains no smali files")
	errUnknownFormat = errors.New("loader: unrecognized input format")

	// Archive / extraction errors.
	errZipBomb                 = errors.New("zip: extraction limit exceeded (possible zip bomb)")
	errZipPathConflict         = errors.New("zip: multiple entries resolve to the same output path")
	errArchiveNoSupportedFiles = errors.New("archive: no supported analysis files found")

	// DEX structural validation.
	errSectionOverlap = errors.New("dex: sections overlap")
	errSectionOOB     = errors.New("dex: section out of bounds")
	errCountTooLarge  = errors.New("dex: section item count exceeds safe limit")

	// FFI / Rust bridge errors.
	ErrRustNotLinked = errors.New("rust library not linked or explicitly skipped")
)

// LoaderError wraps an operation with optional path context.
// Error format: "op path: message" or "op: message" when path is empty.
type LoaderError struct {
	Op   string
	Path string
	err  error
}

func (e *LoaderError) Error() string {
	if e.Path != "" {
		return e.Op + " " + e.Path + ": " + e.err.Error()
	}
	return e.Op + ": " + e.err.Error()
}

func (e *LoaderError) Unwrap() error { return e.err }
