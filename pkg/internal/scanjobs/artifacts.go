package scanjobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var artifactIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

var allowedArtifactExtensions = map[string]struct{}{
	".apk": {}, ".zip": {}, ".dex": {}, ".xapk": {}, ".aab": {}, ".jar": {},
}

type Artifact struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	path     string
}

func ValidateArtifactFilename(filename string) error {
	ext := strings.ToLower(filepath.Ext(filepath.Base(strings.TrimSpace(filename))))
	if _, ok := allowedArtifactExtensions[ext]; !ok {
		return errors.New("unsupported artifact extension")
	}
	return nil
}

func (m *Manager) StoreArtifact(ctx context.Context, filename string, src io.Reader) (Artifact, error) {
	filename = filepath.Base(strings.TrimSpace(filename))
	ext := strings.ToLower(filepath.Ext(filename))
	if err := ValidateArtifactFilename(filename); err != nil {
		return Artifact{}, err
	}

	tmp, err := os.CreateTemp(filepath.Join(m.root, "artifacts"), ".upload-*")
	if err != nil {
		return Artifact{}, fmt.Errorf("create artifact staging file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	hash := sha256.New()
	limited := &contextReader{ctx: ctx, reader: io.LimitReader(src, m.cfg.MaxUploadBytes+1)}
	size, copyErr := io.Copy(io.MultiWriter(tmp, hash), limited)
	if closeErr := tmp.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return Artifact{}, fmt.Errorf("store artifact: %w", copyErr)
	}
	if size == 0 {
		return Artifact{}, errors.New("artifact is empty")
	}
	if size > m.cfg.MaxUploadBytes {
		return Artifact{}, fmt.Errorf("artifact exceeds %d byte limit", m.cfg.MaxUploadBytes)
	}
	if err := validateArtifactMagic(tmpPath, ext); err != nil {
		return Artifact{}, err
	}

	id := hex.EncodeToString(hash.Sum(nil))
	dir := filepath.Join(m.root, "artifacts", id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Artifact{}, fmt.Errorf("create artifact directory: %w", err)
	}
	destination := filepath.Join(dir, "input"+ext)
	if _, statErr := os.Stat(destination); errors.Is(statErr, os.ErrNotExist) {
		if err := os.Rename(tmpPath, destination); err != nil {
			if _, existsErr := os.Stat(destination); existsErr != nil {
				return Artifact{}, fmt.Errorf("commit artifact: %w", err)
			}
		}
	} else if statErr != nil {
		return Artifact{}, fmt.Errorf("stat stored artifact: %w", statErr)
	}
	return Artifact{ID: id, Filename: filename, Size: size, SHA256: id, path: destination}, nil
}

func (m *Manager) ResolveArtifact(id string) (Artifact, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	if !artifactIDPattern.MatchString(id) {
		return Artifact{}, errors.New("invalid artifact ID")
	}
	dir := filepath.Join(m.root, "artifacts", id)
	if !pathWithin(filepath.Join(m.root, "artifacts"), dir) {
		return Artifact{}, errors.New("artifact path escapes store")
	}
	for ext := range allowedArtifactExtensions {
		path := filepath.Join(dir, "input"+ext)
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() {
			return Artifact{ID: id, Filename: "input" + ext, Size: info.Size(), SHA256: id, path: path}, nil
		}
	}
	return Artifact{}, os.ErrNotExist
}

func (a Artifact) Path() string { return a.path }

// ResolveLocalTarget supports the deprecated path-based API without allowing
// it to become an arbitrary local-file read primitive. scanRoot must be
// explicitly configured by the operator.
func ResolveLocalTarget(scanRoot, target string) (string, error) {
	if strings.TrimSpace(scanRoot) == "" {
		return "", errors.New("local path scanning is disabled; upload an artifact instead")
	}
	root, err := filepath.Abs(scanRoot)
	if err != nil {
		return "", fmt.Errorf("resolve scan root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve scan root symlinks: %w", err)
	}
	candidate := filepath.Clean(target)
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve target: %w", err)
	}
	candidate, err = filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve target symlinks: %w", err)
	}
	if !pathWithin(root, candidate) {
		return "", errors.New("target escapes configured scan root")
	}
	info, err := os.Stat(candidate)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("target is not a regular file")
	}
	ext := strings.ToLower(filepath.Ext(candidate))
	if err := ValidateArtifactFilename(candidate); err != nil {
		return "", err
	}
	if err := validateArtifactMagic(candidate, ext); err != nil {
		return "", err
	}
	return candidate, nil
}

func validateArtifactMagic(path, ext string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var header [8]byte
	n, err := io.ReadFull(f, header[:])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("read artifact header: %w", err)
	}
	if ext == ".dex" {
		if n < 8 || string(header[:4]) != "dex\n" || header[7] != 0 {
			return errors.New("file extension does not match DEX content")
		}
		return nil
	}
	if n < 4 || header[0] != 'P' || header[1] != 'K' ||
		!((header[2] == 3 && header[3] == 4) || (header[2] == 5 && header[3] == 6) || (header[2] == 7 && header[3] == 8)) {
		return errors.New("file extension does not match ZIP/APK content")
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.reader.Read(p)
	}
}
