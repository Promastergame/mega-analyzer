package apkloader

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type decodeReader struct {
	ctx context.Context
	r   io.Reader
}

func (r decodeReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func copyDecodeDEX(ctx context.Context, source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if existing, err := os.Stat(destination); err == nil && os.SameFile(info, existing) {
		return fmt.Errorf("DEX input and output must be different files")
	}
	f, err := os.CreateTemp(filepath.Dir(destination), ".dex-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, copyErr := io.Copy(f, decodeReader{ctx: ctx, r: in})
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Rename(f.Name(), destination)
}
