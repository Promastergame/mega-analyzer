package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

func hashSandboxSample(path string) (string, string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", "", 0, err
	}
	if !info.Mode().IsRegular() {
		return "", "", 0, nil
	}
	m, s := md5.New(), sha256.New()
	n, err := io.Copy(io.MultiWriter(m, s), f)
	if err != nil {
		return "", "", 0, err
	}
	return hex.EncodeToString(m.Sum(nil)), hex.EncodeToString(s.Sum(nil)), n, nil
}
