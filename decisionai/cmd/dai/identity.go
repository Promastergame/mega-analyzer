package main

import (
	"crypto/sha256"
	"encoding/hex"
	"decisionai/s1"
	"io"
	"os"
)

func auxiliaryFingerprint(eng *s1.Engine, encPath, rolePath, textPath string) (string, error) {
	paths := []string{}
	if eng.Skills != nil {
		paths = append(paths, findModel(encPath, "encoder-tiny.dte"))
	}
	if len(eng.Experts) > 0 {
		paths = append(paths, findModel(rolePath, "smalirole-model.json"), findModel(textPath, "demo-text-model.json"))
	}
	h := sha256.New()
	for i, path := range paths {
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		part := sha256.New()
		_, err = io.Copy(part, f)
		closeErr := f.Close()
		if err != nil {
			return "", err
		}
		if closeErr != nil {
			return "", closeErr
		}
		h.Write([]byte{byte(i)})
		h.Write(part.Sum(nil))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
