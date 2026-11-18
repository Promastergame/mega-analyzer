//go:build !js || !wasm

package pipeline

import "mega-analyzer/pkg/internal/config"

func newFileScanExecutor(*config.Config) fileScanExecutor { return nil }
