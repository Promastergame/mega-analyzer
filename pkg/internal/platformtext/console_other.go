//go:build !windows

package platformtext

import "strings"

func decodeLegacyConsole(data []byte) string { return strings.ToValidUTF8(string(data), "\ufffd") }
