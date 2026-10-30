package ml

import "os"

func writeFileHelper(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
