package gamemode

import (
	"os"
	"path/filepath"
)

func gamemodeDataFile(name string) string {
	if root := os.Getenv("MEGA_ANALYZER_GAMEMODE_DIR"); root != "" {
		return filepath.Join(root, name)
	}
	if homeDir, err := os.UserHomeDir(); err == nil && homeDir != "" {
		dir := filepath.Join(homeDir, ".analyzer-gamemode")
		if err := os.MkdirAll(dir, 0755); err == nil {
			probe := filepath.Join(dir, ".write-test")
			if err := os.WriteFile(probe, []byte("ok"), 0644); err == nil {
				_ = os.Remove(probe)
				return filepath.Join(dir, name)
			}
		}
	}
	return filepath.Join(os.TempDir(), "mega-analyzer-gamemode", name)
}
