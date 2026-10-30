package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Cache Manager
// ═══════════════════════════════════════════════════════════════════════════════

const (
	// Default cache directory
	DefaultCacheDir = ".analyzer-cache"

	// Cache metadata file
	MetadataFile = "metadata.json"
)

// CacheManager manages analyzer cache
type CacheManager struct {
	cacheDir string
}

// NewCacheManager creates a new cache manager
func NewCacheManager(cacheDir string) *CacheManager {
	if cacheDir == "" {
		cacheDir = DefaultCacheDir
	}
	return &CacheManager{cacheDir: cacheDir}
}

// FSCacheStats holds file system cache statistics
type FSCacheStats struct {
	Path         string    `json:"path"`
	TotalSize    int64     `json:"total_size"`
	FileCount    int       `json:"file_count"`
	OldestFile   string    `json:"oldest_file,omitempty"`
	NewestFile   string    `json:"newest_file,omitempty"`
	LastAccessed time.Time `json:"last_accessed"`
	CacheAge     string    `json:"cache_age"`
}

// GetStats returns cache statistics
func (cm *CacheManager) GetStats() (*FSCacheStats, error) {
	stats := &FSCacheStats{
		Path: cm.cacheDir,
	}

	// Check if cache directory exists
	info, err := os.Stat(cm.cacheDir)
	if os.IsNotExist(err) {
		stats.TotalSize = 0
		stats.FileCount = 0
		return stats, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to access cache directory: %w", err)
	}

	stats.LastAccessed = info.ModTime()

	// Walk directory and collect stats
	var totalSize int64
	var fileCount int
	var oldestTime, newestTime time.Time
	var oldestPath, newPath string

	err = filepath.Walk(cm.cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		fileCount++
		totalSize += info.Size()

		if oldestTime.IsZero() || info.ModTime().Before(oldestTime) {
			oldestTime = info.ModTime()
			oldestPath = path
		}

		if newestTime.IsZero() || info.ModTime().After(newestTime) {
			newestTime = info.ModTime()
			newPath = path
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk cache directory: %w", err)
	}

	stats.TotalSize = totalSize
	stats.FileCount = fileCount

	if oldestPath != "" {
		relPath, _ := filepath.Rel(cm.cacheDir, oldestPath)
		stats.OldestFile = relPath
	}

	if newPath != "" {
		relPath, _ := filepath.Rel(cm.cacheDir, newPath)
		stats.NewestFile = relPath
	}

	// Calculate cache age
	age := time.Since(stats.LastAccessed)
	stats.CacheAge = age.String()

	return stats, nil
}

// Clear removes all cache files. A missing directory is a no-op success:
// there is simply nothing to clear.
func (cm *CacheManager) Clear() error {
	if _, err := os.Stat(cm.cacheDir); os.IsNotExist(err) {
		return nil
	}

	// Remove entire directory
	if err := os.RemoveAll(cm.cacheDir); err != nil {
		return fmt.Errorf("failed to remove cache directory: %w", err)
	}

	// Recreate empty directory
	if err := os.MkdirAll(cm.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to recreate cache directory: %w", err)
	}

	return nil
}

// Prune removes cache files older than specified days and sweeps the empty
// directories left behind. A negative retention is rejected: it would put
// the cutoff in the future and wipe everything.
func (cm *CacheManager) Prune(days int) (int, error) {
	if days < 0 {
		return 0, fmt.Errorf("prune retention must be non-negative, got %d", days)
	}
	if _, err := os.Stat(cm.cacheDir); os.IsNotExist(err) {
		return 0, nil // Cache doesn't exist, nothing to prune
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	removedCount := 0
	var dirs []string

	err := filepath.Walk(cm.cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if path != cm.cacheDir {
				dirs = append(dirs, path)
			}
			return nil
		}

		if info.ModTime().Before(cutoff) {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("failed to remove %s: %w", path, err)
			}
			removedCount++
		}

		return nil
	})

	if err != nil {
		return removedCount, fmt.Errorf("failed to prune cache: %w", err)
	}

	// Deepest first so parents are empty when their turn comes.
	for i := len(dirs) - 1; i >= 0; i-- {
		_ = os.Remove(dirs[i]) // succeeds only when empty; survivors are fine
	}

	return removedCount, nil
}

// PrintStats prints cache statistics in human-readable format
func (s *FSCacheStats) Print() {
	fmt.Println("Cache Statistics")
	fmt.Println("================")
	fmt.Printf("Path:          %s\n", s.Path)
	fmt.Printf("Total size:    %s\n", formatBytes(s.TotalSize))
	fmt.Printf("File count:    %d\n", s.FileCount)
	fmt.Printf("Last accessed: %s\n", s.LastAccessed.Format(time.RFC3339))
	fmt.Printf("Cache age:     %s\n", s.CacheAge)

	if s.OldestFile != "" {
		fmt.Printf("Oldest file:   %s\n", s.OldestFile)
	}

	if s.NewestFile != "" {
		fmt.Printf("Newest file:   %s\n", s.NewestFile)
	}
}

// PrintJSON prints cache statistics in JSON format
func (s *FSCacheStats) PrintJSON() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// formatBytes formats bytes in human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
