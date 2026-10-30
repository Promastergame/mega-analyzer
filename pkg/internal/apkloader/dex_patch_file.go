package apkloader

import (
	"bytes"
	"fmt"
	"os"
)

// WritePatchedDEX publishes a validated image atomically and preserves the
// first backup across multiple method edits. The source must still match the
// image used to compute the patch.
func WritePatchedDEX(path string, original, patched []byte) error {
	if err := verifyDEXIntegrity(patched); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("DEX target is not a regular file: %s", path)
	}
	checkSource := func() error {
		current, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(current, original) {
			return fmt.Errorf("DEX changed before publication: %s", path)
		}
		return nil
	}
	if err := checkSource(); err != nil {
		return err
	}
	backup := path + ".backup"
	if backupInfo, err := os.Lstat(backup); os.IsNotExist(err) {
		file, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
		if err != nil {
			return fmt.Errorf("create DEX backup: %w", err)
		}
		if _, err = file.Write(original); err == nil {
			err = file.Sync()
		}
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(backup)
			return fmt.Errorf("write DEX backup: %w", err)
		}
	} else if err != nil {
		return err
	} else if !backupInfo.Mode().IsRegular() {
		return fmt.Errorf("DEX backup is not a regular file: %s", backup)
	}
	if err := checkSource(); err != nil {
		return err
	}
	return atomicWriteFile(path, patched, info.Mode().Perm())
}
