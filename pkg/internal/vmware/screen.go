package vmware

import (
	"bytes"
	"context"
	"errors"
	"image/png"
	"os"
	"path/filepath"
	"time"
)

// CaptureScreen reads the VM console through VMware Tools. It does not boot,
// unlock or modify the guest, and must run alongside RunSession (not under mu).
func (c *Controller) CaptureScreen(ctx context.Context, vmx, username, password, outputDir string) ([]byte, error) {
	if err := ValidateCredentials(username, password); err != nil {
		return nil, err
	}
	path, _, err := validateVMX(vmx)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(outputDir, ".vmware-screen-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	framePath := filepath.Join(dir, "screen.png")
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := c.command(ctx, "-gu", username, "-gp", password, "captureScreen", path, framePath); err != nil {
		return nil, err
	}
	data, err := readBounded(framePath, 16<<20)
	if err != nil {
		return nil, err
	}
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil || config.Width <= 0 || config.Height <= 0 || config.Width > 8192 || config.Height > 8192 || int64(config.Width)*int64(config.Height) > 34_000_000 {
		return nil, errors.New("VMware вернула недопустимый кадр экрана")
	}
	return data, nil
}
