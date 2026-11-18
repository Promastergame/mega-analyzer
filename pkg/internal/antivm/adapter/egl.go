package adapter

import (
	"context"
	"fmt"
	"strconv"
)

// Legacy Android EGL loaders use ro.kernel.qemu to select one matching driver
// family. Without it, wildcard discovery can mix emulation and SwiftShader
// libraries. Give the same emulation libraries generic names in a disposable
// bind mount, leaving the system image and library contents intact.
func (a *ADBAdapter) preserveEGLDrivers(ctx context.Context, cfg TestConfig, res *ApplyResult) error {
	if a.ResetpropPath == "" {
		return nil
	}
	changesQEMU := false
	for _, p := range cfg.Props {
		if p.Key == "ro.kernel.qemu" && p.Value == "0" {
			changesQEMU = true
			break
		}
	}
	if !changesQEMU {
		return nil
	}
	qemu, err := a.shell(ctx, "getprop ro.kernel.qemu")
	if err != nil {
		return err
	}
	if qemu != "1" {
		return nil
	}
	apiText, err := a.shell(ctx, "getprop ro.build.version.sdk")
	if err != nil {
		return err
	}
	api, err := strconv.Atoi(apiText)
	if err != nil {
		return fmt.Errorf("read API before preserving EGL drivers: %w", err)
	}
	if api < 24 || api > 28 {
		return nil
	}
	gles, err := a.shell(ctx, "getprop ro.kernel.qemu.gles")
	if err != nil {
		return err
	}
	if gles != "1" {
		return nil
	}
	for _, source := range []string{"/vendor/lib64/egl", "/vendor/lib/egl", "/system/lib64/egl", "/system/lib/egl"} {
		// The source is one of the fixed paths above; it is never profile input.
		destination := "/data/local/tmp/mega-antivm/egl" + source
		command := "set -e; src=" + quoteShell(source) + "; dst=" + quoteShell(destination) + `
if [ -f "$src/libEGL_emulation.so" ] && [ -f "$src/libGLESv1_CM_emulation.so" ] && [ -f "$src/libGLESv2_emulation.so" ]; then
    if [ ! -e "$src/libEGL.so" ] || [ ! -e "$src/libGLESv1_CM.so" ] || [ ! -e "$src/libGLESv2.so" ]; then
        mkdir -p "$dst"
        cp -a --preserve=context "$src/." "$dst/"
        context=$(ls -Zd "$src"); context=${context%% *}
        chcon "$context" "$dst"
        chmod 755 "$dst"
        ln -f "$dst/libEGL_emulation.so" "$dst/libEGL.so"
        ln -f "$dst/libGLESv1_CM_emulation.so" "$dst/libGLESv1_CM.so"
        ln -f "$dst/libGLESv2_emulation.so" "$dst/libGLESv2.so"
        mount -o bind "$dst" "$src"
        echo mounted
    fi
fi`
		out, err := a.shell(ctx, command)
		if err != nil {
			return fmt.Errorf("preserve EGL drivers at %s: %w", source, err)
		}
		if out == "mounted" {
			res.Succeeded = append(res.Succeeded, "preserve coherent EGL driver family at "+source+" (temporary bind mount)")
		}
	}
	return nil
}
