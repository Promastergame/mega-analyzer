//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func processIsElevated() (bool, error) { return os.Geteuid() == 0, nil }
func runningOnAndroid() bool {
	if runtime.GOOS == "android" || os.Getenv("TERMUX_VERSION") != "" {
		return true
	}
	_, err := os.Stat("/system/build.prop")
	return runtime.GOOS == "linux" && err == nil
}
func findElevationTool(name string, preferred []string) (string, error) {
	for _, p := range preferred {
		if st, e := os.Stat(p); e == nil && !st.IsDir() && st.Mode()&0111 != 0 {
			return p, nil
		}
	}
	return exec.LookPath(name)
}
func restartElevated(exe string, args []string, cwd string) error {
	var cmd *exec.Cmd
	if runningOnAndroid() {
		su, e := findElevationTool("su", []string{"/system/bin/su", "/system/xbin/su", "/sbin/su"})
		if e != nil {
			return fmt.Errorf("Android -admin needs an already rooted device and a su root manager; no rooting/bypass is attempted: %w", e)
		}
		command, e := androidAdminCommand(exe, args)
		if e != nil {
			return e
		}
		cmd = exec.Command(su, "-c", command)
	} else if runtime.GOOS == "linux" {
		sudo, e := findElevationTool("sudo", []string{"/usr/bin/sudo", "/bin/sudo"})
		if e != nil {
			return fmt.Errorf("Linux -admin needs sudo or an already-root shell: %w", e)
		}
		// Authentication and environment filtering belong to sudo. No -S/-E/passwords.
		argv := append([]string{"--user=root", "--", exe}, args...)
		cmd = exec.Command(sudo, argv...)
	} else {
		return fmt.Errorf("automatic -admin supports Windows, Linux and rooted Android, not %s", runtime.GOOS)
	}
	cmd.Dir = cwd
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("administrator/root web launch was denied, unavailable, or exited with an error: %w", err)
	}
	return nil
}
