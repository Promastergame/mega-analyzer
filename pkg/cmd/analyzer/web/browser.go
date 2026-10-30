// Moved out of the monolithic web_ui.go. See doc.go for the package map.

package web

import (
	"os"
	"os/exec"
	"runtime"
)

func shouldOpenWebUIBrowser() bool {
	return os.Getenv("MEGA_ANALYZER_NO_BROWSER") == ""
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		// Termux has no xdg-open; termux-open-url hands the URL to Android.
		if p, err := exec.LookPath("termux-open-url"); err == nil {
			cmd = exec.Command(p, url)
		} else {
			cmd = exec.Command("xdg-open", url)
		}
	}
	_ = cmd.Start()
}
