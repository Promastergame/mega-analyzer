package web

import "regexp"

// androidPkgRe matches a Java-style Android application id (com.example.app).
// Anything else must never reach `adb shell`: adb joins shell arguments into
// one command line on the device, so "x;reboot" would run as a command.
var androidPkgRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*$`)

func validAndroidPackage(p string) bool {
	return len(p) <= 255 && androidPkgRe.MatchString(p)
}
