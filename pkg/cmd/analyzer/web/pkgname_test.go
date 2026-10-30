package web

import "testing"

func TestValidAndroidPackage(t *testing.T) {
	good := []string{"com.example", "com.example.app_2", "a", "org.mozilla.firefox"}
	bad := []string{"", "com.x;reboot", "com.x && rm -rf /sdcard", "$(id)", "com..x", ".com", "1com.x", "com.x\nid", "com x", "com.x`id`"}
	for _, p := range good {
		if !validAndroidPackage(p) {
			t.Errorf("rejected valid package %q", p)
		}
	}
	for _, p := range bad {
		if validAndroidPackage(p) {
			t.Errorf("accepted unsafe package %q", p)
		}
	}
}
