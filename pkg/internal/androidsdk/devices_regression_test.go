package androidsdk

import (
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestDynamicADBDiscovery(t *testing.T) {
	d := ParseADBDevices("* daemon started successfully *\nWARNING: device monitoring unavailable\nList of devices attached\nphone-B unauthorized\nphone-A device product:a model:Pixel_8 transport_id:1\nphone-A device model:Pixel_8\nemulator-5554 offline\n")
	if len(d) != 3 {
		t.Fatalf("devices: %+v", d)
	}
	s, e := SelectDevice(d, "phone-A")
	if e != nil || s != "phone-A" {
		t.Fatal(s, e)
	}
	for _, id := range []string{"phone-B", "missing"} {
		if _, e := SelectDevice(d, id); e == nil {
			t.Fatal("fallback from", id)
		}
	}
	d = append(d, Device{Serial: "phone-C", State: "device"})
	if _, e := SelectDevice(d, ""); e == nil {
		t.Fatal("ambiguous device accepted")
	}
}
func TestDynamicADBSerialValidation(t *testing.T) {
	for _, s := range []string{"phone-A", "emulator-5554", "192.0.2.1:5555"} {
		if !ValidDeviceSerial(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"WARNING:", "-d", "a b", "a;echo"} {
		if ValidDeviceSerial(s) {
			t.Fatal(s)
		}
	}
}
func TestDynamicAVDNames(t *testing.T) {
	got := ParseAVDNames("INFO\nINFO | diagnostic\nPixel_API_35\nPixel_API_35\nWARNING: unavailable\nlab-two\n")
	if !reflect.DeepEqual(got, []string{"Pixel_API_35", "lab-two"}) {
		t.Fatal(got)
	}
}
func TestDynamicEmptySDKDoesNotHideRealTools(t *testing.T) {
	if DetectFromRoot("", "test").Detected {
		t.Fatal("empty root is SDK")
	}
	empty := t.TempDir()
	if DetectFromRoot(empty, "test").Detected {
		t.Fatal("empty directory is SDK")
	}
	real := t.TempDir()
	mustMkdirAll(t, filepath.Join(real, "platform-tools"))
	mustWriteFile(t, filepath.Join(real, "platform-tools", func() string {
		if runtime.GOOS == "windows" {
			return "adb.exe"
		}
		return "adb"
	}()))
	t.Setenv("ANDROID_SDK_ROOT", empty)
	t.Setenv("ANDROID_HOME", real)
	if !Detect().Detected {
		t.Fatal("invalid first root hid real tools")
	}
}
