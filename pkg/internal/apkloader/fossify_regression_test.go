package apkloader

import "testing"

func TestBrotliVocabularyIsNotInstrumentation(t *testing.T) {
	report := &NativeScanReport{}
	scanNativeStrings(report, []string{"pragmafridayjuniordollar", "clearlyexposedBrowser"})
	if len(report.Findings) != 0 {
		t.Fatalf("dictionary vocabulary produced findings: %+v", report.Findings)
	}
	scanNativeStrings(report, []string{"checking for frida-agent", "de.robv.android.xposed.XposedBridge"})
	if len(report.Findings) != 2 {
		t.Fatalf("real instrumentation references were lost: %+v", report.Findings)
	}
}
