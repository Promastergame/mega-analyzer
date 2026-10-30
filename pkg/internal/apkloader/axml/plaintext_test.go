package axml

import "testing"

func TestDecodePlainXMLPreservesManifestSemantics(t *testing.T) {
	manifest, err := DecodePlainXML([]byte(`<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
  package="com.example.plain" android:versionCode="7">
  <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <application android:allowBackup="false" android:usesCleartextTraffic="false"
    android:dataExtractionRules="@xml/data_extraction_rules">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <data android:scheme="https" android:host="example.com"/>
      </intent-filter>
    </activity>
  </application>
</manifest>`))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Package != "com.example.plain" || manifest.TargetSDK != 34 || len(manifest.Permissions) != 1 {
		t.Fatalf("manifest fields not decoded: %+v", manifest)
	}
	if manifest.Application.AllowBackupDeclared == nil || *manifest.Application.AllowBackupDeclared {
		t.Fatalf("explicit allowBackup=false was not preserved: %+v", manifest.Application)
	}
	if manifest.Application.DataExtractionRules != "@xml/data_extraction_rules" {
		t.Fatalf("data extraction rules missing: %+v", manifest.Application)
	}
	if len(manifest.Activities) != 1 || manifest.Activities[0].Exported == nil || !*manifest.Activities[0].Exported {
		t.Fatalf("activity not decoded: %+v", manifest.Activities)
	}
	filter := manifest.Activities[0].IntentFilts[0]
	if len(filter.DataHost) != 1 || filter.DataHost[0] != "example.com" {
		t.Fatalf("intent filter not decoded: %+v", filter)
	}
}

func TestDecodePlainXMLRejectsNonManifest(t *testing.T) {
	if _, err := DecodePlainXML([]byte(`<resources/>`)); err == nil {
		t.Fatal("expected non-manifest XML rejection")
	}
}
