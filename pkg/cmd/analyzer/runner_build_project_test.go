package main

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/decompiler"
	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/apkloader/axml"
)

func TestBuildProjectZIPWithoutExternalTools(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	t.Setenv("JAVA_HOME", filepath.Join(dir, "no-java"))
	t.Setenv("ANDROID_HOME", filepath.Join(dir, "no-android"))
	t.Setenv("ANDROID_SDK_ROOT", filepath.Join(dir, "no-sdk"))
	t.Setenv("MEGA_TOOLS_DIR", filepath.Join(dir, "no-tools"))
	t.Setenv("MEGA_STANDALONE", "")
	previous := apkloader.Standalone()
	input := filepath.Join(dir, "project.zip")
	f, err := os.Create(input)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, data := range map[string]string{
		"project/AndroidManifest.xml":           `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.nativebuild"><uses-sdk android:minSdkVersion="23"/><application android:label="@string/app_name"/></manifest>`,
		"project/res/values/strings.xml":        `<resources><string name="app_name">Native build</string></resources>`,
		"project/smali/com/example/Value.smali": ".class public Lcom/example/Value;\n.super Ljava/lang/Object;\n.method public static value()I\n.registers 1\nconst/4 v0, 7\nreturn v0\n.end method\n",
	} {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	inputBefore, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "app.apk")
	opts, err := NewCLIParser().Parse([]string{"-build", "-t", input, "-o", output})
	if err != nil {
		t.Fatal(err)
	}
	if err := opts.Validate(); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	app := &App{opts: opts, output: NewOutputWithWriter(NoColorTheme(), false, &log)}
	if err := app.handleRebuild(); err != nil {
		t.Fatalf("build: %v\n%s", err, &log)
	}
	if apkloader.Standalone() != previous {
		t.Fatal("CLI build leaked standalone policy")
	}
	if _, err := os.Stat(filepath.Join(dir, "no-tools")); !os.IsNotExist(err) {
		t.Fatalf("build unpacked compatibility tools: %v", err)
	}
	if !strings.Contains(log.String(), "Build engine: native") {
		t.Fatal(log.String())
	}
	if _, err := apkloader.VerifyV1SignatureOffline(output); err != nil {
		t.Fatal(err)
	}
	verified, err := apkloader.VerifyV2V3Offline(output)
	if err != nil || !verified.V2 || !verified.V3 {
		t.Fatalf("signature: %+v %v", verified, err)
	}
	if err := apkloader.VerifyAlignment(output); err != nil {
		t.Fatal(err)
	}
	archive, err := zip.OpenReader(output)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	binaryManifest, compiledResources := false, false
	for _, entry := range archive.File {
		if strings.HasPrefix(entry.Name, "res/values/") {
			t.Fatalf("uncompiled values XML in APK: %s", entry.Name)
		}
		if entry.Name == "resources.arsc" {
			compiledResources = true
		}
		if entry.Name == "AndroidManifest.xml" {
			r, err := entry.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
			binaryManifest = axml.IsBinaryXML(data)
		}
	}
	if !binaryManifest || !compiledResources {
		t.Fatalf("APK resources were not compiled: manifest=%v ARSC=%v", binaryManifest, compiledResources)
	}
	result, err := decompiler.Decode(context.Background(), output, decompiler.Options{OutputDir: filepath.Join(dir, "decoded"), Standalone: true})
	if err != nil || !result.Complete {
		t.Fatalf("decode built APK: %+v %v", result, err)
	}
	smali, err := os.ReadFile(filepath.Join(result.OutputDir, "smali/com/example/Value.smali"))
	if err != nil || !strings.Contains(string(smali), "const/4 v0, 7") {
		t.Fatalf("DEX lost code: %s %v", smali, err)
	}
	inputAfter, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(inputBefore, inputAfter) {
		t.Fatal("build modified the source ZIP")
	}
}

func TestBuildExternalToolsRequireOptIn(t *testing.T) {
	opts, err := NewCLIParser().Parse([]string{"-build", "-t", "project.zip", "-o", "app.apk", "-standalone", "-allow-external-tools"})
	if err != nil {
		t.Fatal(err)
	}
	if err := opts.Validate(); err == nil {
		t.Fatal("conflicting tool policies accepted")
	}
}
