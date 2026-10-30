// pkg/internal/pipeline/vuln_detectors_extra_test.go
package pipeline

import "testing"

import "mega-analyzer/pkg/internal/types"

// ============================================================================
// Zip-Slip Detector Tests
// ============================================================================

func TestVulnZipSlipDetector(t *testing.T) {
	d := NewVulnZipSlipDetector()

	tests := []detectorTestCase{
		{
			name: "vulnerable: ZipInputStream + getName + FileOutputStream, no sanitization",
			path: "smali/com/app/Unzipper.smali",
			content: `
.class public Lcom/app/Unzipper;
.method public extract(Ljava/util/zip/ZipInputStream;)V
    invoke-virtual {v0}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;
    move-result-object v1
    new-instance v2, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V
.end method
`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryZipSlip,
			wantMatch:    true,
		},
		{
			name: "vulnerable: canonicalization without containment check",
			path: "smali/com/app/SafeUnzipper.smali",
			content: `
.class public Lcom/app/SafeUnzipper;
.method public extract(Ljava/util/zip/ZipInputStream;)V
    invoke-virtual {v0}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;
    move-result-object v1
    invoke-virtual {v2}, Ljava/io/File;->getCanonicalPath()Ljava/lang/String;
    new-instance v2, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V
.end method
`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryZipSlip,
			wantMatch:    true,
		},
		{
			name: "no match: only ZipInputStream mention, no getName/write combo",
			path: "smali/com/app/PlainReader.smali",
			content: `
.class public Lcom/app/PlainReader;
new-instance v0, Ljava/util/zip/ZipInputStream;
`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryZipSlip,
			wantMatch:    false,
		},
		{
			name: "method isolation: unrelated method has dotdot string, unzipping method has no guard",
			path: "smali/com/app/IsolatedUnzipper.smali",
			content: `
.class public Lcom/app/IsolatedUnzipper;
.method public logParent()V
    const-string v0, "parent dir .."
    return-void
.end method

.method public extract(Ljava/util/zip/ZipInputStream;)V
    invoke-virtual {v0}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;
    move-result-object v1
    new-instance v2, Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V
.end method
`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryZipSlip,
			wantMatch:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runDetectorTest(t, d.Detect, tc)
		})
	}
}

// ============================================================================
// Dlopen Obfuscation Detector Tests
// ============================================================================

func TestVulnDlopenObfuscationDetector(t *testing.T) {
	d := NewVulnDlopenObfuscationDetector()

	tests := []detectorTestCase{
		{
			name: "vulnerable: library name built via 2+ StringBuilder appends then loadLibrary",
			path: "smali/com/app/Loader.smali",
			content: `
.class public Lcom/app/Loader;
.method static constructor <clinit>()V
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
    const-string v1, "na"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    const-string v1, "tive"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    invoke-static {v1}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
.end method
`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryDlopenObfuscation,
			wantMatch:    true,
		},
		{
			name: "safe: plain literal loadLibrary, no StringBuilder",
			path: "smali/com/app/PlainLoader.smali",
			content: `
.class public Lcom/app/PlainLoader;
.method static constructor <clinit>()V
    const-string v0, "native"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
.end method
`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryDlopenObfuscation,
			wantMatch:    false,
		},
		{
			name: "safe: single append (fixed prefix + suffix), not obfuscation",
			path: "smali/com/app/OneAppend.smali",
			content: `
.class public Lcom/app/OneAppend;
.method public build(Ljava/lang/String;)V
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
    const-string v1, "lib"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    invoke-static {v1}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
.end method
`,
			fileType:     types.FileTypeSmali,
			wantCategory: types.CategoryDlopenObfuscation,
			wantMatch:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runDetectorTest(t, d.Detect, tc)
		})
	}
}
