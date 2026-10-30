package ml

import "testing"

func TestMLHardeningLibraryReferences(t *testing.T) {
	tests := []struct {
		ref  string
		lib  bool
		name string
	}{
		{"smali_classes12/com/google/gson/Gson.smali", true, "Gson"},
		{"smali_classes123/com/google/gson/Gson.smali", true, "Gson"},
		{`smali_classes42\com\google\gson\Gson.smali`, true, "Gson"},
		{`F:\decoded\smali_classes42\com\google\gson\Gson.smali`, true, "Gson"},
		{"/tmp/decoded/smali_classes42/com/google/gson/Gson.smali", true, "Gson"},
		{"./smali_classes12/com/google/gson/Gson.smali", true, "Gson"},
		{"  smali_classes12/com/google/gson/Gson.smali  ", true, "Gson"},
		{"Lcom/google/gson/Gson;", true, "Gson"},
		{"com/google/gson/Gson.smali", true, "Gson"},
		{"smali_classes42/org/apache/commons/Helper.smali", true, "apache"},
		{"smali_classes42/com/example/app/Main.smali", false, ""},
		{"smali_classes12x/com/google/gson/Gson.smali", false, ""},
		{"smali_classes01/com/google/gson/Gson.smali", false, ""},
		{"smali/com/example/com/google/gson/Helper.smali", false, ""},
		{"smali/xcom/google/gson/Helper.smali", false, ""},
		{"com/example/smali/com/google/gson/Helper.smali", false, ""},
		{"Lcom/example/smali/com/google/gson/Helper;", false, ""},
		{"/tmp/com/google/gson/decoded/smali/com/example/Helper.smali", false, ""},
		{"Lcom/example/app/Main;", false, ""},
		{"", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			if got := IsKnownLibrary(tt.ref); got != tt.lib {
				t.Errorf("IsKnownLibrary(%q) = %v, want %v", tt.ref, got, tt.lib)
			}
			if got := LibraryName(tt.ref); got != tt.name {
				t.Errorf("LibraryName(%q) = %q, want %q", tt.ref, got, tt.name)
			}
		})
	}
}

func TestMLHardeningSmaliSourceRoot(t *testing.T) {
	for _, root := range []string{"smali", "smali_classes2", "smali_classes11", "smali_classes12", "smali_classes999999999999999999999"} {
		if !isSmaliSourceRoot(root) {
			t.Errorf("valid root rejected: %q", root)
		}
	}
	for _, root := range []string{"", "smali_classes", "smali_classes0", "smali_classes1", "smali_classes02", "smali_classes2backup", "smali_classes-2", "smali_classes2/extra"} {
		if isSmaliSourceRoot(root) {
			t.Errorf("invalid root accepted: %q", root)
		}
	}
}
