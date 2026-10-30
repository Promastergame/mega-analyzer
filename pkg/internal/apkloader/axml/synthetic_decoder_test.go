package axml

import (
	"testing"
)

func TestNamespaceStackEdgeCases(t *testing.T) {
	s := newNamespaceStack()

	// 1. activeURIs on empty stack
	if uris := s.activeURIs(); uris != nil {
		t.Errorf("Expected nil for activeURIs on empty stack, got %v", uris)
	}

	// 2. popNamespace underflow
	s.popNamespace() // should not crash

	// 3. leaveElement on depth 0
	s.leaveElement() // should not crash

	// 4. prefixForURI on empty stack
	if prefix := s.prefixForURI(123); prefix != 0xFFFFFFFF {
		t.Errorf("Expected 0xFFFFFFFF for prefixForURI on empty stack, got 0x%x", prefix)
	}

	// 5. Normal workflow with duplicate URIs and reset
	s.pushNamespace(1, 10) // prefix 1, uri 10
	s.pushNamespace(2, 10) // duplicate uri 10
	s.enterElement()
	s.pushNamespace(3, 20) // prefix 3, uri 20

	if prefix := s.prefixForURI(10); prefix != 2 {
		t.Errorf("Expected prefix 2 for uri 10, got %d", prefix)
	}

	uris := s.activeURIs()
	if len(uris) != 2 {
		t.Errorf("Expected 2 active URIs, got %d", len(uris))
	}

	s.leaveElement()
	s.reset()
	if len(s.data) != 0 || s.depth != 0 {
		t.Error("Expected stack to be cleared after reset")
	}
}

func TestEscapeXMLEdgeCases(t *testing.T) {
	// 1. No escape needed
	if got := escapeXML("hello"); got != "hello" {
		t.Errorf("escapeXML('hello') = %q, want 'hello'", got)
	}

	// 2. All escapes needed
	input := `& < > " '`
	want := "&amp; &lt; &gt; &quot; &apos;"
	if got := escapeXML(input); got != want {
		t.Errorf("escapeXML(%q) = %q, want %q", input, got, want)
	}
}

func TestDecoderLookupPrefixAndAttrName(t *testing.T) {
	d := &Decoder{
		nsStack: newNamespaceStack(),
	}

	// 1. lookupPrefix with nil pool or empty uri
	if p := d.lookupPrefix(""); p != "" {
		t.Errorf("Expected empty prefix, got %q", p)
	}

	// 2. attrName index out of bounds
	d.pool = &stringPool{entries: []string{}}
	if name := d.attrName(999); name != SentinelNoString {
		t.Errorf("Expected SentinelNoString, got %q", name)
	}
}

func TestDecoderFormatAttrValue(t *testing.T) {
	d := &Decoder{
		pool: &stringPool{entries: []string{"test-string"}},
	}

	cases := []struct {
		typ     uint8
		data    uint32
		strIdx  uint32
		wantVal string
	}{
		{typeNull, 0, 0, ""},
		{typeReference, 0x7f010002, 0, "@0x7f010002"},
		{typeDynamicRef, 0x7f010002, 0, "@0x7f010002"},
		{typeAttribute, 0x01010003, 0, "?0x01010003"},
		{typeDynamicAttr, 0x01010003, 0, "?0x01010003"},
		{typeString, 0, 0, "test-string"},
		{typeString, 0, 99, ""}, // out of bounds strIdx
		{typeFloat, 0x3f800000, 0, "1"},
		{typeIntDec, 123, 0, "123"},
		{typeIntHex, 0xabc, 0, "0x00000abc"},
		{typeIntBoolean, 0, 0, "false"},
		{typeIntBoolean, 1, 0, "true"},
		{typeIntColorARGB8, 0xff00ff00, 0, "#ff00ff00"},
		{99, 100, 0, "0x64"}, // default
	}

	for _, tc := range cases {
		got := d.formatAttrValue(tc.typ, tc.data, tc.strIdx)
		if got != tc.wantVal {
			t.Errorf("formatAttrValue(%d, 0x%x, %d) = %q, want %q", tc.typ, tc.data, tc.strIdx, got, tc.wantVal)
		}
	}
}

func TestApplyAttrsToManifestAndFinalize(t *testing.T) {
	d := &Decoder{}
	m := &Manifest{
		MetaData: make(map[string]string),
	}

	var curComp *Component
	var curList *[]Component
	var inFilter bool
	var curFilt *IntentFilter

	// 1. Manifest element attributes
	d.applyAttrsToManifest("manifest", []parsedAttr{
		{Name: "package", Value: "com.test.app"},
		{Name: "versionCode", Value: "42"},
		{Name: "versionName", Value: "1.2.3"},
		{Name: "sharedUserId", Value: "android.uid.system"},
		{Name: "compileSdkVersion", Value: "33"},
	}, m, &curComp, &curList, &inFilter, &curFilt)

	if m.Package != "com.test.app" || m.VersionCode != 42 || m.VersionName != "1.2.3" || m.SharedUserID != "android.uid.system" || m.CompileSDK != 33 {
		t.Errorf("Manifest attributes parsed incorrectly: %+v", m)
	}

	// 2. Uses-sdk element attributes
	d.applyAttrsToManifest("uses-sdk", []parsedAttr{
		{Name: "minSdkVersion", Value: "21"},
		{Name: "targetSdkVersion", Value: "33"},
	}, m, &curComp, &curList, &inFilter, &curFilt)

	if m.MinSDK != 21 || m.TargetSDK != 33 {
		t.Errorf("uses-sdk parsed incorrectly: %+v", m)
	}

	// 3. uses-permission & uses-permission-sdk-23
	d.applyAttrsToManifest("uses-permission", []parsedAttr{{Name: "name", Value: "perm.A"}}, m, &curComp, &curList, &inFilter, &curFilt)
	d.applyAttrsToManifest("uses-permission-sdk-23", []parsedAttr{{Name: "name", Value: "perm.B"}}, m, &curComp, &curList, &inFilter, &curFilt)

	if len(m.Permissions) != 1 || m.Permissions[0] != "perm.A" || len(m.OptionalPerms) != 1 || m.OptionalPerms[0] != "perm.B" {
		t.Errorf("Permissions parsed incorrectly: %v, %v", m.Permissions, m.OptionalPerms)
	}

	// 4. uses-feature (required=false vs default true)
	d.applyAttrsToManifest("uses-feature", []parsedAttr{{Name: "name", Value: "feat.A"}, {Name: "required", Value: "false"}}, m, &curComp, &curList, &inFilter, &curFilt)
	d.applyAttrsToManifest("uses-feature", []parsedAttr{{Name: "name", Value: "feat.B"}}, m, &curComp, &curList, &inFilter, &curFilt)

	if len(m.UsesFeatures) != 2 || m.UsesFeatures[0].Name != "feat.A" || m.UsesFeatures[0].Required != false || m.UsesFeatures[1].Name != "feat.B" || m.UsesFeatures[1].Required != true {
		t.Errorf("uses-feature parsed incorrectly: %+v", m.UsesFeatures)
	}

	// 5. application attributes
	d.applyAttrsToManifest("application", []parsedAttr{
		{Name: "name", Value: "MyApplication"},
		{Name: "label", Value: "AppName"},
		{Name: "icon", Value: "icon.png"},
		{Name: "theme", Value: "Theme.Dark"},
		{Name: "debuggable", Value: "true"},
		{Name: "allowBackup", Value: "true"},
		{Name: "usesCleartextTraffic", Value: "true"},
		{Name: "networkSecurityConfig", Value: "xml/net_cfg"},
		{Name: "process", Value: "remote"},
		{Name: "extractNativeLibs", Value: "true"},
		{Name: "hasCode", Value: "true"},
	}, m, &curComp, &curList, &inFilter, &curFilt)

	app := m.Application
	if app.Name != "MyApplication" || app.Label != "AppName" || app.Icon != "icon.png" || app.Theme != "Theme.Dark" ||
		!app.Debuggable || !app.AllowBackup || !app.UsesCleartext || app.NetworkSecCfg != "xml/net_cfg" ||
		app.Process != "remote" || !app.ExtractNativeLibs || !app.HasCode {
		t.Errorf("Application parsed incorrectly: %+v", app)
	}
	if app.AllowBackupDeclared == nil || !*app.AllowBackupDeclared || app.CleartextDeclared == nil || !*app.CleartextDeclared {
		t.Errorf("application boolean presence was not preserved: %+v", app)
	}

	// 6. activity & intent-filter & action & category & data & metadata
	d.applyAttrsToManifest("activity", []parsedAttr{
		{Name: "name", Value: "MainActivity"},
		{Name: "permission", Value: "perm.LAUNCH"},
		{Name: "process", Value: "main"},
		{Name: "exported", Value: "true"},
		{Name: "enabled", Value: "true"},
	}, m, &curComp, &curList, &inFilter, &curFilt)

	d.applyAttrsToManifest("intent-filter", nil, m, &curComp, &curList, &inFilter, &curFilt)
	d.applyAttrsToManifest("action", []parsedAttr{{Name: "name", Value: "action.MAIN"}}, m, &curComp, &curList, &inFilter, &curFilt)
	d.applyAttrsToManifest("category", []parsedAttr{{Name: "name", Value: "category.LAUNCHER"}}, m, &curComp, &curList, &inFilter, &curFilt)
	d.applyAttrsToManifest("data", []parsedAttr{{Name: "scheme", Value: "https"}, {Name: "host", Value: "example.com"}}, m, &curComp, &curList, &inFilter, &curFilt)
	d.finalizeElement("intent-filter", m, &curComp, &curList, &inFilter, &curFilt)

	d.applyAttrsToManifest("meta-data", []parsedAttr{{Name: "name", Value: "api_key"}, {Name: "value", Value: "secret_value"}}, m, &curComp, &curList, &inFilter, &curFilt)
	d.applyAttrsToManifest("meta-data", []parsedAttr{{Name: "name", Value: "api_res"}, {Name: "resource", Value: "@xml/res"}}, m, &curComp, &curList, &inFilter, &curFilt)

	d.finalizeElement("activity", m, &curComp, &curList, &inFilter, &curFilt)

	if len(m.Activities) != 1 {
		t.Fatal("Expected 1 activity parsed")
	}
	act := m.Activities[0]
	if act.Name != "MainActivity" || act.Permission != "perm.LAUNCH" || act.Process != "main" || act.Exported == nil || !*act.Exported || act.Enabled == nil || !*act.Enabled {
		t.Errorf("Activity component parsed incorrectly: %+v", act)
	}
	if len(act.IntentFilts) != 1 || len(act.IntentFilts[0].Actions) != 1 || act.IntentFilts[0].Actions[0] != "action.MAIN" || act.IntentFilts[0].Categories[0] != "category.LAUNCHER" || act.IntentFilts[0].DataScheme[0] != "https" || act.IntentFilts[0].DataHost[0] != "example.com" {
		t.Errorf("Intent filter parsed incorrectly: %+v", act.IntentFilts)
	}
	if m.MetaData["api_key"] != "secret_value" || m.MetaData["api_res"] != "@xml/res" {
		t.Errorf("Metadata parsed incorrectly: %v", m.MetaData)
	}

	// 7. Test provider with authorities
	d.applyAttrsToManifest("provider", []parsedAttr{
		{Name: "name", Value: "MyProvider"},
		{Name: "authorities", Value: "com.test.provider"},
	}, m, &curComp, &curList, &inFilter, &curFilt)
	d.finalizeElement("provider", m, &curComp, &curList, &inFilter, &curFilt)

	if len(m.Providers) != 1 || m.Providers[0].Name != "MyProvider" || m.Providers[0].Authorities != "com.test.provider" {
		t.Errorf("Provider parsed incorrectly: %+v", m.Providers)
	}
}
