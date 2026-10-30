package apkloader

import "testing"

func TestConfigFromValuesFolder(t *testing.T) {
	cases := map[string]string{
		"values":        "default",
		"values-ru":     "ru",
		"values-en-rUS": "en-rUS",
		"values-night":  "night",
		"drawable":      "default", // not a values folder → default fallback
	}
	for in, want := range cases {
		if got := configFromValuesFolder(in); got != want {
			t.Errorf("configFromValuesFolder(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseStringsXml(t *testing.T) {
	xml := []byte(`<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">My &amp; App</string>
    <string name="greeting">Line1\nLine2</string>
    <string name="apos">It\'s here</string>
    <string name="quoted">"  spaced  "</string>
    <string name="empty"/>
    <string name="ph">%1$s items</string>
    <string-array name="colors">
        <item>red</item>
    </string-array>
    <string name="hex">&#x41;&#66;</string>
</resources>`)

	got := parseStringsXml(xml)

	want := map[string]string{
		"app_name": "My & App",
		"greeting": "Line1\nLine2",
		"apos":     "It's here",
		"quoted":   "  spaced  ",
		"ph":       "%1$s items",
		"hex":      "AB",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("parseStringsXml[%q] = %q, want %q", k, got[k], v)
		}
	}
	// Self-closing <string name="empty"/> yields "" (skipped by empty check upstream).
	if v, ok := got["empty"]; ok && v != "" {
		t.Errorf("empty string = %q, want empty", v)
	}
	// <string-array> must not leak in as a string key.
	if _, ok := got["colors"]; ok {
		t.Errorf("string-array 'colors' should not be parsed as a <string>")
	}
}

func TestUnescapeAndroidResString(t *testing.T) {
	cases := map[string]string{
		`plain`:           "plain",
		`a &amp;&lt;&gt;`: "a &<>",
		`&quot;q&quot;`:   `"q"`,
		`tab\there`:       "tab\there",
		`back\\slash`:     `back\slash`,
		`"  keep  "`:      "  keep  ",
		`&#x2764;`:        "❤",
		`&#10003;`:        "✓",
	}
	for in, want := range cases {
		if got := unescapeAndroidResString(in); got != want {
			t.Errorf("unescapeAndroidResString(%q) = %q, want %q", in, got, want)
		}
	}
}
