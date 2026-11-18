package pipeline

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"mega-analyzer/pkg/internal/rules"
	"mega-analyzer/pkg/internal/types"
)

func newSourceRuleContext() *rules.ConditionContext {
	return &rules.ConditionContext{Facts: make(map[string]bool), Sources: make(map[string]map[string]rules.EvidenceSource)}
}

// Rule inputs come from parsed source, not Match.Text/Context/Pattern. Those
// fields can contain a detector's interpretation and would make rules confirm
// their own prose. Sources also make the exact supporting input reviewable.
func addRuleSource(ctx *rules.ConditionContext, kind, value string, source rules.EvidenceSource) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if ctx.Sources[kind] == nil {
		ctx.Sources[kind] = make(map[string]rules.EvidenceSource)
	}
	if _, exists := ctx.Sources[kind][value]; exists {
		return
	}
	ctx.Sources[kind][value] = source
	switch kind {
	case "permission":
		ctx.Permissions = append(ctx.Permissions, value)
	case "api_call":
		ctx.APICalls = append(ctx.APICalls, value)
	case "pattern":
		ctx.Patterns = append(ctx.Patterns, value)
	case "string":
		ctx.Strings = append(ctx.Strings, value)
	case "class":
		ctx.Classes = append(ctx.Classes, value)
	case "method":
		ctx.Methods = append(ctx.Methods, value)
	case "fact":
		ctx.Facts[value] = true
	}
}

func addClassRuleSource(ctx *rules.ConditionContext, class string, source rules.EvidenceSource) {
	addRuleSource(ctx, "class", class, source)
	trimmed := strings.TrimSuffix(strings.TrimPrefix(class, "L"), ";")
	addRuleSource(ctx, "class", strings.ReplaceAll(trimmed, "/", "."), source)
	addRuleSource(ctx, "class", smaliSimpleClass(class), source)
}

func appendFileRuleSources(ctx *rules.ConditionContext, fa *types.FileAnalysis) {
	if fa == nil {
		return
	}
	for _, value := range fa.RecoveredStrings {
		source := rules.EvidenceSource{File: fa.Path, Snippet: value}
		addRuleSource(ctx, "string", value, source)
		addRuleSource(ctx, "pattern", value, source)
	}
	if fa.XMLData != nil && strings.EqualFold(filepath.Base(fa.Path), "AndroidManifest.xml") {
		for _, perm := range fa.XMLData.Permissions {
			addRuleSource(ctx, "permission", perm, rules.EvidenceSource{File: fa.Path, Snippet: perm})
		}
	}
	cls := fa.SmaliClass
	if cls == nil {
		return
	}
	source := rules.EvidenceSource{File: fa.Path, Class: cls.Name, Snippet: cls.Name}
	for _, class := range append([]string{cls.Name, cls.PackageName, cls.SuperClass}, cls.Interfaces...) {
		addClassRuleSource(ctx, class, source)
	}
	for _, field := range cls.Fields {
		s := rules.EvidenceSource{File: fa.Path, Line: field.Line, Class: cls.Name, Snippet: field.Name + ":" + field.Type + " = " + field.Value}
		addRuleSource(ctx, "pattern", s.Snippet, s)
		if field.Value != "" {
			addRuleSource(ctx, "string", strings.Trim(field.Value, "\""), s)
		}
	}
	for i := range cls.Methods {
		method := &cls.Methods[i]
		s := rules.EvidenceSource{File: fa.Path, Line: method.LineStart, Class: cls.Name, Method: method.Name, Snippet: method.FullSignature(cls.Name)}
		addRuleSource(ctx, "method", method.Name, s)
		addRuleSource(ctx, "pattern", s.Snippet, s)
		for _, literal := range method.StringConsts {
			w := s
			w.Line, w.Snippet = literal.Line, firstNonEmpty(literal.Raw, literal.Value)
			addRuleSource(ctx, "string", literal.Value, w)
			addRuleSource(ctx, "pattern", literal.Value, w)
		}
		for _, inv := range method.Invokes {
			w := s
			w.Line, w.Snippet = inv.Line, firstNonEmpty(inv.Raw, inv.FullSignature())
			for _, value := range []string{inv.Class, inv.Method, inv.FullSignature(), smaliSimpleClass(inv.Class), smaliSimpleClass(inv.Class) + "." + inv.Method} {
				addRuleSource(ctx, "api_call", value, w)
			}
			addRuleSource(ctx, "pattern", inv.FullSignature(), w)
			addRuleSource(ctx, "method", inv.Method, w)
			addClassRuleSource(ctx, inv.Class, w)
		}
		if w, ok := fileEncryptionWitness(method, fa.Path, cls.Name); ok {
			addRuleSource(ctx, "fact", "crypto.file_encryption_flow", w)
		}
		if w, ok := plaintextCredentialWriteWitness(method, fa.Path, cls.Name); ok {
			addRuleSource(ctx, "fact", "storage.plaintext_credential_write", w)
		}
	}
}

func appendManifestRuleSources(ctx *rules.ConditionContext, result *types.AnalysisResult) {
	path := filepath.Join(result.TargetDir, "AndroidManifest.xml")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, declaration := range manifestPermissionSources(data, path) {
		addRuleSource(ctx, "permission", declaration.Snippet, declaration)
	}
	min, target, known := androidSDKPolicy(data)
	if known && (min < 17 || target < 17) {
		addRuleSource(ctx, "fact", "android.legacy_js_bridge", rules.EvidenceSource{File: path, Snippet: fmt.Sprintf("minSdkVersion=%d; targetSdkVersion=%d", min, target)})
	}
}

func manifestPermissionSources(data []byte, path string) []rules.EvidenceSource {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var out []rules.EvidenceSource
	for {
		offset := decoder.InputOffset()
		token, err := decoder.Token()
		if err == io.EOF {
			return out
		}
		if err != nil {
			return nil
		}
		element, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		attribute := ""
		switch element.Name.Local {
		case "uses-permission", "uses-permission-sdk-23":
			attribute = "name"
		case "service", "activity", "receiver", "provider":
			attribute = "permission"
		default:
			continue
		}
		for _, attr := range element.Attr {
			if attr.Name.Local == attribute && (attr.Name.Space == "http://schemas.android.com/apk/res/android" || attr.Name.Space == "android") && strings.HasPrefix(attr.Value, "android.permission.") {
				out = append(out, rules.EvidenceSource{File: path, Line: bytes.Count(data[:offset], []byte{'\n'}) + 1, Snippet: attr.Value})
			}
		}
	}
}

// An absent uses-sdk has Android's documented defaults (1; target=min).
// Resource-valued, malformed or nonnumeric declarations stay unknown.
func androidSDKPolicy(data []byte) (min, target int, known bool) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	min, target = 1, 1
	depth, rootSeen, sdkSeen := 0, false, false
	minRaw, targetRaw := "", ""
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, 0, false
		}
		switch item := token.(type) {
		case xml.StartElement:
			depth++
			if depth == 1 {
				if rootSeen || item.Name.Local != "manifest" {
					return 0, 0, false
				}
				rootSeen = true
			}
			if depth != 2 || item.Name.Local != "uses-sdk" {
				continue
			}
			if sdkSeen {
				return 0, 0, false
			}
			sdkSeen = true
			for _, attr := range item.Attr {
				if attr.Name.Space != "http://schemas.android.com/apk/res/android" && attr.Name.Space != "android" {
					continue
				}
				switch attr.Name.Local {
				case "minSdkVersion":
					minRaw = attr.Value
				case "targetSdkVersion":
					targetRaw = attr.Value
				}
			}
		case xml.EndElement:
			depth--
		}
	}
	if !rootSeen {
		return 0, 0, false
	}
	if minRaw != "" {
		var err error
		min, err = strconv.Atoi(minRaw)
		if err != nil || min < 1 {
			return 0, 0, false
		}
	}
	target = min
	if targetRaw != "" {
		var err error
		target, err = strconv.Atoi(targetRaw)
		if err != nil || target < 1 {
			return 0, 0, false
		}
	}
	return min, target, true
}
