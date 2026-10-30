package shared

import (
	"encoding/json"
	"testing"
)

func TestAnalysisTypes(t *testing.T) {
	ci := CallInfo{
		Type:              "invoke-virtual",
		Class:             "Ljava/lang/String;",
		Method:            "length",
		FullCall:          "invoke-virtual {v0}, Ljava/lang/String;->length()I",
		IsSecurityRelated: false,
	}

	mi := MethodInfo{
		Name:            "isPremium",
		ReturnType:      "Z",
		ReturnsBoolean:  true,
		IsAppCode:       true,
		Calls:           []CallInfo{ci},
		SourceLanguage:  LanguageJava,
		SecurityContext: CheckTypePremium,
	}

	classInfo := ClassInfo{
		ClassName:          "Lcom/example/MyClass;",
		IsAppCode:          true,
		Methods:            []MethodInfo{mi},
		TotalMethods:       1,
		BooleanMethodCount: 1,
	}

	b, err := json.Marshal(classInfo)
	if err != nil {
		t.Fatal(err)
	}

	var parsed ClassInfo
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatal(err)
	}

	if parsed.ClassName != "Lcom/example/MyClass;" {
		t.Errorf("expected Lcom/example/MyClass;, got %s", parsed.ClassName)
	}
	if len(parsed.Methods) != 1 {
		t.Errorf("expected 1 method, got %d", len(parsed.Methods))
	}
	if parsed.Methods[0].Name != "isPremium" {
		t.Errorf("expected isPremium, got %s", parsed.Methods[0].Name)
	}
}
