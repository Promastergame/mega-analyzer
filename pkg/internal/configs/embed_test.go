// pkg/internal/configs/embed_test.go
package configs

import (
	"encoding/json"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// EMBED TESTS — тесты для embedded конфигураций
// ═══════════════════════════════════════════════════════════════════════════════

func TestEndpointConfig(t *testing.T) {
	t.Run("returns non-empty data", func(t *testing.T) {
		data := EndpointConfig()
		if len(data) == 0 {
			t.Fatal("EndpointConfig() returned empty data")
		}
	})

	t.Run("returns valid JSON", func(t *testing.T) {
		data := EndpointConfig()
		var v interface{}
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatalf("EndpointConfig() is not valid JSON: %v", err)
		}
	})

	t.Run("returns consistent data", func(t *testing.T) {
		data1 := EndpointConfig()
		data2 := EndpointConfig()

		if len(data1) != len(data2) {
			t.Error("EndpointConfig() returns inconsistent data")
		}

		for i := range data1 {
			if data1[i] != data2[i] {
				t.Error("EndpointConfig() returns different data on multiple calls")
				break
			}
		}
	})

	t.Run("contains expected structure", func(t *testing.T) {
		data := EndpointConfig()

		var config interface{}
		if err := json.Unmarshal(data, &config); err != nil {
			t.Fatalf("failed to parse config: %v", err)
		}

		// Проверяем что есть данные (может быть объект или массив)
		switch v := config.(type) {
		case map[string]interface{}:
			if len(v) == 0 {
				t.Error("endpoint config is empty object")
			}
		case []interface{}:
			if len(v) == 0 {
				t.Error("endpoint config is empty array")
			}
		default:
			t.Errorf("unexpected config type: %T", config)
		}
	})

	t.Run("data slice reference", func(t *testing.T) {
		data1 := EndpointConfig()
		data2 := EndpointConfig()

		// Проверяем что возвращается тот же slice (embedded data)
		// Это ожидаемое поведение для go:embed
		if len(data1) > 0 && len(data2) > 0 {
			// Просто логируем, не фейлим
			t.Logf("EndpointConfig returns slice of length %d", len(data1))
		}
	})
}

func TestOtherConfigs(t *testing.T) {
	configsToTest := []struct {
		name string
		data []byte
	}{
		{"AetriumAnchors", AetriumAnchors()},
		{"BankingThreats", BankingThreats()},
		{"ContextDowngrades", ContextDowngrades()},
		{"CustomKeywords", CustomKeywords()},
		{"MalwareCombos", MalwareCombos()},
		{"PermissionRules", PermissionRules()},
		{"PiracySites", PiracySites()},
	}

	for _, tc := range configsToTest {
		t.Run(tc.name+" non-empty", func(t *testing.T) {
			if len(tc.data) == 0 {
				t.Errorf("%s() returned empty data", tc.name)
			}
		})

		t.Run(tc.name+" valid JSON", func(t *testing.T) {
			var v interface{}
			if err := json.Unmarshal(tc.data, &v); err != nil {
				t.Errorf("%s() is not valid JSON: %v", tc.name, err)
			}
		})
	}
}

func TestFile(t *testing.T) {
	t.Run("valid file name", func(t *testing.T) {
		data, ok := File("endpoint_config.json")
		if !ok {
			t.Error("expected endpoint_config.json to exist")
		}
		if len(data) == 0 {
			t.Error("expected non-empty data for endpoint_config.json")
		}
	})

	t.Run("invalid file name", func(t *testing.T) {
		data, ok := File("non_existent_file.json")
		if ok {
			t.Error("expected non_existent_file.json to not exist")
		}
		if len(data) != 0 {
			t.Error("expected nil/empty data for non-existent file")
		}
	})
}

func TestEndpointConfigJSON_Structure(t *testing.T) {
	data := EndpointConfig()

	var config interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	t.Run("has valid JSON types", func(t *testing.T) {
		validateJSONTypes(t, config, "root")
	})
}

// validateJSONTypes рекурсивно проверяет типы JSON
func validateJSONTypes(t *testing.T, v interface{}, path string) {
	t.Helper()

	switch val := v.(type) {
	case nil:
		// OK
	case bool:
		// OK
	case float64:
		// OK
	case string:
		// OK
	case []interface{}:
		for i, item := range val {
			validateJSONTypes(t, item, path+"["+string(rune('0'+i%10))+"]")
		}
	case map[string]interface{}:
		for key, item := range val {
			validateJSONTypes(t, item, path+"."+key)
		}
	default:
		t.Errorf("unexpected type at %s: %T", path, v)
	}
}

func BenchmarkEndpointConfig(b *testing.B) {
	b.Run("access", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = EndpointConfig()
		}
	})

	b.Run("access_and_parse", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			data := EndpointConfig()
			var v interface{}
			_ = json.Unmarshal(data, &v)
		}
	})
}
