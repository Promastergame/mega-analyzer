package ml

import (
	"testing"
)

// TestEntryPointDetector_ActivityMethods проверяет детекцию Activity методов
func TestEntryPointDetector_ActivityMethods(t *testing.T) {
	detector := NewEntryPointDetector()

	testCases := []struct {
		name           string
		mi             *MethodInfo
		expectedType   EntryPointType
		expectedExport bool
		minPriority    int
	}{
		{
			name: "Activity onCreate",
			mi: &MethodInfo{
				Name:      "onCreate",
				ClassName: "com/myapp/MainActivity",
				FilePath:  "com/myapp/MainActivity.smali",
				RawBody:   []string{"super.onCreate(savedInstanceState);"},
			},
			expectedType:   EntryPointActivity,
			expectedExport: true,
			minPriority:    8,
		},
		{
			name: "Service onStartCommand",
			mi: &MethodInfo{
				Name:      "onStartCommand",
				ClassName: "com/myapp/MyService",
				FilePath:  "com/myapp/MyService.smali",
				RawBody:   []string{"return START_STICKY;"},
			},
			expectedType:   EntryPointService,
			expectedExport: true,
			minPriority:    7,
		},
		{
			name: "BroadcastReceiver onReceive",
			mi: &MethodInfo{
				Name:      "onReceive",
				ClassName: "com/myapp/MyReceiver",
				FilePath:  "com/myapp/MyReceiver.smali",
				RawBody:   []string{"Intent intent = (Intent) p1;"},
			},
			expectedType:   EntryPointReceiver,
			expectedExport: true,
			minPriority:    6,
		},
		{
			name: "ContentProvider query",
			mi: &MethodInfo{
				Name:      "query",
				ClassName: "com/myapp/MyProvider",
				FilePath:  "com/myapp/MyProvider.smali",
				RawBody:   []string{"return cursor;"},
			},
			expectedType:   EntryPointProvider,
			expectedExport: true,
			minPriority:    5,
		},
		{
			name: "Application onCreate",
			mi: &MethodInfo{
				Name:      "onCreate",
				ClassName: "com/myapp/MyApplication",
				FilePath:  "com/myapp/MyApplication.smali",
				RawBody:   []string{"super.onCreate();"},
			},
			expectedType:   EntryPointApplication,
			expectedExport: true,
			minPriority:    6,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := detector.Detect(tc.mi)

			if info == nil {
				t.Fatal("Expected entry point info, got nil")
			}

			if info.Type != tc.expectedType {
				t.Errorf("Expected type %v, got %v", tc.expectedType, info.Type)
			}

			if info.IsExported != tc.expectedExport {
				t.Errorf("Expected IsExported=%v, got %v", tc.expectedExport, info.IsExported)
			}

			if info.Priority < tc.minPriority {
				t.Errorf("Expected priority >= %d, got %d", tc.minPriority, info.Priority)
			}
		})
	}
}

// TestEntryPointDetector_IntentHandling проверяет детекцию Intent handling
func TestEntryPointDetector_IntentHandling(t *testing.T) {
	detector := NewEntryPointDetector()

	testCases := []struct {
		name        string
		mi          *MethodInfo
		hasIntent   bool
		description string
	}{
		{
			name: "Method with Intent handling",
			mi: &MethodInfo{
				Name:      "handleIntent",
				ClassName: "com/myapp/Handler",
				FilePath:  "com/myapp/Handler.smali",
				RawBody:   []string{"Intent intent = getIntent(); String action = intent.getAction();"},
			},
			hasIntent:   true,
			description: "Intent handler method",
		},
		{
			name: "Method with putExtra",
			mi: &MethodInfo{
				Name:      "sendData",
				ClassName: "com/myapp/Sender",
				FilePath:  "com/myapp/Sender.smali",
				RawBody:   []string{"intent.putExtra(\"key\", value);"},
			},
			hasIntent:   true,
			description: "Intent handler method",
		},
		{
			name: "Method without Intent",
			mi: &MethodInfo{
				Name:      "processData",
				ClassName: "com/myapp/Processor",
				FilePath:  "com/myapp/Processor.smali",
				RawBody:   []string{"return processData(input);"},
			},
			hasIntent:   false,
			description: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := detector.Detect(tc.mi)

			if info == nil {
				t.Fatal("Expected entry point info, got nil")
			}

			if info.HasIntent != tc.hasIntent {
				t.Errorf("Expected HasIntent=%v, got %v", tc.hasIntent, info.HasIntent)
			}

			if tc.hasIntent && info.Type == EntryPointUnknown {
				if info.Description != tc.description {
					t.Errorf("Expected description '%s', got '%s'", tc.description, info.Description)
				}
			}
		})
	}
}

// TestEntryPointDetector_BundleHandling проверяет детекцию Bundle handling
func TestEntryPointDetector_BundleHandling(t *testing.T) {
	detector := NewEntryPointDetector()

	testCases := []struct {
		name      string
		mi        *MethodInfo
		hasBundle bool
	}{
		{
			name: "Method with Bundle handling",
			mi: &MethodInfo{
				Name:      "onCreate",
				ClassName: "com/myapp/Activity",
				FilePath:  "com/myapp/Activity.smali",
				RawBody:   []string{"Bundle savedInstanceState = getBundle(); String value = savedInstanceState.getString(\"key\");"},
			},
			hasBundle: true,
		},
		{
			name: "Method with putString",
			mi: &MethodInfo{
				Name:      "saveState",
				ClassName: "com/myapp/Activity",
				FilePath:  "com/myapp/Activity.smali",
				RawBody:   []string{"bundle.putString(\"key\", value);"},
			},
			hasBundle: true,
		},
		{
			name: "Method without Bundle",
			mi: &MethodInfo{
				Name:      "processData",
				ClassName: "com/myapp/Processor",
				FilePath:  "com/myapp/Processor.smali",
				RawBody:   []string{"return processData(input);"},
			},
			hasBundle: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := detector.Detect(tc.mi)

			if info == nil {
				t.Fatal("Expected entry point info, got nil")
			}

			if info.HasBundle != tc.hasBundle {
				t.Errorf("Expected HasBundle=%v, got %v", tc.hasBundle, info.HasBundle)
			}
		})
	}
}

// TestEntryPointDetector_URLHandling проверяет детекцию URL handling
func TestEntryPointDetector_URLHandling(t *testing.T) {
	detector := NewEntryPointDetector()

	testCases := []struct {
		name   string
		mi     *MethodInfo
		hasURL bool
	}{
		{
			name: "Method with URL handling",
			mi: &MethodInfo{
				Name:      "handleURL",
				ClassName: "com/myapp/URLHandler",
				FilePath:  "com/myapp/URLHandler.smali",
				RawBody:   []string{"URL url = new URL(urlString); String host = url.getHost();"},
			},
			hasURL: true,
		},
		{
			name: "Method with URI parsing",
			mi: &MethodInfo{
				Name:      "parseURI",
				ClassName: "com/myapp/URIParser",
				FilePath:  "com/myapp/URIParser.smali",
				RawBody:   []string{"Uri uri = Uri.parse(uriString); String scheme = uri.getScheme();"},
			},
			hasURL: true,
		},
		{
			name: "Method with HTTP connection",
			mi: &MethodInfo{
				Name:      "connect",
				ClassName: "com/myapp/HTTPClient",
				FilePath:  "com/myapp/HTTPClient.smali",
				RawBody:   []string{"HttpURLConnection connection = (HttpURLConnection) url.openConnection();"},
			},
			hasURL: true,
		},
		{
			name: "Method without URL",
			mi: &MethodInfo{
				Name:      "processData",
				ClassName: "com/myapp/Processor",
				FilePath:  "com/myapp/Processor.smali",
				RawBody:   []string{"return processData(input);"},
			},
			hasURL: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := detector.Detect(tc.mi)

			if info == nil {
				t.Fatal("Expected entry point info, got nil")
			}

			if info.HasURL != tc.hasURL {
				t.Errorf("Expected HasURL=%v, got %v", tc.hasURL, info.HasURL)
			}
		})
	}
}

// TestEntryPointDetector_PriorityCalculation проверяет расчет приоритета
func TestEntryPointDetector_PriorityCalculation(t *testing.T) {
	detector := NewEntryPointDetector()

	testCases := []struct {
		name        string
		mi          *MethodInfo
		minPriority int
		maxPriority int
	}{
		{
			name: "Activity with multiple indicators",
			mi: &MethodInfo{
				Name:      "onCreate",
				ClassName: "com/myapp/MainActivity",
				FilePath:  "com/myapp/MainActivity.smali",
				RawBody:   []string{"Intent intent = getIntent(); Bundle bundle = getBundle(); URL url = new URL(urlString);"},
			},
			minPriority: 10, // Activity (9) + Intent (2) + Bundle (1) + URL (3) = 15, capped at 10
			maxPriority: 10,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := detector.Detect(tc.mi)

			if info == nil {
				t.Fatal("Expected entry point info, got nil")
			}

			if info.Priority < tc.minPriority {
				t.Errorf("Expected priority >= %d, got %d", tc.minPriority, info.Priority)
			}

			if info.Priority > tc.maxPriority {
				t.Errorf("Expected priority <= %d, got %d", tc.maxPriority, info.Priority)
			}
		})
	}
}

// TestEntryPointDetector_IsInteresting проверяет определение интересности
func TestEntryPointDetector_IsInteresting(t *testing.T) {
	detector := NewEntryPointDetector()

	testCases := []struct {
		name        string
		info        *EntryPointInfo
		interesting bool
	}{
		{
			name: "High priority entry point",
			info: &EntryPointInfo{
				Type:     EntryPointActivity,
				Priority: 8,
			},
			interesting: true,
		},
		{
			name: "Exported method",
			info: &EntryPointInfo{
				Type:       EntryPointExportedMethod,
				IsExported: true,
				Priority:   5,
			},
			interesting: true,
		},
		{
			name: "Method with Intent handling",
			info: &EntryPointInfo{
				Type:      EntryPointIntentHandler,
				HasIntent: true,
				Priority:  6,
			},
			interesting: true,
		},
		{
			name: "High confidence detection",
			info: &EntryPointInfo{
				Type:       EntryPointUnknown,
				Priority:   3,
				Confidence: 0.9,
			},
			interesting: true,
		},
		{
			name: "Low priority, not exported",
			info: &EntryPointInfo{
				Type:       EntryPointUnknown,
				Priority:   2,
				IsExported: false,
				Confidence: 0.3,
			},
			interesting: false,
		},
		{
			name:        "Nil info",
			info:        nil,
			interesting: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			interesting := detector.IsInteresting(tc.info)

			if interesting != tc.interesting {
				t.Errorf("Expected IsInteresting=%v, got %v", tc.interesting, interesting)
			}
		})
	}
}

// TestEntryPointDetector_NativeMethods проверяет детекцию native методов
func TestEntryPointDetector_NativeMethods(t *testing.T) {
	detector := NewEntryPointDetector()

	testCases := []struct {
		name       string
		mi         *MethodInfo
		isExported bool
	}{
		{
			name: "Native method with native keyword",
			mi: &MethodInfo{
				Name:      "nativeMethod",
				ClassName: "com/myapp/NativeLib",
				FilePath:  "com/myapp/NativeLib.smali",
				RawBody:   []string{"native"},
			},
			isExported: true,
		},
		{
			name: "Method with native in name",
			mi: &MethodInfo{
				Name:      "nativeCalculate",
				ClassName: "com/myapp/Calculator",
				FilePath:  "com/myapp/Calculator.smali",
				RawBody:   []string{"some body"},
			},
			isExported: true,
		},
		{
			name: "Empty body (native method)",
			mi: &MethodInfo{
				Name:      "calculate",
				ClassName: "com/myapp/Calculator",
				FilePath:  "com/myapp/Calculator.smali",
				RawBody:   []string{},
			},
			isExported: true,
		},
		{
			name: "Regular method",
			mi: &MethodInfo{
				Name:      "regularMethod",
				ClassName: "com/myapp/Regular",
				FilePath:  "com/myapp/Regular.smali",
				RawBody:   []string{"return value;"},
			},
			isExported: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := detector.Detect(tc.mi)

			if info == nil {
				t.Fatal("Expected entry point info, got nil")
			}

			if info.IsExported != tc.isExported {
				t.Errorf("Expected IsExported=%v, got %v", tc.isExported, info.IsExported)
			}
		})
	}
}

// TestEntryPointDetector_EdgeCases проверяет граничные случаи
func TestEntryPointDetector_EdgeCases(t *testing.T) {
	detector := NewEntryPointDetector()

	testCases := []struct {
		name string
		mi   *MethodInfo
	}{
		{
			name: "Nil MethodInfo",
			mi:   nil,
		},
		{
			name: "Empty MethodInfo",
			mi:   &MethodInfo{},
		},
		{
			name: "MethodInfo with empty fields",
			mi: &MethodInfo{
				Name:      "",
				ClassName: "",
				FilePath:  "",
				RawBody:   []string{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info := detector.Detect(tc.mi)

			if info == nil {
				t.Fatal("Expected entry point info, got nil")
			}

			// Should not crash and return valid info
			if info.Type < EntryPointUnknown {
				t.Errorf("Invalid entry point type: %v", info.Type)
			}

			if info.Priority < 0 {
				t.Errorf("Invalid priority: %d", info.Priority)
			}

			if info.Confidence < 0.0 || info.Confidence > 1.0 {
				t.Errorf("Invalid confidence: %f", info.Confidence)
			}
		})
	}
}

// TestEntryPointDetector_Integration интеграционный тест
func TestEntryPointDetector_Integration(t *testing.T) {
	detector := NewEntryPointDetector()

	methods := []*MethodInfo{
		// Activity method
		{
			Name:      "onCreate",
			ClassName: "com/myapp/MainActivity",
			FilePath:  "com/myapp/MainActivity.smali",
			RawBody:   []string{"super.onCreate(savedInstanceState);"},
		},
		// Service method
		{
			Name:      "onStartCommand",
			ClassName: "com/myapp/MyService",
			FilePath:  "com/myapp/MyService.smali",
			RawBody:   []string{"return START_STICKY;"},
		},
		// Regular method
		{
			Name:      "processData",
			ClassName: "com/myapp/Processor",
			FilePath:  "com/myapp/Processor.smali",
			RawBody:   []string{"return result;"},
		},
	}

	entryPoints := 0
	interestingPoints := 0

	for _, method := range methods {
		info := detector.Detect(method)
		if info != nil && info.Type != EntryPointUnknown {
			entryPoints++
		}
		if detector.IsInteresting(info) {
			interestingPoints++
		}
	}

	if entryPoints < 2 {
		t.Errorf("Expected at least 2 entry points, got %d", entryPoints)
	}

	if interestingPoints < 2 {
		t.Errorf("Expected at least 2 interesting points, got %d", interestingPoints)
	}
}
