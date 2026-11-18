package main

import (
	"reflect"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestExtractPermissionsUsesManifestDataAndPermissionMatches(t *testing.T) {
	result := &types.AnalysisResult{Files: map[string]*types.FileAnalysis{
		"manifest": {XMLData: &types.XMLAnalysis{Permissions: []string{
			"android.permission.INTERNET", " android.permission.CAMERA ",
		}}},
		"code": {Matches: []types.Match{
			{Categorized: types.Categorized{Category: types.CategoryManifestPermission}, Pattern: "android.permission.CAMERA"},
			{Categorized: types.Categorized{Category: types.CategoryManifestPermission}, Pattern: "android.permission.ACCESS_FINE_LOCATION"},
			{Categorized: types.Categorized{Category: types.CategoryAccessibilityCapability}, Pattern: "android.permission.BIND_ACCESSIBILITY_SERVICE"},
			{Categorized: types.Categorized{Category: types.CategoryAccessibilityCapability}, Pattern: "android:service with AccessibilityService"},
		}},
	}}
	want := []string{
		"android.permission.ACCESS_FINE_LOCATION",
		"android.permission.CAMERA",
		"android.permission.INTERNET",
	}
	if got := extractPermissions(result); !reflect.DeepEqual(got, want) {
		t.Fatalf("permissions = %#v, want %#v", got, want)
	}
}

func TestExtractURLsUsesOnlyValidEndpointCategories(t *testing.T) {
	result := &types.AnalysisResult{Files: map[string]*types.FileAnalysis{"bundle": {Matches: []types.Match{
		{Categorized: types.Categorized{Category: types.CategoryNetworkEndpoint}, Pattern: "https://api.example.com/v1"},
		{Categorized: types.Categorized{Category: types.CategorySuspiciousURL}, Pattern: "wss://socket.example.com/live"},
		{Categorized: types.Categorized{Category: types.CategoryNetworkEndpoint}, Pattern: "not-a-url"},
		{Categorized: types.Categorized{Category: types.CategoryHardcodedSecret}, Pattern: "https://ignored.example.com"},
	}}}}
	want := []string{"https://api.example.com/v1", "wss://socket.example.com/live"}
	if got := extractURLs(result); !reflect.DeepEqual(got, want) {
		t.Fatalf("URLs = %#v, want %#v", got, want)
	}
}
