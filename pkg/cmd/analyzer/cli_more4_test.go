package main

import (
	"strings"
	"testing"
)

// ─── AnalysisProfile.IsValid ───────────────────────────────────────────────────

func TestAnalysisProfile_IsValid_Quick(t *testing.T) {
	if !ProfileQuick.IsValid() {
		t.Error("ProfileQuick should be valid")
	}
}

func TestAnalysisProfile_IsValid_Balanced(t *testing.T) {
	if !ProfileBalanced.IsValid() {
		t.Error("ProfileBalanced should be valid")
	}
}

func TestAnalysisProfile_IsValid_Deep(t *testing.T) {
	if !ProfileDeep.IsValid() {
		t.Error("ProfileDeep should be valid")
	}
}

func TestAnalysisProfile_IsValid_Paranoid(t *testing.T) {
	if !ProfileParanoid.IsValid() {
		t.Error("ProfileParanoid should be valid")
	}
}

func TestAnalysisProfile_IsValid_Unknown(t *testing.T) {
	p := AnalysisProfile("unknown")
	if p.IsValid() {
		t.Error("unknown profile should not be valid")
	}
}

// ─── AnalysisProfile.Description ───────────────────────────────────────────────

func TestAnalysisProfile_Description_Quick(t *testing.T) {
	desc := ProfileQuick.Description()
	if desc == "" || desc == "Unknown profile" {
		t.Errorf("ProfileQuick description should be non-empty: %q", desc)
	}
	if !strings.Contains(desc, "Fast") && !strings.Contains(desc, "quick") {
		t.Errorf("ProfileQuick description should mention speed: %q", desc)
	}
}

func TestAnalysisProfile_Description_Balanced(t *testing.T) {
	desc := ProfileBalanced.Description()
	if desc == "" || desc == "Unknown profile" {
		t.Errorf("ProfileBalanced description empty: %q", desc)
	}
	if !strings.Contains(desc, "Balanced") && !strings.Contains(desc, "balanced") {
		t.Errorf("ProfileBalanced should mention balance: %q", desc)
	}
}

func TestAnalysisProfile_Description_Deep(t *testing.T) {
	desc := ProfileDeep.Description()
	if desc == "" || desc == "Unknown profile" {
		t.Errorf("ProfileDeep description empty: %q", desc)
	}
	if !strings.Contains(desc, "Deep") && !strings.Contains(desc, "call") {
		t.Errorf("ProfileDeep should mention depth or call graph: %q", desc)
	}
}

func TestAnalysisProfile_Description_Paranoid(t *testing.T) {
	desc := ProfileParanoid.Description()
	if desc == "" || desc == "Unknown profile" {
		t.Errorf("ProfileParanoid description empty: %q", desc)
	}
	if !strings.Contains(desc, "Maximum") {
		t.Errorf("ProfileParanoid should mention maximum: %q", desc)
	}
}

func TestAnalysisProfile_Description_Unknown(t *testing.T) {
	p := AnalysisProfile("unknown")
	desc := p.Description()
	if desc != "Unknown profile" {
		t.Errorf("unknown profile should return 'Unknown profile', got %q", desc)
	}
}

// ─── isTruthy ──────────────────────────────────────────────────────────────────

func TestIsTruthy_One(t *testing.T) {
	if !isTruthy("1") {
		t.Error("'1' should be truthy")
	}
}

func TestIsTruthy_True(t *testing.T) {
	if !isTruthy("true") {
		t.Error("'true' should be truthy")
	}
}

func TestIsTruthy_TrueUppercase(t *testing.T) {
	if !isTruthy("TRUE") {
		t.Error("'TRUE' should be truthy (case-insensitive)")
	}
}

func TestIsTruthy_Yes(t *testing.T) {
	if !isTruthy("yes") {
		t.Error("'yes' should be truthy")
	}
}

func TestIsTruthy_On(t *testing.T) {
	if !isTruthy("on") {
		t.Error("'on' should be truthy")
	}
}

func TestIsTruthy_WithSpaces(t *testing.T) {
	if !isTruthy("  true  ") {
		t.Error("'  true  ' should be truthy after trimming")
	}
}

func TestIsTruthy_Zero(t *testing.T) {
	if isTruthy("0") {
		t.Error("'0' should not be truthy")
	}
}

func TestIsTruthy_False(t *testing.T) {
	if isTruthy("false") {
		t.Error("'false' should not be truthy")
	}
}

func TestIsTruthy_No(t *testing.T) {
	if isTruthy("no") {
		t.Error("'no' should not be truthy")
	}
}

func TestIsTruthy_Off(t *testing.T) {
	if isTruthy("off") {
		t.Error("'off' should not be truthy")
	}
}

func TestIsTruthy_Empty(t *testing.T) {
	if isTruthy("") {
		t.Error("empty string should not be truthy")
	}
}

func TestIsTruthy_Random(t *testing.T) {
	if isTruthy("maybe") {
		t.Error("'maybe' should not be truthy")
	}
}

// ─── normalizeResolution ───────────────────────────────────────────────────────

func TestNormalizeResolution_720p(t *testing.T) {
	result := normalizeResolution("720p")
	if result != "720x1280" {
		t.Errorf("expected '720x1280', got %q", result)
	}
}

func TestNormalizeResolution_HD(t *testing.T) {
	result := normalizeResolution("hd")
	if result != "720x1280" {
		t.Errorf("'hd' should alias to '720x1280', got %q", result)
	}
}

func TestNormalizeResolution_1080p(t *testing.T) {
	result := normalizeResolution("1080p")
	if result != "1080x1920" {
		t.Errorf("expected '1080x1920', got %q", result)
	}
}

func TestNormalizeResolution_FHD(t *testing.T) {
	result := normalizeResolution("fhd")
	if result != "1080x1920" {
		t.Errorf("'fhd' should alias to '1080x1920', got %q", result)
	}
}

func TestNormalizeResolution_1440p(t *testing.T) {
	result := normalizeResolution("1440p")
	if result != "1440x2560" {
		t.Errorf("expected '1440x2560', got %q", result)
	}
}

func TestNormalizeResolution_QHD(t *testing.T) {
	result := normalizeResolution("qhd")
	if result != "1440x2560" {
		t.Errorf("'qhd' should alias to '1440x2560', got %q", result)
	}
}

func TestNormalizeResolution_2K(t *testing.T) {
	result := normalizeResolution("2k")
	if result != "1440x2560" {
		t.Errorf("'2k' should alias to '1440x2560', got %q", result)
	}
}

func TestNormalizeResolution_CustomValid(t *testing.T) {
	result := normalizeResolution("800x600")
	if result != "800x600" {
		t.Errorf("custom resolution should be preserved, got %q", result)
	}
}

func TestNormalizeResolution_CustomWithSpaces(t *testing.T) {
	result := normalizeResolution("1024 x 768")
	if result != "1024x768" {
		t.Errorf("resolution with spaces should be parsed, got %q", result)
	}
}

func TestNormalizeResolution_TooSmall(t *testing.T) {
	result := normalizeResolution("100x100")
	if result != "" {
		t.Errorf("resolution < 240 should return empty, got %q", result)
	}
}

func TestNormalizeResolution_TooLarge(t *testing.T) {
	result := normalizeResolution("9000x9000")
	if result != "" {
		t.Errorf("resolution > 8192 should return empty, got %q", result)
	}
}

func TestNormalizeResolution_Empty(t *testing.T) {
	result := normalizeResolution("")
	if result != "" {
		t.Errorf("empty resolution should return empty, got %q", result)
	}
}

func TestNormalizeResolution_NoX(t *testing.T) {
	result := normalizeResolution("720")
	if result != "" {
		t.Errorf("resolution without 'x' should return empty, got %q", result)
	}
}

func TestNormalizeResolution_InvalidWidth(t *testing.T) {
	result := normalizeResolution("abcxdef")
	if result != "" {
		t.Errorf("invalid numbers should return empty, got %q", result)
	}
}

func TestNormalizeResolution_Uppercase(t *testing.T) {
	result := normalizeResolution("720P")
	if result != "720x1280" {
		t.Errorf("'720P' should be case-insensitive, got %q", result)
	}
}

// ─── splitArgs extended ────────────────────────────────────────────────────────

func TestSplitArgs_UnclosedDouble_More(t *testing.T) {
	_, err := splitArgs(`foo "bar`)
	if err == nil {
		t.Error("expected error for unclosed double quote")
	}
}

func TestSplitArgs_UnclosedSingle_More(t *testing.T) {
	_, err := splitArgs("foo 'bar")
	if err == nil {
		t.Error("expected error for unclosed single quote")
	}
}

func TestSplitArgs_Tabs_More(t *testing.T) {
	args, err := splitArgs("foo\tbar\tbaz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 3 {
		t.Errorf("expected 3 args, got %v", args)
	}
}

func TestSplitArgs_QuoteInMiddle_More(t *testing.T) {
	args, err := splitArgs(`foo"bar"baz`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 1 || args[0] != "foobarbaz" {
		t.Errorf("expected 'foobarbaz', got %v", args)
	}
}

// ─── parseFlagsFile extended ───────────────────────────────────────────────────

func TestParseFlagsFile_WithComments_More(t *testing.T) {
	content := `# This is a comment
--verbose
// This is also a comment
--target=/path/to/app.apk
	`
	args, err := parseFlagsFile(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(args) != 2 {
		t.Errorf("expected 2 args after skipping comments, got %d: %v", len(args), args)
	}
}

func TestParseFlagsFile_BadQuotes_More(t *testing.T) {
	content := `--option="unclosed value`
	_, err := parseFlagsFile(content)
	if err == nil {
		t.Error("expected error for unclosed quote")
	}
}

// ─── CLIOptions Is*Command methods ─────────────────────────────────────────────

func TestCLIOptions_IsMLCommand_WithSuggest(t *testing.T) {
	opts := &CLIOptions{MLSuggest: true}
	if !opts.IsMLCommand() {
		t.Error("expected IsMLCommand to return true when MLSuggest is true")
	}
}

func TestCLIOptions_IsMLCommand_Empty(t *testing.T) {
	opts := &CLIOptions{}
	if opts.IsMLCommand() {
		t.Error("expected IsMLCommand to return false when all ML fields are false")
	}
}

func TestCLIOptions_IsMLCommand_WithExport(t *testing.T) {
	opts := &CLIOptions{MLExport: "output.json"}
	if !opts.IsMLCommand() {
		t.Error("expected IsMLCommand to return true when MLExport is set")
	}
}

func TestCLIOptions_IsSandboxCommand_WithAndroidSandbox(t *testing.T) {
	opts := &CLIOptions{AndroidSandbox: true}
	if !opts.IsSandboxCommand() {
		t.Error("expected IsSandboxCommand to return true when AndroidSandbox is true")
	}
}

func TestCLIOptions_IsDecodeCommand_True(t *testing.T) {
	opts := &CLIOptions{Decode: true}
	if !opts.IsDecodeCommand() {
		t.Error("expected IsDecodeCommand to return true when Decode is true")
	}
}

func TestCLIOptions_IsBuildCommand_WithBuild(t *testing.T) {
	opts := &CLIOptions{Build: true}
	if !opts.IsBuildCommand() {
		t.Error("expected IsBuildCommand to return true when Build is true")
	}
}

func TestCLIOptions_IsInterceptCommand_True(t *testing.T) {
	opts := &CLIOptions{Intercept: true}
	if !opts.IsInterceptCommand() {
		t.Error("expected IsInterceptCommand to return true when Intercept is true")
	}
}

func TestCLIOptions_IsServgenCommand_True(t *testing.T) {
	opts := &CLIOptions{Servgen: true}
	if !opts.IsServgenCommand() {
		t.Error("expected IsServgenCommand to return true when Servgen is true")
	}
}

func TestCLIOptions_IsLabDNSCommand_True(t *testing.T) {
	opts := &CLIOptions{LabDNS: true}
	if !opts.IsLabDNSCommand() {
		t.Error("expected IsLabDNSCommand to return true when LabDNS is true")
	}
}

func TestCLIOptions_IsVersionDiffCommand_True(t *testing.T) {
	opts := &CLIOptions{VersionDiff: true}
	if !opts.IsVersionDiffCommand() {
		t.Error("expected IsVersionDiffCommand to return true when VersionDiff is true")
	}
}

func TestCLIOptions_IsFirmwareCommand_True(t *testing.T) {
	opts := &CLIOptions{Firmware: true}
	if !opts.IsFirmwareCommand() {
		t.Error("expected IsFirmwareCommand to return true when Firmware is true")
	}
}

func TestCLIOptions_IsMakeServerCommand_True(t *testing.T) {
	opts := &CLIOptions{MakeServer: true}
	if !opts.IsMakeServerCommand() {
		t.Error("expected IsMakeServerCommand to return true when MakeServer is true")
	}
}

func TestCLIOptions_IsJSDeobfuscateCommand_True(t *testing.T) {
	opts := &CLIOptions{JSDeobfuscate: true}
	if !opts.IsJSDeobfuscateCommand() {
		t.Error("expected IsJSDeobfuscateCommand to return true when JSDeobfuscate is true")
	}
}

func TestCLIOptions_IsJSPatchCommand_True(t *testing.T) {
	opts := &CLIOptions{JSPatch: true}
	if !opts.IsJSPatchCommand() {
		t.Error("expected IsJSPatchCommand to return true when JSPatch is true")
	}
}

// ─── CLIOptions.Validate edge cases ────────────────────────────────────────────

func TestCLIOptions_Validate_VersionDiff_NoInputs(t *testing.T) {
	opts := &CLIOptions{VersionDiff: true}
	err := opts.Validate()
	if err == nil {
		t.Error("expected error for version diff without inputs")
	}
}

func TestCLIOptions_Validate_VersionDiff_OnlyOld(t *testing.T) {
	opts := &CLIOptions{VersionDiff: true, DiffOld: "old.apk"}
	err := opts.Validate()
	if err == nil {
		t.Error("expected error for version diff with only old input")
	}
}

func TestCLIOptions_Validate_VersionDiff_Valid(t *testing.T) {
	opts := &CLIOptions{VersionDiff: true, DiffOld: "old.apk", DiffNew: "new.apk"}
	err := opts.Validate()
	if err != nil {
		t.Errorf("unexpected error for valid version diff: %v", err)
	}
}

func TestCLIOptions_Validate_Firmware_NoTarget(t *testing.T) {
	opts := &CLIOptions{Firmware: true}
	err := opts.Validate()
	if err == nil {
		t.Error("expected error for firmware without target")
	}
}

func TestCLIOptions_Validate_Firmware_Valid(t *testing.T) {
	opts := &CLIOptions{Firmware: true, Target: "firmware.bin"}
	err := opts.Validate()
	if err != nil {
		t.Errorf("unexpected error for valid firmware: %v", err)
	}
}

func TestCLIOptions_Validate_MakeServer_NoTarget(t *testing.T) {
	opts := &CLIOptions{MakeServer: true}
	err := opts.Validate()
	if err == nil {
		t.Error("expected error for make-server without target")
	}
}

func TestCLIOptions_Validate_MakeServer_InvalidPort(t *testing.T) {
	opts := &CLIOptions{MakeServer: true, Target: "app.apk", MakeServerPort: 70000}
	err := opts.Validate()
	if err == nil {
		t.Error("expected error for invalid port > 65535")
	}
}

func TestCLIOptions_Validate_MakeServer_ValidPort(t *testing.T) {
	opts := &CLIOptions{MakeServer: true, Target: "app.apk", MakeServerPort: 8080}
	err := opts.Validate()
	if err != nil {
		t.Errorf("unexpected error for valid make-server: %v", err)
	}
}
