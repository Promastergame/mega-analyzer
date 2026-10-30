// Package axml decodes Android Binary XML and ARSC resource tables.
//
// This is a clean-room implementation written from the public binary
// layout specification of Android resource chunks. No code is taken
// from the AOSP frameworks/base sources or from third-party tools
// (apktool, axmlprinter, AXMLPrinter2). The chunk type enumeration,
// header layout, and string pool encoding follow the documented
// little-endian wire format used since Android 1.x.
//
// References for the format itself (descriptions only, no code):
//   - aapt/aapt2 documentation
//   - "ResourceTypes" header constants (public symbol names only)
//
// Goals:
//   - decode AndroidManifest.xml into plaintext XML
//   - extract uses-permission, application/component metadata
//   - decode resources.arsc into a (key → string-or-id) table
//   - tolerate malformed / truncated / over-allocated chunks
//
// Non-goals:
//   - re-encoding (we do not produce binary output)
//   - full type system (we keep the value formatter compact)
package axml

// Chunk type identifiers as they appear on the wire.
// Values are stable across Android versions.
const (
	chunkNull            uint16 = 0x0000
	chunkStringPool      uint16 = 0x0001
	chunkTable           uint16 = 0x0002
	chunkXML             uint16 = 0x0003
	chunkXMLStartNS      uint16 = 0x0100
	chunkXMLEndNS        uint16 = 0x0101
	chunkXMLStartElement uint16 = 0x0102
	chunkXMLEndElement   uint16 = 0x0103
	chunkXMLCData        uint16 = 0x0104
	chunkXMLResourceMap  uint16 = 0x0180

	chunkTablePackage  uint16 = 0x0200
	chunkTableType     uint16 = 0x0201
	chunkTableTypeSpec uint16 = 0x0202
	chunkTableLibrary  uint16 = 0x0203
)

// Resource value type tags inside Res_value.
const (
	typeNull          uint8 = 0x00
	typeReference     uint8 = 0x01
	typeAttribute     uint8 = 0x02
	typeString        uint8 = 0x03
	typeFloat         uint8 = 0x04
	typeDimension     uint8 = 0x05
	typeFraction      uint8 = 0x06
	typeDynamicRef    uint8 = 0x07
	typeDynamicAttr   uint8 = 0x08
	typeIntDec        uint8 = 0x10
	typeIntHex        uint8 = 0x11
	typeIntBoolean    uint8 = 0x12
	typeIntColorARGB8 uint8 = 0x1c
	typeIntColorRGB8  uint8 = 0x1d
	typeIntColorARGB4 uint8 = 0x1e
	typeIntColorRGB4  uint8 = 0x1f
)

// String pool flags.
const (
	flagSorted uint32 = 1 << 0
	flagUTF8   uint32 = 1 << 8
)

// SentinelNoString is returned by string-pool lookups when the index is
// out of range or marked as -1 by the producer.
const SentinelNoString = "_unknown_"

// Hard limits to keep malformed inputs from exploding memory.
const (
	maxStringPoolEntries = 4 << 20  // 4M strings
	maxAttributesPerNode = 0xFFFF   // 64K attrs - 1, fits in uint16
	maxChunkBytes        = 64 << 20 // 64 MiB single chunk
	maxNestingDepth      = 256      // catches namespace/element loops
)

// Manifest is the structured view of AndroidManifest.xml.
type Manifest struct {
	Package       string            `json:"package,omitempty"`
	VersionCode   uint32            `json:"versionCode,omitempty"`
	VersionName   string            `json:"versionName,omitempty"`
	MinSDK        uint32            `json:"minSdkVersion,omitempty"`
	TargetSDK     uint32            `json:"targetSdkVersion,omitempty"`
	CompileSDK    uint32            `json:"compileSdkVersion,omitempty"`
	SharedUserID  string            `json:"sharedUserId,omitempty"`
	Application   ApplicationInfo   `json:"application"`
	Permissions   []string          `json:"usesPermissions,omitempty"`
	OptionalPerms []string          `json:"optionalPermissions,omitempty"`
	UsesFeatures  []FeatureInfo     `json:"usesFeatures,omitempty"`
	Activities    []Component       `json:"activities,omitempty"`
	Services      []Component       `json:"services,omitempty"`
	Receivers     []Component       `json:"receivers,omitempty"`
	Providers     []Component       `json:"providers,omitempty"`
	MetaData      map[string]string `json:"metaData,omitempty"`
	XMLBytes      []byte            `json:"-"`
}

// ApplicationInfo captures the <application> element.
type ApplicationInfo struct {
	Name       string `json:"name,omitempty"`
	Label      string `json:"label,omitempty"`
	Icon       string `json:"icon,omitempty"`
	Theme      string `json:"theme,omitempty"`
	Debuggable bool   `json:"debuggable,omitempty"`
	// AllowBackup and UsesCleartext are retained for JSON/API compatibility.
	// The Declared pointers preserve the critical absent-vs-false distinction;
	// callers that need Android semantics must use an effective policy.
	AllowBackup         bool   `json:"allowBackup,omitempty"`
	AllowBackupDeclared *bool  `json:"allowBackupDeclared,omitempty"`
	UsesCleartext       bool   `json:"usesCleartextTraffic,omitempty"`
	CleartextDeclared   *bool  `json:"usesCleartextTrafficDeclared,omitempty"`
	NetworkSecCfg       string `json:"networkSecurityConfig,omitempty"`
	FullBackupContent   string `json:"fullBackupContent,omitempty"`
	DataExtractionRules string `json:"dataExtractionRules,omitempty"`
	FullBackupOnly      *bool  `json:"fullBackupOnly,omitempty"`
	Process             string `json:"process,omitempty"`
	ExtractNativeLibs   bool   `json:"extractNativeLibs,omitempty"`
	HasCode             bool   `json:"hasCode,omitempty"`
}

// OptionalBool represents a tri-state boolean value (Present: false means absent).
type OptionalBool struct {
	Present bool `json:"present"`
	Value   bool `json:"value"`
}

// EffectiveAllowBackup returns the effective allowBackup policy.
// Default on Android when attribute is absent is true.
func (app *ApplicationInfo) EffectiveAllowBackup() bool {
	if app.AllowBackupDeclared != nil {
		return *app.AllowBackupDeclared
	}
	return true
}

// EffectiveUsesCleartext returns the effective cleartext traffic policy for a given targetSdk.
// Default for targetSdk <= 27 (Android 8.1 and lower) is true when absent.
// Default for targetSdk >= 28 (Android 9+ pie) is false when absent.
func (app *ApplicationInfo) EffectiveUsesCleartext(targetSdk uint32) bool {
	if app.CleartextDeclared != nil {
		return *app.CleartextDeclared
	}
	if targetSdk > 0 && targetSdk <= 27 {
		return true
	}
	return false
}

// Component models <activity>/<service>/<receiver>/<provider>.
type Component struct {
	Name            string         `json:"name"`
	Exported        *bool          `json:"exported,omitempty"`
	Permission      string         `json:"permission,omitempty"`
	ReadPermission  string         `json:"readPermission,omitempty"`
	WritePermission string         `json:"writePermission,omitempty"`
	Process         string         `json:"process,omitempty"`
	IntentFilts     []IntentFilter `json:"intentFilters,omitempty"`
	Authorities     string         `json:"authorities,omitempty"`
	Enabled         *bool          `json:"enabled,omitempty"`
	// LaunchMode is the raw android:launchMode value ("standard"/"singleTop"/
	// "singleTask"/"singleInstance"/"singleInstancePerTask" or its numeric enum).
	// Relevant to task-hijacking (StrandHogg) analysis.
	LaunchMode string `json:"launchMode,omitempty"`
	// TaskAffinity is the raw android:taskAffinity value. A custom (non-empty,
	// non-package) affinity is the deliberate config that enables task hijacking.
	TaskAffinity string `json:"taskAffinity,omitempty"`
	// GrantUriPermissions reflects android:grantUriPermissions on a <provider>.
	GrantUriPermissions *bool `json:"grantUriPermissions,omitempty"`
	// AutoVerify reflects android:autoVerify declared on one of the
	// component's <intent-filter> elements (Android App Links). Android
	// applies verification per activity, so the flag is lifted to the
	// component level. nil = attribute absent.
	AutoVerify *bool `json:"autoVerify,omitempty"`
}

// IntentFilter is a flattened view of <intent-filter>.
type IntentFilter struct {
	Actions    []string `json:"actions,omitempty"`
	Categories []string `json:"categories,omitempty"`
	DataScheme []string `json:"schemes,omitempty"`
	DataHost   []string `json:"hosts,omitempty"`
}

// FeatureInfo models <uses-feature>.
type FeatureInfo struct {
	Name     string `json:"name"`
	Required bool   `json:"required"`
}
