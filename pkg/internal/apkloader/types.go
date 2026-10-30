package apkloader

// InputType describes the kind of input the loader received.
type InputType uint8

const (
	InputTypeUnknown     InputType = iota
	InputTypeSmaliFolder           // directory with .smali sources
	InputTypeCacheFolder           // directory with runtime cache artifacts
	InputTypeAPKFile               // .apk / .xapk / .apks
	InputTypeArchiveFile           // .zip / .obb / .ipa
	InputTypeDEXFile               // .dex / .vdex / .odex / .oat / .art
	InputTypePatchFile             // .patch / .diff
	InputTypeDirectory             // general directory
)

func (t InputType) String() string {
	switch t {
	case InputTypeDirectory:
		return "Directory"
	case InputTypeSmaliFolder:
		return "SmaliFolder"
	case InputTypeCacheFolder:
		return "CacheFolder"
	case InputTypeAPKFile:
		return "APKFile"
	case InputTypeArchiveFile:
		return "ArchiveFile"
	case InputTypeDEXFile:
		return "DEXFile"
	case InputTypePatchFile:
		return "PatchFile"
	default:
		return "Unknown"
	}
}
