package gnn

// VulnClass represents a GNN vulnerability class in the DEX license/piracy
// taxonomy. The integer values are an ABI contract: the Rust engine returns
// raw class indices across the FFI and they are mapped to names here, so this
// order MUST match rust/crates/omnisec-ml-gnn/src/taxonomy.rs (CLASS_NAMES).
type VulnClass int

const (
	VulnBenign          VulnClass = 0 // no license/piracy signal (negative class)
	VulnLicenseCheck    VulnClass = 1 // legitimate LVL / Play licensing verification
	VulnLicenseBypass   VulnClass = 2 // license check neutralized / always-licensed
	VulnSignatureSpoof  VulnClass = 3 // fake signature / PackageManager proxy
	VulnIntegrityTamper VulnClass = 4 // checksum / anti-tamper hooked or removed
	VulnRepackMarker    VulnClass = 5 // re-sign / store attribution / injected loader
	VulnNativeBridge    VulnClass = 6 // JNI / native licensing or .so protection bridge
	VulnDynamicLoad     VulnClass = 7 // DexClassLoader / reflection-driven payload
	NumVulnClasses                = 8
)

const (
	EdgeControlFlow    uint32 = 0
	EdgeDataDependency uint32 = 1
	EdgeCall           uint32 = 2
	EdgeReturn         uint32 = 3
	EdgeSelfLoop       uint32 = 4
)

// VulnClassName returns a human-readable name for the class. It MUST stay in
// sync (name AND index) with CLASS_NAMES in the Rust taxonomy module.
func VulnClassName(c VulnClass) string {
	switch c {
	case VulnBenign:
		return "benign"
	case VulnLicenseCheck:
		return "license-check"
	case VulnLicenseBypass:
		return "license-bypass"
	case VulnSignatureSpoof:
		return "signature-spoof"
	case VulnIntegrityTamper:
		return "integrity-tamper"
	case VulnRepackMarker:
		return "repack-marker"
	case VulnNativeBridge:
		return "native-bridge"
	case VulnDynamicLoad:
		return "dynamic-load"
	default:
		return "unknown"
	}
}

// Graph represents a CFG/PDG ready for inference.
type Graph struct {
	RowPtrs    []uint64
	ColIndices []uint64
	EdgeTypes  []uint32
	Features   []float32
	NumNodes   uint64
	FeatureDim uint64
}

// Prediction holds the result of GNN inference.
type Prediction struct {
	ClassProbs     []float32
	PredictedClass VulnClass
	Confidence     float32
}
