package gnn

// GNNFinding represents a single GNN-based vulnerability finding for a method.
type GNNFinding struct {
	// Method name (e.g., "Lcom/app/MyClass;->check()V")
	Method string `json:"method"`
	// File path where the method was found
	FilePath string `json:"file_path,omitempty"`
	// Predicted vulnerability class
	VulnClass string `json:"vuln_class"`
	// Confidence of the prediction (0.0 - 1.0)
	Confidence float32 `json:"confidence"`
	// Per-class probabilities
	ClassProbs map[string]float32 `json:"class_probs,omitempty"`
}
