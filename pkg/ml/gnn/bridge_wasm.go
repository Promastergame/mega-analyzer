//go:build js && wasm

package gnn

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"syscall/js"
)

type Model struct{ handle int }

func LoadModel(path string) (*Model, error) {
	if path == "__dummy__" {
		return nil, fmt.Errorf("browser GNN requires trained weights")
	}
	if js.Global().Get("megaGNNLoad").Type() != js.TypeFunction {
		return nil, fmt.Errorf("Rust GNN runtime is unavailable")
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data := js.Global().Get("Uint8Array").New(len(bytes))
	js.CopyBytesToJS(data, bytes)
	handle := js.Global().Call("megaGNNLoad", data).Int()
	if handle == 0 {
		return nil, fmt.Errorf("Rust rejected GNN weights")
	}
	return &Model{handle: handle}, nil
}
func LoadDummyModel() (*Model, error) { return nil, fmt.Errorf("browser GNN requires trained weights") }
func (*Model) IsDummy() bool          { return false }
func (m *Model) Close() {
	if m.handle != 0 {
		js.Global().Call("megaGNNClose", m.handle)
		m.handle = 0
	}
}
func (m *Model) Infer(g *Graph) (*Prediction, error) {
	if m.handle == 0 || g == nil || g.NumNodes == 0 || g.FeatureDim == 0 || g.NumNodes > 65536 || g.FeatureDim > 256 ||
		uint64(len(g.RowPtrs)) != g.NumNodes+1 || uint64(len(g.Features)) != g.NumNodes*g.FeatureDim ||
		len(g.ColIndices) > 1000000 || (len(g.EdgeTypes) != 0 && len(g.EdgeTypes) != len(g.ColIndices)) {
		return nil, fmt.Errorf("invalid GNN graph")
	}
	// One packed, little-endian buffer; Rust validates the complete tensor.
	bytes := make([]byte, 16+8*(len(g.RowPtrs)+len(g.ColIndices))+4*(len(g.EdgeTypes)+len(g.Features)))
	binary.LittleEndian.PutUint32(bytes, uint32(g.NumNodes))
	binary.LittleEndian.PutUint32(bytes[4:], uint32(g.FeatureDim))
	binary.LittleEndian.PutUint32(bytes[8:], uint32(len(g.ColIndices)))
	binary.LittleEndian.PutUint32(bytes[12:], uint32(len(g.EdgeTypes)))
	offset := 16
	for _, values := range [][]uint64{g.RowPtrs, g.ColIndices} {
		for _, v := range values {
			binary.LittleEndian.PutUint64(bytes[offset:], v)
			offset += 8
		}
	}
	for _, v := range g.EdgeTypes {
		binary.LittleEndian.PutUint32(bytes[offset:], v)
		offset += 4
	}
	for _, v := range g.Features {
		binary.LittleEndian.PutUint32(bytes[offset:], math.Float32bits(v))
		offset += 4
	}
	data := js.Global().Get("Uint8Array").New(len(bytes))
	js.CopyBytesToJS(data, bytes)
	out := js.Global().Call("megaGNNInfer", m.handle, data)
	if out.IsNull() || out.IsUndefined() || out.Length() != NumVulnClasses {
		return nil, fmt.Errorf("Rust GNN inference failed")
	}
	probs := make([]float32, NumVulnClasses)
	best := 0
	var sum float64
	for i := range probs {
		p := out.Index(i).Float()
		if math.IsNaN(p) || math.IsInf(p, 0) || p < 0 || p > 1 {
			return nil, fmt.Errorf("invalid GNN probability")
		}
		probs[i] = float32(p)
		sum += p
		if probs[i] > probs[best] {
			best = i
		}
	}
	if math.Abs(sum-1) > 1e-3 {
		return nil, fmt.Errorf("invalid GNN probability sum")
	}
	return &Prediction{ClassProbs: probs, PredictedClass: VulnClass(best), Confidence: probs[best]}, nil
}
