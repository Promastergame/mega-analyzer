// Package hdc implements pure-Go hyperdimensional computing (HDC) used by the
// arbiter as a cheap, explainable similarity layer.
//
// Design goals (mirror the project principles): 100% offline, CPU-only, zero
// external deps. A hypervector is 2048 bits packed into 32 uint64 words, so a
// similarity check is a handful of POPCOUNTs (tens of nanoseconds) and a record
// costs ~256 bytes of RAM. This is the fast k-NN sieve in front of the
// (optional, cgo) GNN and the RAG precedent store.
package hdc

import (
	"hash/fnv"
	"math/bits"
)

// D is the hypervector dimensionality in bits. 2048 bits = 32 uint64 words.
const D = 2048

const words = D / 64

// Vector is a binary hypervector packed into words.
type Vector struct{ w [words]uint64 }

// Atom returns a deterministic pseudo-random hypervector for a symbol.
// Same seed -> same vector across runs (stable, no training, reproducible).
func Atom(seed string) Vector {
	var v Vector
	for i := 0; i < words; i++ {
		h := fnv.New64a()
		_, _ = h.Write([]byte(seed))
		_, _ = h.Write([]byte{byte(i)})
		v.w[i] = h.Sum64()
	}
	return v
}

// Bind combines two vectors (XOR): associates a role with a value. Invertible,
// since (a^b)^b == a. Use it to tie a feature name to its feature value.
func (v Vector) Bind(o Vector) Vector {
	var r Vector
	for i := 0; i < words; i++ {
		r.w[i] = v.w[i] ^ o.w[i]
	}
	return r
}

// Bundle superposes vectors via bitwise majority. The result is similar to all
// of its inputs, which is how a set of features collapses into one signature.
func Bundle(vs ...Vector) Vector {
	var r Vector
	n := len(vs)
	if n == 0 {
		return r
	}
	threshold := n / 2
	for bit := 0; bit < D; bit++ {
		wi, bi := bit/64, uint(bit%64)
		count := 0
		for _, v := range vs {
			if v.w[wi]&(1<<bi) != 0 {
				count++
			}
		}
		// Strict majority; deterministic tie-break on even counts.
		if count > threshold || (n%2 == 0 && count == threshold && bit&1 == 0) {
			r.w[wi] |= 1 << bi
		}
	}
	return r
}

// Hamming returns the number of differing bits between two vectors.
func (v Vector) Hamming(o Vector) int {
	d := 0
	for i := 0; i < words; i++ {
		d += bits.OnesCount64(v.w[i] ^ o.w[i])
	}
	return d
}

// Sim returns similarity in [0,1]: 1 = identical, 0 = fully opposite,
// ~0.5 = unrelated random vectors.
func (v Vector) Sim(o Vector) float32 {
	return 1 - float32(v.Hamming(o))/float32(D)
}

// EncodeFeatures binds each (role,value) pair and bundles them into a single
// signature hypervector. This is what the arbiter hashes a finding/patch into.
func EncodeFeatures(feats map[string]string) Vector {
	if len(feats) == 0 {
		return Vector{}
	}
	bound := make([]Vector, 0, len(feats))
	for role, val := range feats {
		bound = append(bound, Atom("role:"+role).Bind(Atom("val:"+val)))
	}
	return Bundle(bound...)
}
