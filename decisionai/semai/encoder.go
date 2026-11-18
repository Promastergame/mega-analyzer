package semai

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Encoder is a from-scratch, stdlib-only BERT-style Transformer encoder (multi-head self-attention,
// residual + LayerNorm, GELU feed-forward) with a WordPiece tokenizer. It runs on the CPU, needs no CGO,
// and loads the compact DTE1 weights written by scripts/convert_encoder.py.
type Encoder struct {
	fingerprint   string
	Source        string
	hidden, nHead int
	inter, maxPos int
	eps           float32
	lower         bool
	vocab         map[string]int
	pieces        []string
	word          []int8
	wordScale     []float32
	pos, typ0     []float32
	typ1          []float32
	poolW, poolB  []float32
	nliW, nliB    []float32
	embLN         ln
	layers        []layer
	unk, cls, sep int
	cross         *Encoder // optional NLI cross-encoder attached with AttachCross
	acc           accel    // optional native forward pass (Nim, build tag nim)
}

// AttachCross links a fine-tuned NLI cross-encoder (see LoadCrossEncoder) to this bi-encoder.
func (e *Encoder) AttachCross(c *Encoder) { e.cross = c }
func crossOf(e *Encoder) *Encoder {
	if e == nil || !e.cross.HasNLI() {
		return nil
	}
	return e.cross
}

type ln struct{ w, b []float32 }
type lin struct {
	w, b    []float32
	in, out int
}
type layer struct {
	q, k, v, o, f1, f2 lin
	ln1, ln2           ln
}

// Encoding is the result of running the Transformer over one text.
type Encoding struct {
	Pieces []string    // WordPiece tokens including [CLS]/[SEP]
	CLS    []float32   // L2-normalised sentence vector
	Mean   []float32   // L2-normalised mean-pooled vector
	Tokens [][]float32 // L2-normalised contextual token vectors
}

type dteTensor struct {
	Name  string `json:"name"`
	Dtype string `json:"dtype"`
	Shape []int  `json:"shape"`
	Off   int    `json:"offset"`
	Size  int    `json:"size"`
}
type dteMeta struct {
	Format  string      `json:"format"`
	Source  string      `json:"source"`
	Hidden  int         `json:"hidden"`
	Layers  int         `json:"layers"`
	Heads   int         `json:"heads"`
	Inter   int         `json:"inter"`
	VocabSz int         `json:"vocab_size"`
	MaxPos  int         `json:"max_pos"`
	Eps     float64     `json:"eps"`
	Lower   bool        `json:"lower"`
	Vocab   string      `json:"vocab"`
	Tensors []dteTensor `json:"tensors"`
}

// LoadEncoder reads a DTE1 file.
func LoadEncoder(path string) (*Encoder, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseEncoder(b)
}

// ParseEncoder parses DTE1 bytes. All sizes are validated before allocation.
func ParseEncoder(b []byte) (*Encoder, error) { return parseDTE(b, nil) }

// LoadCrossEncoder reads a fine-tuned NLI cross-encoder file that shares the (frozen) vocabulary and word
// embeddings of base, so only the Transformer layers and the classification head are stored.
func LoadCrossEncoder(path string, base *Encoder) (*Encoder, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseDTE(b, base)
}

// BaseModel is the pre-trained checkpoint an encoder was derived from (Source up to " + ").
func BaseModel(source string) string {
	if i := strings.Index(source, " + "); i >= 0 {
		return source[:i]
	}
	return source
}

// ErrBaseRequired identifies a shared-table DTE that needs a compatible encoder.
// Callers can load the requested base and retry without masking other failures.
var ErrBaseRequired = errors.New("encoder requires a compatible base word table")

// LoadCrossEncoderAny accepts self-contained DTEs without a base. A shared-table
// file borrows from the first compatible BaseModel, retaining the legacy first
// non-nil base fallback for files without checkpoint-qualified source names.
func LoadCrossEncoderAny(path string, bases ...*Encoder) (*Encoder, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var base *Encoder
	for _, candidate := range bases {
		if candidate != nil {
			base = candidate
			break
		}
	}
	if len(b) >= 8 && string(b[:4]) == "DTE1" {
		if hl := int(binary.LittleEndian.Uint32(b[4:8])); hl > 0 && 8+hl <= len(b) {
			var m struct {
				Source  string `json:"source"`
				VocabSz int    `json:"vocab_size"`
			}
			if json.Unmarshal(b[8:8+hl], &m) == nil {
				found := false
				for _, c := range bases {
					if c != nil && BaseModel(c.Source) == BaseModel(m.Source) {
						base, found = c, true
						break
					}
				}
				if !found && m.VocabSz == 0 && base != nil && strings.Contains(BaseModel(m.Source), "/") && strings.Contains(BaseModel(base.Source), "/") {
					// Let parseDTE validate the file before reporting that a
					// different base is needed.
					base = nil
				}
			}
		}
	}
	return parseDTE(b, base)
}

func parseDTE(b []byte, base *Encoder) (*Encoder, error) {
	if len(b) < 8 || string(b[:4]) != "DTE1" {
		return nil, fmt.Errorf("encoder: not a DTE1 file")
	}
	hl := int(binary.LittleEndian.Uint32(b[4:8]))
	if hl <= 0 || 8+hl > len(b) {
		return nil, fmt.Errorf("encoder: bad header")
	}
	var m dteMeta
	if err := json.Unmarshal(b[8:8+hl], &m); err != nil {
		return nil, fmt.Errorf("encoder: %v", err)
	}
	if m.Hidden <= 0 || m.Hidden > 2048 || m.Layers <= 0 || m.Layers > 32 || m.Heads <= 0 || m.Hidden%m.Heads != 0 || m.Inter <= 0 || m.Inter > 8192 || m.MaxPos < 8 || m.MaxPos > 4096 {
		return nil, fmt.Errorf("encoder: unsupported dimensions")
	}
	data := b[8+hl:]
	idx := map[string]dteTensor{}
	for _, t := range m.Tensors {
		if t.Off < 0 || t.Size < 0 || t.Off+t.Size > len(data) {
			return nil, fmt.Errorf("encoder: tensor %q out of range", t.Name)
		}
		idx[t.Name] = t
	}
	if m.VocabSz == 0 && base == nil {
		return nil, fmt.Errorf("%w: %s", ErrBaseRequired, BaseModel(m.Source))
	}
	f32 := func(name string, want int) ([]float32, error) {
		t, ok := idx[name]
		if !ok || t.Dtype != "f32" || t.Size != 4*want {
			return nil, fmt.Errorf("encoder: tensor %q missing or wrong size", name)
		}
		out := make([]float32, want)
		for i := range out {
			out[i] = math.Float32frombits(binary.LittleEndian.Uint32(data[t.Off+4*i:]))
		}
		return out, nil
	}
	e := &Encoder{Source: m.Source, hidden: m.Hidden, nHead: m.Heads, inter: m.Inter, maxPos: m.MaxPos, eps: float32(m.Eps), lower: m.Lower}
	ownWord := base == nil || m.VocabSz > 0 // a fine-tuned file may carry its own word table
	// A file with its own table may reuse the base only when tokenizer,
	// quantized weights and scales are all bit-identical. Check before
	// allocating another table; checkpoint names alone are not sufficient.
	if ownWord && base != nil && identicalWordTable(m, idx, data, base) {
		ownWord = false
	}
	if !ownWord {
		if base.hidden != m.Hidden {
			return nil, fmt.Errorf("encoder: hidden size differs from base")
		}
		e.pieces, e.vocab, e.word, e.wordScale = base.pieces, base.vocab, base.word, base.wordScale
		e.unk, e.cls, e.sep, e.lower = base.unk, base.cls, base.sep, base.lower
	} else {
		// Tokenizer sharing is independent of embedding sharing: two
		// fine-tunes may use different word weights with the same vocabulary.
		if identicalTokenizer(m, base) {
			e.pieces, e.vocab = base.pieces, base.vocab
			e.unk, e.cls, e.sep = base.unk, base.cls, base.sep
		} else {
			e.pieces = strings.Split(m.Vocab, "\n")
			if len(e.pieces) != m.VocabSz {
				return nil, fmt.Errorf("encoder: vocab size mismatch")
			}
			e.vocab = make(map[string]int, len(e.pieces))
			for i, p := range e.pieces {
				if _, dup := e.vocab[p]; !dup {
					e.vocab[p] = i
				}
			}
			var ok bool
			if e.unk, ok = e.vocab["[UNK]"]; !ok {
				return nil, fmt.Errorf("encoder: vocab lacks [UNK]")
			}
			if e.cls, ok = e.vocab["[CLS]"]; !ok {
				return nil, fmt.Errorf("encoder: vocab lacks [CLS]")
			}
			if e.sep, ok = e.vocab["[SEP]"]; !ok {
				return nil, fmt.Errorf("encoder: vocab lacks [SEP]")
			}
		}
		wt, ok := idx["word"]
		if !ok || wt.Dtype != "i8r" || wt.Size != m.VocabSz*m.Hidden {
			return nil, fmt.Errorf("encoder: bad word table")
		}
		e.word = make([]int8, wt.Size)
		for i := range e.word {
			e.word[i] = int8(data[wt.Off+i])
		}
	}
	var err error
	if ownWord {
		if e.wordScale, err = f32("word.scale", m.VocabSz); err != nil {
			return nil, err
		}
	}
	if e.pos, err = f32("pos", m.MaxPos*m.Hidden); err != nil {
		return nil, err
	}
	t2, err := f32("type", 2*m.Hidden)
	if err != nil {
		return nil, err
	}
	e.typ0, e.typ1 = t2[:m.Hidden], t2[m.Hidden:]
	if _, has := idx["nli.w"]; has {
		if e.poolW, err = f32("pool.w", m.Hidden*m.Hidden); err != nil {
			return nil, err
		}
		if e.poolB, err = f32("pool.b", m.Hidden); err != nil {
			return nil, err
		}
		if e.nliW, err = f32("nli.w", 3*m.Hidden); err != nil {
			return nil, err
		}
		if e.nliB, err = f32("nli.b", 3); err != nil {
			return nil, err
		}
	}
	getLN := func(p string) (ln, error) {
		w, err := f32(p+".w", m.Hidden)
		if err != nil {
			return ln{}, err
		}
		bb, err := f32(p+".b", m.Hidden)
		return ln{w, bb}, err
	}
	getLin := func(p string, in, out int) (lin, error) {
		w, err := f32(p+".w", in*out)
		if err != nil {
			return lin{}, err
		}
		bb, err := f32(p+".b", out)
		return lin{w, bb, in, out}, err
	}
	if e.embLN, err = getLN("emb_ln"); err != nil {
		return nil, err
	}
	for i := 0; i < m.Layers; i++ {
		var L layer
		p := fmt.Sprintf("l%d.", i)
		for _, it := range []struct {
			dst  *lin
			n    string
			a, b int
		}{{&L.q, "q", m.Hidden, m.Hidden}, {&L.k, "k", m.Hidden, m.Hidden}, {&L.v, "v", m.Hidden, m.Hidden}, {&L.o, "o", m.Hidden, m.Hidden}, {&L.f1, "f1", m.Hidden, m.Inter}, {&L.f2, "f2", m.Inter, m.Hidden}} {
			if *it.dst, err = getLin(p+it.n, it.a, it.b); err != nil {
				return nil, err
			}
		}
		if L.ln1, err = getLN(p + "ln1"); err != nil {
			return nil, err
		}
		if L.ln2, err = getLN(p + "ln2"); err != nil {
			return nil, err
		}
		e.layers = append(e.layers, L)
	}
	if newAccel != nil && os.Getenv("DAI_NO_NIM") == "" {
		e.acc = newAccel(e)
	}
	identity := sha256.New()
	identity.Write(b)
	if m.VocabSz == 0 && base != nil {
		identity.Write([]byte(base.Fingerprint()))
	}
	e.fingerprint = hex.EncodeToString(identity.Sum(nil))
	return e, nil
}

// Loaded tables are immutable during inference. No process-global cache is
// used: sharing is limited to the explicitly supplied, already loaded base.
func identicalTokenizer(m dteMeta, base *Encoder) bool {
	if base == nil || base.lower != m.Lower || len(base.pieces) != m.VocabSz {
		return false
	}
	// Compare without joining/splitting the entire vocabulary again.
	pos := 0
	for i, piece := range base.pieces {
		end := pos + len(piece)
		if end > len(m.Vocab) || m.Vocab[pos:end] != piece {
			return false
		}
		pos = end
		if i+1 < len(base.pieces) {
			if pos >= len(m.Vocab) || m.Vocab[pos] != '\n' {
				return false
			}
			pos++
		}
	}
	return pos == len(m.Vocab)
}

func identicalWordTable(m dteMeta, idx map[string]dteTensor, data []byte, base *Encoder) bool {
	if base.hidden != m.Hidden || base.lower != m.Lower ||
		len(base.pieces) != m.VocabSz || len(base.word) != m.VocabSz*m.Hidden ||
		len(base.wordScale) != m.VocabSz {
		return false
	}
	if !identicalTokenizer(m, base) {
		return false
	}
	wt, ok := idx["word"]
	if !ok || wt.Dtype != "i8r" || wt.Size != len(base.word) {
		return false
	}
	st, ok := idx["word.scale"]
	if !ok || st.Dtype != "f32" || st.Size != 4*len(base.wordScale) {
		return false
	}
	// Tensor ranges were validated by parseDTE before this helper is called.
	for i, v := range base.word {
		if int8(data[wt.Off+i]) != v {
			return false
		}
	}
	for i, v := range base.wordScale {
		if binary.LittleEndian.Uint32(data[st.Off+4*i:]) != math.Float32bits(v) {
			return false
		}
	}
	return true
}

// ---------- tokenizer (BERT BasicTokenizer + WordPiece) ----------

func isPunct(r rune) bool {
	if (r >= 33 && r <= 47) || (r >= 58 && r <= 64) || (r >= 91 && r <= 96) || (r >= 123 && r <= 126) {
		return true
	}
	return unicode.IsPunct(r)
}
func isCJK(r rune) bool {
	return (r >= 0x4E00 && r <= 0x9FFF) || (r >= 0x3400 && r <= 0x4DBF) || (r >= 0x20000 && r <= 0x2A6DF) || (r >= 0xF900 && r <= 0xFAFF)
}

func (e *Encoder) basic(text string) []string {
	var b strings.Builder
	for _, r := range text {
		if r == 0 || r == 0xFFFD || (unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r') {
			continue
		}
		if unicode.IsSpace(r) {
			b.WriteByte(' ')
			continue
		}
		if isCJK(r) {
			b.WriteRune(' ')
			b.WriteRune(r)
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	var out []string
	for _, w := range strings.Fields(b.String()) {
		if e.lower {
			w = strings.ToLower(w)
		}
		var cur []rune
		flush := func() {
			if len(cur) > 0 {
				out = append(out, string(cur))
				cur = cur[:0]
			}
		}
		for _, r := range w {
			if isPunct(r) {
				flush()
				out = append(out, string(r))
			} else {
				cur = append(cur, r)
			}
		}
		flush()
	}
	return out
}

func (e *Encoder) wordpiece(w string) []int {
	if utf8.RuneCountInString(w) > 100 {
		return []int{e.unk}
	}
	rs := []rune(w)
	var ids []int
	for start := 0; start < len(rs); {
		end, found := len(rs), -1
		for ; end > start; end-- {
			s := string(rs[start:end])
			if start > 0 {
				s = "##" + s
			}
			if id, ok := e.vocab[s]; ok {
				found = id
				break
			}
		}
		if found < 0 {
			return []int{e.unk}
		}
		ids = append(ids, found)
		start = end
	}
	return ids
}

// Tokenize returns token ids with [CLS]/[SEP], truncated to maxLen (<= model max).
func (e *Encoder) Tokenize(text string, maxLen int) []int {
	if maxLen <= 2 || maxLen > e.maxPos {
		maxLen = e.maxPos
	}
	ids := []int{e.cls}
	for _, w := range e.basic(text) {
		ids = append(ids, e.wordpiece(w)...)
		if len(ids) >= maxLen-1 {
			break
		}
	}
	if len(ids) > maxLen-1 {
		ids = ids[:maxLen-1]
	}
	return append(ids, e.sep)
}

// Fingerprint binds the exact DTE bytes and any borrowed base weights.
func (e *Encoder) Fingerprint() string {
	if e == nil {
		return ""
	}
	return e.fingerprint
}

// TokenCount counts without max-position truncation. Includes CLS and SEP.
func (e *Encoder) TokenCount(text string) int {
	n := 2
	for _, word := range e.basic(text) {
		n += len(e.wordpiece(word))
	}
	return n
}

// ---------- forward pass ----------

// fastExp32 is a Cephes-style expf ported from nim/dainim.nim (fexp):
// 2^n · p(r), |rel err| ~= 2e-7, branch-free. Stays in float32 so the
// hot softmax loop avoids a float64 round-trip per element.
func fastExp32(x float32) float32 {
	if x < -87 {
		return 0
	}
	if x > 88 {
		return math.MaxFloat32
	}
	f := x*1.44269504 + 0.5
	t := int32(f)
	if float32(t) > f {
		t--
	}
	fx := float32(t)
	r := x - fx*0.693359375 + fx*float32(2.12194440e-4)
	var y float32 = 1.9875691500e-4
	y = y*r + float32(1.3981999507e-3)
	y = y*r + float32(8.3334519073e-3)
	y = y*r + float32(4.1665795894e-2)
	y = y*r + float32(1.6666665459e-1)
	y = y*r + float32(5.0000001201e-1)
	y = y*r*r + r + 1
	return y * math.Float32frombits(uint32(int32(fx)+127)<<23)
}

// fastErf32 is Abramowitz–Stegun 7.1.26 ported from nim/dainim.nim (ferf),
// |abs err| <= 1.5e-7. Uses fastExp32 instead of a float64 exp.
func fastErf32(x float32) float32 {
	a := x
	if a < 0 {
		a = -a
	}
	t := 1 / (1 + 0.3275911*a)
	p := 1.061405429*t - 1.453152027
	p = p*t + 1.421413741
	p = p*t - 0.284496736
	p = p*t + 0.254829592
	e := 1 - p*t*fastExp32(-a*a)
	if x < 0 {
		return -e
	}
	return e
}

// geluFast matches nim/dainim.nim's fused GELU within ~1e-6 and avoids
// math.Erf (float64) per element. NimParity tolerates 1e-4 on the mean.
func geluFast(x float32) float32 { return 0.5 * x * (1 + fastErf32(x*0.70710678)) }

func (l lin) apply(x []float32, n int) []float32 {
	out := make([]float32, n*l.out)
	l.applyInto(x, n, out)
	return out
}

// applyInto writes y[n×out] = x[n×in]·Wᵀ + b, processing 4 tokens together
// so every weight row is loaded once per 4 tokens (same register blocking as
// nim/dainim.nim's non-FASM path). y must have room for n*l.out floats.
func (l lin) applyInto(x []float32, n int, y []float32) {
	ni, no := l.in, l.out
	w, b := l.w, l.b
	t := 0
	for t+4 <= n {
		x0 := t * ni
		x1 := x0 + ni
		x2 := x1 + ni
		x3 := x2 + ni
		y0 := t * no
		for o := 0; o < no; o++ {
			wr := o * ni
			var s0, s1, s2, s3 float32
			for i := 0; i < ni; i++ {
				wv := w[wr+i]
				s0 += x[x0+i] * wv
				s1 += x[x1+i] * wv
				s2 += x[x2+i] * wv
				s3 += x[x3+i] * wv
			}
			bo := b[o]
			y[y0+o] = s0 + bo
			y[y0+no+o] = s1 + bo
			y[y0+2*no+o] = s2 + bo
			y[y0+3*no+o] = s3 + bo
		}
		t += 4
	}
	for t < n {
		x0 := t * ni
		y0 := t * no
		for o := 0; o < no; o++ {
			wr := o * ni
			var s float32
			for i := 0; i < ni; i++ {
				s += x[x0+i] * w[wr+i]
			}
			y[y0+o] = s + b[o]
		}
		t++
	}
}

// dot is a 4-way unrolled float32 dot product (independent accumulators let the
// CPU pipeline the multiplies; ~2-3x faster than the naive loop on SSE2-only targets).
func dot(a, b []float32) float32 {
	n := len(a)
	b = b[:n]
	var s0, s1, s2, s3 float32
	i := 0
	for ; i+4 <= n; i += 4 {
		s0 += a[i] * b[i]
		s1 += a[i+1] * b[i+1]
		s2 += a[i+2] * b[i+2]
		s3 += a[i+3] * b[i+3]
	}
	for ; i < n; i++ {
		s0 += a[i] * b[i]
	}
	return (s0 + s1) + (s2 + s3)
}

func (n ln) apply(x []float32, rows, d int, eps float32) {
	for r := 0; r < rows; r++ {
		v := x[r*d : (r+1)*d]
		var mean float32
		for _, a := range v {
			mean += a
		}
		mean /= float32(d)
		var vr float32
		for _, a := range v {
			vr += (a - mean) * (a - mean)
		}
		inv := float32(1 / math.Sqrt(float64(vr/float32(d)+eps)))
		for i := range v {
			v[i] = (v[i]-mean)*inv*n.w[i] + n.b[i]
		}
	}
}
func gelu(x float32) float32 { return 0.5 * x * float32(1+math.Erf(float64(x)/math.Sqrt2)) }

func normalize(v []float32) []float32 {
	var s float64
	for _, a := range v {
		s += float64(a) * float64(a)
	}
	out := make([]float32, len(v))
	if s == 0 {
		return out
	}
	inv := float32(1 / math.Sqrt(s))
	for i, a := range v {
		out[i] = a * inv
	}
	return out
}

// Encode runs the Transformer. Input is capped at 128 word pieces.
func (e *Encoder) Encode(text string) *Encoding {
	ids := e.Tokenize(text, 128)
	x := e.forward(ids, nil)
	n, d := len(ids), e.hidden
	enc := &Encoding{Pieces: make([]string, n), Tokens: make([][]float32, n)}
	mean := make([]float32, d)
	for t := 0; t < n; t++ {
		enc.Pieces[t] = e.pieces[ids[t]]
		row := x[t*d : (t+1)*d]
		enc.Tokens[t] = normalize(row)
		for i, a := range row {
			mean[i] += a / float32(n)
		}
	}
	enc.CLS = normalize(x[:d])
	enc.Mean = normalize(mean)
	return enc
}

// forward runs embeddings + all layers; seg (optional) holds the token-type id per position.
func (e *Encoder) forward(ids []int, seg []int) []float32 {
	n, d := len(ids), e.hidden
	x := make([]float32, n*d)
	for t, id := range ids {
		row := e.word[id*d : (id+1)*d]
		sc := e.wordScale[id]
		ty := e.typ0
		if seg != nil && seg[t] == 1 {
			ty = e.typ1
		}
		for i := 0; i < d; i++ {
			x[t*d+i] = float32(row[i])*sc + e.pos[t*d+i] + ty[i]
		}
	}
	if e.acc != nil && e.acc.forward(x, n) {
		return x
	}
	e.embLN.apply(x, n, d, e.eps)
	hd := d / e.nHead
	scale := float32(1 / math.Sqrt(float64(hd)))
	// Scratch buffers are allocated once and reused across layers: the old
	// code allocated q/k/v/ctx/a/f/g per layer (~1.4 MiB of garbage per layer
	// at 128 tokens), pressuring the GC on every Encode. Sizes are constant
	// across layers (hidden/inter), so reuse is safe; applyInto fully
	// overwrites its output and ctx is explicitly zeroed per layer.
	inter := e.inter
	q := make([]float32, n*d)
	k := make([]float32, n*d)
	v := make([]float32, n*d)
	ctx := make([]float32, n*d)
	a := make([]float32, n*d)
	f := make([]float32, n*inter)
	g := make([]float32, n*d)
	sc := make([]float32, n)
	for _, L := range e.layers {
		L.q.applyInto(x, n, q)
		L.k.applyInto(x, n, k)
		L.v.applyInto(x, n, v)
		for i := range ctx {
			ctx[i] = 0
		}
		for h := 0; h < e.nHead; h++ {
			off := h * hd
			for i := 0; i < n; i++ {
				mx := float32(-1e30)
				for j := 0; j < n; j++ {
					var s float32
					for c := 0; c < hd; c++ {
						s += q[i*d+off+c] * k[j*d+off+c]
					}
					s *= scale
					sc[j] = s
					if s > mx {
						mx = s
					}
				}
				var z float32
				for j := range sc {
					ev := fastExp32(sc[j] - mx)
					sc[j] = ev
					z += ev
				}
				iz := 1 / z
				for j := 0; j < n; j++ {
					p := sc[j] * iz
					for c := 0; c < hd; c++ {
						ctx[i*d+off+c] += p * v[j*d+off+c]
					}
				}
			}
		}
		L.o.applyInto(ctx, n, a)
		for i := range a {
			a[i] += x[i]
		}
		L.ln1.apply(a, n, d, e.eps)
		L.f1.applyInto(a, n, f)
		for i := range f {
			f[i] = geluFast(f[i])
		}
		L.f2.applyInto(f, n, g)
		for i := range g {
			g[i] += a[i]
		}
		L.ln2.apply(g, n, d, e.eps)
		x, g = g, x
	}
	return x
}

// Cosine of two L2-normalised vectors.
func Cosine(a, b []float32) float64 {
	var s float64
	for i := range a {
		s += float64(a[i]) * float64(b[i])
	}
	return s
}

// MaxSim is a ColBERT-style late-interaction score: for every token of a, its best match in b, averaged.
// Special tokens are ignored.
func MaxSim(a, b *Encoding) float64 {
	if len(a.Tokens) < 3 || len(b.Tokens) < 3 {
		return 0
	}
	var tot float64
	cnt := 0
	for i := 1; i < len(a.Tokens)-1; i++ {
		best := -1.0
		for j := 1; j < len(b.Tokens)-1; j++ {
			if c := Cosine(a.Tokens[i], b.Tokens[j]); c > best {
				best = c
			}
		}
		tot += best
		cnt++
	}
	return tot / float64(cnt)
}

// NLI is the cross-encoder verdict about "premise ⇒ hypothesis".
type NLI struct {
	Entailment    float64 `json:"entailment"`
	Neutral       float64 `json:"neutral"`
	Contradiction float64 `json:"contradiction"`
}

// HasNLI reports whether a fine-tuned classification head is loaded.
func (e *Encoder) HasNLI() bool { return e != nil && e.nliW != nil }

func (e *Encoder) pieceIDs(text string) []int {
	var ids []int
	for _, w := range e.basic(text) {
		ids = append(ids, e.wordpiece(w)...)
		if len(ids) > 200 {
			break
		}
	}
	return ids
}

// Classify jointly encodes [CLS] premise [SEP] hypothesis [SEP] (full cross-attention between both texts)
// and returns calibrated three-way probabilities.
func (e *Encoder) Classify(premise, hypothesis string) NLI {
	a, b := e.pieceIDs(premise), e.pieceIDs(hypothesis)
	const maxTotal = 93 // 96 - three special tokens
	for len(a)+len(b) > maxTotal {
		if len(a) > len(b) {
			a = a[:len(a)-1]
		} else {
			b = b[:len(b)-1]
		}
	}
	ids := append([]int{e.cls}, a...)
	ids = append(ids, e.sep)
	seg := make([]int, len(ids))
	ids = append(ids, b...)
	ids = append(ids, e.sep)
	for len(seg) < len(ids) {
		seg = append(seg, 1)
	}
	x := e.forward(ids, seg)
	d := e.hidden
	pooled := make([]float32, d)
	for o := 0; o < d; o++ {
		s := e.poolB[o]
		for i := 0; i < d; i++ {
			s += x[i] * e.poolW[o*d+i]
		}
		pooled[o] = float32(math.Tanh(float64(s)))
	}
	var lg [3]float64
	for c := 0; c < 3; c++ {
		s := e.nliB[c]
		for i := 0; i < d; i++ {
			s += pooled[i] * e.nliW[c*d+i]
		}
		lg[c] = float64(s)
	}
	mx := math.Max(lg[0], math.Max(lg[1], lg[2]))
	var z float64
	for c := range lg {
		lg[c] = math.Exp(lg[c] - mx)
		z += lg[c]
	}
	return NLI{lg[0] / z, lg[1] / z, lg[2] / z}
}
