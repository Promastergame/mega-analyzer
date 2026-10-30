// Package knownset — быстрый префильтр «известно хорошее / известно плохое» по
// sha256 файла и по PURL пакета.
//
// Устройство подчинено одному правилу: ошибка «хорошее» дороже ошибки «плохое».
// Ложное «известно хорошее» может спрятать вредонос, ложное «известно плохое»
// лишь потратит время аналитика. Поэтому:
//
//   - Плохое хранится ТОЧНО (отсортированный список ключей). Попадание в него
//     достоверно, ложных срабатываний нет по построению.
//   - Хорошее хранится в bloom-фильтре: он крошечный и быстрый, но допускает
//     ложные «да». Его вердикт — подсказка («вероятно известно»), решение о
//     пропуске проверок принимает вызывающий код, и Bad всегда старше Good.
//   - Ключи канонизируются одной функцией и при сборке, и при поиске; схема
//     ключей записана в файл и проверяется при открытии. Расхождение схем даёт
//     ошибку открытия, а не тихий «ничего не найдено».
//   - Файл защищён контрольной суммой: повреждённый фильтр с обнулёнными битами
//     молча пропускал бы всё, поэтому битый файл не открывается.
package knownset

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/purl"
)

// Scheme описывает правила построения ключей. Меняется при любом изменении
// канонизации: старые файлы после этого перестанут открываться намеренно.
const Scheme = "mega/knownset/v1: sha256=lowercase-hex; purl=purl.Key"

const (
	magic        = "MKS1"
	maxFileBytes = 1 << 30 // 1 GiB — потолок разумного файла набора
	maxKeyBytes  = 4096
)

// Decision — итог поиска.
type Decision int

const (
	Unknown   Decision = iota // ключа нет ни в одном наборе
	KnownGood                 // вероятно известное хорошее (bloom, возможен ложный «да»)
	KnownBad                  // достоверно известное плохое (точное совпадение)
)

func (d Decision) String() string {
	switch d {
	case KnownGood:
		return "known-good"
	case KnownBad:
		return "known-bad"
	default:
		return "unknown"
	}
}

// ── Ключи ──────────────────────────────────────────────────────────────────

// KeySHA256 канонизирует шестнадцатеричный sha256.
func KeySHA256(hexDigest string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(hexDigest))
	if len(h) != 64 {
		return "", false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	return "sha256:" + h, true
}

// KeyPURL канонизирует PURL. Строка, которая не разбирается, ключа не даёт.
func KeyPURL(s string) (string, bool) {
	k, ok := purl.KeyOf(s)
	if !ok {
		return "", false
	}
	return "purl:" + k, true
}

// ── Bloom ──────────────────────────────────────────────────────────────────

type bloom struct {
	bits []uint64
	m    uint64 // число бит
	k    uint8
	n    uint64 // число добавленных ключей
}

func newBloom(n int, fpr float64) (*bloom, error) {
	if n < 0 {
		return nil, errors.New("knownset: negative capacity")
	}
	if !(fpr > 0 && fpr < 1) {
		return nil, fmt.Errorf("knownset: false-positive rate %v must be in (0,1)", fpr)
	}
	if n == 0 {
		n = 1
	}
	m := math.Ceil(-float64(n) * math.Log(fpr) / (math.Ln2 * math.Ln2))
	if m > float64(maxFileBytes)*8 {
		return nil, errors.New("knownset: requested filter is too large")
	}
	mm := uint64(m)
	if mm < 64 {
		mm = 64
	}
	k := math.Round(float64(mm) / float64(n) * math.Ln2)
	if k < 1 {
		k = 1
	}
	if k > 30 {
		k = 30
	}
	return &bloom{bits: make([]uint64, (mm+63)/64), m: mm, k: uint8(k)}, nil
}

// hashes — двойное хеширование (Kirsch–Mitzenmacher) от sha256 ключа.
func hashes(key string) (h1, h2 uint64) {
	sum := sha256.Sum256([]byte(key))
	h1 = binary.LittleEndian.Uint64(sum[0:8])
	h2 = binary.LittleEndian.Uint64(sum[8:16]) | 1
	return
}

func (b *bloom) add(key string) {
	h1, h2 := hashes(key)
	for i := uint64(0); i < uint64(b.k); i++ {
		pos := (h1 + i*h2) % b.m
		b.bits[pos/64] |= 1 << (pos % 64)
	}
	b.n++
}

func (b *bloom) has(key string) bool {
	h1, h2 := hashes(key)
	for i := uint64(0); i < uint64(b.k); i++ {
		pos := (h1 + i*h2) % b.m
		if b.bits[pos/64]&(1<<(pos%64)) == 0 {
			return false
		}
	}
	return true
}

// estimatedFPR — ожидаемая доля ложных «да» при текущем заполнении.
func (b *bloom) estimatedFPR() float64 {
	if b.n == 0 || b.m == 0 {
		return 0
	}
	return math.Pow(1-math.Exp(-float64(b.k)*float64(b.n)/float64(b.m)), float64(b.k))
}

// ── Bundle ─────────────────────────────────────────────────────────────────

// Bundle — открытый набор: bloom для хорошего, точный список для плохого.
type Bundle struct {
	good *bloom
	bad  []string // отсортирован, без повторов
}

// Lookup ищет канонический ключ. Bad всегда старше Good.
func (b *Bundle) Lookup(key string) Decision {
	if key == "" {
		return Unknown
	}
	i := sort.SearchStrings(b.bad, key)
	if i < len(b.bad) && b.bad[i] == key {
		return KnownBad
	}
	if b.good != nil && b.good.has(key) {
		return KnownGood
	}
	return Unknown
}

// LookupSHA256 канонизирует и ищет sha256. Нечитаемый хеш — Unknown.
func (b *Bundle) LookupSHA256(hexDigest string) Decision {
	k, ok := KeySHA256(hexDigest)
	if !ok {
		return Unknown
	}
	return b.Lookup(k)
}

// LookupPURL канонизирует и ищет PURL. Нечитаемая строка — Unknown.
func (b *Bundle) LookupPURL(s string) Decision {
	k, ok := KeyPURL(s)
	if !ok {
		return Unknown
	}
	return b.Lookup(k)
}

// Stats — сведения о наборе.
type Stats struct {
	GoodKeys      uint64
	BadKeys       int
	FilterBits    uint64
	Hashes        int
	EstimatedFPR  float64 // ожидаемая доля ложных «известно хорошее»
	FilterBytes   int
	BadTableBytes int
}

// Stats возвращает сведения о наборе.
func (b *Bundle) Stats() Stats {
	s := Stats{BadKeys: len(b.bad)}
	for _, k := range b.bad {
		s.BadTableBytes += len(k)
	}
	if b.good != nil {
		s.GoodKeys, s.FilterBits, s.Hashes = b.good.n, b.good.m, int(b.good.k)
		s.EstimatedFPR = b.good.estimatedFPR()
		s.FilterBytes = len(b.good.bits) * 8
	}
	return s
}

// ── Builder ────────────────────────────────────────────────────────────────

// Builder собирает набор. Ключи дедуплицируются; ключ, попавший и в хорошее,
// и в плохое, остаётся плохим (см. Conflicts).
type Builder struct {
	fpr  float64
	good map[string]struct{}
	bad  map[string]struct{}
}

// NewBuilder создаёт сборщик; fpr — целевая доля ложных «известно хорошее».
func NewBuilder(fpr float64) (*Builder, error) {
	if !(fpr > 0 && fpr < 1) {
		return nil, fmt.Errorf("knownset: false-positive rate %v must be in (0,1)", fpr)
	}
	return &Builder{fpr: fpr, good: map[string]struct{}{}, bad: map[string]struct{}{}}, nil
}

func validKey(k string) bool {
	return k != "" && len(k) <= maxKeyBytes && (strings.HasPrefix(k, "sha256:") || strings.HasPrefix(k, "purl:"))
}

// AddGood добавляет канонический ключ хорошего. Возвращает false, если ключ
// не в каноническом виде (получен не через KeySHA256/KeyPURL).
func (b *Builder) AddGood(key string) bool {
	if !validKey(key) {
		return false
	}
	b.good[key] = struct{}{}
	return true
}

// AddBad добавляет канонический ключ плохого.
func (b *Builder) AddBad(key string) bool {
	if !validKey(key) {
		return false
	}
	b.bad[key] = struct{}{}
	return true
}

// BuildResult — итог сборки.
type BuildResult struct {
	Bundle *Bundle
	// Conflicts — ключи, бывшие и в хорошем, и в плохом: оставлены плохими.
	Conflicts int
}

// Build формирует набор.
func (b *Builder) Build() (BuildResult, error) {
	conflicts := 0
	for k := range b.bad {
		if _, ok := b.good[k]; ok {
			delete(b.good, k)
			conflicts++
		}
	}
	bl, err := newBloom(len(b.good), b.fpr)
	if err != nil {
		return BuildResult{}, err
	}
	for k := range b.good {
		bl.add(k)
	}
	bad := make([]string, 0, len(b.bad))
	for k := range b.bad {
		bad = append(bad, k)
	}
	sort.Strings(bad)
	return BuildResult{Bundle: &Bundle{good: bl, bad: bad}, Conflicts: conflicts}, nil
}

// ── Сериализация ───────────────────────────────────────────────────────────
//
// magic(4) | schemeLen u16 | scheme | k u8 | m u64 | n u64 | words u64 | bits...
// | badCount u64 | (keyLen u16 | key)... | sha256 всего предыдущего (32)

// Encode сериализует набор.
func (b *Bundle) Encode() []byte {
	var buf []byte
	buf = append(buf, magic...)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(Scheme)))
	buf = append(buf, Scheme...)
	g := b.good
	if g == nil {
		g = &bloom{bits: make([]uint64, 1), m: 64, k: 1}
	}
	buf = append(buf, g.k)
	buf = binary.LittleEndian.AppendUint64(buf, g.m)
	buf = binary.LittleEndian.AppendUint64(buf, g.n)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(len(g.bits)))
	for _, w := range g.bits {
		buf = binary.LittleEndian.AppendUint64(buf, w)
	}
	buf = binary.LittleEndian.AppendUint64(buf, uint64(len(b.bad)))
	for _, k := range b.bad {
		buf = binary.LittleEndian.AppendUint16(buf, uint16(len(k)))
		buf = append(buf, k...)
	}
	sum := sha256.Sum256(buf)
	return append(buf, sum[:]...)
}

// Decode разбирает и проверяет набор: контрольная сумма, схема ключей, границы.
func Decode(data []byte) (*Bundle, error) {
	if len(data) > maxFileBytes {
		return nil, errors.New("knownset: file too large")
	}
	if len(data) < len(magic)+32 {
		return nil, errors.New("knownset: file too short")
	}
	body, tail := data[:len(data)-32], data[len(data)-32:]
	if sum := sha256.Sum256(body); string(sum[:]) != string(tail) {
		return nil, errors.New("knownset: checksum mismatch (file is corrupt or truncated)")
	}
	r := &reader{b: body}
	if string(r.take(len(magic))) != magic {
		return nil, errors.New("knownset: bad magic")
	}
	scheme := string(r.take(int(r.u16())))
	if r.err == nil && scheme != Scheme {
		return nil, fmt.Errorf("knownset: key scheme mismatch: file %q, this build %q", scheme, Scheme)
	}
	k := r.u8()
	m := r.u64()
	n := r.u64()
	words := r.u64()
	if r.err != nil {
		return nil, r.err
	}
	if k == 0 || k > 30 || m < 64 || words != (m+63)/64 || words > uint64(len(r.b)-r.off)/8 {
		return nil, errors.New("knownset: invalid filter header")
	}
	bits := make([]uint64, words)
	for i := range bits {
		bits[i] = r.u64()
	}
	badCount := r.u64()
	if r.err != nil {
		return nil, r.err
	}
	if badCount > uint64(len(r.b)-r.off)/3 {
		return nil, errors.New("knownset: invalid bad-key count")
	}
	bad := make([]string, 0, badCount)
	for i := uint64(0); i < badCount; i++ {
		l := int(r.u16())
		key := string(r.take(l))
		if r.err != nil {
			return nil, r.err
		}
		if !validKey(key) {
			return nil, errors.New("knownset: malformed bad key")
		}
		if len(bad) > 0 && key <= bad[len(bad)-1] {
			return nil, errors.New("knownset: bad keys are not strictly sorted")
		}
		bad = append(bad, key)
	}
	if r.off != len(r.b) {
		return nil, errors.New("knownset: trailing garbage")
	}
	return &Bundle{good: &bloom{bits: bits, m: m, k: k, n: n}, bad: bad}, nil
}

// Open читает набор с диска.
func Open(path string) (*Bundle, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > maxFileBytes {
		return nil, errors.New("knownset: file too large")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, nil
}

// Save записывает набор атомарно.
func (b *Bundle) Save(path string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b.Encode(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type reader struct {
	b   []byte
	off int
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.off+n > len(r.b) {
		r.err = errors.New("knownset: unexpected end of data")
		return nil
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out
}
func (r *reader) u8() uint8 {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}
func (r *reader) u16() uint16 {
	if b := r.take(2); b != nil {
		return binary.LittleEndian.Uint16(b)
	}
	return 0
}
func (r *reader) u64() uint64 {
	if b := r.take(8); b != nil {
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}
