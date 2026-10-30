package apkloader

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/parser"
)

func TestSmaliStringLiteralsRoundTrip(t *testing.T) {
	values := []string{"", `C:\temp\new\file`, `literal\n and \"quotes`, "\"\n\r\t\b\f\x00\x01\x1f\x7f", "Привет 世界 😀"}
	p := &DEXParser{strings: values}
	for i, want := range values {
		literal := resolveString(uint32(i), p)
		if !strings.HasPrefix(literal, "\"") || !strings.HasSuffix(literal, "\"") {
			t.Fatalf("not a string literal: %q", literal)
		}
		if got := parser.UnescapeSmaliString(literal[1 : len(literal)-1]); got != want {
			t.Errorf("round trip %q through %q produced %q", want, literal, got)
		}
		for _, c := range literal {
			if c < 0x20 || c == 0x7f {
				t.Errorf("raw control character in %q", literal)
			}
		}
	}
}

func cachedSmaliTestParser(value uint16) *DEXParser {
	return &DEXParser{
		data: []byte{byte(value), byte(value >> 8)},
		classes: []*ClassDef{{ClassName: "Lexample/A;", DirectMethods: []*EncodedMethod{{
			Name: "value", ReturnType: "I", AccessFlags: 8,
			Code: &CodeItem{RegistersSize: 1, Insns: []uint16{value, 0x000f}},
		}}}},
	}
}

func TestSmaliCacheInvalidatesChangedBytecode(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "smali")
	e := &Extractor{}
	for _, value := range []uint16{0x0012, 0x1012, 0x1012} {
		p := cachedSmaliTestParser(value)
		if err := e.generateSmaliIntoCached(context.Background(), p, dir, 2, true); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, "example", "A.smali"))
		if err != nil {
			t.Fatal(err)
		}
		if want := generateSmaliClass(p.classes[0], p); string(got) != want {
			t.Fatalf("cached stale bytecode for %#x:\n%s", value, got)
		}
	}
}

func TestSmaliDecodeCancellationAndPartialFailure(t *testing.T) {
	for _, cache := range []bool{false, true} {
		dir := filepath.Join(t.TempDir(), "smali")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		e := &Extractor{}
		p := cachedSmaliTestParser(0x0012)
		if err := e.generateSmaliIntoCached(ctx, p, dir, 1, cache); !errors.Is(err, context.Canceled) {
			t.Fatalf("cache=%v: cancellation error=%v", cache, err)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("cancelled decode created output: %v", err)
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "blocked"), nil, 0644); err != nil {
			t.Fatal(err)
		}
		p.classes = append(p.classes, &ClassDef{ClassName: "Lblocked/B;"})
		if err := e.generateSmaliIntoCached(context.Background(), p, dir, 1, cache); err == nil {
			t.Fatalf("cache=%v: partial decode reported success", cache)
		}
	}
}

func TestSmaliClassPathRejectsTraversal(t *testing.T) {
	for _, name := range []string{"L../escape;", "Lx/../../escape;", "L/absolute;", `L..\escape;`, "LC:/escape;", "L.;", "L;"} {
		if got := classSmaliRelPath(name); got != "" {
			t.Errorf("accepted %q as %q", name, got)
		}
	}
	if got := classSmaliRelPath("Lexample/A;"); got != filepath.Join("example", "A") {
		t.Fatalf("normal class path=%q", got)
	}
}

func TestSmaliCacheRejectsForgedRecordLengths(t *testing.T) {
	for _, lengths := range [][2]uint64{{1<<32 - 1, 0}, {1, ^uint64(0)}} {
		var data bytes.Buffer
		data.WriteString(cacheMagic)
		data.WriteByte(recPut)
		var header [12]byte
		binary.LittleEndian.PutUint32(header[:4], uint32(lengths[0]))
		binary.LittleEndian.PutUint64(header[4:], lengths[1])
		data.Write(header[:])
		data.Write(make([]byte, 4))
		path := filepath.Join(t.TempDir(), nativeSmaliClassCacheDB)
		if err := os.WriteFile(path, data.Bytes(), 0644); err != nil {
			t.Fatal(err)
		}
		h := &smaliCacheDBHandle{path: path, entries: map[string]SmaliCacheRecord{}}
		if err := h.load(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("forged lengths=%v: %v", lengths, err)
		}
	}
}

func TestSmaliCacheWarmSaveAndPrune(t *testing.T) {
	dir := t.TempDir()
	h := openSmaliCacheDB(dir)
	h.Put("dex", "LA;", "first")
	h.Put("dex", "LB;", "second")
	if err := h.Save(0, 0); err != nil {
		t.Fatal(err)
	}
	h = openSmaliCacheDB(dir)
	stamp := time.Unix(1234567890, 0)
	if err := os.Chtimes(h.path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if got, ok := h.Get("dex", "LA;"); !ok || got != "first" {
		t.Fatalf("cache round trip: %q, %v", got, ok)
	}
	if err := h.Save(0, 0); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(h.path)
	if err != nil || !info.ModTime().Equal(stamp) {
		t.Fatalf("warm save rewrote cache: info=%v, err=%v", info, err)
	}
	if err := h.Save(1, 0); err != nil {
		t.Fatal(err)
	}
	if got := len(openSmaliCacheDB(dir).entries); got != 1 {
		t.Fatalf("prune was not persisted: entries=%d", got)
	}
}

func TestStreamOwnedProgressCountsEmittedClasses(t *testing.T) {
	p := &DEXParser{classes: []*ClassDef{nil, {ClassName: "LA;"}, {}, {ClassName: "LB;"}}}
	var progress [][2]int
	visits := 0
	err := p.StreamOwnedBundle(context.Background(), OwnedDEXOptions{}, func(DEXClassIR, *OwnedEnvironment) error {
		visits++
		return nil
	}, func(done, total int) { progress = append(progress, [2]int{done, total}) })
	if err != nil || visits != 2 || len(progress) != 3 {
		t.Fatalf("err=%v, visits=%d, progress=%v", err, visits, progress)
	}
	for i, step := range progress {
		if step != [2]int{i, 2} {
			t.Fatalf("inconsistent progress: %v", progress)
		}
	}
}

func TestDecodeCacheIncludesSmaliOptions(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "app.apk")
	if err := os.WriteFile(apk, []byte("same APK bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	opts := DecodeOptions{NoResources: true, NoSmali: true}
	base, err := buildDecodeCacheMetadata(apk, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeDecodeCacheMetadata(dir, base); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*DecodeOptions){
		func(o *DecodeOptions) { o.DexBackend = DecompileBackendNative },
		func(o *DecodeOptions) { o.NoSmaliHeaders = true },
		func(o *DecodeOptions) { o.SmaliCfg.UseLocals = true },
		func(o *DecodeOptions) { o.SmaliCfg.APILevel = 28 },
		func(o *DecodeOptions) { o.SmaliCfg.SequentialLabels = true },
		func(o *DecodeOptions) { o.SmaliCfg.NoParameterRegisters = true },
	} {
		changed := opts
		change(&changed)
		meta, err := buildDecodeCacheMetadata(apk, changed)
		if err != nil {
			t.Fatal(err)
		}
		if decodeCacheHit(dir, meta, changed) {
			t.Fatalf("cache ignored changed Smali options: %+v", changed)
		}
	}
}

func TestWalkClassIRBuffersAreIndependent(t *testing.T) {
	p := cachedSmaliTestParser(0x0012)
	p.classes = append(p.classes, &ClassDef{ClassName: "Lexample/B;"})
	var classes []DEXClassIR
	if err := p.WalkClassOwnedProgress(context.Background(), OwnedDEXOptions{}, func(c DEXClassIR) error {
		classes = append(classes, c)
		return nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	first := string(classes[0].IR)
	clear(classes[1].IR)
	clear(p.data)
	if string(classes[0].IR) != first || !strings.Contains(first, "Lexample/A;") {
		t.Fatal("owned class IR aliased another class or parser storage")
	}
}
