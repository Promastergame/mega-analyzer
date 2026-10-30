package apkloader

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
)

// Each class has one direct and one virtual method with three code units.
// The methods share an immutable code_item, as permitted by the DEX format.
func parserWithConcurrentClassData(classCount int) *DEXParser {
	const codeOffset, classDataOffset, classDataSize = 16, 64, 10
	p := &DEXParser{
		data:    make([]byte, classDataOffset+classCount*classDataSize),
		methods: make([]*Method, classCount*2),
		classes: make([]*ClassDef, classCount),
	}
	binary.LittleEndian.PutUint32(p.data[codeOffset+12:], 3)
	binary.LittleEndian.PutUint16(p.data[codeOffset+20:], 0x0e) // return-void
	for i := range p.classes {
		name := fmt.Sprintf("LClass%d;", i)
		offset := classDataOffset + i*classDataSize
		// All method indexes and offsets fit in one ULEB128 byte.
		copy(p.data[offset:], []byte{0, 0, 1, 1, byte(i * 2), 9, codeOffset, byte(i*2 + 1), 1, codeOffset})
		p.classes[i] = &ClassDef{ClassName: name, ClassDataOff: uint32(offset)}
		p.methods[i*2] = &Method{ClassName: name, MethodName: "direct", ReturnType: "V"}
		p.methods[i*2+1] = &Method{ClassName: name, MethodName: "virtual", ReturnType: "V"}
	}
	return p
}

func TestParseAllClassDataCodeMetrics(t *testing.T) {
	const classCount = 64
	p := parserWithConcurrentClassData(classCount)
	if err := p.parseAllClassData(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, class := range p.classes {
		if len(class.DirectMethods) != 1 || len(class.VirtualMethods) != 1 {
			t.Fatalf("missing methods in %s", class.ClassName)
		}
	}
	const wantUnits = classCount * 2 * 3
	if p.Metrics.InstructionCount != wantUnits || p.Metrics.TotalCodeBytes != wantUnits*2 {
		t.Fatalf("code metrics lost updates: got %d units / %d bytes, want %d / %d",
			p.Metrics.InstructionCount, p.Metrics.TotalCodeBytes, wantUnits, wantUnits*2)
	}
}

func TestEnsureCodeConcurrent(t *testing.T) {
	p := parserWithConcurrentClassData(1)
	p.lazyCode = true
	if err := p.parseAllClassData(context.Background()); err != nil {
		t.Fatal(err)
	}
	method := p.classes[0].DirectMethods[0]
	start := make(chan struct{})
	results := make([]*CodeItem, 64)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = method.EnsureCode()
		}(i)
	}
	close(start)
	wg.Wait()
	for i, code := range results {
		if code == nil || code.InsnsSize != 3 || code != results[0] {
			t.Fatalf("caller %d received inconsistent lazy code: %+v", i, code)
		}
	}
}
