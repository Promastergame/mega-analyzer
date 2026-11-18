package apkloader

import (
	"bytes"
	"context"
	"testing"
)

func TestStreamingEnvironmentDoesNotEraseLazyMethodBodies(t *testing.T) {
	p := parserWithConcurrentClassData(2)
	p.lazyCode = true
	if err := p.parseAllClassData(context.Background()); err != nil {
		t.Fatal(err)
	}
	visits := 0
	err := p.StreamOwnedBundle(context.Background(), OwnedDEXOptions{EnableHyperion: true},
		func(unit DEXClassIR, _ *OwnedEnvironment) error {
			visits++
			if bytes.Contains(unit.IR, []byte("# abstract or native")) || bytes.Count(unit.IR, []byte("return-void")) != 2 {
				t.Fatalf("environment pass erased executable methods in %s", unit.ClassName)
			}
			return nil
		}, nil)
	if err != nil || visits != 2 {
		t.Fatalf("stream = %d visits / %v", visits, err)
	}
	for _, class := range p.classes {
		if class.DirectMethods[0].Code != nil || class.VirtualMethods[0].Code != nil {
			t.Fatal("streaming retained parser-owned bytecode after emission")
		}
	}
}

func TestLazyMethodReloadsAfterRelease(t *testing.T) {
	p := parserWithConcurrentClassData(1)
	p.lazyCode = true
	if err := p.parseAllClassData(context.Background()); err != nil {
		t.Fatal(err)
	}
	class := p.classes[0]
	method := class.DirectMethods[0]
	first := method.EnsureCode()
	if first == nil {
		t.Fatal("initial bytecode load failed")
	}
	p.releaseClassCode(class)
	second := method.EnsureCode()
	if second == nil || second == first || second.InsnsSize != first.InsnsSize || second.Insns[2] != 0x0e {
		t.Fatal("released bytecode could not be reloaded independently")
	}
}
