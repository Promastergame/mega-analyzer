package debugger

import (
	"testing"
)

func TestParseUint64_LargeDecimal(t *testing.T) {
	v, err := parseUint64("18446744073709551615")
	if err != nil || v != 18446744073709551615 {
		t.Errorf("got %d, %v", v, err)
	}
}

func TestParseUint64_HexLower(t *testing.T) {
	v, err := parseUint64("0xdeadbeef")
	if err != nil || v != 0xdeadbeef {
		t.Errorf("got %d, %v", v, err)
	}
}

func TestParseUint64_InvalidHex(t *testing.T) {
	_, err := parseUint64("0xGGGG")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestPrintHelp_NoPanic(t *testing.T) {
	printHelp()
}

func TestUnwrapResult_WithResult(t *testing.T) {
	inner := map[string]interface{}{"rip": "0x1000"}
	m := map[string]interface{}{"result": inner}
	got := unwrapResult(m)
	if got["rip"] != "0x1000" {
		t.Errorf("expected unwrapped inner map, got %v", got)
	}
}

func TestUnwrapResult_NoResult(t *testing.T) {
	m := map[string]interface{}{"rip": "0x1000"}
	got := unwrapResult(m)
	if got["rip"] != "0x1000" {
		t.Errorf("expected passthrough, got %v", got)
	}
}

func TestUnwrapResult_Nil(t *testing.T) {
	got := unwrapResult(nil)
	if got != nil {
		t.Errorf("expected nil passthrough, got %v", got)
	}
}

func TestPrintStep_NoPanic(t *testing.T) {
	printStep(map[string]interface{}{
		"result": map[string]interface{}{
			"rip":         "0x401000",
			"instruction": "mov rax, rbx",
			"stop_reason": "step",
		},
	})
}

func TestPrintStep_Empty(t *testing.T) {
	printStep(map[string]interface{}{})
}

func TestPrintRegs_Full(t *testing.T) {
	printRegs(map[string]interface{}{
		"result": map[string]interface{}{
			"rax": "0x0", "rbx": "0x1", "rcx": "0x2", "rdx": "0x3",
			"rsi": "0x4", "rdi": "0x5", "rbp": "0x6", "rsp": "0x7",
			"r8": "0x8", "r9": "0x9", "r10": "0xa", "r11": "0xb",
			"r12": "0xc", "r13": "0xd", "r14": "0xe", "r15": "0xf",
			"rip": "0x401000",
			"flags": map[string]interface{}{
				"zf": true, "sf": false, "cf": false, "of": false,
			},
		},
	})
}

func TestPrintRegs_NoFlags(t *testing.T) {
	printRegs(map[string]interface{}{
		"result": map[string]interface{}{
			"rax": "0x0", "rip": "0x401000",
		},
	})
}

func TestPrintDisas_NoPanic(t *testing.T) {
	printDisas(map[string]interface{}{
		"result": map[string]interface{}{
			"lines": []interface{}{
				map[string]interface{}{
					"address": "0x401000",
					"raw":     "48 89 c8",
					"text":    "mov rax, rcx",
					"is_pc":   true,
				},
				map[string]interface{}{
					"address": "0x401003",
					"raw":     "c3",
					"text":    "ret",
					"is_pc":   false,
				},
			},
		},
	})
}

func TestPrintDisas_Empty(t *testing.T) {
	printDisas(map[string]interface{}{})
}

func TestPrintMem_NoPanic(t *testing.T) {
	printMem(map[string]interface{}{
		"result": map[string]interface{}{
			"address": "0x401000",
			"hex":     "48 89 c8 c3",
		},
	})
}

func TestPrintScan_NoPanic(t *testing.T) {
	printScan(map[string]interface{}{
		"result": map[string]interface{}{
			"matches": []interface{}{
				map[string]interface{}{"address": "0x401000"},
				map[string]interface{}{"address": "0x402000"},
			},
		},
	})
}

func TestPrintScan_Empty(t *testing.T) {
	printScan(map[string]interface{}{})
}

func TestPrintScan_NoMatches(t *testing.T) {
	printScan(map[string]interface{}{
		"result": map[string]interface{}{
			"matches": []interface{}{},
		},
	})
}
