package experimental

// Regression tests for the 2026-09-21 PE audit: mitigation flags are requests,
// not facts. DYNAMICBASE only relocates through a base-relocation table
// (RELOCS_STRIPPED or an empty directory means no ASLR), and GUARD_CF arms
// itself via the load config (no directory means CFG is inert).

import (
	"encoding/binary"
	"testing"
)

func TestPEASLRAndCFGRequireCorroboratingMetadata(t *testing.T) {
	// 0x4160 = HIGH_ENTROPY_VA | DYNAMICBASE | NXCOMPAT | GUARD_CF, but the
	// image is linked /FIXED: RELOCS_STRIPPED, no relocation directory, no
	// load config.
	data := buildMockPE(true, 0x4160, false, false, 0, 0)
	binary.LittleEndian.PutUint16(data[0x44+18:], 3) // EXECUTABLE_IMAGE | RELOCS_STRIPPED
	b, err := analyzePE(reviewPEFile(t, data))
	if err != nil {
		t.Fatal(err)
	}
	if b.ASLR {
		t.Error("ASLR reported with RELOCS_STRIPPED and no relocation directory")
	}
	if b.CFG {
		t.Error("CFG reported without a load config directory")
	}
	if !b.ASLRFlagOnly || !b.CFGFlagOnly {
		t.Errorf("flag-only state not surfaced: ASLRFlagOnly=%v CFGFlagOnly=%v", b.ASLRFlagOnly, b.CFGFlagOnly)
	}
}

func TestPEASLRAndCFGConfirmedWithMetadata(t *testing.T) {
	// Same flags plus the metadata that arms them: a relocation directory
	// (always emitted by buildMockPE) and a load config.
	data := buildMockPE(true, 0x4160, false, true, 0, 0)
	b, err := analyzePE(reviewPEFile(t, data))
	if err != nil {
		t.Fatal(err)
	}
	if !b.ASLR {
		t.Errorf("ASLR not confirmed with relocations present (flag-only=%v)", b.ASLRFlagOnly)
	}
	if !b.HighEntropyASLR {
		t.Error("HighEntropyASLR not confirmed for a 64-bit HIGH_ENTROPY_VA image with ASLR")
	}
	if !b.CFG {
		t.Errorf("CFG not confirmed with load config present (flag-only=%v)", b.CFGFlagOnly)
	}
}
