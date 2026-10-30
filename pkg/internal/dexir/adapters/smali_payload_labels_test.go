package adapters

import (
	"strings"
	"testing"
)

func TestSmaliPayloadReferencesByLabel(t *testing.T) {
	source := strings.Join([]string{
		".class public LLabels;",
		".super Ljava/lang/Object;",
		".method public static run()V",
		"    .registers 1",
		"    fill-array-data v0, :missing",
		"    fill-array-data v0, :second",
		"    fill-array-data v0, :first",
		"    fill-array-data v0, :alias",
		"    return-void",
		"    :first",
		"    .array-data 1",
		"        0x11t",
		"    .end array-data",
		"    :alias",
		"    :second",
		"    .array-data 1",
		"        0x22t",
		"    .end array-data",
		".end method",
	}, "\n")
	cls, err := FromSmaliText(source)
	if err != nil {
		t.Fatal(err)
	}
	m := cls.FindMethod("run", "")
	if m == nil || len(m.Instructions) != 7 {
		t.Fatalf("unexpected method: %+v", m)
	}
	if m.Instructions[0].Payload != nil {
		t.Fatal("missing label attached an unrelated table")
	}
	for index, want := range map[int]byte{1: 0x22, 2: 0x11, 3: 0x22} {
		payload := m.Instructions[index].Payload
		if payload == nil || len(payload.Values) != 1 || payload.Values[0] != want {
			t.Errorf("instruction %d: payload %+v, want byte %#x", index, payload, want)
		}
	}
	if m.Instructions[1].Payload != m.Instructions[3].Payload {
		t.Error("aliases did not resolve to the same table")
	}
	for _, index := range []int{5, 6} {
		if m.Instructions[index].Line <= 0 {
			t.Error("payload lost its source position")
		}
	}
}
