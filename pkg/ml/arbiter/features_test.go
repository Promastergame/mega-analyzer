package arbiter

import (
	"testing"

	"mega-analyzer/pkg/internal/cfg"
)

func mkNode(id int, raws ...string) *cfg.CFGNode {
	instrs := make([]cfg.InstructionRef, 0, len(raws))
	for i, r := range raws {
		op := "const"
		switch {
		case len(r) >= 6 && r[:6] == "invoke":
			op = "invoke-virtual"
		}
		instrs = append(instrs, cfg.InstructionRef{Index: i, Opcode: op, Raw: r})
	}
	return &cfg.CFGNode{ID: id, Instructions: instrs}
}

func TestBlockFeatures_Empty(t *testing.T) {
	feats := BlockFeatures(nil)
	if len(feats) != 0 {
		t.Fatalf("expected empty features for nil node, got %v", feats)
	}

	feats = BlockFeatures(&cfg.CFGNode{})
	if len(feats) != 0 {
		t.Fatalf("expected empty features for node with no instructions, got %v", feats)
	}
}

func TestBlockFeatures_EntropyBuckets(t *testing.T) {
	low := mkNode(1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	feats := BlockFeatures(low)
	if feats["entropy"] != "low" {
		t.Errorf("expected low entropy, got %q", feats["entropy"])
	}

	high := mkNode(2, "xQ9!zR2#kP7$mN4%vB8^wL1&tC6*yH3@jK5(dF0)gS")
	feats = BlockFeatures(high)
	if feats["entropy"] == "low" {
		t.Errorf("expected non-low entropy for high-variance string, got %q", feats["entropy"])
	}
}

func TestBlockFeatures_CryptoRatio(t *testing.T) {
	node := mkNode(1,
		"invoke-static Ljavax/crypto/Cipher;->getInstance",
		"invoke-virtual Ljavax/crypto/Cipher;->doFinal",
		"const/4 v0, 0x0",
		"const/4 v1, 0x1",
	)
	feats := BlockFeatures(node)
	if feats["crypto_ratio"] == "" {
		t.Fatalf("expected crypto_ratio feature to be set")
	}
}

func TestBlockFeatures_APIBigrams(t *testing.T) {
	node := mkNode(1,
		"invoke-virtual {v0}, Ljava/net/Socket;->getOutputStream()",
		"invoke-virtual {v1}, Ljava/io/OutputStream;->write([B)V",
	)
	feats := BlockFeatures(node)

	found := false
	for k := range feats {
		if len(k) > 5 && k[:5] == "api2:" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected at least one api2: bigram feature, got %v", feats)
	}
}

func TestBlockFeatures_TaintDistanceToSink(t *testing.T) {
	sink := mkNode(2, "invoke-static Ljava/lang/Runtime;->exec(Ljava/lang/String;)")
	entry := mkNode(1, "const/4 v0, 0x0")
	entry.Successors = []*cfg.CFGNode{sink}

	feats := BlockFeatures(entry)
	if feats["taint_dist"] != "1" {
		t.Errorf("expected taint_dist=1 (one hop to sink), got %q", feats["taint_dist"])
	}

	feats = BlockFeatures(sink)
	if feats["taint_dist"] != "0" {
		t.Errorf("expected taint_dist=0 for block that is itself a sink, got %q", feats["taint_dist"])
	}
}

func TestBlockFeatures_NoSinkReachable(t *testing.T) {
	node := mkNode(1, "const/4 v0, 0x0")
	feats := BlockFeatures(node)
	if feats["taint_dist"] != "none" {
		t.Errorf("expected taint_dist=none when no sink reachable, got %q", feats["taint_dist"])
	}
}
