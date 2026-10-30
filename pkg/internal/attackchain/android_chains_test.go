package attackchain

import (
	"testing"

	"mega-analyzer/pkg/internal/correlation"
)

func TestIntentToDangerousSinkChain(t *testing.T) {
	ctx := correlation.Group([]*correlation.Signal{
		{ID: "intent", Kind: correlation.KindAudit, Type: correlation.TypeUntrustedIntent},
		{ID: "sink", Kind: correlation.KindAudit, Type: correlation.TypeDangerousSink},
	})
	chain := (IntentToDangerousSinkChain{}).Detect(ctx)
	if chain == nil || !chain.Factors.Reachable || len(chain.Sequence) != 3 {
		t.Fatalf("unexpected chain: %+v", chain)
	}
}

func TestDeepLinkChainRequiresAllStages(t *testing.T) {
	ctx := correlation.Group([]*correlation.Signal{
		{ID: "entry", Kind: correlation.KindAudit, Type: correlation.TypeDeepLinkEntry},
		{ID: "remote", Kind: correlation.KindAudit, Type: correlation.TypeWebViewRemoteLoad},
	})
	if chain := (DeepLinkWebViewRCEChain{}).Detect(ctx); chain != nil {
		t.Fatalf("chain without bridge: %+v", chain)
	}
}
