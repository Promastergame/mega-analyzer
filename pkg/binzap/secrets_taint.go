package binzap

import (
	"mega-analyzer/pkg/binzap/analysis"
	"mega-analyzer/pkg/binzap/ir"
	"mega-analyzer/pkg/binzap/lex"
	"mega-analyzer/pkg/internal/secrets"
)

// secretTaintSeeds bridges the EXISTING secrets scanner into the taint engine
// (INC4). It lowers the token stream, and for every constant string that the
// secrets scanner recognizes as a provider credential, it seeds the holding
// register as a credential taint source. Downstream, if that register reaches
// an insecure sink (log, network, file, IPC), the taint engine reports a
// "hardcoded credential reaches insecure sink" flow. We deliberately do NOT
// build a second secret scanner here; we reuse secrets.DetectProviders.
func secretTaintSeeds(ctx ScanContext, tokens []lex.Token) []TaintSeed {
	prog := ir.LowerTokens(ctx.File, ctx.Dialect, tokens)
	var seeds []TaintSeed
	for _, m := range prog.Methods {
		for _, in := range m.Instrs {
			if in.Op != ir.OpConst || !in.HasStr || in.Dst == "" {
				continue
			}
			findings := secrets.DetectProviders(in.Str, ctx.File)
			if len(findings) == 0 {
				continue
			}
			label := "hardcoded credential"
			if findings[0].Name != "" {
				label = "hardcoded credential: " + findings[0].Name
			}
			seeds = append(seeds, TaintSeed{
				Register: in.Dst,
				Kind:     string(analysis.KindCredential),
				Label:    label,
			})
		}
	}
	return seeds
}
