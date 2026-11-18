package report

import "mega-analyzer/pkg/internal/svgscan"

// SVGHasActiveContent uses the same structural scanner as the main analysis.
// Ordinary SMIL animation and xmlns declarations are not executable content.
func SVGHasActiveContent(data []byte) bool {
	return svgscan.Scan(data).Active()
}
