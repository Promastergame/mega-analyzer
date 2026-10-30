package ml

import (
	"fmt"
	"strings"
)

// ReturnSiteCoverage is the generator's static accounting, not proof of runtime
// behavior. HandledSites includes sites already yielding the requested value;
// it is deliberately not named ModifiedSites. Nil means legacy/unknown.
type ReturnSiteCoverage struct {
	Opcode       string `json:"opcode"`
	TotalSites   int    `json:"total_sites"`
	HandledSites int    `json:"handled_sites"`
}

func countReturnSites(body []string, opcode string) int {
	total := 0
	var state smaliNonCodeState
	for _, raw := range body {
		line := smaliCodeLine(raw)
		if state.skip(line) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == opcode {
			total++
		}
	}
	return total
}

func returnSiteCoverage(body []string, opcode string, handled int) *ReturnSiteCoverage {
	return &ReturnSiteCoverage{
		Opcode:       opcode,
		TotalSites:   countReturnSites(body, opcode),
		HandledSites: handled,
	}
}

func verifyReturnCoverage(body []string, coverage *ReturnSiteCoverage) error {
	if coverage == nil {
		return nil
	}
	switch coverage.Opcode {
	case "return", "return-wide", "return-object":
	default:
		return fmt.Errorf("unsupported coverage opcode: %q", coverage.Opcode)
	}
	if coverage.TotalSites <= 0 || coverage.HandledSites <= 0 || coverage.HandledSites > coverage.TotalSites {
		return fmt.Errorf("invalid return coverage: handled=%d total=%d", coverage.HandledSites, coverage.TotalSites)
	}
	if coverage.TotalSites != countReturnSites(body, coverage.Opcode) {
		return fmt.Errorf("return coverage does not match the original body")
	}
	return nil
}
