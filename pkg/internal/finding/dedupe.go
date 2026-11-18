package finding

import "slices"

func Dedupe(findings []Finding) []Finding {
	byFingerprint := make(map[string]int, len(findings))
	result := make([]Finding, 0, len(findings))
	for _, item := range findings {
		if item.Fingerprint == "" {
			continue
		}
		if index, ok := byFingerprint[item.Fingerprint]; ok {
			existing := &result[index]
			existing.Occurrences += max(1, item.Occurrences)
			if severityRank(item.Severity) > severityRank(existing.Severity) {
				existing.Severity = item.Severity
			}
			if item.Confidence > existing.Confidence {
				existing.Confidence = item.Confidence
			}
			existing.Locations = appendUniqueLocations(existing.Locations, item.Locations)
			existing.Evidence = appendUniqueEvidence(existing.Evidence, item.Evidence)
			existing.Provenance = appendUniqueProvenance(existing.Provenance, item.Provenance)
			if existing.Explanation == nil {
				existing.Explanation = item.Explanation
			}
			continue
		}
		if item.Occurrences <= 0 {
			item.Occurrences = 1
		}
		byFingerprint[item.Fingerprint] = len(result)
		result = append(result, item)
	}
	slices.SortFunc(result, func(a, b Finding) int {
		if rankA, rankB := severityRank(a.Severity), severityRank(b.Severity); rankA != rankB {
			return rankB - rankA
		}
		if a.RuleID != b.RuleID {
			if a.RuleID < b.RuleID {
				return -1
			}
			return 1
		}
		if a.Fingerprint < b.Fingerprint {
			return -1
		}
		if a.Fingerprint > b.Fingerprint {
			return 1
		}
		return 0
	})
	return result
}

func severityRank(value string) int {
	switch value {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info", "informational":
		return 1
	default:
		return 0
	}
}

func appendUniqueLocations(dst, src []Location) []Location {
	for _, candidate := range src {
		found := false
		for _, current := range dst {
			if current == candidate {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, candidate)
		}
	}
	return dst
}

func appendUniqueEvidence(dst, src []Evidence) []Evidence {
	for _, candidate := range src {
		found := false
		for _, current := range dst {
			if current.Digest == candidate.Digest && current.Location == candidate.Location {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, candidate)
		}
	}
	return dst
}

func appendUniqueProvenance(dst, src []Provenance) []Provenance {
	for _, candidate := range src {
		found := false
		for _, current := range dst {
			if current == candidate {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, candidate)
		}
	}
	return dst
}
