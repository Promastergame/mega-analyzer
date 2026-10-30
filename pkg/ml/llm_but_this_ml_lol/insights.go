package llmkeys

import "sort"

// Insights turns a bag of raw candidate strings — everything a scanner pulled
// out of an artifact — into a compact, decision-ready summary: how many are
// real-looking secrets, which credential families appear, how the findings
// cluster, and which unknown-format blobs look anomalous. This is the
// "knowledge extraction" step that sits between raw classification and a report.

// FamilyCount is one entry in a family histogram.
type FamilyCount struct {
	Family string
	Count  int
}

// Insight is the aggregate summary of a batch of candidate values.
type Insight struct {
	// Total is the number of distinct values summarized.
	Total int
	// Secrets is how many were classified as real-looking secrets.
	Secrets int
	// NonSecrets is Total-Secrets.
	NonSecrets int
	// ByFamily is the histogram of detected families (secrets only), sorted by
	// descending count then family name.
	ByFamily []FamilyCount
	// SeverityHigh/Medium/Low count secrets by the same confidence bands the
	// loaders use (>=0.9 high, >=0.7 medium, else low).
	SeverityHigh   int
	SeverityMedium int
	SeverityLow    int
	// MeanConfidence is the average confidence over secrets (0 if none).
	MeanConfidence float64
	// MeanEntropy is the average entropy over all distinct values.
	MeanEntropy float64
	// ClusterCount is the number of structural clusters (see ClusterByFingerprint).
	ClusterCount int
	// TopClusters holds the largest few clusters for at-a-glance triage.
	TopClusters []Cluster
	// Anomalies holds unknown-format, credential-shaped values worth review.
	Anomalies []Anomaly
}

// maxTopClusters and maxReportedAnomalies bound what Summarize returns so the
// summary stays compact regardless of input size.
const (
	maxTopClusters       = 5
	maxReportedAnomalies = 10
)

// Summarize classifies, clusters and anomaly-scans the given values and returns
// an Insight. Values are deduplicated first, so counts reflect distinct
// strings. It is safe to pass thousands of values; the clustering step uses the
// O(n) fingerprint grouping.
func Summarize(values []string) Insight {
	// Deduplicate, preserving order.
	seen := make(map[string]bool, len(values))
	uniq := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		uniq = append(uniq, v)
	}

	ins := Insight{Total: len(uniq)}
	if len(uniq) == 0 {
		return ins
	}

	famCounts := make(map[string]int)
	var confSum, entSum float64
	for _, v := range uniq {
		f, verdict := ExtractWithVerdict(v)
		entSum += f.Entropy
		if verdict.IsSecret {
			ins.Secrets++
			confSum += verdict.Confidence
			switch {
			case verdict.Confidence >= 0.9:
				ins.SeverityHigh++
			case verdict.Confidence >= 0.7:
				ins.SeverityMedium++
			default:
				ins.SeverityLow++
			}
			if f.Family != "" {
				famCounts[f.Family]++
			}
		}
	}
	ins.NonSecrets = ins.Total - ins.Secrets
	ins.MeanEntropy = entSum / float64(len(uniq))
	if ins.Secrets > 0 {
		ins.MeanConfidence = confSum / float64(ins.Secrets)
	}

	ins.ByFamily = sortedFamilyCounts(famCounts)

	clusters := ClusterByFingerprint(uniq)
	ins.ClusterCount = len(clusters)
	if len(clusters) > maxTopClusters {
		ins.TopClusters = clusters[:maxTopClusters]
	} else {
		ins.TopClusters = clusters
	}

	anomalies := DetectAnomalies(uniq, anomalyThreshold)
	if len(anomalies) > maxReportedAnomalies {
		anomalies = anomalies[:maxReportedAnomalies]
	}
	ins.Anomalies = anomalies

	return ins
}

func sortedFamilyCounts(m map[string]int) []FamilyCount {
	out := make([]FamilyCount, 0, len(m))
	for fam, c := range m {
		out = append(out, FamilyCount{Family: fam, Count: c})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Family < out[j].Family
	})
	return out
}
