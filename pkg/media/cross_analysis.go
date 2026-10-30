package media

// CrossAnalysisReport holds the results of analyzing a batch of files
// together, finding correlations and anomalies across the set.
type CrossAnalysisReport struct {
	TotalFiles       int               `json:"total_files"`
	FormatCounts     map[MediaType]int `json:"format_counts"`
	AvgRiskScore     float64           `json:"avg_risk_score"`
	MaxRiskFile      string            `json:"max_risk_file"`
	MaxRiskScore     float64           `json:"max_risk_score"`
	PolyglotCount    int               `json:"polyglot_count"`
	SameDeviceGroups [][]int           `json:"same_device_groups"` // indices into input results
	SimilarPairs     []SimilarityPair  `json:"similar_pairs,omitempty"`
	Anomalies        []string          `json:"anomalies"`
}

// SimilarityPair describes a pair of files with high similarity.
type SimilarityPair struct {
	Index1     int     `json:"index1"`
	Index2     int     `json:"index2"`
	Similarity float64 `json:"similarity"`
	Method     string  `json:"method"`
}

// CrossAnalyze performs batch analysis across multiple results, finding
// correlations and anomalies.
func CrossAnalyze(results []AnalysisResult) CrossAnalysisReport {
	report := CrossAnalysisReport{
		TotalFiles:   len(results),
		FormatCounts: make(map[MediaType]int),
	}

	if len(results) == 0 {
		return report
	}

	var totalRisk float64
	for _, r := range results {
		report.FormatCounts[r.Format]++
		totalRisk += r.RiskScore

		if r.RiskScore > report.MaxRiskScore {
			report.MaxRiskScore = r.RiskScore
			report.MaxRiskFile = r.FilePath
		}
		if r.Classification.IsPolyglot {
			report.PolyglotCount++
		}
	}
	report.AvgRiskScore = totalRisk / float64(len(results))

	// Group by camera serial number
	report.SameDeviceGroups = findSameDeviceGroups(results)

	// Find similar file pairs (metadata comparison)
	report.SimilarPairs = findSimilarPairs(results)

	// Detect anomalies
	report.Anomalies = detectBatchAnomalies(results, report)

	return report
}

// findSameDeviceGroups groups files by their camera serial number.
func findSameDeviceGroups(results []AnalysisResult) [][]int {
	serialMap := make(map[string][]int)

	for i, r := range results {
		serial := ""
		if r.Classification.RecoveredData != nil {
			serial = r.Classification.RecoveredData["BodySerialNumber"]
		}
		if serial == "" {
			if r.Classification.MediaExtra != nil && r.Classification.MediaExtra.Fields != nil {
				serial = r.Classification.MediaExtra.Fields["BodySerialNumber"]
			}
		}
		if serial != "" {
			serialMap[serial] = append(serialMap[serial], i)
		}
	}

	var groups [][]int
	for _, indices := range serialMap {
		if len(indices) > 1 {
			groups = append(groups, indices)
		}
	}
	return groups
}

// findSimilarPairs compares metadata across all file pairs.
func findSimilarPairs(results []AnalysisResult) []SimilarityPair {
	var pairs []SimilarityPair

	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			sim := CompareMetadata(results[i], results[j])
			if sim.Similarity > 0.5 {
				pairs = append(pairs, SimilarityPair{
					Index1:     i,
					Index2:     j,
					Similarity: sim.Similarity,
					Method:     sim.Method,
				})
			}
		}
	}
	return pairs
}

// detectBatchAnomalies finds anomalous patterns across the batch.
func detectBatchAnomalies(results []AnalysisResult, report CrossAnalysisReport) []string {
	var anomalies []string

	// All files from same device with different timestamps
	if len(report.SameDeviceGroups) > 0 {
		anomalies = append(anomalies, "Multiple files from the same device detected")
	}

	// High polyglot ratio
	if report.TotalFiles > 5 {
		polyglotRatio := float64(report.PolyglotCount) / float64(report.TotalFiles)
		if polyglotRatio > 0.5 {
			anomalies = append(anomalies, "High polyglot ratio in batch — possible coordinated attack")
		}
	}

	// Risk score outlier
	if report.MaxRiskScore > 80 && report.AvgRiskScore < 30 {
		anomalies = append(anomalies, "One file has significantly higher risk than the batch average")
	}

	// Many similar files
	if len(report.SimilarPairs) > report.TotalFiles/2 {
		anomalies = append(anomalies, "High number of similar file pairs — possible duplicate/variant set")
	}

	return anomalies
}
