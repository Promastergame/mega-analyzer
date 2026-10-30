package sandbox

import (
	"math"
	"time"

	"mega-analyzer/pkg/ml/neural"
)

func buildNeuralAnalysis(report *Report) *NeuralAnalysis {
	events := collectNeuralEvents(report)
	if len(events) == 0 {
		return nil
	}

	encoder := neural.TimelineEncoder{Buckets: 8}
	timelineVec := encoder.Encode(events)
	timelineScore := clamp01(avg(timelineVec))

	baseline := neural.AnomalyScore{
		Mean:   zeroVec(len(timelineVec)),
		StdDev: onesVec(len(timelineVec)),
	}
	anomalyScore := baseline.Score(timelineVec)

	sandboxScore := clamp01(
		float64(len(report.Processes))*0.15 +
			float64(len(report.Connections))*0.20 +
			float64(len(report.FileChanges.Created)+len(report.FileChanges.Modified))*0.25 +
			float64(report.Behavior.PersistenceCount)*0.10 +
			float64(report.Behavior.PublicConnectionCount)*0.20,
	)

	similarity := 0.0
	if report.AndroidProfile != nil {
		similarity = similarityFromAndroid(report)
	}

	staticScore := clamp01(
		float64(report.Behavior.PermissionWarningCount)*0.18 +
			float64(report.Behavior.DroppedExecutableCount)*0.25 +
			float64(report.Behavior.DroppedScriptCount)*0.15,
	)

	fusion := neural.DefaultFusion()
	risk := fusion.Score(timelineScore, similarity, anomalyScore, staticScore, sandboxScore)

	return &NeuralAnalysis{
		RiskScore:     risk,
		TimelineScore: timelineScore,
		AnomalyScore:  anomalyScore,
		Similarity:    similarity,
		StaticScore:   staticScore,
		SandboxScore:  sandboxScore,
		Signals:       neural.Fingerprint(events),
		Explanation: []string{
			"timeline and dynamic activity were summarized locally",
			"anomaly is measured against a zero baseline until a learned baseline is available",
		},
	}
}

func collectNeuralEvents(report *Report) []neural.Event {
	events := make([]neural.Event, 0, len(report.Processes)+len(report.Connections)+len(report.FileChanges.Created)+len(report.FileChanges.Modified))
	for _, proc := range report.Processes {
		events = append(events, neural.Event{
			At:      proc.FirstSeen,
			Kind:    "process",
			Subject: proc.Name,
			Value:   1,
		})
	}
	for _, conn := range report.Connections {
		events = append(events, neural.Event{
			At:      conn.FirstSeen,
			Kind:    "network:" + conn.Protocol,
			Subject: conn.RemoteAddr,
			Value:   1,
		})
	}
	for _, art := range report.FileChanges.Created {
		events = append(events, neural.Event{
			At:      time.Now().UTC(),
			Kind:    "file:create",
			Subject: art.Path,
			Value:   float64(art.Size),
		})
	}
	for _, art := range report.FileChanges.Modified {
		events = append(events, neural.Event{
			At:      time.Now().UTC(),
			Kind:    "file:modify",
			Subject: art.Path,
			Value:   float64(art.Size),
		})
	}
	return events
}

func similarityFromAndroid(report *Report) float64 {
	if report.AndroidProfile == nil {
		return 0
	}
	score := 0.0
	if report.AndroidProfile.HighRiskPermissionCount > 0 {
		score += math.Min(1, float64(report.AndroidProfile.HighRiskPermissionCount)*0.2)
	}
	if report.AndroidProfile.DangerousPermissionCount > 0 {
		score += math.Min(1, float64(report.AndroidProfile.DangerousPermissionCount)*0.1)
	}
	if len(report.AndroidProfile.ExportedComponents) > 0 {
		score += math.Min(1, float64(len(report.AndroidProfile.ExportedComponents))*0.05)
	}
	return clamp01(score)
}

func avg(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}

func zeroVec(n int) []float64 {
	return make([]float64, n)
}

func onesVec(n int) []float64 {
	v := make([]float64, n)
	for i := range v {
		v[i] = 1
	}
	return v
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
