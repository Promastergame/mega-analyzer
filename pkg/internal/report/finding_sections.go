package report

// Observations describe APIs, permissions and protections. They retain their
// original severity and evidence, but do not crowd out defects in the report.
func splitTypedFindings(items []TypedFindingView) (risks, observations []TypedFindingView) {
	for _, item := range items {
		if item.Kind == "inventory" || item.Kind == "hardening" {
			observations = append(observations, item)
		} else {
			risks = append(risks, item)
		}
	}
	return risks, observations
}
