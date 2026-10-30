package shared

var basePatternsProvider func() []VulnerablePattern

// RegisterBasePatternsProvider wires the base patch pattern catalog into the shared registry.
func RegisterBasePatternsProvider(provider func() []VulnerablePattern) {
	basePatternsProvider = provider
}

// BasePatterns returns the registered base patch patterns.
func BasePatterns() []VulnerablePattern {
	if basePatternsProvider == nil {
		return nil
	}
	return basePatternsProvider()
}
