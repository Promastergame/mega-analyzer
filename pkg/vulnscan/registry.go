package vulnscan

import (
	"fmt"
	"sort"
	"sync"
)

// ScanPhase orders checks along the pipeline.
type ScanPhase string

const (
	PhaseDiscovery   ScanPhase = "discovery"
	PhasePassive     ScanPhase = "passive"
	PhaseActive      ScanPhase = "active"
	PhaseCorrelation ScanPhase = "correlation"
	PhaseReporting   ScanPhase = "reporting"
)

// Invasiveness controls whether a check may run given the user's risk budget.
type Invasiveness string

const (
	InvPassive     Invasiveness = "Passive"     // observes only
	InvSafe        Invasiveness = "Safe"        // sends benign probes
	InvDestructive Invasiveness = "Destructive" // may mutate state
)

// CheckRunner executes a check against a surface, returning raw findings. It is
// optional: descriptors can be registered purely for metadata/topology.
type CheckRunner func(s *Scanner, surface *AttackSurface) []Finding

// CheckDescriptor is the self-registration record for a check. The engine uses
// it to topologically sort execution, filter by invasiveness, and attach
// standards metadata to emitted findings.
type CheckDescriptor struct {
	ID           string
	Name         string
	CWE          []int
	OWASP        []string
	Phase        ScanPhase
	Invasiveness Invasiveness
	Dependencies []string
	Run          CheckRunner
}

// registry is the process-wide check registry.
var (
	registryMu sync.RWMutex
	registry   = map[string]CheckDescriptor{}
)

// RegisterCheck adds (or replaces) a descriptor in the registry.
func RegisterCheck(d CheckDescriptor) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[d.ID] = d
}

// RegisteredChecks returns a snapshot of all descriptors.
func RegisteredChecks() []CheckDescriptor {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]CheckDescriptor, 0, len(registry))
	for _, d := range registry {
		out = append(out, d)
	}
	return out
}

// maxInvasiveness ranks invasiveness levels for filtering.
func invasivenessRank(i Invasiveness) int {
	switch i {
	case InvPassive:
		return 0
	case InvSafe:
		return 1
	case InvDestructive:
		return 2
	default:
		return 1
	}
}

// FilterByInvasiveness returns descriptors at or below the allowed level.
func FilterByInvasiveness(checks []CheckDescriptor, max Invasiveness) []CheckDescriptor {
	limit := invasivenessRank(max)
	var out []CheckDescriptor
	for _, c := range checks {
		if invasivenessRank(c.Invasiveness) <= limit {
			out = append(out, c)
		}
	}
	return out
}

// TopoSortChecks orders checks so that every dependency precedes its dependents.
// Ties are broken by phase order then ID for deterministic runs. Returns an
// error if a dependency cycle or unknown dependency is detected.
func TopoSortChecks(checks []CheckDescriptor) ([]CheckDescriptor, error) {
	byID := make(map[string]CheckDescriptor, len(checks))
	for _, c := range checks {
		byID[c.ID] = c
	}

	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(checks))
	var order []CheckDescriptor

	// Deterministic iteration order.
	ids := make([]string, 0, len(checks))
	for _, c := range checks {
		ids = append(ids, c.ID)
	}
	sort.Slice(ids, func(i, j int) bool {
		pi, pj := phaseRank(byID[ids[i]].Phase), phaseRank(byID[ids[j]].Phase)
		if pi != pj {
			return pi < pj
		}
		return ids[i] < ids[j]
	})

	var visit func(id string) error
	visit = func(id string) error {
		switch color[id] {
		case black:
			return nil
		case gray:
			return fmt.Errorf("check dependency cycle detected at %q", id)
		}
		c, ok := byID[id]
		if !ok {
			return fmt.Errorf("unknown check dependency %q", id)
		}
		color[id] = gray
		deps := append([]string{}, c.Dependencies...)
		sort.Strings(deps)
		for _, dep := range deps {
			if err := visit(dep); err != nil {
				return err
			}
		}
		color[id] = black
		order = append(order, c)
		return nil
	}

	for _, id := range ids {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	return order, nil
}

func phaseRank(p ScanPhase) int {
	switch p {
	case PhaseDiscovery:
		return 0
	case PhasePassive:
		return 1
	case PhaseActive:
		return 2
	case PhaseCorrelation:
		return 3
	case PhaseReporting:
		return 4
	default:
		return 2
	}
}
