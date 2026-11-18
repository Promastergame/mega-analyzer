package textai

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

type DatasetAudit struct {
	InputSamples      int      `json:"input_samples"`
	UniqueSamples     int      `json:"unique_samples"`
	DuplicatesRemoved int      `json:"duplicates_removed"`
	Groups            int      `json:"groups"`
	Negative          int      `json:"negative"`
	Positive          int      `json:"positive"`
	Warnings          []string `json:"warnings"`
}

func prepareDataset(d Dataset) ([]Sample, DatasetAudit, error) {
	audit := DatasetAudit{InputSamples: len(d.Samples), Warnings: []string{}}
	if d.TaskID != Task || len(d.Samples) == 0 || len(d.Samples) > 10000 {
		return nil, audit, fmt.Errorf("task must be %s; dataset needs 1..10000 samples", Task)
	}
	seen := map[string]Sample{}
	groups := map[string]bool{}
	rows := make([]Sample, 0, len(d.Samples))
	bytes := 0
	for i, s := range d.Samples {
		s.Group = strings.TrimSpace(s.Group)
		if s.Group == "" || len(s.Group) > 256 || (s.Label != 0 && s.Label != 1) {
			return nil, audit, fmt.Errorf("sample %d needs a group and binary label", i)
		}
		if err := Validate(s.Input); err != nil {
			return nil, audit, fmt.Errorf("sample %d: %w", i, err)
		}
		bytes += len(s.Input.State) + len(s.Input.Question) + len(s.Input.TrueWhen) + len(s.Input.FalseWhen) + len(s.Input.CandidateCode)
		if bytes > 64*1024*1024 {
			return nil, audit, fmt.Errorf("dataset text limit: 64 MiB")
		}
		sig := normalizedSignature(s.Input)
		if prev, ok := seen[sig]; ok {
			if prev.Label != s.Label {
				return nil, audit, fmt.Errorf("conflicting labels for normalized text at sample %d", i)
			}
			if prev.Group != s.Group {
				return nil, audit, fmt.Errorf("duplicate normalized text across groups %q and %q", prev.Group, s.Group)
			}
			audit.DuplicatesRemoved++
			continue
		}
		seen[sig] = s
		groups[s.Group] = true
		rows = append(rows, s)
		if s.Label == 1 {
			audit.Positive++
		} else {
			audit.Negative++
		}
	}
	// Canonical order makes full-batch optimization independent of input row order.
	signatures := make(map[string]string, len(rows))
	for _, s := range rows {
		sig := normalizedSignature(s.Input)
		signatures[fieldsSignature(s.Input)] = sig
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Group != rows[j].Group {
			return rows[i].Group < rows[j].Group
		}
		return signatures[fieldsSignature(rows[i].Input)] < signatures[fieldsSignature(rows[j].Input)]
	})
	audit.UniqueSamples, audit.Groups = len(rows), len(groups)
	if audit.DuplicatesRemoved > 0 {
		audit.Warnings = append(audit.Warnings, "Повторные записи внутри группы удалены до разделения и обучения.")
	}
	if d.Synthetic {
		audit.Warnings = append(audit.Warnings, "Синтетические шаблоны не измеряют качество на реальных проектах.")
	}
	audit.Warnings = append(audit.Warnings, "Нормализованные дубликаты проверены; перефразировки и неверно заданные группы всё ещё могут создавать утечку.")
	return rows, audit, nil
}

type projectGroup struct {
	name, hash string
	counts     [2]int
}

func splitDataset(rows []Sample) ([3][]Sample, [3]int, error) {
	sets := [3][]Sample{}
	groupCounts := [3]int{}
	groups := map[string]*projectGroup{}
	total := [2]int{}
	for _, s := range rows {
		if groups[s.Group] == nil {
			groups[s.Group] = &projectGroup{name: s.Group, hash: SHA256(s.Group)}
		}
		groups[s.Group].counts[s.Label]++
		total[s.Label]++
	}
	if len(groups) < 10 {
		return sets, groupCounts, fmt.Errorf("need >=10 independent project groups after deduplication")
	}
	ordered := make([]*projectGroup, 0, len(groups))
	for _, g := range groups {
		ordered = append(ordered, g)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i].counts[0]+ordered[i].counts[1], ordered[j].counts[0]+ordered[j].counts[1]
		if a != b {
			return a > b
		}
		return ordered[i].hash < ordered[j].hash
	})
	quotas := [3]int{len(groups) * 6 / 10, len(groups)*8/10 - len(groups)*6/10, len(groups) - len(groups)*8/10}
	counts := [3][2]int{}
	assignments := map[string]int{}
	for _, g := range ordered {
		best, bestCost := -1, math.Inf(1)
		for part := 0; part < 3; part++ {
			if groupCounts[part] == quotas[part] {
				continue
			}
			cost := 0.0
			for label := 0; label < 2; label++ {
				target := float64(total[label]) * float64(quotas[part]) / float64(len(groups))
				before := float64(counts[part][label]) - target
				after := before + float64(g.counts[label])
				cost += (after*after - before*before) / math.Max(1, target)
			}
			if cost < bestCost {
				best, bestCost = part, cost
			}
		}
		assignments[g.name] = best
		groupCounts[best]++
		for label := 0; label < 2; label++ {
			counts[best][label] += g.counts[label]
		}
	}
	for _, s := range rows {
		part := assignments[s.Group]
		sets[part] = append(sets[part], s)
	}
	for part, set := range sets {
		min := 20
		if part == 0 {
			min = 40
		}
		if len(set) < min || counts[part][0] < 5 || counts[part][1] < 5 {
			return sets, groupCounts, fmt.Errorf("split %d needs >=%d unique samples and >=5 per class; got %d rows (%d negative, %d positive); add independent labeled projects", part, min, len(set), counts[part][0], counts[part][1])
		}
	}
	return sets, groupCounts, nil
}

func provenance(rows []Sample) *Provenance {
	p := &Provenance{}
	groups := map[string]bool{}
	var canonical strings.Builder
	for _, s := range rows {
		h := normalizedSignature(s.Input)
		p.SampleHashes = append(p.SampleHashes, h)
		groupHash := SHA256(s.Group)
		groups[groupHash] = true
		canonical.WriteString(groupHash + strconv.Itoa(s.Label) + h + "\n")
	}
	for g := range groups {
		p.GroupHashes = append(p.GroupHashes, g)
	}
	sort.Strings(p.GroupHashes)
	sort.Strings(p.SampleHashes)
	p.DatasetSHA256 = SHA256(canonical.String())
	return p
}
