package arbiter

import (
	"sort"

	"mega-analyzer/pkg/internal/cfg"
)

// MethodDiff — результат сравнения одного метода между версией N и N+1
// по структурному WL-фингерпринту (см. fingerprint.go). Похожесть ниже
// diffSimThreshold трактуется как "тело метода существенно изменилось" —
// это ловит логические правки/инъекции вредоносного кода даже если
// имена классов/методов и косметика (строки, константы, register
// allocation) внутри версии не поменялись, потому что WL-хэш зависит
// только от структуры графа потока управления и грубой категоризации
// опкодов, а не от конкретных литералов.
type MethodDiff struct {
	Key      string  // ClassName + "." + MethodName
	Sim      float32 // похожесть WL-фингерпринтов в [0,1]
	Status   string  // "added" | "removed" | "unchanged" | "modified"
	OldNodes int
	NewNodes int
}

// diffSimThreshold — ниже этого порога метод считается "modified",
// даже если он присутствует в обеих версиях.
const diffSimThreshold = 0.9

func methodKey(g *cfg.ControlFlowGraph) string {
	if g.ClassName == "" {
		return g.MethodName
	}
	return g.ClassName + "." + g.MethodName
}

// DiffVersions сравнивает две версии приложения (набор CFG на функцию
// каждая) через WL-фингерпринты и возвращает по одному MethodDiff на
// каждый метод, встретившийся хотя бы в одной из версий. Это и есть
// "diff-режим версия N vs N+1": быстрый, не требующий выравнивания
// байткода, устойчивый к простому обфускационному переименованию,
// потому что WL-метка не включает исходные имена — только структуру.
func DiffVersions(oldCFGs, newCFGs []*cfg.ControlFlowGraph) []MethodDiff {
	oldByKey := make(map[string]*cfg.ControlFlowGraph, len(oldCFGs))
	for _, g := range oldCFGs {
		if g == nil {
			continue
		}
		oldByKey[methodKey(g)] = g
	}
	newByKey := make(map[string]*cfg.ControlFlowGraph, len(newCFGs))
	for _, g := range newCFGs {
		if g == nil {
			continue
		}
		newByKey[methodKey(g)] = g
	}

	keys := make(map[string]bool, len(oldByKey)+len(newByKey))
	for k := range oldByKey {
		keys[k] = true
	}
	for k := range newByKey {
		keys[k] = true
	}

	diffs := make([]MethodDiff, 0, len(keys))
	for k := range keys {
		oldG, hasOld := oldByKey[k]
		newG, hasNew := newByKey[k]

		switch {
		case hasOld && !hasNew:
			diffs = append(diffs, MethodDiff{
				Key: k, Sim: 0, Status: "removed", OldNodes: len(oldG.Nodes),
			})
		case !hasOld && hasNew:
			diffs = append(diffs, MethodDiff{
				Key: k, Sim: 0, Status: "added", NewNodes: len(newG.Nodes),
			})
		default:
			oldVec := WLFingerprint(oldG)
			newVec := WLFingerprint(newG)
			sim := oldVec.Sim(newVec)
			status := "unchanged"
			if sim < diffSimThreshold {
				status = "modified"
			}
			diffs = append(diffs, MethodDiff{
				Key: k, Sim: sim, Status: status,
				OldNodes: len(oldG.Nodes), NewNodes: len(newG.Nodes),
			})
		}
	}

	sort.Slice(diffs, func(i, j int) bool {
		if diffs[i].Status != diffs[j].Status {
			return statusRank(diffs[i].Status) < statusRank(diffs[j].Status)
		}
		if diffs[i].Sim != diffs[j].Sim {
			return diffs[i].Sim < diffs[j].Sim
		}
		return diffs[i].Key < diffs[j].Key
	})

	return diffs
}

func statusRank(s string) int {
	switch s {
	case "added":
		return 0
	case "modified":
		return 1
	case "removed":
		return 2
	default:
		return 3
	}
}
