package ml

import (
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI CFG — легковесный граф потока управления для выбора гейта
//
// Полный dataflow — overkill для патчера; нужен ответ на один вопрос:
// "какой conditional — entry-gate, ведущий к success-возврату?"
//
// Строим из числовых оффсетов (как smali_offset.go):
//   - парсим инструкции с code-unit оффсетами (smaliUnits)
//   - резолвим numeric branch targets в индексы инструкций
//   - successor'ы: branch → [fallthrough, target], goto → [target], else → [next]
//   - return-узлы классифицируем по подкормленному const (0 vs 1 vs other)
//   - entry-gate = первый conditional на пути от входа к "желаемому" возврату
//
// Используется EntryGateStrategy и PartialBypass для выбора ОДНОГО гейта
// вместо "инвертируй все" (ломает AND) или "окно 3 строки" (хрупко).
// При любом парс-фейле возвращаем ok=false — вызыватель падает на текстовую
// эвристику, никогда не корраптит.
// ═══════════════════════════════════════════════════════════════════════════════

// cfgNode — одна инструкция в потоке.
type cfgNode struct {
	lineIdx int
	mnem    string
	offset  int
	units   int
	delta   int // branch delta (если branch)
	isBr    bool
	isGoto  bool
	retVal  *int32 // const-значение если узел — return с известным дефом
}

// parseCFG строит линейный поток инструкций с оффсетами.
func parseCFG(body []string) ([]cfgNode, map[int]int, bool) {
	nodes := []cfgNode{}
	byOffset := map[int]int{}
	pos := 0
	for i, line := range body {
		trimmed := strings.TrimSpace(line)
		mnem, ok := insnLine(trimmed)
		if !ok {
			continue
		}
		units, known := smaliUnits(mnem)
		if !known {
			return nil, nil, false
		}
		n := cfgNode{lineIdx: i, mnem: mnem, offset: pos, units: units}
		if _, _, isBr := branchRange(mnem); isBr {
			if d, ok := parseTrailingOffset(trimmed); ok {
				n.isBr = true
				n.delta = d
				n.isGoto = strings.HasPrefix(mnem, "goto")
			}
		}
		byOffset[pos] = len(nodes)
		nodes = append(nodes, n)
		pos += units
	}
	if len(nodes) == 0 {
		return nil, nil, false
	}
	return nodes, byOffset, true
}

// cfgSuccessors возвращает индексы successor'ов узла.
func cfgSuccessors(nodes []cfgNode, byOffset map[int]int, idx int) []int {
	if idx < 0 || idx >= len(nodes) {
		return nil
	}
	n := nodes[idx]
	if strings.HasPrefix(n.mnem, "return") || n.mnem == "throw" {
		return nil // терминатор
	}
	if n.isBr {
		targetAbs := n.offset + n.delta
		ti, ok := byOffset[targetAbs]
		if !ok {
			return nil
		}
		if n.isGoto {
			return []int{ti}
		}
		// conditional: fallthrough + target
		if idx+1 < len(nodes) {
			return []int{idx + 1, ti}
		}
		return []int{ti}
	}
	if idx+1 < len(nodes) {
		return []int{idx + 1}
	}
	return nil
}

// classifyReturnValues помечает return-узлы подкормленным const (поиск назад
// до 4 строк, как в ClassifyFunnel). Возвращает map nodeIdx → value.
func classifyReturnValues(body []string, nodes []cfgNode) map[int]int32 {
	out := map[int]int32{}
	for ni, n := range nodes {
		if !strings.HasPrefix(n.mnem, "return") || n.mnem == "return-void" {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(body[n.lineIdx]))
		if len(fields) != 2 {
			continue
		}
		reg := fields[1]
		for j := n.lineIdx - 1; j >= 0 && j >= n.lineIdx-4; j-- {
			t := strings.TrimSpace(body[j])
			if dreg, ok := constDestRegister(t); ok && dreg == reg {
				if cur, lok := constLiteralValue(t); lok {
					v := cur
					out[ni] = v
				}
				break
			}
		}
	}
	return out
}

// FindEntryGateCFG находит entry-gate через CFG: первый conditional,
// достижимый от входа, с которого достижим желаемый возврат.
// desired: 0 или 1 (какое значение возврата считаем целью обхода).
// Возвращает body lineIdx гейта или -1.
func FindEntryGateCFG(body []string, desired int32) int {
	nodes, byOffset, ok := parseCFG(body)
	if !ok {
		return -1
	}
	retVals := classifyReturnValues(body, nodes)
	// Целевые return-узлы: с нужным значением; если ни один не классифицирован —
	// считаем целью любой return (деградация к первому гейту на пути).
	targets := map[int]bool{}
	for ni, v := range retVals {
		if v == desired {
			targets[ni] = true
		}
	}
	if len(targets) == 0 {
		for ni, n := range nodes {
			if strings.HasPrefix(n.mnem, "return") {
				targets[ni] = true
			}
		}
	}
	// Обратная достижимость: от каждого узла можно ли дойти до target?
	// N мало (методы ≤96 строк по safety-гейту) — BFS от каждого conditional.
	for ni, n := range nodes {
		if !n.isBr || n.isGoto {
			continue
		}
		if !isForwardReachable(nodes, byOffset, 0, ni) {
			continue
		}
		// С гейта достижим target?
		for _, succ := range cfgSuccessors(nodes, byOffset, ni) {
			if isForwardReachableToAny(nodes, byOffset, succ, targets) {
				return n.lineIdx
			}
		}
	}
	return -1
}

func isForwardReachable(nodes []cfgNode, byOffset map[int]int, from, to int) bool {
	if from == to {
		return true
	}
	visited := map[int]bool{from: true}
	queue := []int{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, s := range cfgSuccessors(nodes, byOffset, cur) {
			if s == to {
				return true
			}
			if !visited[s] {
				visited[s] = true
				queue = append(queue, s)
			}
		}
	}
	return false
}

func isForwardReachableToAny(nodes []cfgNode, byOffset map[int]int, from int, targets map[int]bool) bool {
	if targets[from] {
		return true
	}
	visited := map[int]bool{from: true}
	queue := []int{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, s := range cfgSuccessors(nodes, byOffset, cur) {
			if targets[s] {
				return true
			}
			if !visited[s] {
				visited[s] = true
				queue = append(queue, s)
			}
		}
	}
	return false
}
