package ml

import (
	"fmt"
	"regexp"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// STRICT SMALI LINT — «round-trip» проверка, которую НЕ ловит regex-валидатор
// ═══════════════════════════════════════════════════════════════════════════════
//
// SmaliValidator.Validate — эвристический (regex) и НЕ знает о параметрических
// регистрах: он не может поймать самый частый класс невалидного smali —
// `.registers N`, где N меньше числа param-регистров метода. Такой патч
// «применяется», но apktool/baksmali падает при сборке APK.
//
// LintSmaliStrict парсит дескриптор метода, считает param-регистры (wide=2,
// this=1) и проверяет:
//
//   L1. Бюджет регистров. Для `.registers N` требуется N ≥ paramRegs. Для
//       `.locals K` бюджет всегда корректен по построению (params отдельно).
//   L2. Пары wide. const-wide/return-wide/*-wide на vX требуют, чтобы пара
//       vX:v(X+1) целиком помещалась в бюджет.
//   L3. Совместимость return-опкода с типом возврата (дублирует Validate, но в
//       строгом режиме — как ошибка).
//   L4. Наличие директивы `.registers`/`.locals`.
//
// Это НЕ трогает существующий Validate (нулевой риск для текущих тестов): строгие
// проверки доступны через новый LintSmaliStrict и метод ValidateStrict.

var lintMethodHeaderRe = regexp.MustCompile(`^\s*\.method\b(.*)$`)
var lintDescRe = regexp.MustCompile(`(\([^)]*\)\S+)`)
var lintRegistersRe = regexp.MustCompile(`\.registers\s+(\d+)`)
var lintLocalsRe = regexp.MustCompile(`\.locals\s+(\d+)`)
var lintVRegRe = regexp.MustCompile(`\bv(\d+)\b`)

// LintSmaliStrict возвращает список СТРОГИХ проблем сгенерированного smali.
// Пустой срез = патч валиден и должен собраться. Ненулевой = патч, скорее всего,
// сломает сборку/рантайм и требует ревью (needs_review).
func LintSmaliStrict(code string) []string {
	issues := make([]string, 0)
	if strings.TrimSpace(code) == "" {
		return []string{"empty smali"}
	}
	lines := validationLines(code)

	// 1. header → дескриптор, static, тип возврата
	header := ""
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), ".method ") {
			header = strings.TrimSpace(l)
			break
		}
	}
	if header == "" {
		issues = append(issues, "missing .method header")
		return issues
	}
	isStatic := strings.Contains(" "+strings.ToLower(header)+" ", " static ")
	sig := ""
	if m := lintDescRe.FindStringSubmatch(header); len(m) > 1 {
		sig = m[1]
	}
	returnType := ""
	if idx := strings.LastIndex(header, ")"); idx != -1 && idx+1 < len(header) {
		returnType = strings.TrimSpace(header[idx+1:])
	}
	paramRegs := countParamRegisters(sig, isStatic)

	// 2. бюджет регистров (L1 + L4)
	budget := -1        // общий бюджет v-регистров, доступных в методе
	usesLocals := false // true → директива .locals
	for _, l := range lines {
		if m := lintRegistersRe.FindStringSubmatch(l); len(m) > 1 {
			n := atoiSafe(m[1])
			budget = n
			if n < paramRegs {
				issues = append(issues, fmt.Sprintf(
					".registers %d < parameter registers %d - apktool/smali cannot assemble this (L1)", n, paramRegs))
			}
			break
		}
		if m := lintLocalsRe.FindStringSubmatch(l); len(m) > 1 {
			usesLocals = true
			budget = atoiSafe(m[1]) + paramRegs
			break
		}
	}
	if budget < 0 {
		issues = append(issues, "missing .registers/.locals directive (L4)")
		return issues
	}

	// 3. Check parsed operands, physical p aliases and wide pairs by position.
	operands := ValidationResult{Valid: true}
	NewSmaliValidator().validateOperandLines(lines, &operands, true)
	for _, issue := range operands.Errors {
		issues = append(issues, issue.Error())
	}

	// 4. invoke/move-result pairing. A common surgical-patch failure is to
	// replace an invoke with nop but leave its move-result behind; the verifier
	// rejects that sequence even though the register counts look correct.
	for _, issue := range lintInvokeResults(lines) {
		issues = append(issues, issue)
	}

	// 5. совместимость return-опкода с типом возврата (L3)
	if returnType != "" {
		for i, l := range lines {
			trimmed := strings.TrimSpace(l)
			if !strings.HasPrefix(trimmed, "return") {
				continue
			}
			opcode := strings.Fields(trimmed)[0]
			if !isReturnOpcodeCompatible(opcode, returnType) {
				issues = append(issues, fmt.Sprintf(
					"line %d: return opcode %s is incompatible with return type %s (L3)", i+1, opcode, returnType))
			}
		}
	}

	// 6. p-регистры вне диапазона параметров (L6). pN — алиас на
	// v(budget-paramRegs+N): N >= paramRegs адресует локальный регистр или
	// вываливается за бюджет → VerifyError в рантайме.
	if sig != "" { // дескриптор распарсился — иначе L6 не применяем
		for i, l := range lines {
			trimmed := strings.TrimSpace(l)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ".") || strings.HasPrefix(trimmed, ":") {
				continue
			}
			for _, m := range svPRegRe.FindAllStringSubmatch(smaliRegisterOperands(trimmed), -1) {
				if atoiSafe(m[1]) >= paramRegs {
					issues = append(issues, fmt.Sprintf(
						"line %d: p%s is outside the parameter register range (total %d) (L6)", i+1, m[1], paramRegs))
				}
			}
		}
	}

	// 7. Дубли меток (L7). Два одинаковых :label в одном методе — baksmali
	// соберёт, но переходы станут неоднозначными; apktool чаще всего падает.
	seenLabels := make(map[string]int)
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if !strings.HasPrefix(trimmed, ":") {
			continue
		}
		label := strings.Fields(trimmed)[0]
		if first, dup := seenLabels[label]; dup {
			issues = append(issues, fmt.Sprintf(
				"line %d: duplicate label %s (first seen on line %d) (L7)", i+1, label, first))
		} else {
			seenLabels[label] = i + 1
		}
	}

	// 8. Парность .method/.end method (L8) — в строгом режиме это ошибка,
	// а не мягкое предупреждение.
	hasEnd := false
	for _, l := range lines {
		if strings.TrimSpace(l) == ".end method" {
			hasEnd = true
			break
		}
	}
	if !hasEnd {
		issues = append(issues, "missing .end method (L8)")
	}

	_ = usesLocals // сохранено для будущих проверок стиля
	return issues
}

// lintInvokeResults checks that every move-result* immediately follows an invoke
// and that its opcode family agrees with the invoked method's return descriptor.
func lintInvokeResults(lines []string) []string {
	issues := make([]string, 0)
	previous := ""
	previousText := ""
	previousLine := 0
	for i, line := range validationLines(strings.Join(lines, "\n")) {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ".") || strings.HasPrefix(trimmed, ":") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		opcode := fields[0]
		if strings.HasPrefix(opcode, "move-result") {
			if strings.HasPrefix(previous, "filled-new-array") {
				if opcode != "move-result-object" {
					issues = append(issues, fmt.Sprintf("line %d: filled-new-array requires move-result-object", i+1))
				}
			} else if !strings.HasPrefix(previous, "invoke-") {
				issues = append(issues, fmt.Sprintf("line %d: %s does not immediately follow an invoke (L5)", i+1, opcode))
			} else {
				returnType := invokeReturnType(previousText)
				if !moveResultCompatible(opcode, returnType) {
					issues = append(issues, fmt.Sprintf("line %d: %s is incompatible with the invoke result on line %d (type %s) (L5)", i+1, opcode, previousLine, returnType))
				}
			}
		}
		previous = opcode
		previousText = trimmed
		previousLine = i + 1
	}
	return issues
}

func invokeReturnType(line string) string {
	idx := strings.LastIndex(line, ")")
	if idx < 0 || idx+1 >= len(line) {
		return ""
	}
	return line[idx+1:]
}

func moveResultCompatible(opcode, returnType string) bool {
	if returnType == "" || returnType == "V" {
		return false
	}
	if opcode == "move-result-wide" {
		return returnType == "J" || returnType == "D"
	}
	if opcode == "move-result-object" {
		return strings.HasPrefix(returnType, "L") || strings.HasPrefix(returnType, "[")
	}
	return opcode == "move-result" && returnType != "J" && returnType != "D" && !strings.HasPrefix(returnType, "L") && !strings.HasPrefix(returnType, "[")
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// ValidateStrict = обычный Validate + строгие проверки регистров/wide/возврата.
// Отдельный метод, чтобы не менять поведение Validate и не ломать существующие
// тесты валидатора. Строгие находки добавляются как ошибки.
func (sv *SmaliValidator) ValidateStrict(smaliCode string) ValidationResult {
	result := sv.Validate(smaliCode)
	for _, issue := range LintSmaliStrict(smaliCode) {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Message: issue,
			Code:    ErrInvalidSmali,
		})
	}
	return result
}
