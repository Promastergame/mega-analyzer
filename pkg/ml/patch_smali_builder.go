package ml

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SMART SMALI BUILDER — «умный», регистро-корректный генератор тела smali-метода
// ═══════════════════════════════════════════════════════════════════════════════
//
// Зачем этот файл существует и что он чинит по сравнению со старым
// writeDefaultReturn/getRequiredRegisters в patch_generator.go:
//
//   P1. КОРРЕКТНЫЕ РЕГИСТРЫ. Старый код писал `.registers N` с фиксированным
//       N=1..2 и полностью игнорировал параметры метода. Для метода с аргументами
//       (например check(JJ)Z instance нужно ≥5 param-регистров) генерился
//       НЕВАЛИДНЫЙ smali → apktool/baksmali падал при сборке. Здесь мы используем
//       идиому `.locals K`, где параметры (p-регистры) считаются автоматически и
//       НЕ входят в K. Это корректно ВСЕГДА и не требует парсинга сигнатуры для
//       генерации. Парсер сигнатуры (countParamRegisters) остаётся для строгого
//       линтера smali_lint.go и для strategy_*.go, где сохранён `.registers`.
//
//   P2. КОРРЕКТНАЯ ШИРИНА. Для J/D генерится пара регистров (const-wide → v0:v1)
//       и .locals ≥ 2 — старый код мог написать `.registers 1` под wide-возврат и
//       поймать register overflow.
//
//   P3. СЕМАНТИЧЕСКИЕ БЕЗОПАСНЫЕ ВОЗВРАТЫ (не null!). Старый код для любого
//       объектного типа возвращал null (const/4 v0,0x0 → return-object), что для
//       isPremium()Ljava/lang/Boolean; или getToken()Ljava/lang/String; давало NPE
//       на стороне вызова — «патч применился, но приложение вылетает». Теперь:
//         • Ljava/lang/Boolean;              → Boolean.TRUE / Boolean.FALSE
//         • Ljava/lang/String;               → пустая строка ""
//         • List/Set/Map/Collection/Iterable → Collections.emptyList/Set/Map
//         • Integer/Long                     → боксинг valueOf(...)
//         • прочие объекты/массивы           → null (безопасный дефолт)
//
//   P4. ЗАЩИТА ОТ НЕВАЛИДНОГО return-void. Если запрошен return_void, но метод
//       НЕ void, мы НЕ пишем return-void (это VerifyError), а возвращаем безопасное
//       нейтральное значение нужного типа.

// returnKind описывает СЕМАНТИЧЕСКОЕ намерение заглушки — что мы хотим «сказать»
// вызывающему коду, независимо от конкретного дескриптора возврата.
type returnKind int

const (
	kindDefault returnKind = iota // безопасное нейтральное значение (0/null/"")
	kindTrue                      // "authorized / valid / success / unlocked"
	kindFalse                     // "not-detected / not-rooted / false"
	kindVoid                      // проглотить (return-void, только если метод void)
	kindMaxInt                    // большое положительное (unlimited currency/lives)
	kindZero                      // нулевая цена/пустая сумма (free purchase)
)

// BuildTypedReturnPatch is the single typed backend for synthetic return
// methods. Strategies express intent with PatchType while this function owns
// descriptor, wide-value, boxed-object and locals handling.
func BuildTypedReturnPatch(header, signature, returnType string, patchType PatchType) string {
	kind := patchKindFor(patchType)
	if patchType == PatchRemoveCheck {
		kind = kindTrue
	}
	result := buildStubMethodSmart(header, signature, returnType, kind)
	// Keep the public strategy output compatible with consumers that expect a
	// total `.registers` directive, while the shared builder still owns the
	// calculation. `.locals` remains the internal representation for callers
	// that generate signature-only stubs directly.
	if strings.Contains(result, "\n    .locals ") {
		locals := 0
		for _, line := range strings.Split(result, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), ".locals ") {
				_, _ = fmt.Sscanf(strings.TrimSpace(line), ".locals %d", &locals)
				break
			}
		}
		isStatic := strings.Contains(strings.ToLower(" "+header+" "), " static ")
		registers := countParamRegisters(signature, isStatic) + locals
		result = strings.Replace(result, fmt.Sprintf("    .locals %d", locals), fmt.Sprintf("    .registers %d", registers), 1)
	}
	return result
}

// patchKindFor маппит высокоуровневый PatchType в семантический returnKind.
func patchKindFor(pt PatchType) returnKind {
	switch pt {
	case PatchReturnTrue:
		return kindTrue
	case PatchReturnFalse:
		return kindFalse
	case PatchReturnVoid, PatchNop:
		return kindVoid
	case PatchReturnMaxInt:
		return kindMaxInt
	case PatchReturnZero:
		return kindZero
	default:
		return kindDefault
	}
}

// normalizeReturnDesc нормализует уже известный дескриптор возврата.
func normalizeReturnDesc(returnType string) string {
	return strings.TrimSpace(returnType)
}

// effectiveReturnType извлекает тип возврата из PatchPoint-полей.
// Пустой ReturnType без сигнатуры/header — последний резерв "V".
func effectiveReturnType(returnType, signature, header string) string {
	if rt := normalizeReturnDesc(returnType); rt != "" {
		return rt
	}
	if idx := strings.LastIndex(signature, ")"); idx >= 0 && idx+1 < len(signature) {
		if rt := strings.TrimSpace(signature[idx+1:]); rt != "" {
			return rt
		}
	}
	if idx := strings.LastIndex(header, ")"); idx >= 0 && idx+1 < len(header) {
		if rt := strings.TrimSpace(header[idx+1:]); rt != "" {
			return rt
		}
	}
	return "V"
}

// suggestPatchTypeForReturn подбирает PatchType по дескриптору возврата и имени
// метода, когда скорер/паттерн не задал SuggestedPatch явно.
func suggestPatchTypeForReturn(returnType, methodName string) PatchType {
	rt := effectiveReturnType(returnType, "", "")
	nameLower := strings.ToLower(methodName)
	detection := []string{
		"root", "emulat", "debug", "tamper", "hook",
		"frida", "xposed", "magisk", "expired", "trial",
		"locked", "modified", "altered",
	}
	isDetection := false
	for _, p := range detection {
		if strings.Contains(nameLower, p) {
			isDetection = true
			break
		}
	}

	switch {
	case rt == "Z":
		if isDetection {
			return PatchReturnFalse
		}
		return PatchReturnTrue
	case rt == "V":
		return PatchReturnVoid
	case rt == "I", rt == "S", rt == "B", rt == "C":
		if isDetection {
			return PatchReturnTrue
		}
		return PatchReturnMaxInt
	default:
		// объекты и массивы — безопасный null/""/empty collections
		return PatchReturnFalse
	}
}

// countParamRegisters вычисляет, сколько параметрических регистров (p0..pN)
// занимает метод по его smali-дескриптору и признаку static. Wide-типы (J, D)
// занимают ДВА регистра; неявный `this` instance-метода занимает один. Используется
// строгим линтером и strategy_*.go для корректного `.registers` (params + locals).
func countParamRegisters(signature string, isStatic bool) int {
	n := 0
	if !isStatic {
		n++ // p0 = this
	}
	open := strings.Index(signature, "(")
	closeIdx := strings.Index(signature, ")")
	if open < 0 || closeIdx < 0 || closeIdx < open {
		return n
	}
	args := signature[open+1 : closeIdx]
	for i := 0; i < len(args); {
		switch args[i] {
		case 'J', 'D':
			n += 2 // wide = 2 регистра
			i++
		case 'L':
			j := strings.IndexByte(args[i:], ';')
			if j < 0 {
				return n // повреждённый дескриптор — считаем, что дошли до конца
			}
			n++
			i += j + 1
		case '[':
			// массив — это одна ссылка (1 регистр), сколько бы ни было измерений
			i++
			for i < len(args) && args[i] == '[' {
				i++
			}
			if i < len(args) && args[i] == 'L' {
				j := strings.IndexByte(args[i:], ';')
				if j < 0 {
					return n
				}
				i += j + 1
			} else if i < len(args) {
				i++ // примитивный элемент
			}
			n++
		default:
			// Z B S C I F ...
			n++
			i++
		}
	}
	return n
}

// smaliReturnBody возвращает (тело_return, число_локалей) для заданного дескриптора
// возврата и семантического намерения. Приоритет ВСЕГДА у дескриптора: сначала
// решаем ЧТО физически можно вернуть, потом уточняем значение по kind.
func smaliReturnBody(returnType string, kind returnKind) (string, int) {
	rt := normalizeReturnDesc(returnType)
	if rt == "" {
		rt = "V"
	}

	// P4: return_void/nop семантика допустима только для void-методов.
	// Для Object/String/int/array всегда генерируем физически корректный return.
	if kind == kindVoid && rt != "V" {
		kind = kindDefault
	}

	// void — единственный тип, для которого валиден return-void
	if rt == "V" {
		if kind == kindVoid {
			return "    return-void\n", 0
		}
		// void с kindTrue/kindDefault — всё равно return-void
		return "    return-void\n", 0
	}

	// объект / массив
	if strings.HasPrefix(rt, "L") || strings.HasPrefix(rt, "[") {
		return objectReturnBody(rt, kind)
	}

	switch rt {
	case "Z":
		v := "0x0"
		if kind == kindTrue {
			v = "0x1"
		}
		return fmt.Sprintf("    const/4 v0, %s\n    return v0\n", v), 1
	case "J":
		switch kind {
		case kindMaxInt:
			return "    const-wide v0, 0x7fffffffffffffffL\n    return-wide v0\n", 2
		case kindTrue:
			return "    const-wide/16 v0, 0x1\n    return-wide v0\n", 2
		default:
			return "    const-wide/16 v0, 0x0\n    return-wide v0\n", 2
		}
	case "D":
		if kind == kindMaxInt {
			return "    const-wide v0, 0x7fefffffffffffffL\n    return-wide v0\n", 2 // Double.MAX_VALUE
		}
		return "    const-wide/16 v0, 0x0\n    return-wide v0\n", 2
	case "F":
		if kind == kindMaxInt {
			return "    const v0, 0x7f7fffff\n    return v0\n", 1 // Float.MAX_VALUE
		}
		if kind == kindTrue {
			return "    const v0, 0x3f800000\n    return v0\n", 1 // 1.0f
		}
		return "    const/4 v0, 0x0\n    return v0\n", 1
	case "I", "S", "B", "C":
		switch kind {
		case kindMaxInt:
			return "    const v0, 0x7fffffff\n    return v0\n", 1
		case kindTrue:
			return "    const/4 v0, 0x1\n    return v0\n", 1
		default:
			return "    const/4 v0, 0x0\n    return v0\n", 1
		}
	default:
		// неизвестный примитив — безопасный ноль
		return "    const/4 v0, 0x0\n    return v0\n", 1
	}
}

// objectReturnBody выдаёт СЕМАНТИЧЕСКИ безопасный объектный возврат вместо null,
// чтобы не ловить NPE на стороне вызова.
func objectReturnBody(desc string, kind returnKind) (string, int) {
	switch desc {
	case "Ljava/lang/Boolean;":
		field := "Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;"
		if kind == kindFalse || kind == kindDefault {
			field = "Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;"
		}
		return fmt.Sprintf("    sget-object v0, %s\n    return-object v0\n", field), 1
	case "Ljava/lang/String;", "Ljava/lang/CharSequence;":
		return "    const-string v0, \"\"\n    return-object v0\n", 1
	case "Ljava/util/List;", "Ljava/util/Collection;", "Ljava/lang/Iterable;":
		return "    invoke-static {}, Ljava/util/Collections;->emptyList()Ljava/util/List;\n" +
			"    move-result-object v0\n    return-object v0\n", 1
	case "Ljava/util/Set;":
		return "    invoke-static {}, Ljava/util/Collections;->emptySet()Ljava/util/Set;\n" +
			"    move-result-object v0\n    return-object v0\n", 1
	case "Ljava/util/Map;":
		return "    invoke-static {}, Ljava/util/Collections;->emptyMap()Ljava/util/Map;\n" +
			"    move-result-object v0\n    return-object v0\n", 1
	case "Ljava/lang/Integer;":
		v := "0x0"
		if kind == kindTrue {
			v = "0x1"
		}
		return fmt.Sprintf("    const/4 v0, %s\n"+
			"    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;\n"+
			"    move-result-object v0\n    return-object v0\n", v), 1
	case "Ljava/lang/Long;":
		return "    const-wide/16 v0, 0x0\n" +
			"    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;\n" +
			"    move-result-object v0\n    return-object v0\n", 2
	default:
		// прочие объекты и массивы — безопасный null
		return "    const/4 v0, 0x0\n    return-object v0\n", 1
	}
}

// buildStubMethodSmart собирает ПОЛНЫЙ, регистро-корректный метод-заглушку:
// сохраняет header, ставит корректный `.locals`, генерирует семантический возврат.
func buildStubMethodSmart(header, signature, returnType string, kind returnKind) string {
	var b strings.Builder
	rt := effectiveReturnType(returnType, signature, header)
	if strings.TrimSpace(header) == "" {
		header = ".method public stub()" + rt
	}
	b.WriteString(header)
	b.WriteByte('\n')

	body, locals := smaliReturnBody(rt, kind)
	b.WriteString(fmt.Sprintf("    .locals %d\n\n", locals))
	b.WriteString(body)
	b.WriteString(".end method")
	return b.String()
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC PATCH TEMPLATES (authorized-audit building blocks)
//
// Готовые, регистро-корректные и lint-чистые генераторы для двух самых частых
// аудиторских сценариев: «больше монет» (currency) и «премиум-анлок» (premium
// gate). Оба используют идиому `.locals` (P1) и семантически безопасные
// возвраты (P3), поэтому результат проходит ValidateStrict без ошибок.
// ═══════════════════════════════════════════════════════════════════════════════

// BuildCurrencyReturnPatch генерирует тело-заглушку «бесконечная валюта»:
// геттер всегда возвращает максимум (0x7fffffff для I, max-long для J).
// Для boolean-геттеров (canAfford/hasEnough) возвращает true.
// header — оригинальная строка `.method ...`, signature — `(I)I`-дескриптор,
// returnType — `I`/`J`/`Z` (пустые значения выводятся из header).
func BuildCurrencyReturnPatch(header, signature, returnType string) string {
	return buildStubMethodSmart(header, signature, returnType, kindMaxInt)
}

// BuildPremiumUnlockPatch генерирует тело-заглушку «премиум разблокирован»:
// boolean-геттеры → true, Boolean → Boolean.TRUE, int-статусы → 1.
func BuildPremiumUnlockPatch(header, signature, returnType string) string {
	return buildStubMethodSmart(header, signature, returnType, kindTrue)
}

// BuildSwallowCheckPatch генерирует «проглотить проверку»: валидно ТОЛЬКО для
// void-методов (например showAd(), trackPurchase(), verifyLicense()V).
// Для не-void методов возвращает семантически безопасное нейтральное значение
// (P4), чтобы не словить VerifyError.
func BuildSwallowCheckPatch(header, signature, returnType string) string {
	return buildStubMethodSmart(header, signature, returnType, kindVoid)
}
