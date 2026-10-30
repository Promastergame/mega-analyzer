// Package piracy — keywords.go
//
// Экспортируемый мост для потребителей, которым нужен ПЛОСКИЙ набор
// watermark-ключей репакеров/warez, а не полный движок Analyze.
//
// Ранее пакет ml хранил хардкод пиратских ссылок (androeed.ru, 4pda.ru,
// apkmody, …) прямо в feedback.go. Теперь единственный источник истины —
// этот пакет: домены, алиасы и watermark-строки 30+ сайтов из DefaultConfig.
// ml просто вызывает WatermarkKeywords() и получает готовую карту damp-весов.
package piracy

import "strings"

// noiseDamp — вес подавления шума. Совпадает с историческим значением 0.01,
// которое ml применял к watermark-строкам, чтобы репакерский «мусор» не тянул
// score метода вверх и не создавал ложные находки.
const noiseDamp = 0.01

// WatermarkKeywords возвращает набор watermark-ключей из DefaultConfig в виде
// map[keyword]damp. Все ключи в нижнем регистре, значение — noiseDamp.
//
// Это прямая замена хардкодного KnownWatermarks в ml: список пиратских сайтов
// живёт в одном месте (piracy) и расширяется добавлением сайта в DefaultConfig.
func WatermarkKeywords() map[string]float64 {
	return WatermarkKeywordsFrom(DefaultConfig)
}

// WatermarkKeywordsFrom строит карту watermark-ключей из произвольного конфига,
// чтобы можно было подложить кастомный или загруженный из файла Config
// (NewDetectorFromFile / NewDetectorFromBytes используют ту же структуру).
func WatermarkKeywordsFrom(cfg Config) map[string]float64 {
	out := make(map[string]float64, len(cfg.Sites)*4+len(cfg.WatermarkPatterns))

	add := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			return
		}
		out[v] = noiseDamp
	}

	for _, s := range cfg.Sites {
		for _, d := range s.Domains {
			add(d)
		}
		for _, a := range s.Aliases {
			add(a)
		}
		for _, w := range s.Watermarks {
			add(w.Value)
		}
		// Historical (сменившие адрес) домены тоже помечаем как шум —
		// старые репаки всё ещё встречаются «в дикой природе».
		for _, d := range s.HistoricalDomains {
			add(d)
		}
	}
	for _, w := range cfg.WatermarkPatterns {
		add(w.Value)
	}
	return out
}
