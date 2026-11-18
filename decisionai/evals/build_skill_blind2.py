"""Blind set #2 (v1.6): written BEFORE the v1.6 changes, scored once, never tuned on.
`plan` lists the skills a multi-step request needs (order-free)."""
import json
F, A, C, T, B = "frontend-design", "artifact-design", "canvas-design", "theme-factory", "brand-guidelines"
single = [
 ("design", "агент верстает как из 2010, нужен скилл посовременнее", [F]),
 ("design", "кнопки и карточки выглядят дешево, прокачай стиль", [F]),
 ("design", "нужна обложка для подкаста png", [C, A, "image-generation"]),
 ("design", "приведи отчёт к нашим корпоративным цветам", [B]),
 ("office", "конвертируй таблицу в xlsx и раскрась заголовки", ["xlsx"]),
 ("office", "сделай 3 слайда с итогами квартала", ["pptx"]),
 ("office", "добавь комментарии в docx договор", ["docx"]),
 ("office", "достань текст из отсканированного договора", ["pdf"]),
 ("writing", "статья слишком канцелярская и пахнет gpt, оживи", ["humanizer"]),
 ("writing", "переведи README на китайский", ["translator"]),
 ("writing", "напиши follow-up клиенту после демо", ["email-writer"]),
 ("writing", "протокол вчерашней планерки с задачами", ["meeting-notes"]),
 ("writing", "напиши пост для сотрудников об инциденте с сервером", ["internal-comms"]),
 ("writing", "мой агент плохо слушается системной инструкции", ["prompt-engineering"]),
 ("code", "segfault после обновления библиотеки, разберись", ["systematic-debugging"]),
 ("code", "оставь замечания к моему коммиту как ревьюер", ["code-review"]),
 ("code", "сквошни последние три коммита", ["git-commit"]),
 ("code", "explain this slow postgres query plan", ["sql-expert"]),
 ("code", "проверь конфиги на открытые секреты", ["security-audit"]),
 ("code", "подними сервис в docker compose", ["docker-deploy"]),
 ("code", "обёртка mcp для нашего crm", ["mcp-builder"]),
 ("code", "в apk поменяй таймер с 30 на 5 секунд", ["apk-reverse"]),
 ("web", "залогинься на сайте и скачай счёт", ["agent-browser"]),
 ("web", "что нового вышло у anthropic на этой неделе", ["web-search"]),
 ("web", "проверь что форма регистрации работает в моем локальном приложении", ["webapp-testing"]),
 ("data", "какие клиенты приносят больше всего выручки, разбей по сегментам", ["data-analysis"]),
 ("data", "линейный график посещаемости по дням", ["inline-charts"]),
 ("media", "нарисуй аватарку в стиле аниме", ["image-generation"]),
 ("media", "гифка с танцующим котом для слака", ["slack-gif-creator"]),
 ("media", "рендер mp4 с анимированными титрами", ["video-remotion"]),
 ("media", "сделай генеративный узор частицами в p5", ["algorithmic-art"]),
 ("meta", "скилл не подхватывается агентом, поправь frontmatter", ["skill-creator"]),
 ("other", "сколько стоит биткоин", ["other"]),
 ("other", "поставь будильник на 7", ["other"]),
 ("other", "что такое любовь", ["other"]),
 ("other", "переведи 500 рублей маме", ["other"]),
]
multi = [
 ("multi", "проанализируй продажи и построй график", ["data-analysis", "inline-charts"]),
 ("multi", "найди свежие новости про ИИ и сделай из них презентацию", ["web-search", "pptx"]),
 ("multi", "переведи статью на английский, а потом убери следы нейросети", ["translator", "humanizer"]),
 ("multi", "найди баг, потом напиши коммит с фиксом", ["systematic-debugging", "git-commit"]),
 ("multi", "сделай лендинг и протестируй его в браузере через playwright", [F, "webapp-testing"]),
 ("multi", "выжимка созвона и письмо участникам с итогами", ["meeting-notes", "email-writer"]),
]
with open("skill-routing-blind2.jsonl", "w", encoding="utf-8") as f:
    for g, q, acc in single:
        f.write(json.dumps({"group": g, "state": q, "accept": acc}, ensure_ascii=False) + "\n")
    for g, q, plan in multi:
        f.write(json.dumps({"group": g, "state": q, "accept": plan, "plan": plan}, ensure_ascii=False) + "\n")
print(len(single) + len(multi))
