"""Hand-labelled golden set for DecisionAI System One (v0, small).
Labels are written by a human reviewer from the state text alone. Split by group into
calibration (odd) and test (even) so metrics are reported on held-out examples."""
import json
Q = {
 "effect": {"type":"noul","instructions":"Подтверждён ли нужный эффект патча?","criteria":{"true":"Эффект наблюдался на текущей сборке","false":"Эффект не наблюдался, тест не запускался или был на другой версии"}},
 "server": {"type":"score","instructions":"Насколько поведение зависит от сервера?","criteria":{"0":"Полностью локально, сеть не участвует","1":"Значение кэшируется с сервера","2":"Сервер проверяет значение","3":"Значение полностью решает сервер"}},
 "role": {"type":"choice","instructions":"Какую роль играет изменённый литерал?","criteria":{"limit":"Лимит или максимум значения","delay":"Задержка, таймер или кулдаун","color":"Цвет или элемент интерфейса","resource_id":"Идентификатор ресурса","other":None}},
 "fp": {"type":"noul","instructions":"Это ложное срабатывание?","criteria":{"true":"Находка не является реальной проблемой","false":"Находка — реальная проблема в коде приложения"}},
 "cat": {"type":"choice","instructions":"Категория находки","criteria":{"secrets":"Утечка секретов, ключей или паролей","crypto":"Слабая криптография или хеширование","network":"Небезопасная сеть, HTTP или отключённая проверка TLS","storage":"Небезопасное хранение данных на устройстве","other":None}},
 "dept": {"type":"choice","instructions":"Which team should handle this?","criteria":{"returns":"Exchanges, wrong or damaged items","shipping":"Delivery status, delays, lost packages","billing":"Charges, invoices, payment problems"}},
 "human": {"type":"noul","instructions":"The customer is asking to talk to a human agent"},
 "tone": {"type":"choice","instructions":"What is the customer's tone?","criteria":{"calm":None,"frustrated":None,"angry":None}},
}
P = [  # (state, labels)
 ("После патча лимит монет в магазине стал 1000 вместо 100. Проверено на текущей сборке, сеть отключена.", {"effect":True,"server":"0","role":"limit"}),
 ("Сборка прошла, но тесты на устройстве не запускались. Значение задержки 500 мс заменено на 50 мс.", {"effect":False,"role":"delay"}),
 ("После замены константы баланс на экране вырос, но после синхронизации с сервером вернулся к прежнему значению.", {"effect":False,"server":"3"}),
 ("Изменён цвет кнопки покупки с 0xFF0000 на 0x00FF00. На скриншоте текущей сборки кнопка зелёная.", {"effect":True,"server":"0","role":"color"}),
 ("Тест прошёл, но на сборке предыдущей версии, не на текущем кандидате. Литерал — максимальное число попыток.", {"effect":False,"role":"limit"}),
 ("Кулдаун способности уменьшен с 30 секунд до 5. На текущей сборке способность перезаряжается за 5 секунд, запросов к серверу нет.", {"effect":True,"server":"0","role":"delay"}),
 ("Значение лимита загружается из ответа сервера при старте и сохраняется в кэш; патч меняет значение по умолчанию.", {"server":"1","role":"limit"}),
 ("Сервер проверяет количество монет при каждой покупке и отклоняет некорректные значения. Эффект на клиенте не наблюдался.", {"effect":False,"server":"2"}),
 ("Изменён идентификатор строки R.string.app_name 0x7f0e001b. Приложение показывает другое название на текущей сборке.", {"effect":True,"role":"resource_id","server":"0"}),
 ("Runtime тест завершился ошибкой: приложение падает при открытии магазина после патча.", {"effect":False}),
 ("Таймер показа рекламы увеличен с 60 до 600 секунд. Проверено на эмуляторе с текущим SHA, реклама появляется через 10 минут.", {"effect":True,"role":"delay","server":"0"}),
 ("Награда за уровень рассчитывается на сервере, клиент только отображает полученное значение.", {"server":"3"}),
]
F = [
 ("Hardcoded API key в ApiClient.smali: const-string \"sk_live_9f8a...\" используется в заголовке Authorization.", {"fp":False,"cat":"secrets"}),
 ("Строка \"password\" найдена в layout как подпись поля ввода (hint), значение не хранится.", {"fp":True,"cat":"other"}),
 ("Используется MessageDigest.getInstance(\"MD5\") для хеширования паролей пользователей.", {"fp":False,"cat":"crypto"}),
 ("TrustManager принимает все сертификаты: checkServerTrusted пустой, используется в продакшен-клиенте.", {"fp":False,"cat":"network"}),
 ("Токен сессии сохраняется в SharedPreferences в открытом виде, MODE_WORLD_READABLE.", {"fp":False,"cat":"storage"}),
 ("Найден ключ в тестовом файле библиотеки com/google/ads/testdata, в приложении не используется.", {"fp":True,"cat":"secrets"}),
 ("Запросы к http://api.example.com идут без TLS, передаётся email пользователя.", {"fp":False,"cat":"network"}),
 ("AES в режиме ECB с ключом, захардкоженным в коде, шифрует локальную базу.", {"fp":False,"cat":"crypto"}),
 ("Логирование отладочной информации отключено в release-сборке, строка Log.d остаётся только в debug.", {"fp":True,"cat":"other"}),
 ("Номер карты пользователя записывается в файл во внешнем хранилище без шифрования.", {"fp":False,"cat":"storage"}),
]
S = [
 ("My order says delivered but nothing arrived. Where is my package?", {"dept":"shipping","human":False,"tone":"frustrated"}),
 ("Hi! Could I exchange the blue sweater for a medium size? Thanks a lot.", {"dept":"returns","human":False,"tone":"calm"}),
 ("You charged me twice for the same order. Fix this NOW or I'm calling my bank.", {"dept":"billing","tone":"angry","human":False}),
 ("I have asked three times now. Can I please just talk to a real person?", {"human":True,"tone":"frustrated"}),
 ("The package is a week late and the tracking hasn't updated since Monday.", {"dept":"shipping","tone":"frustrated","human":False}),
 ("Is there any way to speak to someone about my invoice?", {"dept":"billing","human":True,"tone":"calm"}),
 ("The lamp arrived broken, the glass is shattered. I want a replacement.", {"dept":"returns","human":False}),
 ("This is the worst service ever. Your bot is useless, get me a human manager immediately!", {"human":True,"tone":"angry"}),
 ("Can you send me a copy of the receipt for my last payment?", {"dept":"billing","human":False,"tone":"calm"}),
 ("Thanks, that fixed it!", {"human":False,"tone":"calm"}),
]
rows = []
for name, data in (("patch", P), ("finding", F), ("support", S)):
    for i, (state, labels) in enumerate(data):
        qs = {k: Q[k] for k in labels}
        rows.append({"group": f"{name}-{i}", "split": "calib" if i % 2 else "test",
                     "request": {"state": state, "questions": qs}, "labels": labels})
for split in ("calib", "test"):
    with open(f"golden-{split}.jsonl", "w", encoding="utf-8") as f:
        for r in rows:
            if r["split"] == split:
                r2 = {k: v for k, v in r.items() if k != "split"}
                f.write(json.dumps(r2, ensure_ascii=False) + "\n")
print({s: sum(r["split"] == s for r in rows) for s in ("calib", "test")}, "labels:", sum(len(r["labels"]) for r in rows))
