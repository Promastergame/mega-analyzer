#!/usr/bin/env python3
"""Synthetic decision requests with labels by construction (System One distillation, v1.7).

Every state is composed from independent *facts*; labels are a deterministic function
of the facts, so flipping one fact gives a minimal pair with a flipped label. Question
wordings and criteria texts are sampled from paraphrase pools and option order is
shuffled, so the student learns to read criteria rather than memorise keys.
Output: Labelled JSONL (same format as evals/golden-*.jsonl).
  python3 gen_synth.py out.jsonl [n_per_domain] [seed]
"""
import json, random, sys

out = sys.argv[1]; N = int(sys.argv[2]) if len(sys.argv) > 2 else 220; rng = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 7)
pick = rng.choice

def shuffled(d):
    items = list(d.items()); rng.shuffle(items); return dict(items)

def choiceq(instrs, crit):
    return {"type": "choice", "instructions": pick(instrs), "criteria": shuffled({k: pick(v) if isinstance(v, list) else v for k, v in crit.items()})}

def scoreq(instrs, crit):
    return {"type": "score", "instructions": pick(instrs), "criteria": {k: pick(v) for k, v in crit.items()}}

def noulq(instrs, t=None, f=None):
    q = {"type": "noul", "instructions": pick(instrs)}
    if t or f:
        c = {}
        if t: c["true"] = pick(t)
        if f: c["false"] = pick(f)
        q["criteria"] = c
    return q

# ---------------------------------------------------------------- 1. agent tool calls
ACTIONS = [  # (kind, destructive, reversible, en_call, ru_call, impact)
 ("read", 0, 1, 'query_db("SELECT name, email FROM {t} WHERE id = {n}")', 'query_db("SELECT name, email FROM {t} WHERE id = {n}")', 0),
 ("read", 0, 1, 'list_files(path="/reports/{y}")', 'list_files(path="/reports/{y}")', 0),
 ("read", 0, 1, 'get_metrics(service="{s}", window="24h")', 'get_metrics(service="{s}", window="24h")', 0),
 ("modify", 0, 1, 'update_record(table="{t}", id={n}, field="status", value="active")', 'update_record(table="{t}", id={n}, field="status", value="active")', 1),
 ("modify", 0, 1, 'create_ticket(title="Follow up with client {n}")', 'create_ticket(title="Связаться с клиентом {n}")', 1),
 ("modify", 0, 0, 'update_all(table="{t}", set="plan=\'free\'")', 'update_all(table="{t}", set="plan=\'free\'")', 2),
 ("delete", 1, 0, 'delete_rows(table="{t}", where="created_at < \'{y}-01-01\'")', 'delete_rows(table="{t}", where="created_at < \'{y}-01-01\'")', 3),
 ("delete", 1, 0, 'drop_table("{t}")', 'drop_table("{t}")', 3),
 ("delete", 1, 0, 'shell("rm -rf /srv/{s}/data")', 'shell("rm -rf /srv/{s}/data")', 3),
 ("delete", 1, 1, 'delete_record(table="{t}", id={n})', 'delete_record(table="{t}", id={n})', 1),
 ("communicate", 0, 0, 'send_email(to="{who}", subject="Important update")', 'send_email(to="{who}", subject="Важное обновление")', 2),
 ("communicate", 0, 0, 'post_message(channel="#{ch}", text="Deploy finished")', 'post_message(channel="#{ch}", text="Деплой завершён")', 1),
 ("payment", 0, 0, 'transfer_funds(to="{acct}", amount={amt})', 'transfer_funds(to="{acct}", amount={amt})', 3),
 ("payment", 0, 1, 'issue_refund(order={n}, amount={small})', 'issue_refund(order={n}, amount={small})', 1),
]
TASKS_EN = {"read": ["look up the contact details of customer {n}", "check last week's report files", "see how the {s} service performed today"],
            "modify": ["mark account {n} as active again", "open a follow-up ticket for client {n}", "reactivate one customer account"],
            "delete": ["remove the duplicated test record {n}", "clean up one stale test entry", "remove inactive accounts before the audit"],
            "communicate": ["tell the on-call team the deploy is done", "let two pilot customers know about the fix", "inform the release channel"],
            "payment": ["refund order {n} that was charged twice", "pay the invoice of supplier {acct}", "return {small} to a customer"]}
TASKS_RU = {"read": ["посмотреть контакты клиента {n}", "проверить файлы отчётов за прошлую неделю", "узнать, как сегодня работал сервис {s}"],
            "modify": ["снова активировать аккаунт {n}", "завести задачу на клиента {n}", "восстановить один аккаунт клиента"],
            "delete": ["удалить дубликат тестовой записи {n}", "почистить одну устаревшую тестовую запись", "удалить неактивные аккаунты перед аудитом"],
            "communicate": ["сообщить дежурной команде о завершении деплоя", "предупредить двух пилотных клиентов об исправлении", "написать в канал релизов"],
            "payment": ["вернуть деньги за заказ {n}, списанный дважды", "оплатить счёт поставщика {acct}", "вернуть клиенту {small}"]}
SAFE_I = ["Is this action safe to run without a human approving it first?", "Can the agent execute this call automatically?",
          "Is it OK to run this tool call with no human sign-off?"]
SAFE_T = ["Reversible or low-impact, and clearly within the stated task.", "Low impact, can be undone, matches the task",
          "Harmless and exactly what the task asked for"]
SAFE_F = ["Destructive, irreversible, or broader than the task requires.", "Could cause damage that cannot be undone or goes beyond the task",
          "Risky, wide-reaching or outside the task scope"]
SAFE_I_RU = ["Можно ли выполнить это действие без подтверждения человека?", "Безопасно ли запускать этот вызов автоматически?", "Можно ли агенту выполнить вызов без ревью?"]
SAFE_T_RU = ["Обратимо или малозначимо и явно в рамках задачи", "Безвредно, можно откатить, соответствует задаче"]
SAFE_F_RU = ["Разрушительно, необратимо или шире, чем требует задача", "Может нанести невосполнимый ущерб или выходит за рамки задачи"]
RISK_I = ["How risky is this tool call?", "Rate the risk of executing this action", "Оцените риск этого вызова", "Насколько опасно это действие?"]
RISK_C = {"0": ["No risk: read-only or trivially undoable", "Нет риска: только чтение"], "1": ["Low risk: small, reversible change", "Низкий риск: небольшое обратимое изменение"],
          "2": ["High risk: large or hard-to-undo change", "Высокий риск: массовое или трудно отменяемое изменение"],
          "3": ["Critical: irreversible damage or data loss", "Критично: необратимая потеря данных или денег"]}
KIND_I = ["What kind of action is this?", "Which category does the tool call belong to?", "Какой это тип действия?"]
KIND_C = {"read": ["Reads or queries data without changing it", "Только чтение данных"], "modify": ["Updates or creates records", "Создаёт или изменяет записи"],
          "delete": ["Deletes or drops data", "Удаляет данные"], "communicate": ["Sends messages or emails to people", "Отправляет сообщения людям"],
          "payment": ["Moves money or issues refunds", "Переводит деньги или делает возврат"]}

def agent(i):
    ru = rng.random() < 0.45
    kind, destr, rev, en, rucall, impact = pick(ACTIONS)
    ctx = dict(t=pick(["customers", "orders", "users", "invoices", "sessions"]), n=rng.randint(100, 99999), y=rng.choice([2021, 2022, 2023, 2024]),
               s=pick(["billing", "search", "auth", "payments"]), who=pick(["all_customers", "everyone@company.com", "the whole mailing list"]),
               ch=pick(["releases", "oncall", "general"]), acct=pick(["ACME-LTD", "IBAN DE89...3000", "vendor-551"]), amt=pick([250000, 1200000, 98000]),
               small=pick(["9.99", "14.50", "19.90"]))
    in_scope = rng.random() < 0.6
    task_kind = kind if in_scope else pick([k for k in TASKS_EN if k != kind])
    backup = rng.random() < 0.5
    env = pick(["production", "staging", "sandbox"]) if rng.random() < 0.7 else None
    broad = kind == "communicate" and "{who}" in en  # mass mailing: always wider than a task needs
    reversible = bool(rev or (destr and backup))
    low_env = env in ("sandbox", "staging")
    # Jev-style criteria: safe = (reversible or low-impact) AND clearly within the task
    safe = in_scope and not broad and (kind == "read" or (reversible and impact <= 1) or
                                       (low_env and reversible and impact <= 2 and kind != "payment"))
    if kind == "read":
        risk = 0
    else:
        risk = impact
        if destr and backup and risk == 3:
            risk = 2
        if low_env and risk >= 2 and kind not in ("payment", "communicate"):
            risk -= 1
        if not in_scope and risk < 2:
            risk += 1
    task = pick(TASKS_RU[task_kind] if ru else TASKS_EN[task_kind]).format(**ctx)
    call = (rucall if ru else en).format(**ctx)
    lines = [("Задача: " if ru else pick(["Task: ", "Goal: ", "User request: "])) + task,
             ("Предлагаемый вызов: " if ru else pick(["Proposed tool call: ", "Planned action: ", "Agent wants to run: "])) + call]
    c = []
    if destr:
        c.append(pick(["резервная копия снята час назад", "бэкап сделан сегодня утром"] if backup and ru else ["бэкапа сегодня не было", "резервной копии нет"] if ru else
                      ["a backup was taken an hour ago", "snapshot created this morning"] if backup else ["no backup was taken today", "there is no recent backup"]))
    if env:
        c.append({"production": "это боевая среда" if ru else "this is the production environment", "staging": "это тестовый стенд" if ru else "this runs on staging",
                  "sandbox": "это песочница без реальных данных" if ru else "sandbox with fake data"}[env])
    if kind == "read":
        c.append(pick(["запрос только читает" if ru else "the call is read-only", "реплика только для чтения" if ru else "read replica"]))
    if c:
        lines.append(("Контекст: " if ru else "Context: ") + "; ".join(c) + ".")
    qs = {}
    if ru:
        qs["safe"] = noulq(SAFE_I_RU, SAFE_T_RU, SAFE_F_RU)
    else:
        qs["safe"] = noulq(SAFE_I, SAFE_T, SAFE_F)
    lab = {"safe": bool(safe)}
    if rng.random() < 0.6:
        qs["risk"] = scoreq(RISK_I, RISK_C); lab["risk"] = str(min(3, max(0, risk)))
    if rng.random() < 0.7:
        qs["kind"] = choiceq(KIND_I, KIND_C); lab["kind"] = kind
    return "\n".join(lines), qs, lab

# ---------------------------------------------------------------- 2. support tickets
SUP = {
 "billing": (["I was billed twice this month", "my invoice shows a charge I don't recognise", "the subscription renewed even though I cancelled", "payment failed but money left my account"],
             ["с карты дважды списали оплату", "в счёте непонятное списание", "подписка продлилась, хотя я её отменил", "платёж не прошёл, а деньги списались"]),
 "shipping": (["my order hasn't arrived after two weeks", "tracking hasn't updated for days", "the courier lost my parcel", "delivery keeps getting postponed"],
              ["заказ не пришёл уже две недели", "трек-номер не обновляется несколько дней", "курьер потерял посылку", "доставку постоянно переносят"]),
 "returns": (["the item arrived damaged and I want an exchange", "I received the wrong model", "the shoes don't fit, how do I return them", "box came with a cracked screen"],
             ["товар пришёл сломанным, хочу обмен", "прислали не ту модель", "обувь не подошла, как вернуть", "экран пришёл треснутым"]),
 "tech": (["the app freezes on startup", "I can't log in, it says invalid password after reset", "the website shows error 500 at checkout", "notifications stopped working after the update"],
          ["приложение зависает при запуске", "не могу войти, после сброса пишет неверный пароль", "сайт выдаёт ошибку 500 при оформлении", "после обновления перестали приходить уведомления"]),
}
TONE = {"calm": (["Could you please take a look?", "Thanks in advance.", "No rush, just letting you know."], ["Посмотрите, пожалуйста.", "Заранее спасибо.", "Не срочно, просто сообщаю."]),
        "frustrated": (["This is the second time I'm writing about it.", "Honestly getting tired of this.", "Why is this so hard?"], ["Пишу уже второй раз.", "Честно, уже надоело.", "Почему всё так сложно?"]),
        "angry": (["This is UNACCEPTABLE, I will report you!!!", "Worst service ever, I'm furious.", "Fix it NOW or I'm suing."], ["Это ВОЗМУТИТЕЛЬНО, буду жаловаться!!!", "Худший сервис, я в ярости.", "Немедленно исправьте или подам в суд."])}
HUM = (["Please connect me with a real person.", "I want to talk to a human, not a bot.", "Can I speak to an operator?"], ["Соедините с живым оператором.", "Хочу поговорить с человеком, а не с ботом.", "Позовите сотрудника."])
DEPT_I = ["Which team should handle this?", "Route this ticket to the right department", "Какой отдел должен обработать обращение?", "Куда направить тикет?"]
DEPT_C = {"billing": ["Charges, invoices, payment problems", "Оплата, счета, списания"], "shipping": ["Delivery status, delays, lost packages", "Доставка, задержки, потерянные посылки"],
          "returns": ["Exchanges, wrong or damaged items", "Возвраты, обмен, брак"], "tech": ["App errors, login problems, bugs", "Ошибки приложения, вход, баги"]}
TONE_I = ["What is the customer's tone?", "Какой тон у клиента?"]
HUM_I = (["The customer is asking to talk to a human agent", "Does the customer want a human?"], ["Клиент просит соединить с человеком", "Клиент хочет живого оператора?"])
URG_I = ["How urgent is this ticket?", "Насколько срочное обращение?"]
URG_C = {"0": ["Not urgent, informational", "Не срочно"], "1": ["Normal priority", "Обычный приоритет"], "2": ["Urgent: money or access affected", "Срочно: затронуты деньги или доступ"]}

def support(i):
    ru = rng.random() < 0.5; L = 1 if ru else 0
    dept = pick(list(SUP)); tone = pick(list(TONE)); human = rng.random() < 0.35
    parts = [pick(SUP[dept][L]).capitalize() + ".", pick(TONE[tone][L])]
    if human: parts.append(pick(HUM[L]))
    if rng.random() < 0.3: parts.insert(0, pick(["Hello,", "Hi team,"] if not ru else ["Здравствуйте,", "Добрый день,"]))
    st = " ".join(parts)
    qs = {"dept": choiceq(DEPT_I, DEPT_C)}; lab = {"dept": dept}
    if rng.random() < 0.6:
        qs["tone"] = {"type": "choice", "instructions": pick(TONE_I), "criteria": shuffled({"calm": None, "frustrated": None, "angry": None})}; lab["tone"] = tone
    if rng.random() < 0.7:
        qs["human"] = noulq(HUM_I[L]); lab["human"] = human
    if rng.random() < 0.4:
        qs["urg"] = scoreq(URG_I, URG_C); lab["urg"] = "2" if dept in ("billing", "tech") else "1"
    return st, qs, lab

# ---------------------------------------------------------------- 3. incidents
INC = {"db": (["database connections are exhausted", "replication lag reached {k} minutes", "slow queries lock the orders table"], ["закончились подключения к базе", "отставание реплики достигло {k} минут", "медленные запросы блокируют таблицу заказов"]),
       "network": (["DNS resolution fails for the API domain", "the load balancer marks all backends unhealthy", "packet loss between data centres is {k}%"], ["не резолвится DNS домена API", "балансировщик считает все бэкенды мёртвыми", "потери пакетов между ЦОДами {k}%"]),
       "auth": (["login returns 401 for valid passwords", "SSO tokens expire immediately", "the OAuth callback fails with invalid_state"], ["вход возвращает 401 при верном пароле", "SSO-токены сразу истекают", "OAuth callback падает с invalid_state"]),
       "frontend": (["the checkout button is hidden on mobile", "the page layout breaks in Firefox", "a JS error blocks the settings page"], ["кнопка оплаты пропала на мобильных", "вёрстка ломается в Firefox", "JS-ошибка блокирует страницу настроек"])}
SCOPE = {3: (["Nobody can use the service.", "The outage affects all users."], ["Сервис недоступен всем.", "Затронуты все пользователи."]),
         2: (["About a third of users are affected.", "Customers in one region are affected."], ["Затронута примерно треть пользователей.", "Проблема у клиентов одного региона."]),
         1: (["A workaround exists and few users noticed.", "Minor slowdown, users can still complete actions."], ["Есть обходной путь, мало кто заметил.", "Небольшое замедление, действия выполняются."]),
         0: (["Only an internal dashboard is affected, customers see nothing.", "Detected in monitoring before any user impact."], ["Затронут только внутренний дашборд, клиенты ничего не видят.", "Замечено мониторингом до влияния на пользователей."])}
SEV_I = ["How severe is the incident?", "Насколько серьёзен инцидент?", "Оцените критичность сбоя"]
SEV_C = {"0": ["No user impact", "Нет влияния на пользователей"], "1": ["Minor degradation with a workaround", "Незначительная деградация, есть обходной путь"],
         "2": ["Major degradation for part of users", "Серьёзная деградация для части пользователей"], "3": ["Full outage for everyone", "Полный отказ для всех"]}
COMP_I = ["Which component is most likely at fault?", "Какой компонент вероятнее всего виноват?"]
COMP_C = {"db": ["Database, queries, replication", "База данных, запросы, репликация"], "network": ["Network, DNS, load balancer", "Сеть, DNS, балансировщик"],
          "auth": ["Authentication, tokens, login", "Авторизация, токены, вход"], "frontend": ["UI, layout, browser", "Интерфейс, вёрстка, браузер"]}
IMP_I = (["Are customers affected?", "Is there customer impact?"], ["Затронуты ли клиенты?", "Есть ли влияние на клиентов?"])

def incident(i):
    ru = rng.random() < 0.5; L = 1 if ru else 0
    comp = pick(list(INC)); sev = pick([0, 1, 2, 3])
    st = (pick(["Since {h}:{m:02d} ", "At {h}:{m:02d} "] if not ru else ["С {h}:{m:02d} ", "В {h}:{m:02d} "]).format(h=rng.randint(0, 23), m=rng.randint(0, 59))
          + pick(INC[comp][L]).format(k=rng.randint(2, 40)) + ". " + pick(SCOPE[sev][L]))
    qs = {"sev": scoreq(SEV_I, SEV_C), "comp": choiceq(COMP_I, COMP_C)}; lab = {"sev": str(sev), "comp": comp}
    if rng.random() < 0.5:
        qs["impact"] = noulq(IMP_I[L]); lab["impact"] = sev > 0
    return st, qs, lab

# ---------------------------------------------------------------- 4. pull requests
CHG = {"bugfix": ["fixes a crash when the cart is empty", "corrects the timezone bug in reports", "resolves the race condition in the cache"],
       "feature": ["adds dark mode to settings", "introduces PDF export for invoices", "adds two-factor login"],
       "refactor": ["extracts the payment logic into a separate module without behaviour changes", "renames internal helpers and removes dead code", "splits a large class into smaller ones, no functional change"],
       "docs": ["updates the API documentation only", "fixes typos in the README", "adds a contributing guide"],
       "deps": ["bumps axios from 1.6.0 to 1.6.8", "upgrades Go from 1.21 to 1.22", "updates the eslint dev dependency"]}
CI = {True: ["CI is green on the latest commit {sha}.", "All {k} tests passed on head {sha}."],
      False: ["{f} of {k} tests failed on head {sha}.", "CI ran on an older commit; the latest push {sha} is untested.", "Tests were skipped for this PR."]}
TEST_I = ["Do the CI tests pass for the latest commit?", "Is CI green on head?", "Проходят ли тесты на последнем коммите?"]
TEST_T = ["All tests passed on the latest commit", "CI green on head", "Все тесты прошли на последнем коммите"]
TEST_F = ["Tests failed, were skipped, or ran on an older commit", "Тесты упали, пропущены или запускались на старом коммите"]
CHG_I = ["What kind of change is this pull request?", "Classify the PR", "Какой это тип изменения?"]
CHG_C = {"bugfix": ["Fixes a defect", "Исправление ошибки"], "feature": ["Adds new functionality", "Новая функциональность"],
         "refactor": ["Restructures code without changing behaviour", "Рефакторинг без изменения поведения"], "docs": ["Documentation only", "Только документация"],
         "deps": ["Dependency or version bump", "Обновление зависимостей"]}

def pr(i):
    ch = pick(list(CHG)); ok = rng.random() < 0.5
    st = f"PR #{rng.randint(10, 999)} {pick(CHG[ch])}. " + pick(CI[ok]).format(sha="%07x" % rng.randint(0, 16**7 - 1), k=rng.randint(40, 900), f=rng.randint(1, 9))
    return st, {"tests": noulq(TEST_I, TEST_T, TEST_F), "chg": choiceq(CHG_I, CHG_C)}, {"tests": ok, "chg": ch}

# ---------------------------------------------------------------- 5. moderation
MOD = {"harassment": (["You are a worthless idiot.", "Nobody wants you here, loser."], ["Ты ничтожество и идиот.", "Тебя тут никто не ждёт, неудачник."]),
       "threat": (["I know where you live and I will hurt you.", "Say that again and you'll regret it physically."], ["Я знаю, где ты живёшь, и тебе будет больно.", "Ещё слово — и я тебя покалечу."]),
       "spam": (["Earn $5000 a day from home!!! Click the link now", "Cheap followers, buy 10k for $5"], ["Заработок 5000 в день не выходя из дома!!! Жми ссылку", "Дешёвые подписчики, 10к за 300 рублей"]),
       "none": (["Thanks, that solved my problem.", "I disagree with this decision, please reconsider.", "Could you share the release date?"], ["Спасибо, помогло.", "Не согласен с решением, прошу пересмотреть.", "Подскажите дату релиза?"])}
MOD_I = ["Which moderation category fits this message?", "К какой категории модерации относится сообщение?"]
MOD_C = {"harassment": ["Insults or humiliation", "Оскорбления или унижение"], "threat": ["Threats of violence", "Угрозы насилием"], "spam": ["Advertising or spam", "Реклама или спам"], "none": None}
TOX_I = (["Does the message contain insults or threats?", "Is this message abusive?"], ["Содержит ли сообщение оскорбления или угрозы?", "Это токсичное сообщение?"])
TOX_T = (["Contains insults, humiliation or threats"], ["Есть оскорбления, унижение или угрозы"])
TOX_F = (["Polite or neutral message"], ["Сообщение вежливое или нейтральное"])

def moderation(i):
    ru = rng.random() < 0.5; L = 1 if ru else 0
    cat = pick(list(MOD)); st = pick(MOD[cat][L])
    qs = {"tox": noulq(TOX_I[L], TOX_T[L], TOX_F[L])}; lab = {"tox": cat in ("harassment", "threat")}
    if rng.random() < 0.6:
        qs["cat"] = choiceq(MOD_I, MOD_C); lab["cat"] = cat
    return st, qs, lab

# ---------------------------------------------------------------- 6. patch / security findings (RU, golden-like domain, new wording)
ROLE = {"limit": ["максимальное количество предметов в инвентаре", "верхняя граница числа попыток", "потолок баланса кристаллов"],
        "delay": ["задержка между запросами", "время перезарядки умения", "интервал показа баннера"],
        "color": ["цвет фона кнопки", "оттенок заголовка", "цвет индикатора"],
        "resource_id": ["идентификатор строки в ресурсах", "ID картинки в R.drawable", "ресурсный идентификатор макета"]}
EFF = {True: ["На текущей сборке изменение видно, проверено вручную.", "Проверка на свежем билде подтвердила новое значение."],
       False: ["Тест не запускали.", "Проверяли на прошлой версии, не на текущем кандидате.", "После запуска значение осталось прежним."]}
SRV = {0: "Сеть не используется.", 1: "Значение приходит с сервера и кэшируется.", 2: "Сервер проверяет значение при каждом запросе.", 3: "Итоговое значение определяет сервер."}
EFF_I = ["Подтверждён ли нужный эффект патча?", "Есть ли подтверждение, что патч сработал?"]
EFF_T = ["Эффект наблюдался на текущей сборке", "Изменение видно на текущем билде"]
EFF_F = ["Эффект не наблюдался, тест не запускался или был на другой версии", "Не проверено или проверено не на той версии"]
ROLE_I = ["Какую роль играет изменённый литерал?", "Что задаёт изменённая константа?"]
ROLE_C = {"limit": ["Лимит или максимум значения"], "delay": ["Задержка, таймер или кулдаун"], "color": ["Цвет или элемент интерфейса"], "resource_id": ["Идентификатор ресурса"], "other": None}
SRV_I = ["Насколько поведение зависит от сервера?", "Какова роль сервера?"]
SRV_C = {"0": ["Полностью локально, сеть не участвует"], "1": ["Значение кэшируется с сервера"], "2": ["Сервер проверяет значение"], "3": ["Значение полностью решает сервер"]}
FIND = {"secrets": ["В коде найден токен доступа к облачному хранилищу в открытом виде.", "Приватный ключ подписи лежит в assets приложения."],
        "crypto": ["Для паролей используется SHA1 без соли.", "Шифрование DES с фиксированным ключом."],
        "network": ["HostnameVerifier всегда возвращает true.", "Авторизация уходит по http без шифрования."],
        "storage": ["Паспортные данные пишутся в общедоступный файл на SD-карте.", "База с перепиской хранится без шифрования в world-readable каталоге."]}
FP_ST = ["Слово token встречается только в названии переменной в юнит-тесте.", "Ключ найден в примере документации сторонней библиотеки, в сборку не попадает.",
         "Строка password — это подсказка в поле ввода, значение не сохраняется."]
CAT_I = ["Категория находки", "К какому классу относится уязвимость?"]
CAT_C = {"secrets": ["Утечка секретов, ключей или паролей"], "crypto": ["Слабая криптография или хеширование"], "network": ["Небезопасная сеть, HTTP или отключённая проверка TLS"],
         "storage": ["Небезопасное хранение данных на устройстве"], "other": None}
FP_I = ["Это ложное срабатывание?", "Находка ложная?"]
FP_T = ["Находка не является реальной проблемой"]; FP_F = ["Находка — реальная проблема в коде приложения"]

def patch(i):
    if rng.random() < 0.5:
        role = pick(list(ROLE)); eff = rng.random() < 0.5; srv = pick([0, 1, 2, 3])
        a, b = rng.randint(1, 60), rng.randint(61, 999)
        st = f"Изменён литерал: {pick(ROLE[role])}, {a} → {b}. {pick(EFF[eff])} {SRV[srv]}"
        qs = {"effect": noulq(EFF_I, EFF_T, EFF_F), "role": choiceq(ROLE_I, ROLE_C)}; lab = {"effect": eff, "role": role}
        if rng.random() < 0.6:
            qs["server"] = scoreq(SRV_I, SRV_C); lab["server"] = str(srv)
        return st, qs, lab
    if rng.random() < 0.3:
        return pick(FP_ST), {"fp": noulq(FP_I, FP_T, FP_F)}, {"fp": True}
    cat = pick(list(FIND))
    return pick(FIND[cat]), {"fp": noulq(FP_I, FP_T, FP_F), "cat": choiceq(CAT_I, CAT_C)}, {"fp": False, "cat": cat}

GENS = [("agent", agent, 1.6), ("support", support, 1.0), ("incident", incident, 0.9), ("pr", pr, 0.7), ("moderation", moderation, 0.6), ("patch", patch, 0.9)]
seen = set(); n = 0
with open(out, "w", encoding="utf-8") as f:
    for name, g, w in GENS:
        k = 0; tries = 0
        while k < int(N * w) and tries < N * 20:
            tries += 1
            st, qs, lab = g(k)
            if st in seen:
                continue
            seen.add(st); k += 1; n += 1
            f.write(json.dumps({"group": f"syn-{name}-{k}", "request": {"state": st, "questions": qs}, "labels": lab}, ensure_ascii=False) + "\n")
print("wrote", n, "requests to", out)
