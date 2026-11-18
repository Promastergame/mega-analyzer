#!/usr/bin/env python3
"""v1.11 data: broad, compositional, *unlabelled* requests for Jev-as-offline-teacher.
Targets the failure modes of v1.8 (see README v1.11): safe-but-modifying tool calls, critical vs high
risk, incident scope/negation, support tone/department, false-positive findings (text + JSON state),
Android patch effects (server dependence, literal role). Labels come only from Jev.
  python3 gen_synth3.py out.jsonl [n=4000] [seed=31]"""
import json, random, sys, os
out = sys.argv[1]; N = int(sys.argv[2]) if len(sys.argv) > 2 else 4000
R = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 31); P = R.choice
def maybe(x, p=0.5): return x if R.random() < p else ""
def noul(instr, t=None, f=None):
    q = {"type": "noul", "instructions": instr}
    if t: q["criteria"] = {"true": t, "false": f}
    return q
def choice(instr, crit):
    keys = list(crit); R.shuffle(keys); return {"type": "choice", "instructions": instr, "criteria": {k: crit[k] for k in keys}}
def score(instr, levels):
    return {"type": "score", "instructions": instr, "criteria": {str(i): v for i, v in enumerate(levels)}}
def pick_qs(pool, lo=2, hi=3):
    ks = list(pool); R.shuffle(ks); return {k: pool[k]() for k in ks[:R.randint(lo, min(hi, len(ks)))]}

# ---------- A. agent tool calls ----------
ID = lambda: R.randint(100, 99999)
CALLS = [  # (ru task, en task, call, kind)
 (lambda i: (f"исправить опечатку в имени пользователя {i}", f"fix the typo in user {i}'s display name", f'update_user(id={i}, display_name="{P(["Anna Petrova","Ivan Sidorov","Maria Lee","John Smith"])}")'), "modify"),
 (lambda i: (f"обновить цену товара SKU-{i}", f"update the price of SKU-{i}", f'update_price(sku="SKU-{i}", price={R.randint(100,9999)})'), "modify"),
 (lambda i: (f"обновить цены всех товаров категории", f"update prices in the category", f'bulk_update_prices(category="{P(["shoes","toys","books"])}", change="+{R.randint(5,40)}%")'), "modify"),
 (lambda i: (f"посчитать заказы за прошлую неделю", f"count last week's orders", 'run_sql("SELECT count(*) FROM orders WHERE created_at > now() - interval \'7 days\'")'), "read"),
 (lambda i: (f"найти email клиента {i}", f"look up customer {i}'s email", f'run_sql("SELECT email FROM customers WHERE id = {i}")'), "read"),
 (lambda i: (f"проверить статус сервиса", f"check the service status", f'http_get("https://status.internal/{P(["api","billing","auth"])}")'), "read"),
 (lambda i: (f"удалить тестовую запись {i}", f"delete test record {i}", f'delete_rows(table="{P(["orders","users","events"])}", where="id = {i}")'), "delete"),
 (lambda i: (f"удалить тестовую запись {i}", f"delete test record {i}", f'delete_rows(table="{P(["orders","users","events"])}")'), "delete"),
 (lambda i: (f"удалить тестового пользователя", f"remove a test user", f'drop_table("{P(["users","customers","payments"])}")'), "delete"),
 (lambda i: (f"почистить старые логи", f"clean up old logs", f'delete_files(path="logs/{R.randint(2019,2023)}/*")'), "delete"),
 (lambda i: (f"заархивировать логи прошлого года", f"archive last year's logs", f'move_files(src="logs/{R.randint(2019,2023)}/*", dst="archive/")'), "modify"),
 (lambda i: (f"вернуть деньги клиенту {i} за заказ", f"refund customer {i} for one order", f'refund(order_id={i}, amount={R.randint(5,500)})'), "payment"),
 (lambda i: (f"перевести зарплату одному сотруднику", f"pay one employee's salary", f'transfer(to="{P(["employee_"+str(i),"all_employees"])}", amount={R.randint(1000,200000)})'), "payment"),
 (lambda i: (f"написать клиенту {i} про задержку", f"tell customer {i} about the delay", f'send_email(to="{P(["customer_"+str(i)+"@mail.com","all_customers"])}", subject="Delay")'), "communicate"),
 (lambda i: (f"включить тёмную тему в настройках", f"enable dark mode in settings", 'set_config(key="ui.theme", value="dark")'), "modify"),
 (lambda i: (f"включить тёмную тему в настройках", f"enable dark mode in settings", 'set_config(key="auth.require_2fa", value=false)'), "modify"),
 (lambda i: (f"перезапустить зависший воркер", f"restart the stuck worker", f'restart_service("{P(["worker-3","api-gateway","postgres-primary"])}")'), "modify"),
 (lambda i: (f"показать список файлов отчёта", f"list the report files", f'list_files(path="/reports/{R.randint(2020,2025)}")'), "read"),
 (lambda i: (f"сделать dry-run миграции", f"dry-run the migration", f'migrate(db="prod", dry_run={P(["true","false"])})'), "modify"),
]
CTX_RU = ["старое значение сохраняется в истории и восстанавливается одной кнопкой", "бэкап сделан час назад", "бэкапа нет", "это боевая база", "это песочница с тестовыми данными",
          "реплика только для чтения", "операцию нельзя отменить", "в таблице {n} записей", "запрос только читает", "файлы сначала копируются и могут быть возвращены", "изменение проходит ревью позже", ""]
CTX_EN = ["the previous value is kept in history and can be restored in one click", "a backup was taken an hour ago", "there is no backup", "this is the production database", "this is a sandbox with fake data",
          "read-only replica", "the operation cannot be undone", "the table has {n} rows", "the query only reads", "files are copied first and can be moved back", "the change is reviewed later anyway", ""]
SAFE_I = [("Is this action safe to run without a human approving it first?", "Reversible or low-impact, and clearly within the stated task.", "Destructive, irreversible, or broader than the task requires."),
          ("Можно ли выполнить это действие без подтверждения человеком?", "Обратимо или малозначимо и строго в рамках задачи", "Разрушительно, необратимо или шире задачи"),
          ("Can the agent auto-execute this call?", None, None), ("Нужно ли спросить человека перед этим вызовом?", None, None)]
def agent():
    ru = R.random() < 0.5; fn, kind = P(CALLS); t_ru, t_en, call = fn(ID())
    ctx = [c.format(n=f"{R.randint(1,900)}{P([' 000',',000',''])}") for c in R.sample(CTX_RU if ru else CTX_EN, R.randint(0, 2)) if c]
    st = (f"Задача: {t_ru}.\nПредлагаемый вызов: {call}" if ru else f"Task: {t_en}.\nProposed tool call: {call}") + (("\nКонтекст: " if ru else "\nContext: ") + "; ".join(ctx) + "." if ctx else "")
    pool = {"safe": lambda: noul(*P(SAFE_I)),
            "risk": lambda: score(P(["How risky is this tool call?", "Насколько рискован этот вызов?"]), P([["No risk: read-only or trivially undoable", "Low risk: small, reversible change", "High risk: large or hard-to-undo change", "Critical: irreversible damage or data loss"],
                                                                                                         ["Нет риска", "Низкий: маленькое обратимое изменение", "Высокий: крупное или трудно отменяемое", "Критический: необратимый ущерб или потеря данных"]])),
            "kind": lambda: choice(P(["What kind of action is this?", "Какого типа это действие?"]), {"read": "Reads or queries data without changing it", "modify": "Creates or changes records", "delete": "Deletes or drops data", "payment": "Moves money or issues refunds", "communicate": "Sends messages or emails to people"}),
            "within_task": lambda: noul(P(["Is the call limited to what the task asks for?", "Вызов не выходит за рамки задачи?"]), "Affects only what the task needs", "Touches more than the task needs")}
    return st, pick_qs(pool)

# ---------- B. incidents ----------
COMP = {"auth": ("вход и токены", "login and tokens"), "payments": ("оплата", "payments"), "api": ("API и балансировщик", "the API and load balancer"), "db": ("база данных", "the database"), "search": ("поиск", "search"), "notifications": ("уведомления", "notifications")}
SYM = {"auth": [("пользователи не могут войти: refresh-токены отклоняются", "users cannot log in: refresh tokens are rejected"), ("часть входов падает с invalid_signature", "some logins fail with invalid_signature")],
       "payments": [("платежи картой не проходят", "card payments fail"), ("каждый десятый платёж висит в pending", "one in ten payments hangs in pending")],
       "api": [("все запросы к API возвращают 502", "every API request returns 502"), ("p99 латентность выросла до 3 секунд", "p99 latency rose to 3 seconds")],
       "db": [("реплика отстаёт на 40 минут", "the replica lags 40 minutes"), ("основная база не принимает записи, диск заполнен", "the primary rejects writes, the disk is full")],
       "search": [("поиск возвращает пустую выдачу", "search returns empty results"), ("подсказки в поиске тормозят", "search suggestions are slow")],
       "notifications": [("push-уведомления приходят с задержкой в час", "push notifications arrive an hour late"), ("письма не отправляются", "emails are not being sent")]}
SCOPE = [("у всех пользователей", "for all users", 3), ("у пользователей одного региона", "for users in one region", 2), ("у нескольких клиентов", "for a few customers", 1), ("только на стейджинге, клиенты не затронуты", "only on staging, no customers affected", 0),
         ("только у внутреннего тестового аккаунта", "only for an internal test account", 0), ("сайт не открывается ни у кого", "the site is down for everyone", 3)]
def incident():
    ru = R.random() < 0.5; c = P(list(COMP)); s = P(SYM[c]); sc = P(SCOPE)
    since = f"{R.randint(0,23):02d}:{P(['05','15','30','47'])}"
    st = (f"С {since} {s[0]} {sc[0]}." + maybe(f" Причина: {P(['ротация ключей','смена DNS','релиз 4.2','переполнение диска','истёк сертификат'])}.") + maybe(" Обходного пути нет.", .3) + maybe(" Откат уже идёт.", .3)) if ru else \
         (f"Since {since} {s[1]} {sc[1]}." + maybe(f" Cause: {P(['key rotation','a DNS change','release 4.2','a full disk','an expired certificate'])}.") + maybe(" No workaround.", .3) + maybe(" Rollback in progress.", .3))
    pool = {"sev": lambda: score(P(["Насколько серьёзен инцидент?", "How severe is this incident?"]), P([["SEV4: нет влияния на клиентов", "SEV3: мелкая деградация", "SEV2: серьёзная деградация части пользователей", "SEV1: полный отказ ключевой функции"],
                                                                                                    ["No customer impact", "Minor degradation", "Major degradation for some users", "Full outage of a key function"]])),
            "component": lambda: choice(P(["Какой компонент затронут?", "Which component is affected?"]), {k: v[1] for k, v in COMP.items()}),
            "impact": lambda: noul(P(["Затронуты ли клиенты?", "Are customers affected?"]), "Real customers see the problem", "Only internal, staging or no one")}
    return st, pick_qs(pool)

# ---------- C. support ----------
TOP = {"shipping": [("когда доставят мой заказ", "when will my order be delivered"), ("посылка не пришла уже 10 дней", "my package hasn't arrived in 10 days")],
       "billing": [("с карты списали дважды", "I was charged twice"), ("пришлите чек за последний платёж", "send me a receipt for my last payment")],
       "returns": [("хочу вернуть куртку, не подошёл размер", "I want to return the jacket, wrong size"), ("как оформить возврат", "how do I start a return")],
       "tech": [("приложение вылетает при входе", "the app crashes on login"), ("не приходит код подтверждения", "the verification code never arrives")],
       "general": [("у вас есть подарочные карты", "do you sell gift cards"), ("какие у вас часы работы", "what are your opening hours")]}
TONE = {"calm": [("Подскажите, пожалуйста, {x}?", "Could you tell me {x}? No rush, thank you."), ("Здравствуйте! {x}.", "Hi! {x}.")],
        "frustrated": [("Уже третий раз пишу: {x}. Сколько можно ждать?", "Third time writing: {x}. How long do I have to wait?")],
        "angry": [("{x}!!! ЭТО ВОЗМУТИТЕЛЬНО, верните деньги или я пишу в суд!", "{x}!!! THIS IS UNACCEPTABLE, refund me or I'm calling my lawyer!")]}
def support():
    ru = R.random() < 0.5; dep = P(list(TOP)); tp = P(TOP[dep]); tone = P(list(TONE)); tpl = P(TONE[tone])
    st = tpl[0 if ru else 1].format(x=tp[0 if ru else 1]) + maybe(P([" Соедините с оператором.", " Хочу поговорить с живым человеком."] if ru else [" Let me talk to a person.", " Connect me to an agent."]), .3)
    pool = {"department": lambda: choice(P(["Which team should handle this?", "Какой отдел должен обработать обращение?"]), {"shipping": "Delivery status, delays, lost packages", "billing": "Charges, receipts, invoices", "returns": "Returns and exchanges", "tech": "App or account technical problems", "general": "Other questions"}),
            "tone": lambda: choice(P(["What is the customer's tone?", "Какой тон у клиента?"]), {"calm": "Calm, polite", "frustrated": "Frustrated or impatient", "angry": "Angry, hostile or threatening"}),
            "frustration": lambda: score(P(["How frustrated is the customer?", "Насколько клиент раздражён?"]), ["Calm", "Frustrated", "Very angry"]),
            "wants_human": lambda: noul(P(["Does the customer ask for a human?", "Просит ли клиент живого оператора?"]))}
    return st, pick_qs(pool)

# ---------- D. findings ----------
RULES = [("secret/stripe-key", "secret"), ("secret/aws-access-key", "secret"), ("secret/generic-api-key", "secret"), ("secret/jwt", "secret"), ("sql/injection", "injection"), ("log/debug-output", "logging"), ("net/cleartext-http", "network"), ("crypto/md5", "crypto")]
PROPS = [("placeholder", True), ("test_file", True), ("expired", True), ("library", True), ("debug_only", True), ("verified_real", False), ("sink_network", False), ("sink_log", False), ("user_input", False)]
PTXT = {"placeholder": ("значение — плейсхолдер вида sk_test_XXXX", "the value is a placeholder like sk_test_XXXX"), "test_file": ("файл лежит в папке unit-тестов", "the file is in the unit-test folder"),
        "expired": ("токен истёк два года назад", "the token expired two years ago"), "library": ("код из сторонней библиотеки-примера", "code from a third-party sample library"),
        "debug_only": ("строка есть только в debug-сборке", "the line exists only in the debug build"), "verified_real": ("ключ проверен и рабочий", "the key was verified as live"),
        "sink_network": ("значение уходит в сеть", "the value is sent over the network"), "sink_log": ("значение пишется в лог release-сборки", "the value is written to the release log"),
        "user_input": ("в запрос попадает ввод пользователя", "user input reaches the query")}
def finding():
    ru = R.random() < 0.6; rule, cat = P(RULES); props = R.sample(PROPS, R.randint(1, 2))
    if R.random() < 0.45:
        d = {"rule_id": rule, "severity": P(["info", "low", "medium", "high", "critical"]), "confidence": round(R.uniform(.3, .99), 2)}
        for p, _ in props:
            d.update({"placeholder": {"placeholder": True}, "test_file": {"file": "src/test/java/FooTest.java"}, "expired": {"expired": True}, "library": {"library": True, "file": "com/vendor/sample/Demo.smali"},
                      "debug_only": {"build": "debug"}, "verified_real": {"verified": True, "verdict": "real-looking"}, "sink_network": {"sink": "network"}, "sink_log": {"sink": "log"}, "user_input": {"source": "user_input"}}[p])
        st = json.dumps(d, ensure_ascii=False)
    else:
        st = (f"Сканер сработал на правило {rule}: " if ru else f"The scanner flagged {rule}: ") + "; ".join(PTXT[p][0 if ru else 1] for p, _ in props) + "."
    pool = {"fp": lambda: noul(P(["Это ложное срабатывание?", "Это ложное срабатывание сканера?", "Is this a false positive?"])),
            "severity": lambda: score(P(["Насколько опасна находка?", "How severe is the finding?"]), ["Нет риска", "Низкий", "Средний", "Высокий"] if ru else ["None", "Low", "Medium", "High"]),
            "cat": lambda: choice(P(["Категория находки", "Finding category"]), {"secret": "Hard-coded secret or key", "injection": "Injection", "logging": "Sensitive logging", "network": "Insecure network", "crypto": "Weak cryptography", "other": "Other"})}
    return st, pick_qs(pool)

# ---------- E. Android patch effects (RU) ----------
CH = [("лимит попыток", "limit"), ("задержку показа рекламы", "delay"), ("цену подписки", "price"), ("флаг премиума", "flag"), ("строку с названием", "label"), ("идентификатор ресурса", "id"), ("баланс монет", "balance")]
OBS = [("Проверено на эмуляторе с текущим SHA: эффект виден.", 0), ("После синхронизации с сервером значение вернулось к прежнему.", 3), ("Значение загружается из ответа сервера при старте и кэшируется; патч меняет значение по умолчанию.", 2),
       ("Сервер проверяет значение при каждой покупке.", 3), ("Изменение только в отрисовке UI, сеть не участвует.", 0), ("Эффект виден до перезапуска, потом приходит конфиг с сервера.", 2), ("Проверки на устройстве не было.", 1)]
def patch():
    ch, role = P(CH); obs = R.sample(OBS, R.randint(1, 2))
    st = f"Патч меняет {ch}: константа {R.randint(1,99)} → {R.randint(100,9999)} в {P(['MainActivity','BillingManager','AdsConfig','Limits'])}.smali. " + " ".join(o for o, _ in obs)
    pool = {"effect": lambda: noul(P(["Подтверждён ли нужный эффект патча?", "Работает ли патч на самом деле?"])),
            "server": lambda: score("Насколько поведение зависит от сервера?", ["Не зависит", "Слабо", "Частично", "Полностью решает сервер"]),
            "role": lambda: choice("Какую роль играет изменённый литерал?", {"limit": "Лимит или счётчик", "delay": "Задержка или таймер", "price": "Цена", "flag": "Флаг включения функции", "label": "Текст интерфейса", "id": "Идентификатор ресурса", "balance": "Баланс или валюта"})}
    return st, pick_qs(pool)

GEN = [(agent, .3), (incident, .17), (support, .18), (finding, .2), (patch, .15)]
tests = set()
for f in ["evals/golden-test.jsonl", "evals/hard-cases.jsonl", "evals/distill/decision-blind.jsonl", "evals/jev-compare/cases.jsonl"]:
    if os.path.exists(f):
        for l in open(f, encoding="utf-8"):
            s = json.loads(l)["request"]["state"]; tests.add(s if isinstance(s, str) else json.dumps(s, ensure_ascii=False))
seen = set(); rows = []
while len(rows) < N:
    g = R.choices([g for g, _ in GEN], [w for _, w in GEN])[0]; st, qs = g()
    if st in seen or st in tests: continue
    seen.add(st); rows.append({"group": f"syn3-{len(rows)}", "request": {"state": st, "questions": qs}})
with open(out, "w", encoding="utf-8") as f:
    for r in rows: f.write(json.dumps(r, ensure_ascii=False) + "\n")
print("wrote", len(rows), "questions", sum(len(r["request"]["questions"]) for r in rows))
