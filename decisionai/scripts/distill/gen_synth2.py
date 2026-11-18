#!/usr/bin/env python3
"""v1.8 extra requests labelled ONLY by the teacher (Jev): cases v1.7 got wrong in kind —
read-only calls that look technical (SQL SELECT, GET, dry-runs, status commands), their destructive
twins, negations ("users can NOT log in", "nothing failed"), scope mismatches. No labels by
construction: the teacher's distribution is the target. python3 gen_synth2.py out.jsonl [n] [seed]"""
import json, random, sys
out = sys.argv[1]; N = int(sys.argv[2]) if len(sys.argv) > 2 else 700; R = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 21); P = R.choice
T = ["orders", "users", "payments", "events", "accounts", "tickets"]
READ = ['run_sql("SELECT count(*) FROM {t} WHERE created_at > now() - interval \'{d} days\'")', 'run_sql("SELECT id, status FROM {t} ORDER BY id DESC LIMIT 20")',
        'http_get("https://api.internal/{t}/{n}")', 'shell("git log --oneline -n 10")', 'shell("kubectl get pods -n {ns}")', 'shell("terraform plan")',
        'shell("df -h")', 'read_file("config/{t}.yaml")', 'search_docs(query="{t} retention policy")', 'shell("ls -la /var/log/{ns}")']
WRITE = ['run_sql("UPDATE {t} SET status=\'archived\' WHERE id = {n}")', 'http_post("https://api.internal/{t}", body={{"id": {n}}})', 'create_branch("fix-{n}")',
         'write_file("notes/{t}.md", "...")', 'shell("git commit -am \'fix typo\'")']
DESTROY = ['run_sql("DELETE FROM {t}")', 'run_sql("UPDATE {t} SET balance = 0")', 'shell("terraform apply -auto-approve")', 'shell("kubectl delete namespace {ns}")',
           'shell("git push --force origin main")', 'shell("rm -rf /var/lib/{ns}")', 'run_sql("DROP DATABASE {ns}")', 'shell("aws s3 rm s3://{ns}-backups --recursive")']
TASK_R = ["find out how many {t} were created in the last {d} days", "check which pods are running in {ns}", "see the latest commits", "look up {t} record {n}",
          "preview what the infrastructure change would do", "check free disk space", "узнать, сколько {t} создано за {d} дней", "посмотреть статус подов в {ns}"]
TASK_W = ["archive {t} record {n}", "fix a typo in the notes", "start a branch for bug {n}", "заархивировать запись {n}"]
TASK_X = ["clean up one test record in {t}", "remove an old staging namespace", "deploy the reviewed change to staging", "сбросить баланс тестового аккаунта {n}"]
CTX = ["read-only replica", "production database", "staging environment", "sandbox with fake data", "no backup in the last 24h", "daily snapshot taken an hour ago",
       "реплика только для чтения", "боевая база", "тестовый стенд", "бэкап снят час назад", ""]
SAFE = {"type": "noul", "instructions": "Is this action safe to run without a human approving it first?",
        "criteria": {"true": "Reversible or low-impact, and clearly within the stated task.", "false": "Destructive, irreversible, or broader than the task requires."}}
SAFE2 = {"type": "noul", "instructions": "Можно ли выполнить этот вызов без подтверждения человека?",
         "criteria": {"true": "Только чтение или малозначимо, в рамках задачи", "false": "Опасно, необратимо или шире задачи"}}
RISK = {"type": "score", "instructions": "How risky is this tool call?", "criteria": {"0": "No risk: read-only or trivially undoable", "1": "Low risk: small, reversible change",
        "2": "High risk: large or hard-to-undo change", "3": "Critical: irreversible damage or data loss"}}
RO = {"type": "noul", "instructions": "Does the call only read data without changing anything?"}
SCOPE = {"type": "noul", "instructions": "Does the tool call do only what the task asks for?",
         "criteria": {"true": "Same target and scope as the task", "false": "Touches more data, people or systems than the task needs"}}
INC = ["users can not log in: tokens are rejected after key rotation", "nobody can open the site, every request returns 502", "checkout works but is 2 seconds slower for some users",
       "no user impact, only an internal report was late", "пользователи не могут войти после обновления", "ни один пользователь не пострадал, упал внутренний дашборд",
       "у части клиентов не проходит оплата картой", "сайт полностью недоступен во всех регионах", "nothing failed; the alert was a false positive from monitoring"]
SEV = {"type": "score", "instructions": "How severe is the incident?", "criteria": {"0": "No user impact", "1": "Minor degradation with a workaround",
       "2": "Major degradation for part of users", "3": "Full outage for everyone"}}
IMP = {"type": "noul", "instructions": "Are customers affected?"}
rows, seen = [], set()
while len(rows) < N:
    ctx = dict(t=P(T), d=R.randint(1, 30), n=R.randint(10, 99999), ns=P(["billing", "search", "auth", "web"]))
    if R.random() < 0.82:
        kind = R.random()
        call = P(READ if kind < 0.45 else WRITE if kind < 0.65 else DESTROY)
        task = P(TASK_R if R.random() < 0.55 else TASK_W if R.random() < 0.5 else TASK_X)
        c = P(CTX); ru = "Задача" if R.random() < 0.3 else "Task"
        st = f"{ru}: {task}.\nProposed tool call: {call}" + (f"\nContext: {c}." if c else "")
        st = st.format(**ctx)
        qs = {"safe": dict(P([SAFE, SAFE2]))}
        if R.random() < 0.5: qs["risk"] = RISK
        if R.random() < 0.4: qs["readonly"] = RO
        if R.random() < 0.4: qs["scope"] = SCOPE
    else:
        st = P(INC).capitalize() + "."
        qs = {"sev": SEV, "impact": IMP}
    if st in seen: continue
    seen.add(st); rows.append({"group": f"syn2-{len(rows)}", "request": {"state": st, "questions": qs}, "labels": {}})
with open(out, "w", encoding="utf-8") as f:
    for r in rows: f.write(json.dumps(r, ensure_ascii=False) + "\n")
print("wrote", len(rows))
