#!/usr/bin/env python3
"""v1.12 smart data: a cheap LLM (default mistralai/mistral-small-24b-instruct-2501 via OpenRouter, ~$0.08/M
output tokens) *writes* diverse, realistic states for the everyday System One jobs; the questions are
attached from fixed pools; labels come later from Jev (jev_teacher.py). Each call asks for 10 texts with
a random persona / language / difficulty / target outcome, so texts are not template clones.
  OPENROUTER_API_KEY=... python3 gen_llm.py out.jsonl [calls=400] [seed=51]"""
import json, os, random, sys, re, time, urllib.request, concurrent.futures as cf
out = sys.argv[1]; CALLS = int(sys.argv[2]) if len(sys.argv) > 2 else 400; R = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 51)
KEY = os.environ["OPENROUTER_API_KEY"]; MODEL = os.environ.get("GEN_MODEL", "mistralai/mistral-small-24b-instruct-2501")
N = lambda i, t=None, f=None: ({"type": "noul", "instructions": i} | ({"criteria": {"true": t, "false": f}} if t else {}))
C = lambda i, c: {"type": "choice", "instructions": i, "criteria": c}
S = lambda i, lv: {"type": "score", "instructions": i, "criteria": {str(j): v for j, v in enumerate(lv)}}
SAFE = ("Reversible or low-impact, and clearly within the stated task.", "Destructive, irreversible, or broader than the task requires.")
TASKS = {
 "lead": ("an inbound B2B sales lead message or CRM note (who they are, company size, budget, timeline, need)", ["clearly hot", "clearly not a fit", "ambiguous", "student or job seeker", "big company but no budget"],
          [N("Should sales book a demo?"), S("How qualified is this lead?", ["Not a fit", "Weak", "Possible", "Good", "Hot"]), C("Customer segment", {"smb": "Small business", "mid": "Mid-market", "ent": "Enterprise"})]),
 "moderation": ("a user comment on a forum, marketplace or social app", ["spam or ad", "scam or phishing", "insult or harassment", "harsh but legitimate criticism", "perfectly normal", "sarcastic joke"],
          [N("Does this comment violate community guidelines?", "Spam, scams, harassment or abuse", "Normal content, including harsh but fair criticism"), C("Comment category", {"spam": "Spam or advertising", "scam": "Fraud or phishing", "harassment": "Insults or harassment", "ok": "Acceptable content"})]),
 "review": ("a product or app review", ["very positive", "very negative", "mixed", "positive with one small complaint", "angry about delivery but likes the product"],
          [S("What star rating fits this review?", ["1 star", "2 stars", "3 stars", "4 stars", "5 stars"]), C("Review sentiment", {"pos": "Positive", "neg": "Negative", "mixed": "Mixed"}), N("Does the reviewer report a product problem?")]),
 "intent": ("a message a user sends to a SaaS support chatbot", ["wants to cancel", "wants to upgrade", "billing question", "bug report", "feature request", "small talk", "angry and might leave"],
          [C("What does the user want?", {"cancel": "Cancel or close the account", "upgrade": "Upgrade the plan", "billing": "Billing question", "bug": "Report a bug", "feature": "Feature request", "smalltalk": "Small talk"}), N("Is the customer at risk of churning?")]),
 "pii": ("a chat or support message", ["contains an email or phone", "contains a card number", "contains an ID/passport number", "no personal data at all", "mentions a name and city only", "contains an order number only"],
          [N("Does the message contain personal data that must be redacted?", "Email, phone, card, passport or similar identifiers", "Nothing that identifies or exposes a person"), N("Does the message include a payment card number?")]),
 "injection": ("a task for an AI assistant followed by a document/email/web page it must process (format: 'Assistant task: ...\\nDocument: ...')", ["the document hides a prompt injection", "the document is benign", "the document has an obvious jailbreak", "the document politely asks the reader to do something normal"],
          [N("Does the document try to hijack the assistant (prompt injection)?")]),
 "grounded": ("a support-bot exchange in the format 'Context: ...\\nQuestion: ...\\nBot answer: ...'", ["the answer is correct and supported", "the answer contradicts the context", "the answer invents facts", "the answer dodges the question"],
          [N("Is the bot's answer supported by the context?", "Every claim is backed by the context", "It contradicts or adds facts not in the context"), N("Did the bot actually answer the question?"), S("Answer quality", ["Wrong or harmful", "Unhelpful", "Partly right", "Correct and complete"])]),
 "urgency": ("a work email (start with 'Email: ')", ["production outage", "hard deadline tomorrow", "routine request this week", "newsletter or promo", "FYI only"],
          [S("How urgent is this email?", ["Can ignore", "Low", "Normal", "High", "Drop everything"]), N("Does this need a reply today?"), C("Which folder?", {"action": "Needs action", "fyi": "FYI / reading", "promo": "Promotions"})]),
 "convo": ("a short chat transcript with lines 'user: ...' and 'assistant: ...'", ["assistant apologises and fixes it", "assistant is rude", "assistant helps partly", "user asks for a refund", "assistant ignores the problem"],
          [N("Did the assistant apologise?"), N("Did the assistant resolve the user's issue?"), N("Was the assistant rude or dismissive?"), N("Is the user asking for a refund?")]),
 "agent": ("an AI agent step in the format 'Task: ...\\nProposed tool call: fn(args)\\nContext: ...'", ["safe read-only query", "small reversible edit within the task", "destructive or irreversible", "broader than the task (all users/all rows)", "money transfer", "sends messages to many people", "looks dangerous but is a dry run or sandbox"],
          [N("Is this action safe to run without a human approving it first?", *SAFE), S("How risky is this tool call?", ["No risk: read-only or trivially undoable", "Low risk: small, reversible change", "High risk: large or hard-to-undo change", "Critical: irreversible damage or data loss"]),
           C("What kind of action is this?", {"read": "Reads or queries data without changing it", "modify": "Creates or changes records", "delete": "Deletes or drops data", "payment": "Moves money or issues refunds", "communicate": "Sends messages or emails to people"})]),
 "incident": ("an on-call incident report", ["full outage for everyone", "partial degradation for some users", "internal or staging only, no customer impact", "minor cosmetic issue", "explicitly says users are NOT affected"],
          [S("How severe is this incident?", ["No customer impact", "Minor degradation", "Major degradation for some users", "Full outage of a key function"]), N("Are customers affected?", "Real customers see the problem", "Only internal, staging or no one")]),
 "support": ("a customer support ticket for an online store", ["delivery problem", "double charge", "return request", "app login problem", "general question", "furious customer demanding a manager"],
          [C("Which team should handle this?", {"shipping": "Delivery status, delays, lost packages", "billing": "Charges, receipts, invoices", "returns": "Returns and exchanges", "tech": "App or account technical problems", "general": "Other questions"}),
           C("What is the customer's tone?", {"calm": "Calm, polite", "frustrated": "Frustrated or impatient", "angry": "Angry, hostile or threatening"}), N("Does the customer ask for a human?")]),
}
RU_Q = {}  # questions stay as written; Jev handles both languages
STYLE = ["short and casual", "long and detailed", "with typos", "formal", "with numbers and names", "tricky: the obvious keyword points the wrong way"]

def ask(task, lang, outcome, style):
    desc = TASKS[task][0]
    msg = (f"Write 10 different realistic examples of {desc}. Language: {lang}. Each example should be: {outcome}; style: {style}. "
           "Vary people, products, companies, numbers and wording a lot; no placeholders like [name]. "
           'Return ONLY a JSON array of 10 strings.')
    body = {"model": MODEL, "messages": [{"role": "user", "content": msg}], "temperature": 1.0, "max_tokens": 3500}
    for a in range(4):
        try:
            r = urllib.request.Request("https://openrouter.ai/api/v1/chat/completions", json.dumps(body).encode(), {"Content-Type": "application/json", "Authorization": "Bearer " + KEY})
            with urllib.request.urlopen(r, timeout=120) as f: d = json.load(f)
            txt = d["choices"][0]["message"]["content"]; m = re.search(r"\[.*\]", txt, re.S)
            try: arr = json.loads(m.group(0)) if m else []
            except Exception:  # truncated / slightly invalid JSON: salvage complete string literals
                arr = [json.loads('"' + x + '"') for x in re.findall(r'"((?:[^"\\]|\\.){15,1500})"', txt)]
            return [s.strip() for s in arr if isinstance(s, str) and 15 < len(s) < 1500], (d.get("usage") or {}).get("cost", 0) or 0
        except Exception as e:
            time.sleep(2 ** a)
    return [], 0

jobs = []
for i in range(CALLS):
    t = R.choice(list(TASKS)); jobs.append((t, R.choice(["Russian", "English", "Russian", "English", "Russian with some English terms"]), R.choice(TASKS[t][1]), R.choice(STYLE)))
rows, cost, seen = [], 0.0, set()
with cf.ThreadPoolExecutor(8) as ex:
    for (t, lang, oc, st), (texts, c) in zip(jobs, ex.map(lambda j: ask(*j), jobs)):
        cost += c
        for s in texts:
            if s in seen: continue
            seen.add(s); qs = TASKS[t][2]
            pick = R.sample(range(len(qs)), R.randint(1, min(3, len(qs))))
            rows.append({"group": f"llm-{len(rows)}", "task": t, "request": {"state": s, "questions": {f"q{j}": qs[j] for j in pick}}})
with open(out, "w", encoding="utf-8") as f:
    for r in rows: f.write(json.dumps(r, ensure_ascii=False) + "\n")
print("wrote", len(rows), "states from", CALLS, f"calls, cost ${cost:.4f}")
