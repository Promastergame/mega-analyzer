import json, re, http.server
CRIT = {"noul": {"true": "да", "false": "нет"}, "choice": {"a": "вариант А", "b": "вариант Б", "c": "вариант В"},
        "score": {"0": "нет", "1": "мало", "2": "средне", "3": "много"}}
LAB = {"noul": True, "choice": "b", "score": "2"}
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        b = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        p = b["messages"][0]["content"]
        if p.startswith("You create"):
            types = re.search(r"in this order: ([a-z, ]+)\.", p).group(1).split(", ")
            k = int(re.search(r"Then write (\d+) cases", p).group(1))
            qs = {f"q{i}_{t}": {"type": t, "instructions": f"Вопрос {i} типа {t}?", "criteria": CRIT[t]} for i, t in enumerate(types)}
            cases = [{"state": f"Тестовый текст номер {j} про сервер, деньги и пользователей, достаточно длинный.",
                      "labels": {q: LAB[v["type"]] for q, v in qs.items()}} for j in range(k)]
            cases.append({"state": "коротко", "labels": {}})
            out = {"questions": qs, "cases": cases}
        else:
            ids = re.findall(r'"([a-z0-9_]+)": (true\|false|"key")', p)
            disagree = "номер 0 " in p   # case 0: teacher disagrees on everything
            out = {}
            for q, f in ids:
                t = q.split("_", 1)[1]
                out[q] = ({"noul": False, "choice": "c", "score": "0"} if disagree else LAB)[t]
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"message": {"content": json.dumps(out, ensure_ascii=False)}}).encode())
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", 11555), H).serve_forever()
