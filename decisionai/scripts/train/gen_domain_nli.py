#!/usr/bin/env python3
"""Synthetic domain NLI pairs (ru/en) about build/test/effect/server/hash statements.
Label semantics: premise = what is known (state), hypothesis = a criterion.
  entailment    - the premise guarantees the hypothesis
  contradiction - the premise rules the hypothesis out
  neutral       - the premise says nothing decisive ("not run" is NOT "failed")
Held-out phrasing: the LAST phrase of every list is never used for training (eval only)."""
import random, json, itertools

C = {
 "test": dict(
  pos=["Тест прошёл.", "Тесты пройдены успешно.", "Проверка завершилась успешно.", "Все тесты зелёные.", "Тест поведения прошёл.", "The test passed.", "All tests passed successfully.", "The tests are green.", "The test run finished without failures.", "Автотесты отработали без замечаний."],
  neg=["Тест не прошёл.", "Тест завершился ошибкой.", "Тесты упали.", "Проверка провалена.", "Тест поведения не пройден.", "The test failed.", "Tests did not pass.", "The test run ended with an error.", "Some tests are red.", "Автотесты свалились с ошибкой."],
  nr=["Тесты не запускались.", "Тест ещё не выполнялся.", "Проверку не проводили.", "The tests were not run.", "No tests have been executed yet.", "Тестирование пока не начиналось."]),
 "build": dict(
  pos=["Сборка прошла успешно.", "Сборка завершилась без ошибок.", "Проект собран.", "The build succeeded.", "The build completed without errors.", "Артефакт успешно собран."],
  neg=["Сборка завершилась ошибкой.", "Сборка не удалась.", "Проект не собирается.", "The build failed.", "The build broke with compile errors.", "Сборка упала с ошибкой компиляции."],
  nr=["Сборку не запускали.", "The build was not started.", "Сборка ещё не выполнялась."]),
 "effect": dict(
  pos=["Эффект подтверждён.", "Эффект получен на реальном устройстве.", "Патч сработал как задумано.", "The effect was confirmed.", "The patch works as intended.", "Нужное поведение наблюдается."],
  neg=["Эффект не обнаружен.", "Эффекта нет.", "Патч не сработал.", "The effect was not observed.", "The patch has no effect.", "Желаемого поведения не наблюдается."],
  nr=["Эффект не проверяли.", "Работу патча ещё не проверяли.", "The effect has not been checked.", "Поведение пока не измерялось."]),
 "server": dict(
  pos=["Приложение работает без сервера.", "Серверной зависимости нет.", "The app works offline.", "No server dependency.", "Всё выполняется локально."],
  neg=["Приложение требует сервер.", "Есть серверная зависимость.", "The app needs a server connection.", "Без сервера функция не работает."],
  nr=["Зависимость от сервера не проверялась.", "Server dependency was not checked."]),
 "hash": dict(
  pos=["Хэш совпадает с проверенным.", "Проверена актуальная версия.", "The hash matches the tested one.", "Тестировался именно этот файл."],
  neg=["Хэш не совпадает.", "Проверялась устаревшая версия.", "The hash does not match.", "Тест выполнялся на копии другого файла."],
  nr=["Хэш не сверяли.", "The hash was not compared."]),
 "app": dict(
  pos=["Приложение запускается.", "The app launches normally.", "Приложение стартует без проблем."],
  neg=["Приложение падает при запуске.", "Приложение не запускается.", "The app crashes on startup."],
  nr=["Запуск приложения не проверяли.", "Startup was not tested."]),
}
UNREL = ["Сегодня хорошая погода.", "Кошка спит на диване.", "The weather is nice today.", "Мы пошли гулять в парк.", "Он купил хлеб и молоко.", "She is reading a book.", "The meeting is at noon.", "Поезд прибыл вовремя.", "Дети играют во дворе.", "Dinner is ready."]

def split(lst, held):
    return (lst[:-1], lst[-1:]) if len(lst) > 2 else (lst[:1], lst[1:])

def label(kind_p, kind_h):
    if kind_p == kind_h: return "entailment"
    if kind_p == "pos" and kind_h == "neg": return "contradiction"
    if kind_p == "neg" and kind_h == "pos": return "contradiction"
    if kind_p == "pos" and kind_h == "nr": return "contradiction"
    if kind_p == "nr" and kind_h == "pos": return "neutral"
    return "neutral"

def join(rng, parts):
    j = rng.choice([" ", " ", ", ", " и ", ", но ", "; ", " but ", ", "])
    out = parts[0]
    for p in parts[1:]:
        q = p if j in (" ",) else p[0].lower() + p[1:]
        out = out.rstrip(".") + j.rstrip(" ") + (" " if j.strip() else "") + q if j != " " else out + " " + q
    return out

def make(rng, held, n):
    pick = (lambda l: rng.choice(split(l, True)[1] or l)) if held else (lambda l: rng.choice(split(l, True)[0]))
    out = []
    names = list(C)
    for _ in range(n):
        r = rng.random()
        if r < 0.33:   # same-concept pair
            c = rng.choice(names); kp, kh = rng.choice(["pos", "neg", "nr"]), rng.choice(["pos", "neg", "nr"])
            out.append((pick(C[c][kp]), pick(C[c][kh]), label(kp, kh)))
        elif r < 0.68:  # different concepts -> neutral (hard negatives: same polarity, different subject)
            c1, c2 = rng.sample(names, 2)
            k1 = rng.choice(["pos", "neg", "nr"]); k2 = k1 if rng.random() < 0.6 else rng.choice(["pos", "neg", "nr"])
            out.append((pick(C[c1][k1]), pick(C[c2][k2]), "neutral"))
        elif r < 0.92:   # compound premise, single hypothesis
            cs = rng.sample(names, rng.randint(2, 3)); parts = []; kinds = {}
            for c in cs:
                k = rng.choice(["pos", "neg", "nr"]); kinds[c] = k; parts.append(pick(C[c][k]))
            h = rng.choice(names + names[:3]); kh = rng.choice(["pos", "neg"])
            lab = label(kinds[h], kh) if h in kinds else "neutral"
            out.append((rng.choice([" ", " ", ", ", " и ", ", но ", "; ", " but ", ", "]).join(parts) if False else join(rng, parts), pick(C[h][kh]), lab))
        else:           # unrelated
            c = rng.choice(names); k = rng.choice(["pos", "neg"])
            a, b = (rng.choice(UNREL), pick(C[c][k])) if rng.random() < .5 else (pick(C[c][k]), rng.choice(UNREL))
            out.append((a, b, "neutral"))
    # compound hypotheses
    for _ in range(n // 6):
        cs = rng.sample(names, 2); kinds = {c: rng.choice(["pos", "neg", "nr"]) for c in cs}
        hs = [(c, rng.choice(["pos", "neg"])) for c in cs]
        prem = join(rng, [pick(C[c][k]) for c, k in kinds.items()])
        labs = [label(kinds[c], k) for c, k in hs]
        lab = "contradiction" if "contradiction" in labs else ("entailment" if all(l == "entailment" for l in labs) else "neutral")
        hyp = pick(C[hs[0][0]][hs[0][1]]).rstrip(".") + " и " + pick(C[hs[1][0]][hs[1][1]])[0].lower() + pick(C[hs[1][0]][hs[1][1]])[1:]
        out.append((prem, hyp, lab))
    return out

if __name__ == "__main__":
    rng = random.Random(7)
    json.dump({"train": make(rng, False, 14000), "heldout": make(rng, True, 900)}, open("domain_nli.json", "w"), ensure_ascii=False)
    print("ok")
