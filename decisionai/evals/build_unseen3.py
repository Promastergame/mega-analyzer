#!/usr/bin/env python3
"""unseen3 (v1.17): blind set for unfamiliar words in everyday numeric situations.
Written by hand before the v1.17 model finished training; nothing was tuned on it.
Covers have/need, shortfall size, limits, deadlines, comparisons and flags with
made-up nouns and units, in JSON and in plain text, RU and EN."""
import json
TF = lambda t, f: {"true": t, "false": f}
SC = {"0": "Хватает полностью", "1": "Не хватает 1-3", "2": "Не хватает 4-10", "3": "Не хватает больше 10"}
C = []
def add(state, qs, labels): C.append({"group": f"unseen3-{len(C)}", "request": {"state": state, "questions": qs}, "labels": labels})

add({"у_Нафани_шмурдиков": 12, "стоимость_брякалки": 9},
    {"a": {"type": "noul", "instructions": "Хватит ли Нафане шмурдиков на брякалку?"},
     "b": {"type": "score", "instructions": "Насколько велика нехватка шмурдиков?", "criteria": SC}},
    {"a": True, "b": "0"})
add("У гнома Бульбуса в мешке 3 фигульки. Волшебный колпак стоит 17 фигулек.",
    {"a": {"type": "noul", "instructions": "Может ли Бульбус купить колпак прямо сейчас?", "criteria": TF("Может, фигулек достаточно", "Не может, фигулек мало")},
     "b": {"type": "score", "instructions": "Сколько примерно не хватает до колпака?", "criteria": SC}},
    {"a": False, "b": "3"})
add({"запас_тринитов": 40, "нужно_тринитов": 44, "станция": "Кассиопея-4"},
    {"a": {"type": "noul", "instructions": "Будет ли дефицит тринитов на станции?"},
     "b": {"type": "score", "instructions": "Насколько большая нехватка?", "criteria": SC}},
    {"a": True, "b": "2"})
add("Marlo has 25 glimmers in her pouch. A ride on the sky-whale costs 30 glimmers.",
    {"a": {"type": "noul", "instructions": "Can Marlo afford the sky-whale ride?"},
     "b": {"type": "noul", "instructions": "Is Marlo short of glimmers?"}},
    {"a": False, "b": True})
add({"balance_zorbs": 300, "price_zorbs": 120, "item": "hover-boots"},
    {"a": {"type": "noul", "instructions": "Does the buyer have enough zorbs for the hover-boots?"}},
    {"a": True})
add({"значение_флюкса": 73, "лимит_флюкса": 60, "датчик": "Б-12"},
    {"a": {"type": "noul", "instructions": "Флюкс превышает лимит?"},
     "b": {"type": "noul", "instructions": "Показания датчика в норме?"}},
    {"a": True, "b": False})
add("Датчик хрумзы показывает 18 единиц. Допустимый максимум 25 единиц.",
    {"a": {"type": "noul", "instructions": "Уровень хрумзы в пределах нормы?"}},
    {"a": True})
add({"дней_до_ярмарки": 6, "дней_на_вязание_свитера": 9},
    {"a": {"type": "noul", "instructions": "Успеет ли бабушка Агриппина связать свитер к ярмарке?"}},
    {"a": False})
add("До запуска дирижабля осталось 14 дней, работы ещё на 5 дней.",
    {"a": {"type": "noul", "instructions": "Команда успеет к запуску?"},
     "b": {"type": "noul", "instructions": "Будет ли опоздание с запуском?"}},
    {"a": True, "b": False})
add({"хватает_клея": False, "проект": "модель фрегата"},
    {"a": {"type": "noul", "instructions": "Клея хватает?"}},
    {"a": False})
add({"цена_Вжух": 410, "цена_Бдыщ": 380, "цена_Тыгыдык": 455},
    {"a": {"type": "choice", "instructions": "Какой вариант самый дешёвый?", "criteria": {"Вжух": "Самокат Вжух", "Бдыщ": "Самокат Бдыщ", "Тыгыдык": "Самокат Тыгыдык"}}},
    {"a": "Бдыщ"})
add("Лодка «Ряска»: скорость 12 узлов. Лодка «Мурена»: скорость 19 узлов.",
    {"a": {"type": "choice", "instructions": "Какая лодка быстрее?", "criteria": {"ryaska": "Ряска", "murena": "Мурена"}}},
    {"a": "murena"})
add({"в_наличии_кругляшей": 7, "требуется_кругляшей": 7},
    {"a": {"type": "noul", "instructions": "Хватит ли кругляшей?"},
     "b": {"type": "score", "instructions": "Насколько велика нехватка?", "criteria": SC}},
    {"a": True, "b": "0"})
add("На складе 2 ящика пупырки, а для заказа требуется 9 ящиков.",
    {"a": {"type": "noul", "instructions": "Можно ли собрать заказ из того, что есть на складе?"},
     "b": {"type": "score", "instructions": "Какова нехватка ящиков?", "criteria": SC}},
    {"a": False, "b": "2"})
add({"items": ["брумс", "клякс", "фрип", "дзынь"]},
    {"a": {"type": "noul", "instructions": "В списке больше 3 элементов?"}},
    {"a": True})
add({"накоплено_кредитов": 1500, "стоимость_апгрейда_гипердвигателя": 1800, "пилот": "Зоркий Ёж"},
    {"a": {"type": "noul", "instructions": "Получится ли у пилота оплатить апгрейд гипердвигателя?"},
     "b": {"type": "noul", "instructions": "Пилоту не хватает кредитов?"}},
    {"a": False, "b": True})
add("Yara needs 8 moonstones to open the gate and has 11.",
    {"a": {"type": "noul", "instructions": "Does Yara have enough moonstones to open the gate?"}},
    {"a": True})
add({"свободно_гигабайт": 3, "размер_обновления_гигабайт": 12},
    {"a": {"type": "noul", "instructions": "Поместится ли обновление на диск?"},
     "b": {"type": "choice", "instructions": "Что делать в первую очередь?", "criteria": {"free": "Освободить место на диске", "install": "Сразу ставить обновление", "ignore": "Ничего не делать"}}},
    {"a": False, "b": "free"})
add("Кошка Мурзилла съела 2 порции корма из 5, положенных на день.",
    {"a": {"type": "noul", "instructions": "Кошка уже съела всю дневную норму?"}},
    {"a": False})
add({"мест_в_тарантасе": 4, "пассажиров": 6},
    {"a": {"type": "noul", "instructions": "Все пассажиры поместятся в тарантас?"},
     "b": {"type": "score", "instructions": "Насколько не хватает мест?", "criteria": SC}},
    {"a": False, "b": "1"})
with open(__file__.replace("build_unseen3.py", "unseen3.jsonl"), "w", encoding="utf-8") as f:
    for c in C: f.write(json.dumps(c, ensure_ascii=False) + "\n")
print(len(C), sum(len(c["labels"]) for c in C))
