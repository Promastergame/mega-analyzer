#!/usr/bin/env python3
"""syn7: programmatic data with labels by construction (no teacher).

Targets the "still dumb on unfamiliar words/situations" failures: quantity
sufficiency, shortfall size, comparisons, thresholds, flags, counting and
deadlines, phrased with unusual nouns/units/made-up names, JSON and text states.

usage: gen_synth7.py N SEED OUT.labelled.jsonl [--holdout]
--holdout uses a disjoint vocabulary (names/units/items) for a generalization dev set.
"""
import json, random, sys

def plural(n, forms):
    one, few, many = forms
    n = abs(int(n)) % 100
    if 11 <= n <= 14: return many
    n %= 10
    if n == 1: return one
    if 2 <= n <= 4: return few
    return many

NAMES_A = ["Петя","Маша","Гоша","Зульфия","Ярослав","Кира","Тимур","Ассоль","Борислав","Нюра","Элвин","Фёкла","Мирон","Злата","Агафон"]
NAMES_B = ["Савва","Ульяна","Игнат","Лукерья","Радомир","Виолетта","Ефим","Сабина","Платон","Аглая"]
# unit: (one, few, many), items: (nom, gen), verb
UNITS_A = [
  (("монета","монеты","монет"), [("бургер","бургера"),("билет в кино","билета"),("леденец","леденца")]),
  (("кристалл","кристалла","кристаллов"), [("меч","меча"),("щит из драконьей чешуи","щита"),("зелье лечения","зелья")]),
  (("рубль","рубля","рублей"), [("самокат","самоката"),("наушники","наушников"),("абонемент","абонемента")]),
  (("золотой","золотых","золотых"), [("плащ","плаща"),("подкова","подковы"),("карта сокровищ","карты")]),
  (("жетон","жетона","жетонов"), [("поездка на аттракционе","поездки"),("игрушка","игрушки")]),
  (("кредит","кредита","кредитов"), [("апгрейд корабля","апгрейда"),("топливный элемент","элемента")]),
]
UNITS_B = [
  (("ракушка","ракушки","ракушек"), [("бусы","бус"),("лодка","лодки")]),
  (("зубль","зубля","зублей"), [("кваргл","кваргла"),("тримбус","тримбуса")]),
  (("талер","талера","талеров"), [("сундук","сундука"),("подзорная труба","трубы")]),
  (("очко опыта","очка опыта","очков опыта"), [("новый уровень","уровня"),("навык","навыка")]),
]
# capacity-like (have vs need of a resource)
RES_A = [("литр","литра","литров","бензина","поездка до дачи"),("гигабайт","гигабайта","гигабайт","свободного места","установка игры"),
         ("место","места","мест","в автобусе","экскурсия класса"),("кг","кг","кг","муки","выпечка тортов"),
         ("час","часа","часов","свободного времени","подготовка к экзамену")]
RES_B = [("метр","метра","метров","ткани","пошив палатки"),("патрон","патрона","патронов","в запасе","охота на слизней"),
         ("кубометр","кубометра","кубометров","воды в баке","полив теплицы")]

POS = 0.96; NEG = 0.04

def soft(p):
    return round(POS if p else NEG, 3)

def score_label(keys, idx):
    lab = {k: 0.0 for k in keys}
    lab[keys[idx]] = 0.9
    if idx > 0: lab[keys[idx-1]] += 0.05
    else: lab[keys[idx]] += 0.05
    if idx < len(keys)-1: lab[keys[idx+1]] += 0.05
    else: lab[keys[idx]] += 0.05
    return {k: round(v, 3) for k, v in lab.items()}

def choice_label(keys, good):
    lab = {k: 0.02 for k in keys}
    lab[good] = round(1 - 0.02*(len(keys)-1), 3)
    return lab

class G:
    def __init__(self, rng, hold):
        self.r = rng; self.hold = hold
        self.names = NAMES_B if hold else NAMES_A
        self.units = UNITS_B if hold else UNITS_A
        self.res = RES_B if hold else RES_A

    def state(self, fields, text, extra=None):
        r = self.r
        mode = r.random()
        if mode < 0.35:
            d = dict(fields);
            if r.random() < 0.6: d["ситуация"] = text
            if extra: d.update(extra)
            return d
        if mode < 0.7:
            return text + ("" if not extra else " " + " ".join(f"{k}: {v}." for k, v in extra.items()))
        d = {"описание": text}
        if extra: d.update(extra)
        return d

    # ---------------- money sufficiency ----------------
    def money(self):
        r = self.r
        name = r.choice(self.names)
        uf, items = r.choice(self.units)
        item, item_gen = r.choice(items)
        cost = r.randint(2, 60)
        kind = r.random()
        if kind < 0.45: have = r.randint(max(0, cost-12), cost-1)
        elif kind < 0.6: have = cost
        else: have = r.randint(cost, cost+25)
        short = max(0, cost-have)
        text = r.choice([
            f"У {gen(name)} есть {have} {plural(have,uf)}. {cap(item)} стоит {cost} {plural(cost,uf)}.",
            f"{name} хочет {item}. Цена — {cost} {plural(cost,uf)}, в кошельке {have} {plural(have,uf)}.",
            f"{cap(item)} стоит {cost} {plural(cost,uf)}. У {gen(name)} накоплено {have}.",
            f"Баланс {gen(name)}: {have} {plural(have,uf)}. Нужно {cost} {plural(cost,uf)} на {item}.",
        ])
        unit_key = uf[2].split()[0]
        fields = r.choice([
            {f"{unit_key}_есть": have, f"цена_{item_gen.split()[0]}": cost},
            {"баланс": have, "стоимость": cost},
            {"есть": have, "нужно": cost, "товар": item},
            {"бюджет": have, "price": cost},
        ])
        extra = None
        if r.random() < 0.25: extra = {"хватает": have >= cost}
        st = self.state(fields, text, extra)
        qs, labs = {}, {}
        enough = have >= cost
        f = r.random()
        if f < 0.3:
            qs["q_buy"] = {"type": "noul", "instructions": r.choice([f"Может ли {name} купить {item} прямо сейчас?", f"Хватит ли {plural(5,uf)} на {item}?", f"Хватает ли денег на покупку?", f"{name} может себе это позволить?"])}
            labs["q_buy"] = soft(enough)
        elif f < 0.55:
            qs["q_buy"] = {"type": "noul", "instructions": r.choice([f"Не хватает ли {gen(name)} {plural(5,uf)}?", "Есть ли нехватка средств?", f"Придётся ли {dat(name)} ещё копить?", "Денег недостаточно?"])}
            labs["q_buy"] = soft(not enough)
        else:
            qs["q_buy"] = {"type": "noul", "instructions": r.choice(["Может ли купить?", "Хватает?", "Достаточно ли средств?"]),
                           "criteria": {"true": r.choice(["Денег хватает или больше нужного", "Средств достаточно"]), "false": r.choice(["Денег не хватает", "Средств недостаточно"])}}
            labs["q_buy"] = soft(enough)
        # shortfall score
        if r.random() < 0.8:
            k1 = r.randint(1, 4); k2 = k1 + r.randint(2, 6)
            m = uf[2]
            crit = {"0": r.choice(["Денег хватает полностью", "Нехватки нет", "Хватает"]),
                    "1": (f"Не хватает 1-{k1} {m} (чуть-чуть)" if k1 > 1 else "Не хватает совсем чуть-чуть (1)"),
                    "2": f"Не хватает {k1+1}-{k2} {m} (прилично)",
                    "3": r.choice([f"Не хватает больше {k2} {m} (сильно)", f"Нехватка {k2+1}+ {m}"])}
            idx = 0 if short == 0 else 1 if short <= k1 else 2 if short <= k2 else 3
            qs["q_short"] = {"type": "score", "instructions": r.choice(["Насколько велика нехватка?", f"Сколько {m} не хватает?", "Насколько сильно не хватает денег?"]), "criteria": crit}
            labs["q_short"] = score_label(list(crit), idx)
        if r.random() < 0.5:
            crit = {"buy": r.choice(["Купить сейчас", f"Сразу купить {item}"]), "save": r.choice(["Подождать и накопить", "Копить дальше"])}
            if r.random() < 0.5: crit = {"save": crit["save"], "buy": crit["buy"]}
            qs["q_act"] = {"type": "choice", "instructions": r.choice(["Что разумнее сделать сейчас?", f"Как поступить {dat(name)}?"]), "criteria": crit}
            labs["q_act"] = choice_label(list(crit), "buy" if enough else "save")
        return "money", st, qs, labs

    # ---------------- resource capacity ----------------
    def resource(self):
        r = self.r
        one, few, many, what, goal = r.choice(self.res)
        uf = (one, few, many)
        need = r.randint(3, 80)
        have = r.randint(max(0, need-30), need+30)
        enough = have >= need
        text = r.choice([
            f"Для задачи «{goal}» нужно {need} {plural(need,uf)} {what}. Сейчас есть {have}.",
            f"Есть {have} {plural(have,uf)} {what}, а на «{goal}» требуется {need}.",
            f"Задача: {goal}. Требуется: {need} {plural(need,uf)}. В наличии: {have} {plural(have,uf)}.",
        ])
        fields = r.choice([{"в_наличии": have, "требуется": need}, {"available": have, "required": need}, {"остаток": have, "необходимо": need, "задача": goal}])
        st = self.state(fields, text)
        qs, labs = {}, {}
        if r.random() < 0.6:
            qs["q"] = {"type": "noul", "instructions": r.choice([f"Хватит ли {what}?", "Ресурса достаточно для задачи?", f"Получится ли выполнить «{goal}» с тем, что есть?", "Is there enough?"])}
            labs["q"] = soft(enough)
        else:
            qs["q"] = {"type": "noul", "instructions": r.choice([f"Не хватит {what}?", "Будет дефицит?", "Нужно ли докупить/добыть ещё?"])}
            labs["q"] = soft(not enough)
        if r.random() < 0.6:
            ratio = have / need
            crit = {"0": "Ресурса с запасом", "1": "Ровно впритык или почти хватает", "2": "Не хватает заметно", "3": "Не хватает больше половины"}
            idx = 0 if ratio >= 1.15 else 1 if ratio >= 0.9 else 2 if ratio >= 0.5 else 3
            qs["q2"] = {"type": "score", "instructions": "Оцени ситуацию с запасом", "criteria": crit}
            labs["q2"] = score_label(list(crit), idx)
        return "resource", st, qs, labs

    # ---------------- comparison ----------------
    def compare(self):
        r = self.r
        pool = (["Зигзаг","Мурлык","Тортилла","Кракен","Бублик","Стриж","Лотос","Вихрь"] if not self.hold else ["Пиксель","Шмель","Гранит","Ирис"])
        a, b = r.sample(pool, 2)
        attr = r.choice([("цена", "дешевле", -1, "₽"), ("скорость", "быстрее", +1, "км/ч"), ("вес", "легче", -1, "кг"), ("ёмкость", "вместительнее", +1, "л"), ("рейтинг", "лучше по рейтингу", +1, "★")])
        key, adj, sign, unit = attr
        va = r.randint(1, 100); vb = va
        while vb == va: vb = r.randint(1, 100)
        text = r.choice([f"Вариант «{a}»: {key} {va} {unit}. Вариант «{b}»: {key} {vb} {unit}.",
                         f"{a} — {va} {unit}, {b} — {vb} {unit} ({key})."])
        fields = {a: {key: va}, b: {key: vb}} if r.random() < 0.5 else {f"{key}_{a}": va, f"{key}_{b}": vb}
        st = self.state(fields, text)
        better = a if (va - vb) * sign > 0 else b
        crit = {a: f"Вариант {a}", b: f"Вариант {b}"}
        if r.random() < 0.5: crit = {b: crit[b], a: crit[a]}
        qs = {"q": {"type": "choice", "instructions": f"Какой вариант {adj}?", "criteria": crit}}
        labs = {"q": choice_label(list(crit), better)}
        if r.random() < 0.5:
            qs["q2"] = {"type": "noul", "instructions": f"{a} {adj}, чем {b}?"}
            labs["q2"] = soft(better == a)
        return "compare", st, qs, labs

    # ---------------- threshold ----------------
    def threshold(self):
        r = self.r
        m = r.choice([("температура","°C","Перегрев?", "Температура в норме?"), ("давление в котле","бар","Превышено давление?", "Давление в пределах нормы?"),
                      ("уровень шума","дБ","Слишком шумно?", "Шум допустимый?"), ("влажность","%","Влажность выше лимита?", "Влажность в норме?"),
                      ("нагрузка CPU","%","Сервер перегружен?", "Нагрузка нормальная?"), ("концентрация флогистона","ppm","Флогистона слишком много?", "Флогистон в допустимых пределах?")])
        name, unit, q_over, q_ok = m
        lim = r.randint(20, 120)
        val = r.randint(max(0, lim-40), lim+40)
        if val == lim: val += 1
        over = val > lim
        text = r.choice([f"{cap(name)}: {val} {unit}. Допустимый максимум — {lim} {unit}.", f"Датчик показывает {val} {unit} ({name}), лимит {lim} {unit}."])
        fields = r.choice([{"значение": val, "лимит": lim, "параметр": name}, {"value": val, "max": lim}, {"текущее": val, "порог": lim}])
        st = self.state(fields, text)
        if r.random() < 0.5:
            qs = {"q": {"type": "noul", "instructions": q_over}}; labs = {"q": soft(over)}
        else:
            qs = {"q": {"type": "noul", "instructions": q_ok}}; labs = {"q": soft(not over)}
        if r.random() < 0.5:
            d = val - lim
            crit = {"0": "В норме", "1": "Небольшое превышение (до 10%)", "2": "Заметное превышение (10-30%)", "3": "Сильное превышение (больше 30%)"}
            pct = d / lim
            idx = 0 if d <= 0 else 1 if pct <= 0.1 else 2 if pct <= 0.3 else 3
            qs["q2"] = {"type": "score", "instructions": "Насколько серьёзна ситуация?", "criteria": crit}
            labs["q2"] = score_label(list(crit), idx)
        return "threshold", st, qs, labs

    # ---------------- flags / status ----------------
    def flags(self):
        r = self.r
        obj = r.choice(["двигатель", "портал", "холодильник", "телепорт", "насос", "робот-пылесос", "шлюз", "генератор щита"] if not self.hold else ["маяк", "лифт", "фонтан"])
        ok = r.random() < 0.5
        mode = r.random()
        if mode < 0.4:
            st = {f"{obj.replace(' ','_')}_исправен": ok, "объект": obj}
        elif mode < 0.7:
            st = f"Статус: {obj} — " + (r.choice(["работает штатно", "исправен", "в порядке", "online"]) if ok else r.choice(["сломан", "неисправен", "не работает", "offline", "вышел из строя"])) + "."
        else:
            st = {"объект": obj, "статус": (r.choice(["OK", "работает", "активен"]) if ok else r.choice(["ошибка", "сломан", "отключён"]))}
        if r.random() < 0.6:
            qs = {"q": {"type": "noul", "instructions": r.choice([f"Работает ли {obj}?", f"{cap(obj)} исправен?", f"Можно ли пользоваться: {obj}?"])}}; labs = {"q": soft(ok)}
        else:
            qs = {"q": {"type": "noul", "instructions": r.choice([f"Нужен ли ремонт: {obj}?", f"{cap(obj)} сломан?", f"Есть ли неисправность?"])}}; labs = {"q": soft(not ok)}
        return "flags", st, qs, labs

    # ---------------- counting ----------------
    def count(self):
        r = self.r
        things = r.choice([("задачи", ["починить кран", "купить хлеб", "позвонить бабушке", "сдать отчёт", "выгулять ящера", "полить кактус", "обновить сервер", "написать тест"]),
                           ("ошибки", ["timeout", "NullPointer", "диск полон", "403", "OOM", "битый кэш", "кривой UTF-8"]),
                           ("гости", ["Аня", "Боб", "Вера", "Глеб", "Дуся", "Ерофей", "Жора", "Зоя"])])
        noun, pool = things
        n = r.randint(0, min(7, len(pool)))
        items = r.sample(pool, n)
        k = r.randint(1, 5)
        st = r.choice([{noun: items or "нет", "всего": n}, {"список": items or "пусто", "тип": noun}, f"Список ({noun}): " + (", ".join(items) if items else "пусто") + "."])
        qs = {"q": {"type": "noul", "instructions": r.choice([f"Больше {k} элементов в списке?", f"Их больше, чем {k}?"])}}
        labs = {"q": soft(n > k)}
        if r.random() < 0.5:
            qs["q0"] = {"type": "noul", "instructions": "Список пустой?"}; labs["q0"] = soft(n == 0)
        if r.random() < 0.5:
            crit = {"0": "Ни одного", "1": "1-2", "2": "3-4", "3": "5 и больше"}
            idx = 0 if n == 0 else 1 if n <= 2 else 2 if n <= 4 else 3
            qs["q2"] = {"type": "score", "instructions": "Сколько их?", "criteria": crit}; labs["q2"] = score_label(list(crit), idx)
        return "count", st, qs, labs

    # ---------------- deadlines ----------------
    def deadline(self):
        r = self.r
        name = r.choice(self.names)
        task = r.choice(["доклад", "ремонт звездолёта", "курсовая", "переезд", "релиз", "свадебный торт", "отчёт для гильдии"])
        left = r.randint(0, 20)
        need = r.randint(1, 15)
        ok = left >= need
        text = r.choice([f"До дедлайна ({task}) осталось {left} {plural(left,('день','дня','дней'))}. Работы ещё на {need} {plural(need,('день','дня','дней'))}.",
                         f"{name} делает: {task}. Нужно {need} дн., срок через {left} дн."])
        fields = r.choice([{"дней_осталось": left, "дней_нужно": need}, {"days_left": left, "days_needed": need, "task": task}])
        st = self.state(fields, text)
        if r.random() < 0.6:
            qs = {"q": {"type": "noul", "instructions": r.choice([f"Успеет ли {name} к сроку?", "Укладываемся в срок?", "Можно успеть вовремя?"])}}; labs = {"q": soft(ok)}
        else:
            qs = {"q": {"type": "noul", "instructions": r.choice(["Сорвём дедлайн?", "Будет опоздание?", f"{name} не успеет?"])}}; labs = {"q": soft(not ok)}
        if r.random() < 0.6:
            crit = {"0": "Срочности нет", "1": "Низкая", "2": "Средняя", "3": "Высокая, надо спешить", "4": "Уже горит / не успеваем"}
            slack = left - need
            idx = 4 if slack < 0 else 3 if slack <= 1 else 2 if slack <= 4 else 1 if slack <= 8 else 0
            qs["q2"] = {"type": "score", "instructions": "Насколько это срочно?", "criteria": crit}; labs["q2"] = score_label(list(crit), idx)
        return "deadline", st, qs, labs

def cap(s): return s[:1].upper() + s[1:]
def gen(name):
    if name.endswith("я"): return name[:-1] + "и"
    if name.endswith("а"): return name[:-1] + ("и" if name[-2:-1] in "гкхжшщч" else "ы")
    if name.endswith("й"): return name[:-1] + "я"
    if name[-1] in "ьяаеиоуюэ": return name
    return name + "а"
def dat(name):
    if name.endswith("я") or name.endswith("а"): return name[:-1] + "е"
    if name.endswith("й"): return name[:-1] + "ю"
    if name[-1] in "ьеиоуюэ": return name
    return name + "у"

def main():
    n, seed, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
    hold = "--holdout" in sys.argv
    r = random.Random(seed); g = G(r, hold)
    kinds = [(g.money, 3), (g.resource, 2), (g.compare, 1.5), (g.threshold, 1.5), (g.flags, 1), (g.count, 1), (g.deadline, 1.5)]
    fs = [k for k, w in kinds]; ws = [w for k, w in kinds]
    with open(out, "w", encoding="utf-8") as f:
        for i in range(n):
            task, st, qs, labs = r.choices(fs, ws)[0]()
            f.write(json.dumps({"group": f"syn7{'h' if hold else ''}-{i}", "task": task, "request": {"state": st, "questions": qs}, "labels": labs}, ensure_ascii=False) + "\n")

if __name__ == "__main__": main()
