"""
Podział puli sędziego na listy sędziowskie - sama reguła.

MODUŁ-LIŚĆ: bez bazy i bez sieci (`app.db` łączy się z bazą przy imporcie),
żeby każdy grosz tej reguły chodził w teście.

SKĄD TO SIĘ WZIĘŁO (25.09.2026). Komisja chce wypłacić sędziemu miesiąc nie
jednym rachunkiem, tylko kilkoma: pula 1000 zł brutto idzie na listy A, B, C,
każda to osobna „Lista sędziowska" z własnym numerem w księdze okręgu.

ZASADY (decyzje użytkownika):
  - Na listy rozkłada się MECZE sędziego z tego miesiąca - kwota listy to
    brutto jej meczów. W obrębie list wolno ręcznie przesunąć kwotę
    (`manual_shift`, w złotych z groszami), ale suma przesunięć ma być zerem:
    suma list = pula brutto co do grosza.
  - Zwrot kosztów dojazdu (bez podatku) zostaje przy meczu, na liście, na
    której mecz leży. Przesunięcie go nie dotyka.
  - Każda lista to OSOBNY rachunek: koszty uzyskania 20% tylko wtedy, gdy
    brutto TEJ listy przekracza 200 zł, podatek 12% i zaokrąglenia jak
    w `settlement_rates._tax_parts` (art. 63 ordynacji). Dlatego netto
    z podziałem może się różnić od netto bez podziału - ekran pokazuje różnicę
    przed zapisem.
  - Zestawienie miesiąca zostawia sędziego jednym wierszem z pełnym brutto,
    a koszty, podatek i netto są SUMĄ list (`applied_values`).
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from app import settlement_rates as R
from app.settlement_money import money, money_sum

#: Litery kolejnych list. Więcej niż osiem list w miesiącu to już nie podział,
#: tylko pomyłka.
LETTERS = "ABCDEFGH"
MAX_LISTS = len(LETTERS)

STATUS_DRAFT = "draft"
STATUS_ISSUED = "issued"
STATUS_VOID = "void"
STATUSES = (STATUS_DRAFT, STATUS_ISSUED, STATUS_VOID)

#: Rodzaj dokumentu w księdze `province_settlement_documents`.
DOCUMENT_KIND = "lista"
#: Znacznik unieważnionego numeru w księdze - numer zostaje, nie wraca do puli.
DOCUMENT_VOID = "anulowana"


def _cents(value: Any) -> int:
    return int(round(money(value) * 100))


def _pln(cents: int) -> float:
    return money(cents / 100)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


# ---------------------------------------------------------------------------
# Wejście
# ---------------------------------------------------------------------------

def normalize_lists(raw: Any) -> list[dict]:
    """
    Listy z klienta (albo z bazy) w jednym kształcie:
    ``[{"letter": "A", "match_keys": [...], "manual_shift": 0.0}]``.

    Litery nadajemy od nowa, po kolei - usunięcie listy B z trzech robi z C
    nową B, zamiast zostawiać dziurę w nazwach. Powtórzony klucz meczu na
    tej samej liście liczy się raz. Śmieci (nie-lista, nie-słownik) znikają,
    a o tym, czego brakuje, mówi dopiero `problems`.
    """
    if not isinstance(raw, list):
        return []
    out: list[dict] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        keys: list[str] = []
        for key in item.get("match_keys") or []:
            text = _s(key)
            if text and text not in keys:
                keys.append(text)
        out.append(
            {
                "letter": LETTERS[index] if index < MAX_LISTS else f"#{index + 1}",
                "match_keys": keys,
                "manual_shift": money(item.get("manual_shift")),
            }
        )
    return out


def default_lists(match_keys: Iterable[str], count: int = 2) -> list[dict]:
    """Pierwszy szkic: wszystkie mecze na liście A, reszta list pusta."""
    count = max(1, min(MAX_LISTS, int(count or 1)))
    keys = [_s(k) for k in match_keys if _s(k)]
    return [
        {"letter": LETTERS[i], "match_keys": keys if i == 0 else [], "manual_shift": 0.0}
        for i in range(count)
    ]


def reconcile(lists: list[dict], match_keys: Iterable[str]) -> tuple[list[dict], list[str]]:
    """
    Szkic z bazy dopasowany do meczów, które miesiąc ma DZIŚ.

    Mecz, który zniknął z rozliczenia (odwołana obsada), wypada z listy; mecz,
    który doszedł, trafia na listę A. Każda taka zmiana wraca jako zdanie do
    pokazania - szkic nie może zmienić się po cichu.
    """
    current = [_s(k) for k in match_keys if _s(k)]
    known = set(current)
    lists = normalize_lists(lists) or default_lists(current, 1)
    notes: list[str] = []
    placed: set[str] = set()
    for item in lists:
        kept = []
        for key in item["match_keys"]:
            if key not in known:
                notes.append(f"Mecz {key} nie należy już do rozliczenia tego miesiąca - zdjęto go z listy {item['letter']}.")
                continue
            if key in placed:
                notes.append(f"Mecz {key} był na dwóch listach - zostawiono go na pierwszej.")
                continue
            placed.add(key)
            kept.append(key)
        item["match_keys"] = kept
    fresh = [key for key in current if key not in placed]
    if fresh:
        lists[0]["match_keys"].extend(fresh)
        notes.append(
            f"Doszło {len(fresh)} {_plural(len(fresh), 'nowy mecz', 'nowe mecze', 'nowych meczów')} - "
            f"trafiły na listę {lists[0]['letter']}."
        )
    return lists, notes


def _plural(count: int, one: str, few: str, many: str) -> str:
    if count == 1:
        return one
    last_two, last = count % 100, count % 10
    if 2 <= last <= 4 and not 12 <= last_two <= 14:
        return few
    return many


# ---------------------------------------------------------------------------
# Sprawdzenie
# ---------------------------------------------------------------------------

def problems(
    lists: list[dict],
    matches: list[dict],
    *,
    for_issue: bool = False,
) -> list[str]:
    """
    Co jest nie tak z podziałem - zdania dla człowieka, puste = w porządku.

    `matches`: mecze puli, każdy ze słownikiem ``{"match_key", "gross", ...}``.
    `for_issue`: wydanie list jest ostrzejsze - co najmniej dwie listy i żadnej
    pustej (lista na 0,00 zł to numer w księdze bez pieniędzy).
    """
    out: list[str] = []
    by_key = {_s(m.get("match_key")): m for m in matches}
    if not lists:
        return ["Podział nie ma żadnej listy."]
    if len(lists) > MAX_LISTS:
        out.append(f"Najwięcej {MAX_LISTS} list - jest {len(lists)}.")

    seen: dict[str, str] = {}
    for item in lists:
        for key in item["match_keys"]:
            if key not in by_key:
                out.append(f"Mecz {key} (lista {item['letter']}) nie należy do rozliczenia tego miesiąca.")
            elif key in seen:
                out.append(f"Mecz {_label(by_key[key])} jest na liście {seen[key]} i {item['letter']} - może być tylko na jednej.")
            else:
                seen[key] = item["letter"]
    missing = [by_key[k] for k in by_key if k not in seen]
    if missing:
        names = ", ".join(_label(m) for m in missing[:4]) + (" i inne" if len(missing) > 4 else "")
        out.append(f"{len(missing)} {_plural(len(missing), 'mecz nie jest', 'mecze nie są', 'meczów nie jest')} na żadnej liście: {names}.")

    calc = compute(lists, matches)
    remainder = calc["remainder"]
    if remainder:
        word = "zostało do rozdzielenia" if remainder > 0 else "rozdzielono za dużo o"
        out.append(
            f"Rozdzielono {_fmt(calc['allocated'])} z {_fmt(calc['pool']['gross'])} - "
            f"{word} {_fmt(abs(remainder))}."
        )
    for item in calc["lists"]:
        if item["gross"] < 0:
            out.append(f"Lista {item['letter']} wychodzi na minus ({_fmt(item['gross'])}) - zmniejsz przesunięcie.")
        elif for_issue and item["gross"] == 0:
            out.append(f"Lista {item['letter']} jest pusta - usuń ją albo przenieś na nią kwotę.")
    if for_issue and len(lists) < 2:
        out.append("Do wydania potrzebne są co najmniej dwie listy - jedna lista to zwykłe zestawienie.")
    return out


def _label(match: dict) -> str:
    code = _s(match.get("code") or match.get("match_code"))
    day = _s(match.get("day"))
    if code and len(day) >= 10:
        return f"{code} ({day[8:10]}.{day[5:7]})"
    return code or _s(match.get("match_key"))


def _fmt(value: float) -> str:
    text = f"{abs(money(value)):,.2f}".replace(",", " ").replace(".", ",")
    return f"{'-' if value < 0 else ''}{text} zł"


# ---------------------------------------------------------------------------
# Rachunek
# ---------------------------------------------------------------------------

def compute(lists: list[dict], matches: list[dict]) -> dict:
    """
    Kwoty każdej listy i całego podziału, obok rachunku bez podziału.

    Brutto listy = brutto jej meczów + przesunięcie. Koszty, podstawa, podatek
    i netto - z `_tax_parts` od brutto TEJ listy. Dojazd listy to dojazdy jej
    meczów (bez podatku, bez przesunięć). Mecz spoza puli nie wnosi kwoty -
    o nim mówi `problems`.
    """
    by_key = {_s(m.get("match_key")): m for m in matches}
    pool_gross = money_sum(m.get("gross") for m in matches)
    pool_travel = money_sum(m.get("travel") for m in matches)

    rows: list[dict] = []
    used: set[str] = set()
    for item in lists:
        keys = [k for k in item["match_keys"] if k in by_key and k not in used]
        used.update(keys)
        matches_gross = money_sum(by_key[k].get("gross") for k in keys)
        shift = money(item.get("manual_shift"))
        gross = _pln(_cents(matches_gross) + _cents(shift))
        parts = R._tax_parts(gross) if gross > 0 else {"gross": gross, "costs": 0, "taxable": 0, "tax": 0, "net": gross}
        travel = money_sum(by_key[k].get("travel") for k in keys)
        rows.append(
            {
                "letter": item["letter"],
                "match_keys": list(item["match_keys"]),
                "match_count": len(keys),
                "matches_gross": matches_gross,
                "manual_shift": shift,
                "gross": gross,
                "costs": int(parts["costs"]),
                "taxable": int(parts["taxable"]),
                "tax": int(parts["tax"]),
                "net": money(parts["net"]),
                "travel": travel,
                "total": money_sum([parts["net"], travel]),
            }
        )

    unsplit = R._tax_parts(pool_gross)
    split_totals = {
        "gross": money_sum(r["gross"] for r in rows),
        "costs": sum(r["costs"] for r in rows),
        "taxable": sum(r["taxable"] for r in rows),
        "tax": sum(r["tax"] for r in rows),
        "net": money_sum(r["net"] for r in rows),
        "travel": money_sum(r["travel"] for r in rows),
    }
    split_totals["total"] = money_sum([split_totals["net"], split_totals["travel"]])
    unsplit_totals = {
        "gross": money(unsplit["gross"]),
        "costs": int(unsplit["costs"]),
        "taxable": int(unsplit["taxable"]),
        "tax": int(unsplit["tax"]),
        "net": money(unsplit["net"]),
        "travel": pool_travel,
        "total": money_sum([unsplit["net"], pool_travel]),
    }
    allocated = split_totals["gross"]
    return {
        "pool": {"gross": pool_gross, "travel": pool_travel, "matches": len(by_key)},
        "lists": rows,
        "split": split_totals,
        "unsplit": unsplit_totals,
        "allocated": allocated,
        "remainder": _pln(_cents(pool_gross) - _cents(allocated)),
        "difference": {
            # Dodatnie = z podziałem sędzia dostaje WIĘCEJ.
            "net": _pln(_cents(split_totals["net"]) - _cents(unsplit_totals["net"])),
            "tax": split_totals["tax"] - unsplit_totals["tax"],
            "costs": split_totals["costs"] - unsplit_totals["costs"],
        },
    }


def applied_values(calc: dict) -> dict:
    """Koszty, podstawa, podatek, netto i razem do wiersza zestawienia - suma list."""
    split = calc["split"]
    return {
        "costs": split["costs"],
        "taxable": split["taxable"],
        "tax": split["tax"],
        "net": split["net"],
        "total": split["total"],
    }


# ---------------------------------------------------------------------------
# Wydane listy wobec dzisiejszego miesiąca
# ---------------------------------------------------------------------------

def issued_state(snapshot: Optional[list[dict]], lists: list[dict], matches: list[dict]) -> dict:
    """
    Czy wydane listy nadal zgadzają się z miesiącem.

    Zgadzają się, gdy (1) każdy dzisiejszy mecz jest na dokładnie jednej
    liście i nic ponad to, (2) brutto każdej listy jest takie jak w dniu
    wydania. Wtedy zestawienie liczy koszty i podatek z list. Inaczej listy są
    NIEAKTUALNE: zestawienie wraca do rachunku bez podziału i mówi dlaczego -
    zero cichej zmiany kwot.
    """
    reasons: list[str] = []
    list_keys = [k for item in lists for k in item["match_keys"]]
    now_keys = {_s(m.get("match_key")) for m in matches}
    extra = [k for k in list_keys if k not in now_keys]
    fresh = [k for k in now_keys if k not in set(list_keys)]
    if extra:
        reasons.append(
            f"Na listach {_plural(len(extra), 'jest mecz', 'są mecze', 'jest meczów')}, "
            f"których nie ma w tym rozliczeniu ({len(extra)}) - np. odwołana obsada albo inne przełączniki widoku."
        )
    if fresh:
        reasons.append(
            f"W miesiącu {_plural(len(fresh), 'jest mecz', 'są mecze', 'jest meczów')} spoza list ({len(fresh)})."
        )
    calc = compute(lists, matches)
    if not reasons and snapshot:
        issued_gross = {str(item.get("letter")): money(item.get("gross")) for item in snapshot}
        for row in calc["lists"]:
            before = issued_gross.get(row["letter"])
            if before is not None and _cents(before) != _cents(row["gross"]):
                reasons.append(
                    f"Brutto listy {row['letter']} zmieniło się od wydania: {_fmt(before)} → {_fmt(row['gross'])} "
                    "(zmiana stawek albo meczów)."
                )
    if not reasons:
        bad = problems(lists, matches, for_issue=True)
        reasons.extend(bad)
    return {"current": not reasons, "reasons": reasons, "calc": calc}


def numbers_label(numbers: Iterable[str]) -> str:
    """
    „SL/09/2026/4-6" dla kolejnych numerów z jednego miesiąca, inaczej po
    przecinku („SL/09/2026/4, SL/09/2026/7").
    """
    items = [_s(n) for n in numbers if _s(n)]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    prefixes = {n.rsplit("/", 1)[0] for n in items}
    try:
        seqs = [int(n.rsplit("/", 1)[1]) for n in items]
    except (IndexError, ValueError):
        return ", ".join(items)
    if len(prefixes) == 1 and seqs == list(range(seqs[0], seqs[0] + len(seqs))):
        return f"{items[0]}-{seqs[-1]}"
    return ", ".join(items)


def list_badge(status: str, lists: list[dict], numbers: list[str], state: Optional[dict]) -> dict:
    """Krótka informacja do wiersza sędziego: „3 listy", szkic albo nieaktualne."""
    count = len(lists)
    return {
        "status": status,
        "lists": count,
        "numbers": list(numbers or []),
        "label": numbers_label(numbers or []),
        "current": bool(state["current"]) if state else None,
        "reasons": list(state["reasons"]) if state else [],
    }
