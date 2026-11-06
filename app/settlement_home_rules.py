"""
Historia miejsca zamieszkania sędziego - reguły bez bazy (decyzja właściciela 06.11.2026).

Okręg może zapisać w panelu: „zmiana na obecne miejsce zamieszkania nastąpiła po dniu X,
wcześniej była miejscowość Y". Mecze do dnia X (włącznie, czas polski) liczą dojazd z Y,
późniejsze - z miasta, które dziś podaje ZPRP. Zapis okręgu jest silniejszy niż blokada
z chwili rozliczenia (`settlement_home_lock`): to jawna korekta człowieka.

Drugie źródło takiego zapisu to wgrana LISTA PRZEJAZDÓW (PDF z BAZY) jako ostatni moment
ze starymi danymi: trasa „Dom-Hala-Dom" mówi, skąd sędzia wtedy jeździł. Porównanie
z dzisiejszym miastem z ZPRP wskazuje, komu się zmieniło (`compare_list`).
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import date, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

_PL = ZoneInfo("Europe/Warsaw")

SOURCE_MANUAL = "manual"
SOURCE_LIST = "list"
SOURCES = (SOURCE_MANUAL, SOURCE_LIST)


def _s(value: Any) -> str:
    return " ".join(str(value or "").split())


def fold(value: Any) -> str:
    """Porównanie napisów bez wielkości liter, ogonków i zbędnych spacji."""
    from app.settlement_rates import strip_dia

    return " ".join(strip_dia(_s(value)).lower().replace("-", " ").split())


def same_city(a: Any, b: Any) -> bool:
    if not _s(a) or not _s(b):
        return False
    if fold(a) == fold(b):
        return True
    from app.national_lookup_rules import same_city as national_same

    return national_same(a, b)


def local_day(when: Any) -> date | None:
    """Dzień meczu po czasie polskim."""
    if when is None:
        return None
    if isinstance(when, datetime):
        stamp = when if when.tzinfo else when.replace(tzinfo=_PL)
        return stamp.astimezone(_PL).date()
    if isinstance(when, date):
        return when
    try:
        return local_day(datetime.fromisoformat(str(when)))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Historia
# ---------------------------------------------------------------------------

def home_for(entries: Iterable[tuple[date, str]], day: date | None) -> str | None:
    """
    Miasto z historii dla dnia meczu albo None (= dzisiejsze miasto z ZPRP).

    `entries` - (ostatni dzień w starym mieście, miasto). Wpis obowiązuje od dnia
    po poprzednim wpisie do swojego dnia włącznie.
    """
    if day is None:
        return None
    for until, city in sorted(entries, key=lambda item: item[0]):
        if day <= until and _s(city):
            return _s(city)
    return None


def timeline(entries: Iterable[tuple[date, str]], current: Any) -> list[dict]:
    """Odcinki do pokazania: [{city, from, to}] - ostatni to miasto dzisiejsze (to = None)."""
    out: list[dict] = []
    start: date | None = None
    for until, city in sorted(entries, key=lambda item: item[0]):
        out.append({"city": _s(city), "from": start.isoformat() if start else None, "to": until.isoformat()})
        start = until + timedelta(days=1)
    if _s(current):
        out.append({"city": _s(current), "from": start.isoformat() if start else None, "to": None})
    return out


def clean_entry(city: Any, until: Any) -> tuple[str, date]:
    """Walidacja wpisu z panelu - czytelny komunikat zamiast cichej odmowy."""
    name = _s(city)
    if not name:
        raise ValueError("Podaj poprzednie miejsce zamieszkania.")
    if len(name) > 80:
        raise ValueError("Nazwa miejscowości jest za długa.")
    if isinstance(until, datetime):
        until = until.date()
    if not isinstance(until, date):
        try:
            until = date.fromisoformat(str(until))
        except ValueError as exc:
            raise ValueError("Podaj dzień, do którego obowiązywało poprzednie miejsce zamieszkania.") from exc
    return name, until


# ---------------------------------------------------------------------------
# Lista przejazdów (PDF z BAZY)
# ---------------------------------------------------------------------------

_DATE = re.compile(r"^(\d{2})\.(\d{2})\.(\d{4})$")
_PERIOD = re.compile(r"(\d{2}\.\d{2}\.\d{4})\s*[-–]\s*(\d{2}\.\d{2}\.\d{4})")
_LP = re.compile(r"^\d{1,4}$")
_UPPER = "A-ZĄĆĘŁŃÓŚŹŻÄÖÜ"
_NAME = re.compile(rf"^[{_UPPER}][{_UPPER}'\-]+(?:[ \-][{_UPPER}][{_UPPER}'\-]+)* [{_UPPER}][^\d]*$")
_NUMBER = re.compile(r"^[A-ZĄĆĘŁŃÓŚŹŻ]{1,6}/\S+/\d+\S*$")


def _pl_date(text: str) -> date | None:
    match = _DATE.match(text.strip())
    if not match:
        return None
    try:
        return date(int(match.group(3)), int(match.group(2)), int(match.group(1)))
    except ValueError:
        return None


def split_route(route: Any) -> tuple[str, str] | None:
    """
    „Dom-Hala-Dom" -> (dom, hala). Nazwy z łącznikiem („Bielsko-Biała",
    „Kędzierzyn-Koźle") rozpoznajemy po tym, że dom stoi na obu końcach.
    """
    text = _s(route)
    best: tuple[str, str] | None = None
    for i, ch in enumerate(text):
        if ch != "-":
            continue
        home = text[:i].strip()
        if not home or not text.endswith("-" + home):
            continue
        middle = text[i + 1 : len(text) - len(home) - 1].strip(" -")
        if middle:
            best = (home, middle)  # najdłuższy dom wygrywa (pętla idzie w prawo)
    return best


def parse_travel_list(text: str) -> dict:
    """
    Tekst listy przejazdów -> {number, from, to, judges: {nazwa: {homes: Counter, last: {city: day}, trips}}}.

    Wiersz sędziego: „Lp" (sama liczba), potem „NAZWISKO Imię"; dalej pary
    data + trasa. Wiersze „Razem ..." i nagłówki tabeli pomijamy.
    """
    lines = [_s(line) for line in str(text or "").splitlines()]
    lines = [line for line in lines if line]
    number = ""
    period_from = period_to = None
    judges: dict[str, dict] = {}
    current: str | None = None
    for index, line in enumerate(lines):
        if not number and _NUMBER.match(line):
            number = line
        if period_from is None:
            found = _PERIOD.search(line)
            if found:
                period_from, period_to = _pl_date(found.group(1)), _pl_date(found.group(2))
                continue
        if line.startswith(("Razem ", "str. ")):
            continue
        if _LP.match(line):
            # Długie nazwisko łamie się w komórce na dwie-trzy linie - sklejamy do daty.
            parts = []
            for follow in lines[index + 1 : index + 4]:
                if _pl_date(follow) is not None:
                    break
                parts.append(follow)
            name = " ".join(parts)
            if parts and _NAME.match(name):
                current = name
                judges.setdefault(current, {"homes": Counter(), "last": {}, "trips": 0})
                continue
        day = _pl_date(line)
        if day is not None and current and index + 1 < len(lines):
            split = split_route(lines[index + 1])
            # Długa trasa łamie się w komórce („...-Siemianowice" / „Śląskie").
            if split is None and index + 2 < len(lines):
                split = split_route(lines[index + 1] + " " + lines[index + 2])
            if split is None:
                continue
            home = split[0]
            slot = judges[current]
            slot["homes"][home] += 1
            slot["trips"] += 1
            if day > slot["last"].get(home, date.min):
                slot["last"][home] = day
    return {
        "number": number,
        "from": period_from,
        "to": period_to,
        "judges": {name: data for name, data in judges.items() if data["trips"]},
    }


def name_key(value: Any) -> str:
    """Klucz nazwiska niezależny od kolejności („ANDERS Magdalena" == „Magdalena Anders")."""
    return " ".join(sorted(fold(value).split()))


def compare_list(
    parsed: Mapping[str, Any],
    judges: Iterable[Mapping[str, Any]],
    history: Mapping[str, list[tuple[date, str]]] | None = None,
) -> dict:
    """
    Kto jeździł z innego miasta niż to, które ZPRP podaje dziś.

    `judges` - [{judge_id, name, home_city}] okręgu. Wynik per sędzia listy:
      status `changed` (proponowany wpis: miasto z listy do końca okresu listy),
      `same`, `declared` (zmiana już zapisana), `no_city` (ZPRP nie podaje miasta),
      `unknown` (nazwisko spoza okręgu).
    """
    index: dict[str, list[Mapping[str, Any]]] = {}
    for judge in judges:
        index.setdefault(name_key(judge.get("name")), []).append(judge)
    until = parsed.get("to")
    history = history or {}
    rows: list[dict] = []
    for name, data in (parsed.get("judges") or {}).items():
        homes: Counter = data["homes"]
        # Miasto z listy: ostatnie użyte (przy dwóch w jednym okresie liczy się późniejsze).
        listed = max(data["last"].items(), key=lambda item: (item[1], homes[item[0]]))[0] if data["last"] else ""
        found = index.get(name_key(name)) or []
        row = {
            "name": name,
            "list_city": listed,
            "list_cities": [city for city, _ in homes.most_common()],
            "trips": data["trips"],
            "judge_id": None,
            "current": None,
            "status": "unknown",
            "until": until.isoformat() if isinstance(until, date) else None,
        }
        if len(found) == 1:
            judge = found[0]
            current = _s(judge.get("home_city"))
            row.update(judge_id=str(judge.get("judge_id")), current=current or None, name=_s(judge.get("name")) or name)
            declared = home_for(history.get(str(judge.get("judge_id"))) or [], until) if isinstance(until, date) else None
            if declared and same_city(declared, listed):
                row["status"] = "declared"
            elif not current:
                row["status"] = "no_city"
            elif same_city(current, listed):
                row["status"] = "same"
            else:
                row["status"] = "changed"
        elif len(found) > 1:
            row["status"] = "ambiguous"
        rows.append(row)
    order = {"changed": 0, "no_city": 1, "ambiguous": 2, "unknown": 3, "declared": 4, "same": 5}
    rows.sort(key=lambda r: (order.get(r["status"], 9), fold(r["name"])))
    return {
        "number": parsed.get("number") or "",
        "from": parsed["from"].isoformat() if isinstance(parsed.get("from"), date) else None,
        "to": until.isoformat() if isinstance(until, date) else None,
        "rows": rows,
        "counts": dict(Counter(r["status"] for r in rows)),
    }
