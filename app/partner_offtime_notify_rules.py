"""Reguły powiadomienia „Twój partner zgłosił niedyspozycję”.

Bez bazy i bez sieci - tylko porównanie dwóch list i tekst powiadomienia.

Aplikacja po KAŻDEJ zmianie w ZPRP odsyła na ``PUT /partner-offtimes/{id}``
całą swoją listę niedyspozycji. Serwer nie dostaje więc zdarzenia „dodano
wpis”, tylko stan przed i po. Nową niedyspozycją jest termin (data od-do),
którego w poprzedniej liście nie było. Zmiana samego opisu nie jest nowym
terminem - partner nie musi o niej wiedzieć. Przesunięcie dat już tak.

Daty przychodzą w trzech zapisach, bo listę wysyłają różne ekrany:
``2026-10-12`` (tabela ZPRP), ``12.10.2026`` (starsze widoki ZPRP) i pełne
ISO z ``Z`` (wpis zapisany lokalnie przed odczytem z ZPRP - lokalna północ
w Polsce to 22:00 albo 23:00 dnia POPRZEDNIEGO w UTC). Dlatego datę liczymy
w strefie Europe/Warsaw, a nie z pierwszych dziesięciu znaków napisu.
"""
from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from typing import Any, Iterable, List, Optional, Tuple
from zoneinfo import ZoneInfo

WARSAW = ZoneInfo("Europe/Warsaw")

#: Ile terminów wypisujemy w treści, zanim zostanie samo „+N”.
MAX_LISTED = 3
#: Opis z ZPRP bywa długi; w powiadomieniu wystarczy jego początek.
MAX_INFO = 80

Range = Tuple[date, date]


def parse_offtime_date(value: Any) -> Optional[date]:
    raw = str(value or "").strip()
    if not raw or raw.startswith("0000-00-00"):
        return None
    if "T" in raw:
        try:
            moment = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        if moment.tzinfo is None:
            return moment.date()
        return moment.astimezone(WARSAW).date()
    for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            pass
    return None


def offtime_entries(data_json: Any) -> Optional[List[dict]]:
    """Lista wpisów albo None, gdy to nie jest lista.

    None znaczy „nie znamy stanu wyjściowego”. Ekran ustawień potrafi wysłać
    ``{}``, gdy na telefonie nie ma jeszcze pliku niedyspozycji. Porównanie
    z takim stanem ogłosiłoby partnerowi WSZYSTKIE terminy jako nowe.
    """
    if isinstance(data_json, (str, bytes, bytearray)):
        try:
            data_json = json.loads(data_json)
        except ValueError:
            return None
    if not isinstance(data_json, list):
        return None
    return [item for item in data_json if isinstance(item, dict)]


def _range_of(item: dict) -> Optional[Range]:
    start = parse_offtime_date(item.get("dateFrom"))
    end = parse_offtime_date(item.get("dateTo")) or start
    if not start or not end:
        return None
    return (start, end) if start <= end else (end, start)


def new_future_offtimes(old_data: Any, new_data: Any, today: date) -> List[dict]:
    """Wpisy z nowej listy, których terminu nie było w starej.

    Pomija terminy już zakończone i powtórzenia tego samego terminu.
    Zwraca ``[]``, gdy którakolwiek lista nie jest listą.
    """
    old_items = offtime_entries(old_data)
    new_items = offtime_entries(new_data)
    if old_items is None or new_items is None:
        return []
    known = {r for r in (_range_of(item) for item in old_items) if r}
    fresh: List[dict] = []
    seen = set()
    for item in new_items:
        span = _range_of(item)
        if not span or span in known or span in seen:
            continue
        if span[1] < today:
            continue
        seen.add(span)
        fresh.append({"from": span[0], "to": span[1], "info": str(item.get("info") or "").strip()})
    fresh.sort(key=lambda entry: (entry["from"], entry["to"]))
    return fresh


def _format_range(start: date, end: date) -> str:
    if start == end:
        return start.strftime("%d.%m.%Y")
    if start.year == end.year:
        return f"{start.strftime('%d.%m')}–{end.strftime('%d.%m.%Y')}"
    return f"{start.strftime('%d.%m.%Y')}–{end.strftime('%d.%m.%Y')}"


def _clip(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def notification_text(full_name: str, entries: Iterable[dict]) -> Tuple[str, str]:
    items = list(entries)
    name = _clip(str(full_name or "").strip(), 60) or "Partner"
    title = (
        "Twój partner zgłosił niedyspozycję"
        if len(items) == 1
        else "Twój partner zgłosił niedyspozycje"
    )
    ranges = [_format_range(e["from"], e["to"]) for e in items[:MAX_LISTED]]
    body = f"{name}: {', '.join(ranges)}"
    if len(items) > MAX_LISTED:
        body += f" (+{len(items) - MAX_LISTED})"
    if len(items) == 1 and items[0]["info"]:
        body += f" · {_clip(items[0]['info'], MAX_INFO)}"
    return title, body


def event_key(judge_id: str, entries: Iterable[dict]) -> str:
    """Stały identyfikator zgłoszenia - osobny kafelek na każde zgłoszenie.

    Ten sam zestaw terminów wysłany drugi raz (ponowienie kolejki w aplikacji)
    zastępuje swoje powiadomienie zamiast dokładać kopię.
    """
    seed = "|".join(
        [str(judge_id)]
        + [f"{e['from'].isoformat()}/{e['to'].isoformat()}" for e in entries]
    )
    return "poff-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]
