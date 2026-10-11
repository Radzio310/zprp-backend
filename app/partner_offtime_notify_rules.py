"""Reguły powiadomienia „Twój partner zgłosił / odwołał niedyspozycję”.

Bez bazy i bez sieci - tylko porównanie dwóch list i tekst powiadomienia.

Aplikacja po KAŻDEJ zmianie w ZPRP odsyła na ``PUT /partner-offtimes/{id}``
całą swoją listę niedyspozycji. Serwer nie dostaje więc zdarzenia „dodano
wpis”, tylko stan przed i po. Nową niedyspozycją jest termin (data od-do),
którego w poprzedniej liście nie było; odwołaną - termin, który z niej
zniknął. Zmiana samego opisu nie zmienia terminu - partner nie musi o niej
wiedzieć. Przesunięcie dat już tak (jedno powiadomienie „zmienił”).

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
from typing import Any, Iterable, List, NamedTuple, Optional, Tuple
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


class OfftimeChange(NamedTuple):
    added: List[dict]
    removed: List[dict]

    def __bool__(self) -> bool:
        return bool(self.added or self.removed)


def _future_spans(items: List[dict], today: date) -> "dict[Range, dict]":
    spans: "dict[Range, dict]" = {}
    for item in items:
        span = _range_of(item)
        if not span or span[1] < today or span in spans:
            continue
        spans[span] = {"from": span[0], "to": span[1], "info": str(item.get("info") or "").strip()}
    return spans


def _sorted(entries: Iterable[dict]) -> List[dict]:
    return sorted(entries, key=lambda entry: (entry["from"], entry["to"]))


def diff_future_offtimes(old_data: Any, new_data: Any, today: date) -> OfftimeChange:
    """Terminy dodane i odwołane między starą a nową listą.

    Liczą się tylko terminy jeszcze niezakończone; powtórzenia tego samego
    terminu liczą się raz. Gdy którakolwiek lista nie jest listą - pusto.

    Pusta nowa lista przy kilku odwołanych naraz NIE jest odwołaniem.
    Aplikacja usuwa terminy pojedynczo i po każdym odsyła listę, a pustą
    listę daje też nieudany odczyt z ZPRP (wygasła sesja zwraca stronę bez
    tabeli). Lepiej przemilczeć rzadkie prawdziwe „usuń wszystko” niż
    powiedzieć partnerowi, że ktoś jest wolny, gdy nie jest.
    """
    old_items = offtime_entries(old_data)
    new_items = offtime_entries(new_data)
    if old_items is None or new_items is None:
        return OfftimeChange([], [])
    before = _future_spans(old_items, today)
    after = _future_spans(new_items, today)
    added = _sorted(entry for span, entry in after.items() if span not in before)
    removed = _sorted(entry for span, entry in before.items() if span not in after)
    if not new_items and len(removed) > 1:
        removed = []
    return OfftimeChange(added, removed)


def _format_range(start: date, end: date) -> str:
    if start == end:
        return start.strftime("%d.%m.%Y")
    if start.year == end.year:
        return f"{start.strftime('%d.%m')}–{end.strftime('%d.%m.%Y')}"
    return f"{start.strftime('%d.%m.%Y')}–{end.strftime('%d.%m.%Y')}"


def _clip(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _ranges(entries: List[dict]) -> str:
    text = ", ".join(_format_range(e["from"], e["to"]) for e in entries[:MAX_LISTED])
    if len(entries) > MAX_LISTED:
        text += f" (+{len(entries) - MAX_LISTED})"
    return text


def _with_info(body: str, entry: dict) -> str:
    return f"{body} · {_clip(entry['info'], MAX_INFO)}" if entry["info"] else body


def notification_text(full_name: str, change: OfftimeChange) -> Tuple[str, str]:
    added, removed = change.added, change.removed
    name = _clip(str(full_name or "").strip(), 60) or "Partner"
    if added and not removed:
        title = (
            "Twój partner zgłosił niedyspozycję"
            if len(added) == 1
            else "Twój partner zgłosił niedyspozycje"
        )
        body = f"{name}: {_ranges(added)}"
        return title, _with_info(body, added[0]) if len(added) == 1 else body
    if removed and not added:
        if len(removed) == 1:
            return (
                "Twój partner odwołał niedyspozycję",
                f"{name}: {_ranges(removed)} – termin odwołany",
            )
        return (
            "Twój partner odwołał niedyspozycje",
            f"{name}: {_ranges(removed)} – terminy odwołane",
        )
    if len(added) == 1 and len(removed) == 1:
        # Edycja dat w aplikacji: jeden termin znika, jeden przybywa.
        body = f"{name}: {_ranges(removed)} → {_ranges(added)}"
        return "Twój partner zmienił niedyspozycję", _with_info(body, added[0])
    return (
        "Twój partner zmienił niedyspozycje",
        f"{name}: nowe {_ranges(added)}; odwołane {_ranges(removed)}",
    )


def event_key(judge_id: str, change: OfftimeChange) -> str:
    """Stały identyfikator zgłoszenia - osobny kafelek na każde zgłoszenie.

    Ta sama zmiana wysłana drugi raz (ponowienie kolejki w aplikacji)
    zastępuje swoje powiadomienie zamiast dokładać kopię.
    """
    parts = [str(judge_id)]
    for sign, entries in (("+", change.added), ("-", change.removed)):
        parts += [f"{sign}{e['from'].isoformat()}/{e['to'].isoformat()}" for e in entries]
    return "poff-" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:24]
