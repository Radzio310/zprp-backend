"""
Nazwiska sedziow - reguly bez bazy i bez sieci.

Skad dziury: lista okregu potrafi nie miec sedziego, ktory ma obsady (dopisany
w ZPRP w trakcie sezonu, zarchiwizowany, spoza okregu), albo miec zamiast
nazwiska jego NUMER. W zestawieniu i na PDF stal wtedy goly „465".

Publiczne API meczu (`pokaz_mecze_szczegoly.php?Zawody=<id>`) podaje obsade
numerami RAZEM z nazwiskami i miastem:

    "NrSedzia_pierwszy": 465,
    "NrSedzia_pierwszy_nazwisko": "BLOCH Wojciech",
    "NrSedzia_pierwszy_miasto": "Nakło Śląskie",

wiec kazdy mecz sedziego mowi, jak on sie nazywa - bez zgadywania. Numer sedziego
jest w ZPRP globalny, wiec dziala to takze dla sedziow spoza okregu.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from app.settlement_engine import split_judge_name
from app.settlement_venues import _records, pretty_city

#: Gniazda obsady w odpowiedzi API (pola `NrSedzia_<gniazdo>`).
SLOTS = ("pierwszy", "drugi", "sekretarz", "czas", "delegat", "delegat2")

_EPOCH = datetime.min.replace(tzinfo=timezone.utc)


def _s(value: Any) -> str:
    return " ".join(str(value if value is not None else "").split())


def is_missing_name(name: Any, judge_id: Any = "") -> bool:
    """Brak nazwiska: pusto, sam numer albo numer sedziego zamiast nazwiska."""
    text = _s(name)
    return not text or text.isdigit() or text == _s(judge_id)


def given_first(name: Any) -> str:
    """
    „BLOCH Wojciech" (tak pisze API meczu) -> „Wojciech BLOCH" (tak pisze lista
    okregu), zeby na wydruku wszystkie nazwiska staly jednym zapisem.
    """
    text = _s(name)
    parts = split_judge_name(text)
    if not parts:
        return text
    surname, given = parts
    return f"{given} {surname}".strip()


def officials_from_record(record: Any) -> list[dict]:
    """Obsada jednego meczu: numer, nazwisko i miasto z kazdego zajetego gniazda."""
    if not isinstance(record, dict):
        return []
    out: list[dict] = []
    for slot in SLOTS:
        judge_id = _s(record.get(f"NrSedzia_{slot}"))
        name = _s(record.get(f"NrSedzia_{slot}_nazwisko"))
        # „0" to PUSTE GNIAZDO - ZPRP tak zapisuje zdjeta obsade.
        if not judge_id or judge_id == "0" or is_missing_name(name, judge_id):
            continue
        out.append(
            {
                "judge_id": judge_id,
                "name": name,
                "city": pretty_city(record.get(f"NrSedzia_{slot}_miasto")),
                "slot": slot,
            }
        )
    return out


def officials_from_payload(payload: Any) -> list[dict]:
    """Obsada z odpowiedzi API - w obu jej ksztaltach (`{"0": [...]}` i `[[...]]`)."""
    for record in _records(payload):
        found = officials_from_record(record)
        if found:
            return found
    return []


def match_id_of(match_key: Any) -> str:
    """„d:194144" -> „194144"; klucz bez numeru meczu ZPRP -> pusty napis."""
    tail = _s(match_key).split(":", 1)[-1]
    return tail if tail.isdigit() else ""


def _stamp(value: Optional[datetime]) -> datetime:
    if value is None:
        return _EPOCH
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def pick_unnamed(
    rows: Iterable[tuple[Any, Any, Optional[datetime]]],
    names: dict[str, str],
    *,
    only: Optional[set[str]] = None,
    per_judge: int = 3,
    limit: int = 60,
) -> dict[str, list[str]]:
    """
    Sedziowie bez nazwiska i mecze, o ktore warto zapytac - najnowsze pierwsze.

    `rows` to trojki (numer sedziego, klucz meczu, data). Kilka meczow na
    sedziego, bo obsada bywa zmieniona po fakcie i najnowszy mecz moze go juz
    nie miec.
    """
    by_judge: dict[str, list[tuple[datetime, str]]] = {}
    for judge_id, match_key, match_at in rows:
        key = _s(judge_id)
        if not key or (only is not None and key not in only):
            continue
        if not is_missing_name(names.get(key, ""), key):
            continue
        match_id = match_id_of(match_key)
        if match_id:
            by_judge.setdefault(key, []).append((_stamp(match_at), match_id))

    out: dict[str, list[str]] = {}
    for judge_id in sorted(by_judge):
        picked: list[str] = []
        for _, match_id in sorted(by_judge[judge_id], key=lambda item: item[0], reverse=True):
            if match_id not in picked:
                picked.append(match_id)
            if len(picked) >= per_judge:
                break
        out[judge_id] = picked
        if len(out) >= limit:
            break
    return out
