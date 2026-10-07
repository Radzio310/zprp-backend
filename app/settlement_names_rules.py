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


def merge_names(
    seen: dict[str, str],
    zprp_list: dict[str, str],
    panel: dict[str, str],
) -> tuple[dict[str, str], list[dict]]:
    """
    Nazwisko pod numerem sędziego z trzech źródeł - i konflikty między nimi.

    `seen` - obsady meczów (numer i nazwisko z jednego gniazda), `zprp_list` -
    lista „Sędziowie i Delegaci" z ZPRP, `panel` - lista prowadzona ręcznie
    w panelu okręgu.

    Do 07.10.2026 panel wygrywał ZAWSZE. Zgłoszenie Wojtka Kaszni: był na
    liście dwa razy, a pod jednym z numerów stały cudze mecze - ręczny wpis
    w panelu przypisał jego nazwisko do numeru innej osoby, a mecze idą po
    NUMERZE z obsady ZPRP. Teraz panel wygrywa tylko wtedy, gdy to ta sama
    osoba co w ZPRP (inny zapis: „Jan Nowak" / „NOWAK Jan"); gdy ZPRP pod tym
    numerem zna KOGO INNEGO, wygrywa ZPRP, a rozbieżność wraca jako konflikt
    do pokazania komisji.
    """
    from app.match_bombs_rules import same_person

    zprp: dict[str, str] = {}
    for source in (seen, zprp_list):
        for judge_id, name in source.items():
            key = _s(judge_id)
            if key and not is_missing_name(name, key):
                zprp[key] = _s(name)
    out = dict(zprp)
    conflicts: list[dict] = []
    for judge_id, name in panel.items():
        key = _s(judge_id)
        if not key or is_missing_name(name, key):
            continue
        official = zprp.get(key)
        if official and not same_person(official, name):
            conflicts.append({"judge_id": key, "panel_name": _s(name), "zprp_name": official})
            continue
        out[key] = _s(name)
    conflicts.sort(key=lambda item: item["judge_id"])
    return out, conflicts


def duplicate_names(names: dict[str, str], judge_ids: Iterable[str]) -> list[dict]:
    """
    To samo nazwisko pod kilkoma numerami wśród `judge_ids` (np. sędziowie
    okresu) - [{name, judge_ids}]. Zwykle pomyłka w numerze albo dwie
    kartoteki tej samej osoby w ZPRP; komisja musi to zobaczyć.
    """
    from app.match_bombs_rules import same_person

    ids = sorted({_s(j) for j in judge_ids if _s(j)})
    groups: list[list[str]] = []
    for judge_id in ids:
        name = names.get(judge_id, "")
        if is_missing_name(name, judge_id):
            continue
        for group in groups:
            if same_person(names.get(group[0], ""), name):
                group.append(judge_id)
                break
        else:
            groups.append([judge_id])
    return [
        {"name": names.get(group[0], ""), "judge_ids": group}
        for group in groups
        if len(group) > 1
    ]

