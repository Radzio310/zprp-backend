"""
Obsada 2.0 (24.09.2026) - reguły wspólnego szkicu kolejki, dziennika zapisów
do ZPRP, par mentorskich i nagłówka sędziego.

MODUŁ-LIŚĆ: bez bazy i sieci, żeby każda reguła chodziła w teście. Trasy
(`app/province_assignment_board.py`) i zapis do ZPRP (`app/zprp/assignments.py`)
tylko je wołają.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Iterable, Mapping, Optional

from app.match_market_rules import names_match

#: Limit szkicu kolejki: pozycji i bajtów zapisanego JSON-a.
DRAFT_MAX_ITEMS = 2000
DRAFT_MAX_BYTES = 1_000_000

CHANGE_KINDS = frozenset({"slot", "hall"})

#: Gniazdo w każdym z trzech zapisów, jakie krążą po systemie: moduł obsadowy
#: („pierwszy"), migawka i formularz ZPRP („sedzia1") i pole formularza
#: („NrSedzia_pierwszy"). Dziennik i `expect` mówią językiem MODUŁU.
SLOT_ALIASES: dict[str, str] = {
    "pierwszy": "pierwszy",
    "drugi": "drugi",
    "sekretarz": "sekretarz",
    "czas": "czas",
    "delegat": "delegat",
    "delegat2": "delegat2",
    "sedzia1": "pierwszy",
    "sedzia2": "drugi",
}
SELECT_ALIASES: dict[str, str] = {
    "nrsedzia_pierwszy": "pierwszy",
    "nrsedzia_drugi": "drugi",
    "nrsedzia_sekretarz": "sekretarz",
    "nrsedzia_czas": "czas",
    "nrsedzia_delegat": "delegat",
    "nrsedzia_delegat2": "delegat2",
}


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def normalize_slot(value: Any) -> str:
    """Gniazdo w słowniku modułu albo pusty napis, gdy to nie gniazdo."""
    text = _s(value).lower()
    return SELECT_ALIASES.get(text) or SLOT_ALIASES.get(text, "")


# ───────────────────────────── nagłówek sędziego ─────────────────────────────


def _given(part: str) -> str:
    return part[:1].upper() + part[1:].lower()


def display_name(name: Any) -> str:
    """
    „NAZWISKO Imię" - tak, jak podpisuje ludzi formularz ZPRP.

    Człony pisane w całości wielkimi literami to nazwisko (także dwuczłonowe).
    Bez takiego członu przyjmujemy zapis listy związku „Nazwisko Imię" -
    pierwszy człon to nazwisko.
    """
    parts = [part for part in _s(name).split() if part]
    if not parts:
        return ""
    caps = [part for part in parts if len(part) > 1 and part.isupper()]
    if caps and len(caps) < len(parts):
        rest = [part for part in parts if part not in caps]
        return " ".join([*caps, *(_given(part) for part in rest)])
    if len(parts) == 1:
        return parts[0].upper()
    return " ".join([parts[0].upper(), *(_given(part) for part in parts[1:])])


# ─────────────────────────────── pary mentorskie ───────────────────────────────


def clean_pair_ids(raw: Any) -> list[str]:
    """Dwa różne numery pary sędziowskiej, posortowane. Inaczej ValueError."""
    ids = [_s(item) for item in (raw or []) if _s(item)]
    unique = sorted(set(ids))
    if len(unique) != 2 or len(ids) != 2:
        raise ValueError("Para sędziowska to dokładnie dwóch różnych sędziów")
    return unique


def clean_mentor_ids(raw: Any, pair_ids: Iterable[str]) -> list[str]:
    """
    Mentorzy pary: pusto (usuń) albo jeden-dwóch różnych sędziów spoza pary.

    Para mentorska to zwykle dwoje ludzi, ale zdarza się, że opiekę trzyma
    jedna osoba - tego nie blokujemy.
    """
    ids: list[str] = []
    for item in raw or []:
        text = _s(item)
        if text and text not in ids:
            ids.append(text)
    if len(ids) > 2:
        raise ValueError("Para mentorska to najwyżej dwóch sędziów")
    if set(ids) & {_s(item) for item in pair_ids}:
        raise ValueError("Mentor nie może być w parze, którą prowadzi")
    return sorted(ids)


# ────────────────────────────── szkic kolejki ──────────────────────────────


def dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def load_list(value: Any) -> list:
    """Kolumna JSON jako lista - także wtedy, gdy wróciła napisem albo pusta."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        if not value.strip():
            return []
        try:
            value = json.loads(value)
        except ValueError:
            return []
    return list(value) if isinstance(value, (list, tuple)) else []


def clean_draft_changes(raw: Any) -> list[dict]:
    """
    Zmiany kolejki gotowe do zapisu - serwer ich nie interpretuje, tylko pilnuje
    kształtu i limitów, żeby jeden zły klient nie zapchał wspólnego szkicu.

    Każda pozycja to obiekt z `id`, `match_id` i `kind` („slot" albo „hall");
    reszta pól przechodzi bez zmian. Odmowa mówi, co jest nie tak.
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("Szkic kolejki musi być listą zmian")
    if len(raw) > DRAFT_MAX_ITEMS:
        raise ValueError(f"Za dużo zmian w kolejce - limit to {DRAFT_MAX_ITEMS}")
    out: list[dict] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Zmiana nr {index} nie jest obiektem")
        if not _s(item.get("id")):
            raise ValueError(f"Zmiana nr {index} nie ma identyfikatora")
        if not _s(item.get("match_id")):
            raise ValueError(f"Zmiana nr {index} nie wskazuje meczu")
        kind = _s(item.get("kind"))
        if kind not in CHANGE_KINDS:
            raise ValueError(f"Zmiana nr {index}: nieznany rodzaj '{kind}' (slot albo hall)")
        if kind == "slot" and not normalize_slot(item.get("slot")):
            raise ValueError(f"Zmiana nr {index}: nieznane gniazdo '{_s(item.get('slot'))}'")
        out.append(item)
    if len(dump(out).encode("utf-8")) > DRAFT_MAX_BYTES:
        raise ValueError("Szkic kolejki jest za duży - limit to 1 MB")
    return out


def draft_conflict(base_rev: Any, current_rev: Any) -> bool:
    """Zapis na starej wersji szkicu - ktoś inny zapisał w międzyczasie."""
    try:
        return int(base_rev or 0) != int(current_rev or 0)
    except (TypeError, ValueError):
        return True


# ─────────────────────────── expect i dziennik ZPRP ───────────────────────────


def same_person(a: Any, b: Any) -> bool:
    """Ta sama osoba - albo oba gniazda puste. Pusty z niepustym to różnica."""
    left, right = _s(a), _s(b)
    if not left and not right:
        return True
    if not left or not right:
        return False
    if " ".join(left.lower().split()) == " ".join(right.lower().split()):
        return True
    return names_match(left, right)


def expect_conflicts(
    expect: Optional[Mapping[str, Any]],
    actual: Mapping[str, Any],
    *,
    same: Callable[[Any, Any], bool] = same_person,
) -> dict[str, dict[str, str]]:
    """
    Gniazda, w których ZPRP ma dziś kogoś innego, niż widział użytkownik.

    `expect` to {gniazdo: „NAZWISKO Imię" | ""} w dowolnym zapisie gniazda
    (moduł, formularz, pole), `actual` - {gniazdo modułu: nazwisko} z formularza
    wczytanego tuż przed zapisem. Klucz wyniku to gniazdo TAK, JAK PRZYSZŁO,
    żeby klient trafił w swoje. Nieznane gniazdo w `expect` to błąd klienta,
    a nie „zgoda" - wraca jako konflikt z pustym `actual`, żeby nie zapisać
    czegoś, czego nikt nie sprawdził.
    """
    out: dict[str, dict[str, str]] = {}
    for raw_slot, wanted in (expect or {}).items():
        slot = normalize_slot(raw_slot)
        expected = _s(wanted)
        if not slot:
            out[_s(raw_slot)] = {"expected": expected, "actual": ""}
            continue
        current = _s(actual.get(slot))
        if not same(expected, current):
            out[_s(raw_slot)] = {"expected": expected, "actual": current}
    return out


def journal_slot_rows(
    sent: Iterable[str],
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    ids_after: Optional[Mapping[str, Any]] = None,
    ids_before: Optional[Mapping[str, Any]] = None,
    same: Callable[[Any, Any], bool] = same_person,
) -> list[dict[str, Optional[str]]]:
    """
    Wiersze dziennika dla jednego udanego zapisu obsady.

    Tylko gniazda WYSŁANE i tylko te, w których osoba się zmieniła - gniazdo
    wysłane bez zmiany to nie zdarzenie. `before` i `after` to nazwiska
    z formularza przed i po zapisie (słownik modułu), `ids_*` - numery
    sędziów, gdy je znamy (panel podaje numer nowego, numer poprzedniego
    rozpoznajemy po nazwisku z listy okręgu).
    """
    rows: list[dict[str, Optional[str]]] = []
    seen: set[str] = set()
    for raw in sent:
        slot = normalize_slot(raw)
        if not slot or slot in seen:
            continue
        seen.add(slot)
        was, now = _s(before.get(slot)), _s(after.get(slot))
        if same(was, now):
            continue
        rows.append(
            {
                "kind": "slot",
                "slot": slot,
                "before_id": _s((ids_before or {}).get(slot)) or None,
                "before_name": was or None,
                "after_id": (_s((ids_after or {}).get(slot)) or None) if now else None,
                "after_name": now or None,
            }
        )
    return rows


def reverted_for(reverted_of: Any, slot: str) -> Optional[int]:
    """
    Który wpis dziennika cofa ten wiersz: jedna liczba dla całego zapisu albo
    słownik {gniazdo: numer wpisu}.
    """
    value = reverted_of
    if isinstance(reverted_of, Mapping):
        value = None
        for key, item in reverted_of.items():
            if normalize_slot(key) == slot or _s(key) == slot:
                value = item
                break
    text = _s(value)
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def group_batches(rows: Iterable[Mapping[str, Any]]) -> list[dict]:
    """
    Wiersze dziennika (od najnowszego) zebrane w partie „Zapisz w ZPRP".

    Wiersz to {"batch_id", "actor", "at", "item"}. Partia bierze autora i czas
    z NAJNOWSZEGO wiersza, a pozycje trzyma w kolejności zapisu (od
    najstarszej) - tak czyta się ją jak listę kroków.
    """
    batches: dict[str, dict] = {}
    order: list[str] = []
    for row in rows:
        batch_id = _s(row.get("batch_id"))
        if batch_id not in batches:
            batches[batch_id] = {
                "batch_id": batch_id,
                "actor": _s(row.get("actor")),
                "at": row.get("at"),
                "items": [],
            }
            order.append(batch_id)
        batches[batch_id]["items"].append(dict(row.get("item") or {}))
    out = []
    for batch_id in order:
        batch = batches[batch_id]
        batch["items"].sort(key=lambda item: int(item.get("id") or 0))
        out.append(batch)
    return out


def match_label(state: Mapping[str, Any], code: Any = "") -> str:
    """„S/JmM/12 SPR Gliwice - MKS Zabrze" - podpis meczu w historii zapisów."""
    number = _s(state.get("RozgrywkiCode")) or _s(code)
    host = _s(state.get("ID_zespoly_gosp_ZespolNazwa"))
    guest = _s(state.get("ID_zespoly_gosc_ZespolNazwa"))
    teams = " - ".join(item for item in (host, guest) if item)
    return " ".join(item for item in (number, teams) if item)
