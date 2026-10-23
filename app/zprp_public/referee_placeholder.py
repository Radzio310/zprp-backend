"""Brak obsady w terminarzu ZPRP - placeholder zamiast sędziego.

ZPRP nie zostawia pustej roli: w nieobsadzone miejsce wstawia „osobę" o
nazwisku „--- ---" (bywa „-- --", „---", kropka, „brak", „NN") - często z
WSPÓLNYM numerem dla tysięcy meczów. Portal brał ją za prawdziwego sędziego:
profil „--- ---" z 4287 meczami w 334 rozgrywkach, „-- -- 10 meczów razem" w
parze, wyszukiwarka, Moje.

Decyzja właściciela (23.10.2026, ostateczna): „--- ---" to PUSTE POLE - wszędzie
znika. Taki slot nie jest sędzią ani partnerem, nie liczy się nigdzie, nie ma
profilu ani linku i nie zostawia po sobie napisu („brak obsady", wolne miejsce).

- `is_placeholder_referee(id, name)` - jedno źródło prawdy (czyste, bez bazy).
- `clean_official(id, name)` - (id, nazwisko) do zapisu: placeholder -> (None, None).
  Synchronizacja woła to w `_match_values`, więc nowe dane przychodzą już czyste.
- `cleanup(engine)` - jednorazowe (idempotentne) sprzątanie istniejących wierszy:
  partiami, w wątku w tle (`cleanup_in_background`), start serwera nie czeka.
- Numery-placeholdery (wspólne dla wielu meczów, zawsze bez nazwiska) zostają
  zapamiętane w `zprp_public_sync_state` (klucz `STATE_KEY`): stary link
  `/sedziowie/<numer>` po sprzątaniu nie ma już meczów, a ma powiedzieć „to nie
  sędzia", nie „nie znamy".

Zastrzeżenie: w ZPRP bywa też PRAWDZIWY sędzia, którego nazwisko terminarz
ukrywa za „--- ---" (np. numer 1107 w Śląskiem). Zgodnie z decyzją także on jest
tu pustym polem (BAZA_web nie dopytuje już o jego nazwisko); numer z `source_json`
zostaje, gdyby trzeba to było odwrócić.
Do rejestru placeholderów trafia jednak tylko numer, który NIE może być jedną
osobą (te same godziny w kilku meczach naraz albo bardzo wiele meczów), żeby
profil prawdziwej osoby nie mówił „to nie jest sędzia".
"""

from __future__ import annotations

import logging
import re
import threading
import time
import unicodedata
from typing import Any, Iterable, Optional

log = logging.getLogger(__name__)

#: Kolumny obsady meczu (id, nazwisko) w `zprp_public_matches`.
REFEREE_SLOTS = (("referee_1_id", "referee_1_name"), ("referee_2_id", "referee_2_name"))
OFFICIAL_SLOTS = REFEREE_SLOTS + (
    ("delegate_1_id", "delegate_1_name"),
    ("delegate_2_id", "delegate_2_name"),
    ("secretary_id", "secretary_name"),
    ("timekeeper_id", "timekeeper_name"),
)

STATE_KEY = "referee_placeholders_v1"
ERROR_CODE = "REFEREE_PLACEHOLDER"
ERROR_MESSAGE = "To nie jest sędzia - tak ZPRP oznacza brak obsady"

# Same myślniki (każdego rodzaju), kropki, podkreślenia, kropki dekoracyjne, gwiazdki,
# ukośniki i znaki zapytania - z odstępami albo bez.
_MARKS_RE = re.compile(r"^[\s\-‐-―−_.,·•*/?]*$")
# Słowa, którymi ręcznie wpisuje się brak osoby (porównanie bez kropek i odstępów).
_WORDS = ("brak", "brak obsady", "brak sedziego", "nn", "n.n.", "nieobsadzony", "nieobsadzona", "nieobsadzone")
# Znacznik na końcu nazwiska po długim odstępie („KOWALCZYK Jan          O").
_TAIL_RE = re.compile(r"\s{2,}\S\s*$")
# Numer, który nie jest numerem: same zera, same znaki z `_MARKS_RE`.
_ZERO_RE = re.compile(r"^0+$")

# Numery-placeholdery poznane z danych (sprzątanie + stan w bazie). Czytane bez blokady:
# podmiana całego zbioru jest atomowa.
_known_ids: frozenset[str] = frozenset()

# Rejestr: numer bez żadnego nazwiska, który w tylu różnych godzinach stał w dwóch
# meczach naraz, nie jest jedną osobą. Albo ma więcej meczów niż kariera sędziego.
CLASH_SLOTS = 3
SHARED_MATCHES = 1500


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _fold(value: str) -> str:
    s = unicodedata.normalize("NFKD", value.lower())
    s = "".join(ch for ch in s if not unicodedata.combining(ch)).replace("ł", "l")
    return re.sub(r"[\s.]+", "", s)


_FOLDED_WORDS = frozenset(_fold(w) for w in _WORDS)


def is_blank_name(name: Any) -> bool:
    """Nazwisko, którego w istocie nie ma: puste albo placeholder."""
    s = _TAIL_RE.sub("", _text(name)).strip()
    return not s or bool(_MARKS_RE.match(s)) or _fold(s) in _FOLDED_WORDS


def is_placeholder_name(name: Any) -> bool:
    """Wpisany znacznik braku obsady („--- ---", „brak", „NN") - nie samo puste pole."""
    return bool(_text(name)) and is_blank_name(name)


def is_placeholder_id(referee_id: Any) -> bool:
    """Numer, który nie wskazuje osoby: pusty, same zera, same kreski albo znany placeholder."""
    s = _text(referee_id)
    return not s or bool(_ZERO_RE.match(s)) or bool(_MARKS_RE.match(s)) or s in _known_ids


def is_placeholder_referee(referee_id: Any, name: Any) -> bool:
    """Czy slot obsady to BRAK OBSADY.

    Tak, gdy nazwisko jest znacznikiem (niezależnie od numeru - ZPRP daje placeholderowi
    wspólny numer), albo gdy nazwiska nie ma, a numer nic nie wskazuje. Pusty numer z
    prawdziwym nazwiskiem albo prawdziwy numer bez nazwiska w terminarzu - to sędzia."""
    if is_placeholder_name(name):
        return True
    return is_blank_name(name) and is_placeholder_id(referee_id)


def clean_official(referee_id: Any, name: Any) -> tuple[Optional[str], Optional[str]]:
    """(numer, nazwisko) do zapisu: brak obsady -> (None, None); śmieciowy numer -> None."""
    if is_placeholder_referee(referee_id, name):
        return None, None
    rid = None if is_placeholder_id(referee_id) else _text(referee_id)
    return rid, (_text(name) or None)


def clean_match_officials(values: dict[str, Any], slots: Iterable[tuple[str, str]] = OFFICIAL_SLOTS) -> dict[str, Any]:
    """Czyści sloty obsady w słowniku meczu (w miejscu, zwraca ten sam słownik).

    Działa tylko na kluczach, które słownik ma - karta bez obsady zostaje bez obsady."""
    for idc, nmc in slots:
        if idc in values or nmc in values:
            rid, name = clean_official(values.get(idc), values.get(nmc))
            if idc in values:
                values[idc] = rid
            if nmc in values:
                values[nmc] = name
    return values


_OFFICIAL_ROLES = (("referee_1", "Sędzia"), ("referee_2", "Sędzia"), ("delegate_1", "Delegat"),
                   ("delegate_2", "Delegat"), ("secretary", "Sekretarz"), ("timekeeper", "Czas"))


def match_officials(match: dict[str, Any]) -> list[dict[str, Any]]:
    """Obsada strony meczu: tylko wyznaczone osoby, w stałej kolejności ról.

    Placeholder („--- ---") jest pustym polem, więc znika bez śladu - bez wolnego
    miejsca i bez napisu (decyzja właściciela 23.10.2026)."""
    m = clean_match_officials(dict(match))
    return [{"role": label, "id": m.get(f"{col}_id"), "name": m.get(f"{col}_name")}
            for col, label in _OFFICIAL_ROLES if m.get(f"{col}_name")]


def known_ids() -> frozenset[str]:
    return _known_ids


def remember_ids(ids: Iterable[Any]) -> None:
    global _known_ids
    new = {_text(i) for i in ids if _text(i)}
    if not new.issubset(_known_ids):
        _known_ids = frozenset(_known_ids | new)


def forget_ids() -> None:
    """Dla testów."""
    global _known_ids
    _known_ids = frozenset()


def ids_from_state(value: Any) -> set[str]:
    if isinstance(value, str):
        import json

        try:
            value = json.loads(value)
        except ValueError:
            return set()
    ids = value.get("ids") if isinstance(value, dict) else None
    return {_text(i) for i in ids or [] if _text(i)}


def candidate_ids(pairs: Iterable[tuple[Any, Any, int]]) -> dict[str, int]:
    """Numery stojące WYŁĄCZNIE przy znaczniku braku obsady (albo bez nazwiska).

    `pairs` = (numer, nazwisko, liczba meczów) ze wszystkich slotów. Numer, który choć
    raz ma prawdziwe nazwisko, jest osobą i nie wchodzi tu nigdy."""
    marked: dict[str, int] = {}
    real: set[str] = set()
    for rid, name, n in pairs:
        r = _text(rid)
        if not r:
            continue
        if is_placeholder_name(name):
            marked[r] = marked.get(r, 0) + int(n or 0)
        elif not is_blank_name(name):
            real.add(r)
    return {r: n for r, n in marked.items() if r not in real}


# ---------------------------------------------------------------------------
# Sprzątanie istniejących wierszy (wątek w tle przy starcie)
# ---------------------------------------------------------------------------


def _tables():
    from app.db import zprp_public_matches, zprp_public_sync_state

    return zprp_public_matches, zprp_public_sync_state


def _clash_slots(conn, M, referee_id: str) -> int:
    """W ilu różnych godzinach ten numer stał w więcej niż jednym meczu naraz."""
    from sqlalchemy import func, or_, select

    q = (
        select(M.c.scheduled_at)
        .where(or_(M.c.referee_1_id == referee_id, M.c.referee_2_id == referee_id), M.c.scheduled_at.isnot(None))
        .group_by(M.c.scheduled_at)
        .having(func.count() > 1)
    )
    return len(conn.execute(q).fetchall())


def _load_state(conn, S) -> set[str]:
    from sqlalchemy import select

    row = conn.execute(select(S.c.value_json).where(S.c.key == STATE_KEY)).first()
    return ids_from_state(row[0]) if row else set()


def _save_state(conn, S, ids: set[str]) -> None:
    from sqlalchemy import select

    value = {"ids": sorted(ids)}
    if conn.execute(select(S.c.key).where(S.c.key == STATE_KEY)).first():
        conn.execute(S.update().where(S.c.key == STATE_KEY).values(value_json=value))
    else:
        conn.execute(S.insert().values(key=STATE_KEY, value_json=value))


def _null_slot(conn, M, idc: str, nmc: str, rid: Any, name: Any, *, id_only: bool, batch: int) -> int:
    """UPDATE partiami po `batch` meczów (ten sam warunek działa w Postgresie i SQLite)."""
    from sqlalchemy import and_, select

    def eq(col, value):
        return col.is_(None) if value is None else col == value

    cond = and_(eq(M.c[idc], rid), eq(M.c[nmc], name))
    values = {idc: None} if id_only else {idc: None, nmc: None}
    total = 0
    while True:
        ids = select(M.c.match_id).where(cond).limit(batch).scalar_subquery()
        done = conn.execute(M.update().where(M.c.match_id.in_(ids)).values(**values)).rowcount or 0
        conn.commit()
        total += done
        if done < batch:
            return total
        time.sleep(0.02)  # oddech dla bazy między partiami


def cleanup(engine, *, batch: int = 2000, tables=None) -> dict[str, Any]:
    """Zeruje placeholdery obsady w istniejących meczach. Idempotentne: drugi przebieg
    nie ma czego dotknąć. Zwraca {"updated": n, "placeholder_ids": [...]}."""
    from sqlalchemy import func, select

    M, S = tables or _tables()
    updated = 0
    with engine.connect() as conn:
        groups: dict[tuple[str, str], list[tuple[Any, Any, int]]] = {}
        for idc, nmc in OFFICIAL_SLOTS:
            groups[(idc, nmc)] = [
                (r[0], r[1], int(r[2]))
                for r in conn.execute(select(M.c[idc], M.c[nmc], func.count()).group_by(M.c[idc], M.c[nmc])).fetchall()
            ]
        conn.commit()

        # Rejestr: numery wyłącznie przy znaczniku, które nie mogą być jedną osobą.
        stored = _load_state(conn, S)
        cands = candidate_ids(p for pairs in groups.values() for p in pairs)
        shared = {rid for rid, n in cands.items()
                  if _ZERO_RE.match(rid) or n >= SHARED_MATCHES or _clash_slots(conn, M, rid) >= CLASH_SLOTS}
        conn.commit()
        if not (shared | stored).issubset(stored):
            _save_state(conn, S, stored | shared)
            conn.commit()
        remember_ids(stored | shared)

        for (idc, nmc), pairs in groups.items():
            for rid, name, _n in pairs:
                if _text(rid) == "" and _text(name) == "":
                    continue  # puste pole zostaje puste - czytelnicy już je pomijają
                if is_placeholder_referee(rid, name):
                    updated += _null_slot(conn, M, idc, nmc, rid, name, id_only=False, batch=batch)
                elif _text(rid) and is_placeholder_id(rid):
                    updated += _null_slot(conn, M, idc, nmc, rid, name, id_only=True, batch=batch)
    return {"updated": updated, "placeholder_ids": sorted(_known_ids)}


def _run(engine) -> None:
    try:
        started = time.monotonic()
        out = cleanup(engine)
        if out["updated"]:
            log.info("[zprp_public] brak obsady: wyzerowano %s slotów w %.1fs (numery: %s)",
                     out["updated"], time.monotonic() - started, ", ".join(out["placeholder_ids"]) or "-")
    except Exception as exc:  # noqa: BLE001 - pomocnicze, start aplikacji ma przejść
        log.warning("[zprp_public] sprzątanie braku obsady pominięte: %r", exc)


def cleanup_in_background(engine) -> None:
    """Start serwera (app/db.py): sprzątanie w osobnym wątku, nic nie czeka."""
    if engine.dialect.name != "postgresql":
        return
    threading.Thread(target=_run, args=(engine,), name="referee-placeholders", daemon=True).start()


async def load_known_ids() -> frozenset[str]:
    """Rejestr z bazy (inny proces mógł go uzupełnić). Błąd = to, co już wiemy."""
    try:
        from sqlalchemy import select

        from app.db import database, zprp_public_sync_state as S

        row = await database.fetch_one(select(S.c.value_json).where(S.c.key == STATE_KEY))
        if row:
            remember_ids(ids_from_state(row["value_json"]))
    except Exception:  # noqa: BLE001
        pass
    return _known_ids
