"""ProEl jako zapas godziny i wyniku na kartach meczów (jedno miejsce dla wszystkich list).

Wołane z `enrich.enrich_matches` - przed wyliczeniem zwycięzcy - więc terminarz,
„Dziś", listy drużyn i klubów, wyszukiwarka i ekran meczu widzą to samo.
Reguły w `proel_card_rules` (bez bazy). Tylko odczyt; nigdy nie psuje karty:
każdy błąd (brak tabel ProEla, zepsuty blob) = karta bez zapasu.

Koszt: pytamy wyłącznie o mecze bez wyniku z ostatnich 30 dni (do dziś) i mecze
bez godziny z okolic dzisiejszego dnia; wynik ekstrakcji (mały słownik, nie blob)
leży w pamięci `_TTL` sekund, więc LIVE i odświeżanie list nie czytają blobów co tick.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Iterable, List

from app import time_pl as TP
from app.zprp_public import proel_card_rules as PR

log = logging.getLogger(__name__)

_TTL = 30.0
_MAX = 80
_memo: Dict[str, tuple] = {}


def invalidate() -> None:
    _memo.clear()


def _blob(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


async def _rows(ids: List[str], codes: List[str]) -> List[dict]:
    from sqlalchemy import or_, select

    from app.db import database, proel_match_state as S, saved_matches as T
    from app.proel_training_key import TRAINING_KEY_LIKE

    cond = []
    if ids:
        cond.append(T.c.zprp_match_id.in_(ids))
    if codes:
        cond.append(T.c.match_number.in_(codes))
    if not cond:
        return []
    found = await database.fetch_all(
        select(T.c.match_number, T.c.zprp_match_id, T.c.status, T.c.data_json, S.c.live_started_at)
        .select_from(T.outerjoin(S, S.c.match_number == T.c.match_number))
        .where(or_(*cond))
        .where(~T.c.match_number.ilike(TRAINING_KEY_LIKE))
    )
    out = []
    for r in found:
        d = dict(r._mapping) if hasattr(r, "_mapping") else dict(r)
        d["blob"] = _blob(d.pop("data_json", None))
        out.append(d)
    return out


async def apply_proel_fallback(items: Iterable[dict]) -> None:
    """Uzupełnia karty bez godziny/wyniku z ProEla i oznacza źródła (mutuje). Nigdy nie rzuca."""
    cards = [c for c in items if isinstance(c, dict) and c.get("match_id")]
    if not cards:
        return
    now = TP.warsaw_now()
    try:
        wanted = [c for c in cards if any(PR.needs(c, now))][:_MAX]
        clock = time.monotonic()
        todo = [c for c in wanted if not (str(c["match_id"]) in _memo and clock - _memo[str(c["match_id"])][0] < _TTL)]
        if todo:
            ids = sorted({str(c["match_id"]) for c in todo})
            codes = sorted({str(c.get("match_code") or "").strip() for c in todo} - {""})
            rows = await _rows(ids, codes)
            for c in todo:
                _memo[str(c["match_id"])] = (clock, PR.extract(PR.pick_row(rows, c), c))
            if len(_memo) > 4000:
                for key in [k for k, v in _memo.items() if clock - v[0] >= _TTL]:
                    _memo.pop(key, None)
        for c in wanted:
            hit = _memo.get(str(c["match_id"]))
            if hit and hit[1]:
                PR.apply(c, hit[1])
    except Exception as exc:  # ProEl jest dodatkiem - karta zostaje z danymi ZPRP
        log.debug("[zprp_public] zapas ProEl pominięty: %s", exc)
    for c in cards:
        PR.mark_sources(c, now)
