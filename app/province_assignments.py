"""
Modul obsadowego - mecze do obsadzenia.

⚠ Zrodlem meczow jest NASZA migawka terminarza (`province_matches`), ta sama,
z ktorej zyja gielda i rozliczenia - a nie scrape ZPRP przy kazdym wejsciu.
Monitor odswieza ja czterema petlami (5 min, 15 min, 45 min, 4 h), zna hale,
termin, numer meczu i cala obsade jako pary numer + nazwisko. Dzieki temu lista
otwiera sie od razu, da sie po niej filtrowac i policzyc braki. Swiezosc
POJEDYNCZEGO meczu bierzemy dopiero przy jego otwarciu, wprost z formularza
ZPRP (`/zprp/obsada/match-form`) - i to on rozstrzyga przy zapisie.

Decyzja uzytkownika z 11.09.2026: pokazujemy WSZYSTKO, co obsadza okreg
(rozgrywki okregowe, puchar wojewodzki i powierzone grupy II ligi), razem
z meczami bez terminu i bez hali - te najlatwiej przeoczyc.

⚠ `state_json` potrafi wrocic z bazy SUROWYM NAPISEM (asyncpg bez kodeka jsonb),
wiec kazdy odczyt idzie przez `state_dict` - patrz gielda.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import and_, or_, select

from app import assignment_rules as A
from app import settlement_origin as O
from app import settlement_rates as R
from app.db import (
    database,
    province_competitions,
    province_match_events,
    province_matches,
    province_module_config,
)
from app.match_market_rules import (
    is_managed_by_province,
    league_level,
    managed_prefixes_for,
    state_dict,
)
from app.province_settlements import require_province
from app.settlement_province import display, spellings
from app.settlement_seasons import season_of

router = APIRouter(prefix="/province/assignments", tags=["province_assignments"])

#: Ile meczow oddajemy w jednej odpowiedzi. Sezon okregu to ok. 2000 meczow,
#: a obsadowy patrzy na najblizsze tygodnie - wiecej i tak nikt nie przeczyta.
LIMIT = 600


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value or "").strip()


def _iso(value: Any) -> Optional[str]:
    return value.isoformat() if value else None


def _day_start(day: date) -> datetime:
    return datetime.combine(day, time.min, tzinfo=timezone.utc)


async def _managed_prefixes(province: str) -> list[str]:
    """Ligi powierzone okregowi (IIM4, IIK4 na Slasku) - z panelu albo z katalogu."""
    row = await database.fetch_one(
        select(province_module_config.c.managed_prefixes).where(
            province_module_config.c.province == province
        )
    )
    return managed_prefixes_for(province, row["managed_prefixes"] if row else None)


async def own_prefixes_of(province: str) -> set[str]:
    """
    Przedrostki numerow NASZEGO okregu - wyczytane z jego wlasnego terminarza.

    Migawka trzyma nie tylko mecze okregu: monitor sledzi TAKZE mecze z list
    poszczegolnych sedziow, wiec sedzia ze Slaska sedziujacy w Kujawsko-Pomorskiem
    wnosi do niej „K/IIIM". Na liscie obsadowego takie mecze nie maja czego
    szukac - okreg ich nie obsadza. Rozpoznajemy je tak samo, jak rozliczenia:
    po przedrostku numeru, a nasze przedrostki bierzemy z faktow, nie z mapy
    wojewodztw (`app/settlement_origin.py`).
    """
    rows = await database.fetch_all(
        select(province_matches.c.match_code, province_matches.c.state_json).where(
            province_matches.c.province.in_(spellings(province))
        )
    )
    codes = [
        _s(state_dict(row["state_json"]).get("RozgrywkiCode") or row["match_code"])
        for row in rows
    ]
    return O.own_prefixes(codes)


async def _competition_names(province: str) -> dict[str, str]:
    """
    Nazwy rozgrywek („II Liga Kobiet gr. 4") po kodzie z numeru meczu.

    Numer meczu niesie sam kod, a nazwe zna pobranie klubow
    (`province_competitions`). Brak nazwy nie jest awaria - zostaje kod.
    """
    rows = await database.fetch_all(
        select(province_competitions.c.code, province_competitions.c.name).where(
            province_competitions.c.province == province
        )
    )
    out: dict[str, str] = {}
    for row in rows:
        code = _s(row["code"]).upper()
        name = _s(row["name"])
        if code and name:
            out.setdefault(code, name)
    return out


def _item(row: Any, state: dict, code: str, names: dict[str, str]) -> dict:
    """Jeden mecz listy: fakty z migawki plus policzony stan obsady."""
    competition = A.competition_key(code)
    status = A.crew_status(state, code)
    at = row["match_at"]
    return {
        "match_id": _s(row["match_id"]),
        "code": code,
        "competition": competition,
        "competition_label": names.get(competition.upper(), ""),
        "category": A.match_category(code),
        "level": league_level(code),
        "match_at": _iso(at),
        "day": at.date().isoformat() if at else None,
        "round": _s(state.get("kolejka") or state.get("Kolejka")),
        "host": _s(state.get("ID_zespoly_gosp_ZespolNazwa")),
        "guest": _s(state.get("ID_zespoly_gosc_ZespolNazwa")),
        "hall": _s(state.get("Hala_nazwa")),
        "city": _s(state.get("Hala_miasto")),
        "address": " ".join(
            x for x in (_s(state.get("Hala_ulica")), _s(state.get("Hala_numer"))) if x
        ),
        "crew": A.crew(state),
        "needs": A.crew_needs(code),
        "status": status,
        "approved": bool(row["approved"]),
        "protocol_status": _s(state.get("protocol_status")),
        "updated_at": _iso(row["last_seen_at"] or row["updated_at"]),
    }


def _haystack(item: dict) -> str:
    people = " ".join(
        _s(person and person.get("name")) for person in (item.get("crew") or {}).values()
    )
    return " ".join(
        [
            item["code"],
            item["competition_label"],
            item["category"],
            item["host"],
            item["guest"],
            item["hall"],
            item["city"],
            item["round"],
            people,
        ]
    ).lower()


def _facets(items: list[dict], key: str, label_of) -> list[dict]:
    out: dict[str, dict] = {}
    for item in items:
        value = item[key]
        if not value:
            continue
        entry = out.setdefault(
            value, {"key": value, "label": label_of(item), "matches": 0, "slots": 0}
        )
        entry["matches"] += 1
        entry["slots"] += item["status"]["gaps"]
    return sorted(out.values(), key=lambda entry: (-entry["slots"], entry["label"] or entry["key"]))


@router.get("", summary="Mecze do obsadzenia")
async def list_matches(
    province: str = Query(...),
    date_from: Optional[date] = Query(None, description="Domyślnie od dziś"),
    date_to: Optional[date] = Query(None),
    competition: Optional[str] = Query(None, description="Kod rozgrywek, np. IIK4 albo S/JmM"),
    category: Optional[str] = Query(None),
    q: Optional[str] = Query(None, description="Drużyna, numer meczu, hala albo sędzia"),
    only_gaps: bool = Query(False, description="Tylko mecze z dziurą w obsadzie"),
    include_past: bool = Query(False, description="Także mecze sprzed dziś"),
    undated: bool = Query(True, description="Także mecze bez terminu"),
):
    key = require_province(province)
    managed = await _managed_prefixes(key)
    names = await _competition_names(key)
    own = await own_prefixes_of(key)

    start = date_from or (None if include_past else _now().date())
    where = [
        province_matches.c.province.in_(spellings(key)),
        province_matches.c.active.is_(True),
    ]
    bounds = []
    if start:
        bounds.append(province_matches.c.match_at >= _day_start(start))
    if date_to:
        bounds.append(province_matches.c.match_at < _day_start(date_to + timedelta(days=1)))
    if bounds:
        dated = and_(*bounds)
        # Mecz bez terminu nie ma jak wpasc w zakres dat, a przeoczyc go najlatwiej.
        where.append(or_(dated, province_matches.c.match_at.is_(None)) if undated else dated)
    elif not undated:
        where.append(province_matches.c.match_at.is_not(None))

    rows = await database.fetch_all(select(province_matches).where(and_(*where)))

    window: list[dict] = []
    for row in rows:
        state = state_dict(row["state_json"])
        code = _s(state.get("RozgrywkiCode") or row["match_code"])
        if not code or R.is_test_competition(code):
            continue
        # Zakres: tylko to, co obsadza okreg - rozgrywki okregowe, puchar
        # wojewodzki i grupy II ligi powierzone temu okregowi.
        if not is_managed_by_province(code, managed):
            continue
        # Mecz innego okregu z listy sedziego - obsadza go tamten okreg.
        if O.is_other_district(code, own):
            continue
        window.append(_item(row, state, code, names))

    competitions = _facets(window, "competition", lambda item: item["competition_label"])
    categories = _facets(window, "category", lambda item: item["category"])

    items = window
    if competition:
        wanted = competition.strip().upper()
        items = [item for item in items if item["competition"].upper() == wanted]
    if category:
        items = [item for item in items if item["category"] == category]
    if only_gaps:
        items = [item for item in items if item["status"]["gaps"]]
    if q and q.strip():
        needle = q.strip().lower()
        items = [item for item in items if needle in _haystack(item)]

    # Najpierw najblizsze terminy, mecze bez terminu na koncu - ale w widoku,
    # nie poza nim: wlasnie one czekaja najdluzej.
    items.sort(key=lambda item: (item["day"] is None, item["day"] or "", item["code"]))

    totals = {
        "matches": len(window),
        "shown": min(len(items), LIMIT),
        "to_fill": sum(1 for item in window if item["status"]["gaps"]),
        "slots": sum(item["status"]["gaps"] for item in window),
        "soft": sum(1 for item in window if not item["status"]["gaps"] and item["status"]["soft"]),
        "complete": sum(1 for item in window if item["status"]["state"] == A.COMPLETE),
        "no_hall": sum(1 for item in window if not item["hall"]),
        "no_date": sum(1 for item in window if not item["day"]),
    }

    return {
        "province": key,
        "display": display(key),
        "season": season_of(_now()),
        "window": {"from": start.isoformat() if start else None, "to": _iso(date_to)},
        "matches": items[:LIMIT],
        "totals": totals,
        "competitions": competitions,
        "categories": categories,
    }


@router.get("/{match_id}", summary="Jeden mecz z migawki okręgu")
async def match_detail(match_id: str, province: str = Query(...)):
    """
    Mecz z naszej migawki plus jego ostatnie zmiany.

    Obsada z tej odpowiedzi jest tak swieza, jak ostatni przebieg monitora -
    przy otwarciu meczu panel i tak pyta ZPRP o formularz, bo to on rozstrzyga
    przy zapisie. Tutaj chodzi o to, zeby bylo co pokazac od razu.
    """
    key = require_province(province)
    row = await database.fetch_one(
        select(province_matches).where(
            and_(
                province_matches.c.province.in_(spellings(key)),
                province_matches.c.match_id == _s(match_id),
            )
        )
    )
    if row is None:
        raise HTTPException(404, "Nie znamy takiego meczu w terminarzu okręgu")

    state = state_dict(row["state_json"])
    code = _s(state.get("RozgrywkiCode") or row["match_code"])
    names = await _competition_names(key)

    events = await database.fetch_all(
        select(province_match_events)
        .where(
            and_(
                province_match_events.c.province.in_(spellings(key)),
                province_match_events.c.match_id == _s(match_id),
            )
        )
        .order_by(province_match_events.c.created_at.desc())
        .limit(20)
    )

    return {
        "province": key,
        "match": _item(row, state, code, names),
        "history": [
            {
                "kind": _s(event["event_type"]),
                "title": _s(event["title"]),
                "body": _s(event["body"]),
                "at": _iso(event["created_at"]),
            }
            for event in events
        ],
    }
