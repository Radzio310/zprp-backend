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

Decyzje z 16.09.2026 (regula w `app/assignment_scope.py`, wspolna z automatem):
  - lista pokazuje JEDEN sezon, domyslnie biezacy; sezon meczu rozstrzyga
    `ID_sezon` przeliczony na rok przez katalog zwiazku. Poprzednie sezony
    sa tylko do podgladu (`read_only`),
  - II liga domyslnie znika (`include_league=false`) - jej obsady ustala zwiazek,
  - termin to tryb `when`: tylko z data / wszystkie / tylko bez daty,
  - mecz bez rozpoznanego sezonu nie wchodzi na liste, ale jest policzony.

⚠ `state_json` potrafi wrocic z bazy SUROWYM NAPISEM (asyncpg bez kodeka jsonb),
wiec kazdy odczyt idzie przez `state_dict` - patrz gielda.
"""

from __future__ import annotations

import re
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import and_, select

from app import assignment_rules as A
from app import assignment_scope as S
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
from app.zprp_seasons import lookup_season_ids, season_catalog

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


def _as_utc(moment: Optional[datetime]) -> Optional[datetime]:
    """Naiwny znacznik czytamy jako UTC - Postgres oddaje strefe, SQLite nie."""
    if moment is None:
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


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


async def resolve_seasons(
    rows: list[tuple[Any, dict]], catalog: dict[str, S.Season]
) -> dict[str, Optional[int]]:
    """
    Rok poczatku sezonu kazdego meczu (`None` = nie da sie ustalic).

    Najpierw to, co wie migawka. O mecze, ktorych sezonu migawka nie zna,
    pytamy publiczne API - na krotkiej smyczy, bo panel jest otwarty.
    Wspolne dla listy i automatu, zeby oba widzialy ten sam sezon.
    """
    out: dict[str, Optional[int]] = {}
    unknown: list[str] = []
    for row, state in rows:
        match_id = _s(row["match_id"])
        start = S.match_season_start(
            state, catalog=catalog, column=row["season"], match_at=row["match_at"]
        )
        out[match_id] = start
        if start is None:
            unknown.append(match_id)
    if unknown:
        for match_id, sid in (await lookup_season_ids(unknown)).items():
            if sid in catalog:
                out[match_id] = catalog[sid].start
    return out


def _code_order(code: str) -> tuple:
    """„S/JmM/3" przed „S/JmM/17" - numer meczu po liczbie, nie po napisie."""
    return tuple(int(part) if part.isdigit() else part for part in re.split(r"(\d+)", code))


def _host_table_by_club(state: dict, clubs: Optional[dict[str, dict]]) -> int:
    """Ilu stolikowych stawia sam klub gospodarza - po NAZWIE drużyny."""
    if not clubs:
        return 0
    from app.province_clubs_scrape import team_key

    rule = clubs.get(team_key(state.get("ID_zespoly_gosp_ZespolNazwa"))) or {}
    return int(rule.get("table_by_club", 0) or 0)


def _item(
    row: Any,
    state: dict,
    code: str,
    names: dict[str, str],
    clubs: Optional[dict[str, dict]] = None,
) -> dict:
    """Jeden mecz listy: fakty z migawki plus policzony stan obsady."""
    competition = A.competition_key(code)
    table_by_club = _host_table_by_club(state, clubs)
    status = A.crew_status(state, code, table_by_club)
    at = row["match_at"]
    stage = S.round_info(state)
    score_host = _s(state.get("wynik_gosp_full"))
    score_guest = _s(state.get("wynik_gosc_full"))
    return {
        "match_id": _s(row["match_id"]),
        "code": code,
        "competition": competition,
        "competition_label": names.get(competition.upper(), ""),
        "category": A.match_category(code),
        "level": league_level(code),
        "match_at": _iso(at),
        "score": (
            {"host": score_host, "guest": score_guest, "label": f"{score_host}:{score_guest}"}
            if score_host and score_guest else None
        ),
        "day": at.date().isoformat() if at else None,
        "round": _s(state.get("kolejka") or state.get("Kolejka")),
        # Kolejka do widoku „Kolejki" i do linii granicy kolejki na liscie.
        "round_key": stage["key"],
        "round_phase": stage["phase"],
        "round_name": stage["name"],
        "round_no": stage["no"],
        "round_span": stage["span"],
        "host": _s(state.get("ID_zespoly_gosp_ZespolNazwa")),
        "guest": _s(state.get("ID_zespoly_gosc_ZespolNazwa")),
        "hall": _s(state.get("Hala_nazwa")),
        "city": _s(state.get("Hala_miasto")),
        "address": " ".join(
            x for x in (_s(state.get("Hala_ulica")), _s(state.get("Hala_numer"))) if x
        ),
        "crew": A.crew(state),
        "needs": A.club_crew_needs(code, table_by_club),
        # Gospodarz stawia drugiego stolikowego sam - obsadowy widzi, czemu
        # jeden stolikowy to tu komplet.
        "table_by_club": table_by_club,
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
            item["round_name"],
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
    past_only: bool = Query(False, description="Tylko mecze rozegrane lub już rozpoczęte"),
    undated: Optional[bool] = Query(None, description="Przestarzałe - zamiast tego `when`"),
    when: Optional[str] = Query(None, description="dated | all | undated"),
    season: Optional[int] = Query(
        None, description="Rok początku sezonu (2026 = 2026/2027); domyślnie bieżący"
    ),
    include_league: bool = Query(
        False, description="Także II liga - jej obsady ustala związek, więc domyślnie nie"
    ),
    show_unknown: bool = Query(False, description="Także mecze bez rozpoznanego sezonu"),
):
    from app.assignment_context import _club_rules

    key = require_province(province)
    managed = await _managed_prefixes(key)
    names = await _competition_names(key)
    own = await own_prefixes_of(key)
    catalog = await season_catalog()
    clubs = await _club_rules(key)

    today = _now().date()
    current = S.current_start(catalog, today)
    chosen = int(season) if season else current
    # Poprzedni sezon to podglad: bez zakresu od dzis, bez automatu i zapisu.
    read_only = chosen != current
    mode = S.normalize_when(when, undated)

    start = None if read_only else (date_from or (None if include_past or past_only else today))
    end = None if read_only else date_to

    rows = await database.fetch_all(
        select(province_matches).where(
            and_(
                province_matches.c.province.in_(spellings(key)),
                province_matches.c.active.is_(True),
            )
        )
    )

    candidates: list[tuple[Any, dict, str]] = []
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
        candidates.append((row, state, code))

    seasons_of = await resolve_seasons([(row, state) for row, state, _ in candidates], catalog)

    per_season: dict[int, int] = {}
    counts = {"league": 0, "dated": 0, "no_date": 0, "unknown": 0}
    window: list[dict] = []
    for row, state, code in candidates:
        at = _as_utc(row["match_at"])
        has_score = bool(_s(state.get("wynik_gosp_full")) and _s(state.get("wynik_gosc_full")))
        if past_only and not has_score and (at is None or at >= _now()):
            continue
        match_season = seasons_of.get(_s(row["match_id"]))
        if match_season is not None:
            per_season[match_season] = per_season.get(match_season, 0) + 1
            if match_season != chosen:
                continue
        # Zakres dat dotyczy meczow z terminem. Mecz bez terminu nie ma jak
        # w niego wpasc, a przeoczyc go najlatwiej - o nim decyduje `when`.
        if at is not None:
            if start and at < _day_start(start):
                continue
            if end and at >= _day_start(end + timedelta(days=1)):
                continue
        if S.is_league(code):
            counts["league"] += 1
            if not include_league:
                continue
        if match_season is None:
            # Mecz bez sezonu to kandydat do obsadzenia TERAZ, wiec nie ma go
            # w podgladzie starego sezonu. Liczymy go tylko wtedy, gdy przeszedlby
            # reszte filtrow - licznik ma mowic, ile meczow pokaze „Pokaz".
            if read_only or not S.when_allows(mode, at is not None):
                continue
            counts["unknown"] += 1
            if not show_unknown:
                continue
        counts["dated" if at is not None else "no_date"] += 1
        if not S.when_allows(mode, at is not None):
            continue
        item = _item(row, state, code, names, clubs)
        item["season_unknown"] = match_season is None
        window.append(item)

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
    # nie poza nim: wlasnie one czekaja najdluzej. W obrebie dnia godzina,
    # potem numer meczu po liczbie (/3 przed /17).
    items.sort(
        key=lambda item: (
            item["day"] is None,
            item["day"] or "",
            item["match_at"] or "",
            _code_order(item["code"]),
        )
    )
    if past_only:
        items.reverse()

    totals = {
        "matches": len(window),
        "shown": min(len(items), LIMIT),
        "to_fill": sum(1 for item in window if item["status"]["gaps"]),
        "slots": sum(item["status"]["gaps"] for item in window),
        "soft": sum(1 for item in window if not item["status"]["gaps"] and item["status"]["soft"]),
        "complete": sum(1 for item in window if item["status"]["state"] == A.COMPLETE),
        "no_hall": sum(1 for item in window if not item["hall"]),
        # Liczniki pigulek terminu licza sie PRZED wyborem trybu - inaczej
        # „Bez terminu" pokazywalo zero zawsze, gdy wlaczone jest „Z terminem".
        "dated": counts["dated"],
        "no_date": counts["no_date"],
        # II liga w tym sezonie i zakresie - takze wtedy, gdy jest ukryta.
        "league": counts["league"],
        "unknown_season": counts["unknown"],
    }

    chosen_season = S.season_for_start(catalog, chosen)
    # Na liscie sezonow tylko te, o ktorych cos wiemy, plus zawsze biezacy.
    starts = sorted(
        {year for year in per_season if year <= current} | {current, chosen}, reverse=True
    )
    seasons = [
        {
            "start": year,
            "id": S.season_for_start(catalog, year).id,
            "label": S.season_for_start(catalog, year).label,
            "short": S.season_for_start(catalog, year).short,
            "current": year == current,
            "matches": per_season.get(year, 0),
        }
        for year in starts
    ]

    return {
        "province": key,
        "display": display(key),
        "season": chosen_season.label,
        "season_start": chosen,
        "season_id": chosen_season.id,
        "current_season": current,
        "read_only": read_only,
        "seasons": seasons,
        "when": mode,
        "include_league": include_league,
        "window": {"from": start.isoformat() if start else None, "to": _iso(end)},
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

    from app.assignment_context import _club_rules

    state = state_dict(row["state_json"])
    code = _s(state.get("RozgrywkiCode") or row["match_code"])
    names = await _competition_names(key)
    clubs = await _club_rules(key)

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
        "match": _item(row, state, code, names, clubs),
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
