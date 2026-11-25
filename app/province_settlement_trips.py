"""
Wyjazd zbiorczy zwyklych meczow - warstwa bazy i trasa HTTP (25.11.2026).

Regula siedzi w silniku (`settlement_engine._mark_day_trips`): ten sam sedzia,
ten sam dzien, ta sama miejscowosc i ten sam PLATNIK = jeden dojazd. Silnik nie
zna bazy, wiec TUTAJ ustalamy dwie rzeczy i wpisujemy je w obsady, zanim pojda
do jakiegokolwiek rachunku (`province_settlements._base`):

  * `Assignment.payer` - kto placi za mecz: klub (kluby scalone w jeden budzet
    to jeden platnik), a `OKREG`, gdy placi okreg. Wziete z `club_scope`
    (`payer_of`), czyli z tego samego rozpoznania, co obciazenia klubow,
  * `Assignment.trip_mode` - reczna decyzja z panelu (tabela
    `province_trip_decisions`), wygrywa z automatem.

Zapis decyzji przechodzi przez ta sama bramke co zdejmowanie meczu z rozliczen.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import date, datetime, timezone
from typing import Any, Literal, Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import settlement_cache as SC
from app import settlement_engine as E
from app.db import database, province_trip_decisions
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import panel_read_gate, panel_write_gate
from app.settlement_seasons import season_of

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/province/settlements/trips",
    tags=["province_settlements"],
    dependencies=[Depends(panel_write_gate(PANEL_SETTLEMENTS, "Wspólny dojazd w rozliczeniach"))],
)

TD = province_trip_decisions
_PL = ZoneInfo("Europe/Warsaw")


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def load_decisions(province: str) -> dict[tuple[str, str], str]:
    """(sedzia, mecz) -> "together" | "separate"."""
    rows = await database.fetch_all(select(TD).where(TD.c.province == province))
    out: dict[tuple[str, str], str] = {}
    for row in rows:
        mode = _s(row["mode"])
        if mode in E.TRIP_MODES:
            out[(_s(row["judge_id"]), _s(row["match_key"]))] = mode
    return out


async def _budget_owner(province: str) -> dict[str, str]:
    """Klub -> klub glowny jego wspolnego budzetu (puste, gdy nie ma budzetow)."""
    try:
        from app import province_club_budgets as CB
        from app import province_club_budgets_rules as BR

        return BR.member_map(await CB.budget_groups(province))
    except Exception as exc:  # budzety to dodatek: bez nich platnikiem jest sam klub
        logger.warning("[trips] %s: budzety klubow: %s", province, exc)
        return {}


def _pl_day(value: Optional[datetime]) -> Optional[date]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(_PL).date()


async def annotate_trips(
    province: str,
    assignments: list[E.Assignment],
    *,
    central_versions: list,
    province_versions: list,
    now: datetime,
) -> None:
    """Wpisuje platnika i reczna decyzje w obsady (na miejscu, przed pamiecia podreczna)."""
    try:
        decisions = await load_decisions(province)
    except Exception as exc:  # chwilowy blad: automat
        logger.warning("[trips] %s: odczyt decyzji: %s", province, exc)
        decisions = {}
    for item in assignments:
        item.trip_mode = decisions.get((item.judge_id, item.match_key))

    wanted = _eligible(assignments)
    if not wanted:
        return
    payers = await _payers(
        province, wanted, central_versions=central_versions, province_versions=province_versions, now=now
    )
    for item in wanted:
        item.payer = payers.get(item.match_key)


def _eligible(assignments: list[E.Assignment]) -> list[E.Assignment]:
    return [
        item
        for item in assignments
        if item.fixed_gross is None
        and (_pl_day(item.match_at) or date.min) >= E.TRIP_SHARE_SINCE
    ]


async def _payers(
    province: str,
    wanted: list[E.Assignment],
    *,
    central_versions: list,
    province_versions: list,
    now: datetime,
    load_hosts: bool = True,
    hosts: Optional[dict[str, str]] = None,
    guests: Optional[dict[str, str]] = None,
) -> dict[str, Optional[str]]:
    """match_key -> platnik (klub scalony w budzet, `OKREG` albo None = nieznany)."""
    try:
        from app.settlement_club_scope import club_scope_many

        probe = await asyncio.to_thread(
            E.settle_judges,
            wanted,
            province=province,
            central_versions=central_versions,
            province_versions=province_versions,
            now=now,
            include_future=True,
            include_zprp=True,
            share_trips=False,
        )
        by_season: dict[str, list] = {}
        for entry in probe:
            for match in entry.matches:
                if match.day is not None:
                    by_season.setdefault(season_of(match.day), []).append(match)
        scope = await club_scope_many(
            province, by_season, load_hosts=load_hosts, extra_hosts=hosts, extra_guests=guests
        )
        owner = await _budget_owner(province)
    except Exception as exc:  # bez platnika automat nie skleja - dojazdy zostaja jak byly
        logger.warning("[trips] %s: platnicy meczow: %s", province, exc)
        return {}
    payer_of = scope.get("payer_of") or {}
    out: dict[str, Optional[str]] = {}
    for item in wanted:
        club = payer_of.get(item.match_key)
        out[item.match_key] = (owner.get(club) or club) if club else None
    return out


async def annotate_forecast(
    province: str,
    judge_id: str,
    assignments: list[E.Assignment],
    *,
    central_versions: list,
    province_versions: list,
    now: datetime,
    hosts: Optional[dict[str, str]] = None,
    guests: Optional[dict[str, str]] = None,
) -> None:
    """
    Platnik i reczna decyzja dla meczow DOSLANYCH z telefonu (prognoza, 25.11.2026).

    Tak samo jak `annotate_trips` na obsadach z bazy, ale liczymy tylko te
    kilka meczow: tabele klubow i budzety czyta `club_scope_many` bez stanow
    wszystkich meczow okregu (`load_hosts=False`), a gospodarza niesie telefon
    (`hosts`: klucz meczu -> faktyczny gospodarz) albo napis „gospodarz - gosc".
    Reczna decyzja: klucz meczu, a gdy go nie ma - ten sam numer meczu
    (`f:123` z telefonu = `d:123` w bazie). Platnik nieznany = dojazdy osobno.
    """
    if not assignments:
        return
    from app.settlement_forecast_rules import match_id_of

    try:
        rows = await database.fetch_all(
            select(TD).where((TD.c.province == province) & (TD.c.judge_id == _s(judge_id)))
        )
    except Exception as exc:  # chwilowy blad: automat
        logger.warning("[trips] %s: decyzje do prognozy: %s", province, exc)
        rows = []
    by_key: dict[str, str] = {}
    by_id: dict[str, str] = {}
    for row in rows:
        mode = _s(row["mode"])
        if mode in E.TRIP_MODES:
            by_key[_s(row["match_key"])] = mode
            by_id.setdefault(match_id_of(row["match_key"]), mode)
    for item in assignments:
        item.trip_mode = by_key.get(item.match_key) or by_id.get(match_id_of(item.match_key))

    wanted = _eligible(assignments)
    if not wanted:
        return
    payers = await _payers(
        province,
        wanted,
        central_versions=central_versions,
        province_versions=province_versions,
        now=now,
        load_hosts=False,
        hosts=hosts,
        guests=guests,
    )
    for item in wanted:
        item.payer = payers.get(item.match_key)


class TripBody(BaseModel):
    province: str
    judge_id: str
    match_key: str
    #: together = „licz razem" (bez wlasnego dojazdu), separate = „licz osobno"
    #: (wlasny dojazd), auto = wroc do automatu (kasuje decyzje).
    mode: Literal["together", "separate", "auto"]
    user: Optional[str] = None


def verdicts_from_entries(entries: list) -> list[dict[str, str]]:
    """
    Werdykty wspolnego dojazdu z JUZ POLICZONEGO rozliczenia (lisc, bez bazy).

    Tylko obsady w sytuacji do scalenia albo z reczna decyzja - dojazd reszty sie
    nie zmienia, statystyki policza go same. `shared` znaczy dokladnie to, co w
    panelu: ten mecz ma travel 0 z powodu wspolnego dojazdu (`travel_shared`).
    Gdy ten sam sedzia ma w meczu kilka rol, `shared` tylko wtedy, gdy wszystkie.
    """
    out: dict[tuple[str, str], str] = {}
    for entry in entries:
        for match in entry.matches:
            if not (match.trip_candidate or match.trip_mode in E.TRIP_MODES):
                continue
            key = (_s(entry.judge_id), _s(match.match_key))
            result = "shared" if match.travel_shared else "own"
            if out.get(key) == "own":
                continue
            out[key] = result
    return [
        {"judge_id": judge, "match_key": match, "result": result}
        for (judge, match), result in sorted(out.items())
    ]


async def compute_verdicts(province: str, *, include_future: bool = True) -> list[dict[str, str]]:
    """
    Werdykty z TEGO SAMEGO przeliczenia co panel (`load_settlement`): wspolna baza
    okregu (obsady z platnikiem i reczna decyzja), podzial okreg / kluby
    (`club_scope_many`), silnik z wlaczona regula. Zakres dat: od 01.11.2026.
    """
    from app import province_settlements as PS
    from app.settlement_club_scope import club_scope_many

    base = await PS._base(province)
    wanted = _eligible(list(base["assignments"]))
    if not wanted:
        return []
    common = dict(
        province=province,
        central_versions=base["central_versions"],
        province_versions=base["province_versions"],
        now=_now(),
        include_future=include_future,
        include_zprp=True,
        names=base["names"],
    )
    probe = await asyncio.to_thread(E.settle_judges, wanted, share_trips=False, **common)
    by_season: dict[str, list] = {}
    for entry in probe:
        for match in entry.matches:
            if match.day is not None:
                by_season.setdefault(season_of(match.day), []).append(match)
    scope = await club_scope_many(province, by_season)
    outside = scope["match_keys"]
    excluded = scope.get("excluded_keys") or set()
    inside = [i for i in wanted if i.match_key not in outside and i.match_key not in excluded]
    outer = [i for i in wanted if i.match_key in outside]

    def settle() -> list:
        entries = E.settle_judges(inside, **common)
        if outer:
            entries = entries + E.settle_judges(outer, **common)
        return entries

    return verdicts_from_entries(await asyncio.to_thread(settle))


@router.get("", summary="Wspólny dojazd: decyzje i werdykty okręgu (do statystyk)")
async def list_trip_decisions(
    province: str,
    include_future: bool = True,
    _access: None = Depends(panel_read_gate(PANEL_SETTLEMENTS, "Odczyt decyzji o wspólnym dojeździe")),
):
    """
    `items` - reczne decyzje `together`/`separate`. `verdicts` - gotowy wynik
    serwera dla obsad od 01.11.2026 w sytuacji do scalenia (z pamieci
    `settlement_cache`, uniewazniany tak jak reszta rozliczen).
    """
    from app.province_settlements import require_province

    key = require_province(province)
    decisions = await load_decisions(key)
    verdicts: Optional[list] = None
    try:
        verdicts = await SC.remember(
            "trip-verdicts", key, (bool(include_future),), lambda: compute_verdicts(key, include_future=include_future)
        )
    except Exception as exc:  # bez werdyktow statystyki licza lokalna regula
        logger.warning("[trips] %s: werdykty: %s", key, exc)
    body: dict[str, Any] = {
        "province": key,
        "items": [
            {"judge_id": judge, "match_key": match, "mode": mode}
            for (judge, match), mode in sorted(decisions.items())
        ],
    }
    if verdicts is not None:
        body["verdicts"] = verdicts
    return body


@router.put("", summary="Wspólny dojazd: licz razem / licz osobno / automat")
async def set_trip_mode(body: TripBody):
    from app.province_settlements import require_province

    key = require_province(body.province)
    judge_id = _s(body.judge_id)
    match_key = _s(body.match_key)
    if not judge_id or not match_key:
        raise HTTPException(400, "Brak sędziego albo meczu.")
    if body.mode == "auto":
        await database.execute(
            delete(TD).where(
                (TD.c.province == key) & (TD.c.judge_id == judge_id) & (TD.c.match_key == match_key)
            )
        )
        message = "Dojazd liczy się automatycznie."
    else:
        values = {"mode": body.mode, "updated_by": _s(body.user) or None, "updated_at": _now()}
        await database.execute(
            pg_insert(TD)
            .values(province=key, judge_id=judge_id, match_key=match_key, **values)
            .on_conflict_do_update(
                index_elements=[TD.c.province, TD.c.judge_id, TD.c.match_key], set_=values
            )
        )
        message = (
            "Ten mecz liczy się razem z innym - bez własnego dojazdu."
            if body.mode == "together"
            else "Ten mecz ma własny dojazd."
        )
    # base=True: decyzja siedzi w obsadach, a one sa we wspolnej bazie okregu.
    SC.bump(key, reason=f"wspólny dojazd: {body.mode}")
    logger.info("[trips] %s %s/%s: %s (%s)", key, judge_id, match_key, body.mode, body.user)
    return {"ok": True, "mode": body.mode, "message": message}

