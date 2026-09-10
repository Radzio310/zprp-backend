"""
Pobieranie klubow okregu: rozgrywki sezonu -> druzyny -> kluby.

Konto komisyjne wchodzi na zakladke „Rozgrywki", a dla kazdych rozgrywek na ich
liste druzyn. Stamtad mamy komplet, ktorego nie da sie zlozyc z terminarza:
numer rozgrywek, kod, kategoria i plec oraz numer DRUZYNY i numer KLUBU. Mecze
w naszej bazie niosa same nazwy druzyn, wiec to tutaj powstaje slownik nazwa ->
druzyna -> klub, po ktorym pozniej ida obciazenia.

Sezony ida ta sama regula co przy rozliczeniach (`settlement_seasons`):
pierwsze pobranie w historii okregu bierze wszystkie, kazde nastepne sam
biezacy, a reczne z panelu nadrabia sezony nigdy nie pobrane w calosci.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from httpx import AsyncClient
from sqlalchemy import and_, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import (
    database,
    province_club_seasons,
    province_club_teams,
    province_clubs,
    province_competitions,
    province_settlement_runs,
)
from app.deps import get_settings
from app.province_clubs_scrape import (
    Competition,
    club_display_name,
    parse_competitions,
    parse_seasons,
    parse_selected_province,
    parse_teams,
)
from app.settlement_province import canonical
from app.settlement_seasons import normalize_season_label, plan_seasons, season_of
from app.utils import fetch_with_correct_encoding
from app.zprp_accounts import credentials_for
from app.zprp.officials import (
    _extract_menu_href_from_page,
    _login_zprp_and_get_cookies,
)

logger = logging.getLogger(__name__)

#: Odstep miedzy zapytaniami o liste druzyn. ZPRP to jedna maszyna zwiazku.
COMPETITION_REQUEST_DELAY = 0.25

#: Rodzaj przebiegu w `province_settlement_runs` - ta sama tabela, bo to ta sama
#: maszyneria sledzenia (`run_is_active`, komunikat w panelu).
RUN_KIND = "clubs"

SYNC_INTERVAL_HOURS = 24


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value or "").strip()


def _path(href: str) -> str:
    """Odsylacz ze strony na sciezke do pobrania."""
    text = _s(href).replace("&amp;", "&")
    if not text:
        return ""
    if text.startswith("?"):
        return "/index.php" + text
    if text.startswith("/"):
        return text
    return "/" + text


async def start_run(province: str, kind: str = RUN_KIND) -> int:
    """Wiersz przebiegu, zanim cokolwiek ruszy - jego numer dostaje klient."""
    new_id = await database.execute(
        insert(province_settlement_runs).values(
            province=canonical(province) or province, kind=kind, started_at=_now()
        )
    )
    return int(new_id)


async def last_run(province: str) -> Optional[dict]:
    row = await database.fetch_one(
        select(province_settlement_runs)
        .where(
            and_(
                province_settlement_runs.c.province == (canonical(province) or province),
                province_settlement_runs.c.kind.like(f"{RUN_KIND}%"),
            )
        )
        .order_by(province_settlement_runs.c.started_at.desc())
        .limit(1)
    )
    return dict(row) if row else None


async def completed_seasons(province: str) -> list[str]:
    rows = await database.fetch_all(
        select(province_club_seasons.c.season).where(
            province_club_seasons.c.province == province
        )
    )
    return [_s(row["season"]) for row in rows]


async def _store_season(
    province: str,
    season: str,
    season_id: str,
    competitions: list[Competition],
    teams: list[dict],
) -> None:
    """
    Migawka sezonu: kasujemy stare wiersze i wpisujemy to, co przed chwila
    zobaczylismy. Druzyna wycofana z rozgrywek ma zniknac z panelu, a nie zostac
    na wieki z zerowym obciazeniem.
    """
    now = _now()
    await database.execute(
        province_competitions.delete().where(
            and_(
                province_competitions.c.province == province,
                province_competitions.c.season == season,
            )
        )
    )
    await database.execute(
        province_club_teams.delete().where(
            and_(
                province_club_teams.c.province == province,
                province_club_teams.c.season == season,
            )
        )
    )

    for item in competitions:
        await database.execute(
            insert(province_competitions).values(
                province=province,
                season=season,
                competition_id=item.id,
                season_id=season_id,
                name=item.name,
                code=item.code,
                gender=item.gender,
                category=item.category,
                kind=item.kind,
                state=item.state,
                teams_required=item.teams_required,
                teams_registered=item.teams_registered,
                fetched_at=now,
            )
        )

    for row in teams:
        await database.execute(insert(province_club_teams).values(**row, fetched_at=now))

    # Kluby, ktorych jeszcze nie znamy. Nazwe i ustawienia zapisane recznie
    # w panelu ZOSTAWIAMY - stad `do_nothing`.
    names: dict[str, list[str]] = {}
    for row in teams:
        club_id = _s(row.get("club_id"))
        if club_id:
            names.setdefault(club_id, []).append(_s(row.get("team_name")))
    for club_id, team_names in names.items():
        statement = pg_insert(province_clubs).values(
            province=province,
            club_id=club_id,
            display_name=club_display_name(team_names),
            updated_at=now,
        )
        await database.execute(
            statement.on_conflict_do_nothing(
                index_elements=[province_clubs.c.province, province_clubs.c.club_id]
            )
        )

    await database.execute(
        pg_insert(province_club_seasons)
        .values(
            province=province,
            season=season,
            completed_at=now,
            competitions=len(competitions),
            teams=len(teams),
        )
        .on_conflict_do_update(
            index_elements=[province_club_seasons.c.province, province_club_seasons.c.season],
            set_={"completed_at": now, "competitions": len(competitions), "teams": len(teams)},
        )
    )


async def _collect_season(
    client: AsyncClient,
    cookies: dict,
    *,
    base_href: str,
    season_id: str,
    province_id: str,
) -> tuple[list[Competition], list[dict], str]:
    """Rozgrywki i druzyny jednego sezonu. Zwraca takze etykiete sezonu."""
    path = f"/index.php?a=rozgrywki&Filtr_sezon={season_id}"
    if province_id:
        path += f"&Filtr_woj={province_id}"
    _, html = await fetch_with_correct_encoding(client, path, method="GET", cookies=cookies)

    competitions = parse_competitions(html)
    label = ""
    for option in parse_seasons(html):
        if option.id == season_id:
            label = normalize_season_label(option.label)
            break
    if not label and competitions:
        label = normalize_season_label(competitions[0].season_label)

    teams: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for competition in competitions:
        target = _path(competition.teams_path) or (
            f"/index.php?a=rozgrywki&b=zespoly&IdRozgr={competition.id}&Filtr_sezon={season_id}"
        )
        try:
            _, page = await fetch_with_correct_encoding(
                client, target, method="GET", cookies=cookies
            )
        except Exception as exc:
            # Jedne rozgrywki bez listy nie moga wywalic calego sezonu.
            logger.warning("[clubs] druzyny %s: %s", competition.id, exc)
            continue
        for team in parse_teams(page):
            key = (team.team_id, competition.id)
            if key in seen:
                continue
            seen.add(key)
            teams.append(
                {
                    "province": "",  # uzupelnia wolajacy
                    "season": "",
                    "team_id": team.team_id,
                    "competition_id": competition.id,
                    "team_name": team.name,
                    "name_key": team.key,
                    "team_province": team.province,
                    "club_id": team.club_id,
                    "category": competition.category,
                    "gender": competition.gender,
                    "competition_name": competition.name,
                    "competition_code": competition.code,
                }
            )
        await asyncio.sleep(COMPETITION_REQUEST_DELAY)

    return competitions, teams, label


async def refresh_clubs(
    province: str,
    *,
    username: Optional[str] = None,
    password: Optional[str] = None,
    kind: str = RUN_KIND,
    full_check: bool = False,
    run_id: Optional[int] = None,
) -> dict:
    """
    Pelne odswiezenie drzewa klubow okregu.

    `full_check` (reczne puszczenie z panelu) nadrabia sezony, ktorych nigdy nie
    pobrano w calosci. Bez niego schodzi sam biezacy sezon.
    """
    province = canonical(province)
    if not province:
        return {"province": "", "ok": False, "error": "Nieznane województwo"}
    settings = get_settings()

    if run_id is None:
        run_id = await start_run(province, kind)

    async def finish(ok: bool, **fields: Any) -> dict:
        await database.execute(
            update(province_settlement_runs)
            .where(province_settlement_runs.c.id == int(run_id))
            .values(finished_at=_now(), ok=ok, **fields)
        )
        return {"province": province, "ok": ok, **fields}

    credentials = (username, password) if username and password else credentials_for(province, "sync")
    if not credentials or not credentials[0] or not credentials[1]:
        return await finish(False, error="Brak konta ZPRP dla tego okręgu")

    try:
        async with AsyncClient(
            base_url=settings.ZPRP_BASE_URL, follow_redirects=True, timeout=60.0
        ) as client:
            cookies = await _login_zprp_and_get_cookies(client, credentials[0], credentials[1])

            _, home = await fetch_with_correct_encoding(
                client, "/index.php", method="GET", cookies=cookies
            )
            href = _extract_menu_href_from_page(
                home,
                label_regex=r"^\s*Rozgrywki\s*$",
                href_regex=r"\ba=rozgrywki\b",
                human_label="Rozgrywki",
            )
            _, first = await fetch_with_correct_encoding(
                client, _path(href), method="GET", cookies=cookies
            )

            options = parse_seasons(first)
            province_id = parse_selected_province(first)
            by_label = {normalize_season_label(item.label): item.id for item in options}
            by_label.pop("", None)

            current = season_of(_now())
            plan = plan_seasons(
                available=[item.label for item in options],
                completed=await completed_seasons(province),
                current=current,
                full_check=full_check,
            )

            total_competitions = 0
            total_teams = 0
            done: list[str] = []
            for season in plan:
                season_id = by_label.get(season)
                if not season_id:
                    # Sezon, ktorego lista ZPRP nie zna - nie ma czego pobrac.
                    continue
                competitions, teams, label = await _collect_season(
                    client,
                    cookies,
                    base_href=href,
                    season_id=season_id,
                    province_id=province_id,
                )
                label = label or season
                for row in teams:
                    row["province"] = province
                    row["season"] = label
                await _store_season(province, label, season_id, competitions, teams)
                total_competitions += len(competitions)
                total_teams += len(teams)
                done.append(label)

        return await finish(
            True,
            judges=total_competitions,   # kolumny tej tabeli sluza tu za liczniki
            matches=total_teams,
            outside_matches=len(done),
        )
    except Exception as exc:
        logger.exception("[clubs] odświeżanie %s nie powiodło się", province)
        return await finish(False, error=str(exc)[:500])


async def run_clubs_sync_scheduler() -> None:
    """
    Dobowa petla: biezacy sezon dla okregow z wlaczonymi Rozliczeniami.

    Osobna od petli rozliczen, zeby dluga lista klubow nie opoznila pobrania
    meczow (i odwrotnie).
    """
    from app.province_settlement_sync import enabled_provinces
    from app.settlement_runs import run_is_active
    from app.zprp_accounts import configured_provinces

    await asyncio.sleep(180)  # niech serwer i rozliczenia ruszą pierwsze
    while True:
        try:
            wanted = set(await enabled_provinces("settlements"))
            configured = configured_provinces()
            for province in sorted(wanted):
                if province not in configured:
                    continue
                previous = await last_run(province)
                if previous and run_is_active(
                    previous.get("started_at"), previous.get("finished_at"), _now()
                ):
                    continue
                if previous and previous.get("finished_at"):
                    from datetime import timedelta

                    if _now() - previous["finished_at"] < timedelta(hours=SYNC_INTERVAL_HOURS):
                        continue
                logger.info("[clubs] odświeżam %s", province)
                await refresh_clubs(province, kind=RUN_KIND)
        except Exception:
            logger.exception("[clubs] pętla dobowa")
        await asyncio.sleep(30 * 60)
