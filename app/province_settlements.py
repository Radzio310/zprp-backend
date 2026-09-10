"""
Rozliczenia i statystyki okregowe - warstwa HTTP.

Caly rachunek robi `settlement_engine`; tutaj tylko czytamy fakty z bazy,
dobieramy tabele stawek i oddajemy wynik. Zaden endpoint nie liczy kwoty na
wlasna reke - inaczej po miesiacu bylyby trzy rachunki zamiast jednego.
"""

from __future__ import annotations

import asyncio
import calendar
import logging
from datetime import date, datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, func, select

from app import settlement_engine as E
from app import settlement_rates as R
from app.db import (
    central_rates,
    database,
    okreg_rates,
    province_judges,
    province_modules,
    province_match_overrides,
    province_settlement_matches,
)
from app.province_settlement_sync import (
    last_run,
    module_enabled,
    refresh_province,
    start_run,
)
from app.settlement_province import canonical, display, spellings
from app.settlement_runs import cooldown_left, run_is_active

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province/settlements", tags=["province_settlements"])

MODULES = ("stats", "settlements")


def require_province(province: str) -> str:
    """
    Klucz naszych tabel (np. "SLASKIE") albo 400.

    Kazde wejscie tego modulu przechodzi tedy. Pierwsza wersja zapisywala
    wojewodztwo tak, jak przyslal je klient ("ŚLĄSKIE"), a pytala o "SLASKIE" -
    wlaczony modul odpowiadal wiec „wylaczony". Patrz `app/settlement_province.py`.
    """
    key = canonical(province)
    if not key:
        raise HTTPException(400, f"Nieznane województwo: {province}")
    return key

#: Skroty tablic rejestracyjnych - czesc numeru dokumentu (SL/01/2026/1).
PROVINCE_SHORT: dict[str, str] = {
    "DOLNOSLASKIE": "DS",
    "KUJAWSKOPOMORSKIE": "KP",
    "LUBELSKIE": "LU",
    "LUBUSKIE": "LB",
    "LODZKIE": "LD",
    "MALOPOLSKIE": "MA",
    "MAZOWIECKIE": "MZ",
    "OPOLSKIE": "OP",
    "PODKARPACKIE": "PK",
    "PODLASKIE": "PD",
    "POMORSKIE": "PM",
    "SLASKIE": "SL",
    "SWIETOKRZYSKIE": "SW",
    "WARMINSKOMAZURSKIE": "WM",
    "WIELKOPOLSKIE": "WP",
    "ZACHODNIOPOMORSKIE": "ZP",
}


def province_short(province: str) -> str:
    return PROVINCE_SHORT.get(R.province_key(province), R.province_key(province)[:2] or "XX")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def month_range(year: int, month: int) -> tuple[date, date]:
    if not 1 <= month <= 12:
        raise HTTPException(400, "Miesiąc poza zakresem")
    last = calendar.monthrange(year, month)[1]
    return date(year, month, 1), date(year, month, last)


async def _versions(province: str) -> tuple[list[dict], list[dict]]:
    central_rows = await database.fetch_all(
        select(central_rates).order_by(central_rates.c.id.asc())
    )
    province_rows = await database.fetch_all(
        select(okreg_rates)
        .where(okreg_rates.c.province.in_(spellings(province)))
        .order_by(okreg_rates.c.id.asc())
    )
    return [dict(r) for r in central_rows], [dict(r) for r in province_rows]


async def _judge_names(province: str) -> dict[str, str]:
    rows = await database.fetch_all(
        select(province_judges.c.judge_id, province_judges.c.full_name)
        .where(province_judges.c.province.in_(spellings(province)))
    )
    return {str(r["judge_id"]): str(r["full_name"] or "") for r in rows}


async def _assignments(
    province: str,
    *,
    judge_ids: Optional[list[str]] = None,
) -> list[E.Assignment]:
    query = select(province_settlement_matches).where(
        and_(
            province_settlement_matches.c.province == province,
            province_settlement_matches.c.active.is_(True),
        )
    )
    if judge_ids:
        query = query.where(province_settlement_matches.c.judge_id.in_(judge_ids))
    # Zakres tniemy dopiero w silniku: mecz bez daty ma tam wlasna regule i
    # odsianie go tutaj zabraloby ja bezpowrotnie.
    rows = await database.fetch_all(query)

    # Reczne wyjatki na meczu - tu potrzebny jest tylko potrojny ryczałt
    # stolikowego. Jeden slownik na okreg, zamiast zapytania na mecz.
    marked = await database.fetch_all(
        select(province_match_overrides.c.match_key).where(
            and_(
                province_match_overrides.c.province == province,
                province_match_overrides.c.triple_table.is_(True),
            )
        )
    )
    triple_keys = {str(row["match_key"]) for row in marked}

    out: list[E.Assignment] = []
    for row in rows:
        out.append(
            E.Assignment(
                match_key=str(row["match_key"]),
                judge_id=str(row["judge_id"]),
                match_at=row["match_at"],
                match_code=str(row["match_code"] or ""),
                role=str(row["role"] or R.ROLE_FIELD),
                origin=str(row["origin"] or "district"),
                city=str(row["city"] or ""),
                hall=str(row["hall"] or ""),
                home_city=str(row["home_city"] or ""),
                teams=str(row["teams"] or ""),
                round_text=row["round_text"],
                series_text=row["series_text"],
                distance_km=float(row["distance_km"]) if row["distance_km"] is not None else None,
                distance_source=row["distance_source"],
                approved=row["approved"],
                triple_table=str(row["match_key"]) in triple_keys,
            )
        )
    return out


async def load_settlement(
    province: str,
    *,
    year: int,
    month: int,
    include_future: bool = False,
    include_zprp: bool = False,
    judge_ids: Optional[list[str]] = None,
) -> dict:
    """
    Jedno wejscie dla panelu, aplikacji i PDF-ow.

    `include_zprp` - czy doliczyc obsady rozliczane przez ZPRP (boiskowi
    i delegaci na meczach centralnych, stoliki MP). Domyslnie NIE, bo to jest
    rozliczenie OKREGU. Przelacznik ma tylko panel webowy; aplikacja sedziego
    nie przekazuje go nigdy.
    """
    province = require_province(province)
    date_from, date_to = month_range(year, month)
    central_versions, province_versions = await _versions(province)
    names = await _judge_names(province)
    assignments = await _assignments(province, judge_ids=judge_ids)
    now = _now()

    entries = E.settle_judges(
        assignments,
        province=province,
        central_versions=central_versions,
        province_versions=province_versions,
        now=now,
        date_from=date_from,
        date_to=date_to,
        include_future=include_future,
        include_zprp=include_zprp,
        names=names,
    )
    # Obsady ZPRP liczymy ZAWSZE, niezaleznie od przelacznika: wylaczone musza
    # sie wytlumaczyc („1 mecz poza rozliczeniem okregu"), zamiast znikac bez
    # slowa, a przelacznik pokazuje, ile ich dojdzie.
    zprp = E.zprp_matches(
        assignments,
        now=now,
        date_from=date_from,
        date_to=date_to,
        include_future=include_future,
    )

    return {
        "province": province,
        "period": {"year": year, "month": month, "from": date_from.isoformat(), "to": date_to.isoformat()},
        "include_future": include_future,
        "include_zprp": include_zprp,
        "entries": entries,
        "totals": E.totals_of(entries),
        "travel": E.travel_rows(entries),
        "zprp": zprp,
    }


# ---------------------------------------------------------------------------
# Serializacja
# ---------------------------------------------------------------------------

def _match_json(match: E.SettledMatch) -> dict:
    return {
        "match_key": match.match_key,
        "match_at": match.match_at.isoformat() if match.match_at else None,
        "day": match.day.isoformat() if match.day else None,
        "code": match.match_code,
        "category": match.category,
        "level": match.level,
        # ⚠ „x3" doklejamy do ROLI, bo to jedyne pole, ktore aplikacja sedziego
        # juz pokazuje przy meczu - dzieki temu potrojny ryczałt widac bez
        # wydawania nowego builda. W bazie rola zostaje czysta.
        "role": match.role + (" x3" if match.triple_table else ""),
        "origin": match.origin,
        "city": match.city,
        "teams": match.teams,
        "distance_km": match.distance_km,
        "distance_source": match.distance_source,
        "km_rate": match.km_rate,
        "gross": match.gross,
        "travel": match.travel,
        "travel_shared": match.travel_shared,
        "future": match.future,
        "approved": match.approved,
        "stage": match.stage,
        "stage_guessed": match.stage_guessed,
        "status": match.status,
        "zprp_reason": match.zprp_reason,
        "triple_table": match.triple_table,
    }


def _zprp_json(match: E.ZprpMatch) -> dict:
    """Obsada rozliczana przez ZPRP - BEZ kwot, bo okreg ich nie wyplaca."""
    return {
        "match_key": match.match_key,
        "judge_id": match.judge_id,
        "match_at": match.match_at.isoformat() if match.match_at else None,
        "day": match.day.isoformat() if match.day else None,
        "code": match.match_code,
        "category": match.category,
        "role": match.role,
        "city": match.city,
        "teams": match.teams,
        "future": match.future,
        "reason": match.reason,
        "reason_label": R.ZPRP_REASONS.get(match.reason, ""),
    }


def _zprp_summary(matches: list[E.ZprpMatch], *, included: bool) -> dict:
    reasons: dict[str, int] = {}
    for item in matches:
        reasons[item.reason] = reasons.get(item.reason, 0) + 1
    return {
        "included": included,
        "count": len(matches),
        "judges": len({m.judge_id for m in matches}),
        "reasons": reasons,
    }


def _entry_json(entry: E.JudgeSettlement, *, with_matches: bool) -> dict:
    payload = {
        "judge_id": entry.judge_id,
        "name": entry.judge_name,
        "matches": entry.match_count,
        "future": entry.future_count,
        "gross": entry.gross,
        "costs": entry.costs,
        "taxable": entry.taxable,
        "tax": entry.tax,
        "net": entry.net,
        "travel": entry.travel,
        "total": entry.total,
        "missing_distance": entry.missing_distance,
        "missing_rate": entry.missing_rate,
        "guessed_stage": entry.guessed_stage,
    }
    if with_matches:
        payload["rows"] = [_match_json(m) for m in entry.matches]
    return payload


def _travel_json(row: E.TravelRow) -> dict:
    return {
        "judge_id": row.judge_id,
        "name": row.judge_name,
        "day": row.day.isoformat() if row.day else None,
        "route": row.route,
        "one_way_km": row.one_way_km,
        "total_km": row.total_km,
        "rate": row.rate,
        "amount": row.amount,
    }


# ---------------------------------------------------------------------------
# Moduly (panel admina)
# ---------------------------------------------------------------------------

class ModuleToggleRequest(BaseModel):
    enabled: bool


@router.get("/modules", summary="Które okręgi mają włączone Statystyki i Rozliczenia")
async def list_modules():
    rows = await database.fetch_all(select(province_modules))
    # Klucz odpowiedzi to NAZWA dla czlowieka ("ŚLĄSKIE"), bo tak identyfikuje
    # wojewodztwa aplikacja. Wiersze sprzed ujednolicenia zapisu i po nim zlewaja
    # sie tu w jeden wpis.
    out: dict[str, dict[str, bool]] = {}
    for row in rows:
        entry = out.setdefault(display(row["province"]), {})
        module = str(row["module"])
        entry[module] = entry.get(module, False) or bool(row["enabled"])
    return {"modules": MODULES, "provinces": out}


@router.put("/modules/{province}/{module}", summary="Włącz lub wyłącz moduł w okręgu")
async def set_module(province: str, module: str, payload: ModuleToggleRequest):
    if module not in MODULES:
        raise HTTPException(400, f"Nieznany moduł: {module}")
    key = require_province(province)

    from sqlalchemy.dialects.postgresql import insert as pg_insert

    # Wiersze pod inna pisownia (sprzed ujednolicenia) znikaja przy pierwszym
    # przelaczeniu - inaczej dwa wiersze tego samego okregu moglyby mowic dwie
    # rozne rzeczy.
    legacy = [name for name in spellings(key) if name != key]
    if legacy:
        await database.execute(
            province_modules.delete().where(
                and_(
                    province_modules.c.province.in_(legacy),
                    province_modules.c.module == module,
                )
            )
        )

    statement = pg_insert(province_modules).values(
        province=key, module=module, enabled=payload.enabled
    )
    await database.execute(
        statement.on_conflict_do_update(
            index_elements=[province_modules.c.province, province_modules.c.module],
            set_={"enabled": payload.enabled},
        )
    )
    return {"province": display(key), "module": module, "enabled": payload.enabled}


# ---------------------------------------------------------------------------
# Odczyt
# ---------------------------------------------------------------------------

@router.get("/status", summary="Kiedy dane okręgu schodziły ostatni raz")
async def status(province: str = Query(...)):
    key = require_province(province)
    run = await last_run(key)
    now = _now()

    def iso(value):
        return value.isoformat() if value else None

    return {
        "province": key,
        "display": display(key),
        "stats_enabled": await module_enabled(key, "stats"),
        "settlements_enabled": await module_enabled(key, "settlements"),
        "last_run": {
            "id": run.get("id"),
            "kind": run.get("kind"),
            "started_at": iso(run.get("started_at")),
            "finished_at": iso(run.get("finished_at")),
            # Klient sledzi przebieg w tle po `id` i tym znaczniku.
            "running": run_is_active(
                run.get("started_at"),
                run.get("finished_at"),
                now,
                run.get("heartbeat_at"),
            ),
            "ok": run.get("ok"),
            "judges": run.get("judges"),
            "matches": run.get("matches"),
            "outside_matches": run.get("outside_matches"),
            "error": run.get("error"),
            # Jakie sezony objal przebieg - pierwszy i reczny potrafia ich
            # miec kilkanascie, zwykly tylko biezacy.
            "seasons": [s for s in str(run.get("seasons") or "").split(",") if s],
        } if run else None,
    }


@router.get("/summary", summary="Rozliczenie okręgu za miesiąc")
async def summary(
    province: str = Query(...),
    year: int = Query(...),
    month: int = Query(...),
    include_future: bool = Query(False),
    include_zprp: bool = Query(False, description="Dolicz obsady rozliczane przez ZPRP"),
):
    key = require_province(province)
    if not await module_enabled(key, "settlements"):
        raise HTTPException(403, "Moduł Rozliczeń nie jest włączony w tym okręgu")

    data = await load_settlement(
        key, year=year, month=month, include_future=include_future, include_zprp=include_zprp
    )
    return {
        "province": data["province"],
        "period": data["period"],
        "include_future": include_future,
        "include_zprp": include_zprp,
        "totals": data["totals"],
        "entries": [_entry_json(e, with_matches=False) for e in data["entries"]],
        "zprp": _zprp_summary(data["zprp"], included=include_zprp),
        "document_number_hint": await next_document_number(key, year, month, "zestawienie", peek=True),
    }


async def _solo_table_matches(province: str, keys: list[str]) -> set[str]:
    """
    Mecze, na ktorych przy stoliku stal JEDEN sedzia.

    Tylko tam wolno zaproponowac potrojny ryczałt - a liczbe stolikowych zna
    caly okreg, nie pojedynczy sedzia, wiec pytamy o nia osobno.
    """
    if not keys:
        return set()
    rows = await database.fetch_all(
        select(
            province_settlement_matches.c.match_key,
            func.count().label("crew"),
        )
        .where(
            and_(
                province_settlement_matches.c.province == province,
                province_settlement_matches.c.match_key.in_(keys),
                province_settlement_matches.c.role == R.ROLE_TABLE,
                province_settlement_matches.c.active.is_(True),
            )
        )
        .group_by(province_settlement_matches.c.match_key)
    )
    return {str(row["match_key"]) for row in rows if int(row["crew"] or 0) == 1}


async def _judge_payload(
    key: str,
    judge_id: str,
    *,
    year: int,
    month: int,
    include_future: bool,
    include_zprp: bool,
) -> dict:
    """
    Wspolna tresc `/judge/{id}` i `/me`.

    Osobna funkcja, a nie wolanie jednej trasy z drugiej: trasa wolana wprost
    dostaje za niepodany parametr obiekt `Query(False)`, ktory jest PRAWDZIWY -
    aplikacja sedziego dostalaby wtedy po cichu obsady ZPRP.
    """
    data = await load_settlement(
        key,
        year=year,
        month=month,
        include_future=include_future,
        include_zprp=include_zprp,
        judge_ids=[judge_id],
    )
    entry = next((e for e in data["entries"] if e.judge_id == judge_id), None)
    if entry is None:
        names = await _judge_names(key)
        entry = E.JudgeSettlement(judge_id=judge_id, judge_name=names.get(judge_id, ""))
    payload = _entry_json(entry, with_matches=True)
    solo = await _solo_table_matches(key, [item.match_key for item in entry.matches])
    for row in payload.get("rows") or []:
        row["triple_allowed"] = bool(
            row["match_key"] in solo
            and str(row["role"]).startswith(R.ROLE_TABLE)
            and R.triple_table_allowed(row["code"], R.ROLE_TABLE, key)
        )

    return {
        "province": key,
        "period": data["period"],
        "include_future": include_future,
        "include_zprp": include_zprp,
        "entry": payload,
        "travel": [_travel_json(r) for r in E.travel_rows([entry])],
        # Obsady ZPRP tego sedziego. Doliczone przelacznikiem siedza tez
        # w `entry.rows` ze znacznikiem `zprp_reason`; niedoliczone - tylko tu,
        # zeby ekran mogl powiedziec, czemu mecz nie ma kwoty.
        "zprp": [_zprp_json(m) for m in data["zprp"] if m.judge_id == judge_id],
    }


@router.get("/judge/{judge_id}", summary="Rozliczenie jednego sędziego, z meczami")
async def judge_detail(
    judge_id: str,
    province: str = Query(...),
    year: int = Query(...),
    month: int = Query(...),
    include_future: bool = Query(False),
    include_zprp: bool = Query(False, description="Dolicz obsady rozliczane przez ZPRP"),
):
    key = require_province(province)
    return await _judge_payload(
        key,
        judge_id,
        year=year,
        month=month,
        include_future=include_future,
        include_zprp=include_zprp,
    )


@router.get("/travel", summary="Lista kosztów przejazdów za miesiąc")
async def travel(
    province: str = Query(...),
    year: int = Query(...),
    month: int = Query(...),
    include_future: bool = Query(False),
    include_zprp: bool = Query(False, description="Dolicz obsady rozliczane przez ZPRP"),
    judge_ids: Optional[str] = Query(None, description="Numery sędziów po przecinku"),
):
    key = require_province(province)
    ids = [x.strip() for x in (judge_ids or "").split(",") if x.strip()] or None
    data = await load_settlement(
        key,
        year=year,
        month=month,
        include_future=include_future,
        include_zprp=include_zprp,
        judge_ids=ids,
    )
    rows = [_travel_json(r) for r in data["travel"]]
    return {
        "province": key,
        "period": data["period"],
        "rows": rows,
        "total": sum(r["amount"] for r in rows),
        "total_km": sum(r["total_km"] for r in rows),
    }


@router.get("/me", summary="Moje rozliczenie okręgowe - dla aplikacji sędziego")
async def mine(
    province: str = Query(...),
    judge_id: str = Query(...),
    year: int = Query(...),
    month: int = Query(...),
    include_future: bool = Query(False),
):
    key = require_province(province)
    if not await module_enabled(key, "settlements"):
        raise HTTPException(403, "Moduł Rozliczeń nie jest włączony w tym okręgu")
    # „Moje rozliczenie OKREGOWE": obsady ZPRP nigdy nie wchodza tu do kwot -
    # decyzja uzytkownika z 10.09.2026. Ekran dostaje je osobno, bez pieniedzy.
    return await _judge_payload(
        key,
        judge_id,
        year=year,
        month=month,
        include_future=include_future,
        include_zprp=False,
    )


@router.get("/months", summary="Sumy miesiąc po miesiącu - do siatki sezonów")
async def months(
    province: str = Query(...),
    include_future: bool = Query(False),
    include_zprp: bool = Query(False, description="Dolicz obsady rozliczane przez ZPRP"),
    judge_id: Optional[str] = Query(None, description="Tylko ten sędzia (aplikacja sędziego)"),
):
    """
    Kwoty kazdego miesiaca, w ktorym cos jest - do mapy ciepla w wyborze okresu.

    Liczy tym samym rachunkiem co `/summary` za pojedynczy miesiac, wiec kwota
    w kafelku siatki to kwota, ktora pokaze sie po kliknieciu w ten miesiac.
    """
    key = require_province(province)
    if not await module_enabled(key, "settlements"):
        raise HTTPException(403, "Moduł Rozliczeń nie jest włączony w tym okręgu")
    central_versions, province_versions = await _versions(key)
    assignments = await _assignments(key, judge_ids=[judge_id] if judge_id else None)
    rows = E.monthly_totals(
        assignments,
        province=key,
        central_versions=central_versions,
        province_versions=province_versions,
        now=_now(),
        include_future=include_future,
        include_zprp=include_zprp,
    )
    return {
        "province": key,
        "judge_id": judge_id,
        "include_future": include_future,
        "include_zprp": include_zprp,
        "months": rows,
    }


# ---------------------------------------------------------------------------
# Odswiezanie
# ---------------------------------------------------------------------------

class RefreshRequest(BaseModel):
    province: str
    username: Optional[str] = None
    password: Optional[str] = None
    with_outside: bool = True
    #: Reczne puszczenie z panelu: sprawdz, czy kazdy sezon byl chociaz raz
    #: pobrany w calosci, i nadrob brakujace. Automatyczne odswiezenie z ekranu
    #: sedziego tego NIE wysyla - pobiera tylko biezacy sezon. Patrz
    #: `settlement_seasons.plan_seasons`.
    full_check: bool = False


#: Zadania w tle trzymamy w zbiorze - asyncio trzyma do nich tylko slaba
#: referencje i porzucony task potrafi zniknac w polowie pobierania.
_BACKGROUND: set = set()


@router.post("/refresh", summary="Wymuś odświeżenie danych okręgu (w tle)")
async def refresh(payload: RefreshRequest):
    """
    Zaczyna pobieranie W TLE i od razu oddaje numer przebiegu.

    Pelne pobranie okregu to kilkaset zapytan do ZPRP i trwa minuty - czekanie
    na nie w jednym zapytaniu HTTP konczylo sie przekroczeniem czasu po stronie
    telefonu. Klient sledzi przebieg przez `/status` (`last_run.id`).
    """
    key = require_province(payload.province)
    if not (await module_enabled(key, "stats") or await module_enabled(key, "settlements")):
        raise HTTPException(403, "Żaden moduł okręgowy nie jest włączony w tym okręgu")

    now = _now()
    previous = await last_run(key)
    if previous and run_is_active(
        previous.get("started_at"),
        previous.get("finished_at"),
        now,
        previous.get("heartbeat_at"),
    ):
        return {"province": key, "started": False, "running": True, "run_id": previous.get("id")}

    with_credentials = bool(payload.username and payload.password)
    if previous and not with_credentials:
        left = cooldown_left(previous.get("finished_at"), previous.get("ok"), now)
        if left is not None:
            minutes = max(1, round(left.total_seconds() / 60))
            # Zadnej cichej blokady: klient dostaje zdanie do pokazania.
            return {
                "province": key,
                "started": False,
                "running": False,
                "run_id": previous.get("id"),
                "message": f"Dane odświeżono przed chwilą - kolejne odświeżenie możliwe za {minutes} min.",
            }

    run_id = await start_run(key, "manual")
    task = asyncio.create_task(
        refresh_province(
            key,
            username=payload.username,
            password=payload.password,
            kind="manual",
            with_outside=payload.with_outside,
            full_check=payload.full_check,
            run_id=run_id,
        )
    )
    _BACKGROUND.add(task)
    task.add_done_callback(_BACKGROUND.discard)
    return {"province": key, "started": True, "running": True, "run_id": run_id}


# ---------------------------------------------------------------------------
# Numeracja dokumentow
# ---------------------------------------------------------------------------

async def next_document_number(
    province: str, year: int, month: int, kind: str, *, peek: bool = False
) -> str:
    """
    Kolejny numer w okregu, miesiacu i rodzaju dokumentu: `SL/01/2026/1`.

    `peek` podaje numer, ktory PADNIE - nie rezerwuje go. Rezerwacja nastepuje
    dopiero przy zapisie dokumentu, bo numer bez wydruku to dziura w ksiazce.
    """
    from app.db import province_settlement_documents

    row = await database.fetch_one(
        select(province_settlement_documents.c.seq)
        .where(
            and_(
                province_settlement_documents.c.province == province,
                province_settlement_documents.c.kind == kind,
                province_settlement_documents.c.period_year == year,
                province_settlement_documents.c.period_month == month,
            )
        )
        .order_by(province_settlement_documents.c.seq.desc())
        .limit(1)
    )
    seq = int(row["seq"]) + 1 if row else 1
    return f"{province_short(province)}/{month:02d}/{year}/{seq}"


# ---------------------------------------------------------------------------
# Statystyki sedziego (BEZ pieniedzy)
# ---------------------------------------------------------------------------
#
# Osobny router, bo to osobny modul i osobne uprawnienie. Kwot tu NIE MA i nie
# wolno ich tu dolozyc - sedzia oglada swoje obciazenie, nie swoj rachunek.

stats_router = APIRouter(prefix="/province/stats", tags=["province_stats"])


def _season_of(day: Optional[date]) -> str:
    if not day:
        return ""
    year = day.year if day.month >= 9 else day.year - 1
    return f"{year}/{year + 1}"


@stats_router.get("/me", summary="Moje statystyki - dla aplikacji sędziego")
async def my_stats(
    province: str = Query(...),
    judge_id: str = Query(...),
    season: Optional[str] = Query(None, description="np. 2026/2027; brak = wszystko"),
    brief: bool = Query(False, description="Same sumy, bez listy meczów - dla kafla na ekranie Więcej"),
    include_future: bool = Query(
        False,
        description="Wlicz mecze jeszcze nierozegrane - przełącznik jak w rozliczeniu",
    ),
):
    key = require_province(province)
    if not await module_enabled(key, "stats"):
        raise HTTPException(403, "Moduł Statystyk nie jest włączony w tym okręgu")

    rows = await database.fetch_all(
        select(province_settlement_matches).where(
            and_(
                province_settlement_matches.c.province == key,
                province_settlement_matches.c.judge_id == judge_id,
                province_settlement_matches.c.active.is_(True),
            )
        )
    )

    now = _now()
    matches: list[dict] = []
    # Lista sezonow ze WSZYSTKICH meczow, zanim odfiltrujemy wybrany. Dotad
    # liczona byla po filtrze, wiec po wyborze sezonu (aplikacja wybiera
    # najnowszy od razu) pigulki kurczyly sie do jednej i minione sezony
    # znikaly z ekranu.
    all_seasons: set[str] = set()
    for row in rows:
        when = row["match_at"]
        day = when.date() if when else None
        season_label = _season_of(day)
        if season_label:
            all_seasons.add(season_label)
        if season and season_label != season:
            continue
        code = str(row["match_code"] or "")
        matches.append({
            "match_key": str(row["match_key"]),
            "match_at": when.isoformat() if when else None,
            "day": day.isoformat() if day else None,
            "season": season_label,
            "code": code,
            "category": R.category_label(code),
            "level": R.match_level(code),
            "role": str(row["role"] or ""),
            "origin": str(row["origin"] or ""),
            "city": str(row["city"] or ""),
            "hall": str(row["hall"] or ""),
            "teams": str(row["teams"] or ""),
            "distance_km": float(row["distance_km"]) if row["distance_km"] is not None else None,
            "future": bool(when and when > now),
        })

    matches.sort(key=lambda m: m["match_at"] or "", reverse=True)

    seasons = sorted(all_seasons, reverse=True)
    # Co wchodzi do sum: domyslnie tylko rozegrane, z przelacznikiem takze
    # przyszle - ta sama umowa co `include_future` w rozliczeniu.
    counted = matches if include_future else [m for m in matches if not m["future"]]

    def tally(field: str) -> dict[str, int]:
        out: dict[str, int] = {}
        for item in counted:
            value = str(item.get(field) or "").strip()
            if value:
                out[value] = out.get(value, 0) + 1
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))

    by_month: dict[str, int] = {}
    for item in counted:
        if item["day"]:
            by_month[item["day"][:7]] = by_month.get(item["day"][:7], 0) + 1

    distances = [m["distance_km"] for m in counted if m["distance_km"] is not None]

    return {
        "province": key,
        "judge_id": judge_id,
        "season": season,
        "seasons": seasons,
        "include_future": include_future,
        "totals": {
            "matches": len(counted),
            "future": sum(1 for m in matches if m["future"]),
            "district": sum(1 for m in counted if m["origin"] == "district"),
            "outside": sum(1 for m in counted if m["origin"] == "outside"),
            "km": round(sum(distances) * R.ROUND_TRIP, 1),
            "cities": len({m["city"] for m in counted if m["city"]}),
            "halls": len({m["hall"] for m in counted if m["hall"]}),
            "longest_km": max(distances) if distances else 0,
        },
        "by_category": tally("category"),
        "by_role": tally("role"),
        "by_level": tally("level"),
        "by_city": tally("city"),
        "by_month": dict(sorted(by_month.items())),
        # Kafel na ekranie Wiecej potrzebuje tylko sum - lista meczow sezonu
        # to najciezsza czesc odpowiedzi.
        "matches": [] if brief else matches,
    }
