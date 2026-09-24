"""
Ręczne mecze z rachunkiem (np. SPARING) - warstwa HTTP i most do rozliczeń.

Mecz dopisany z karty klubu w panelu klubów BAZA_web. Cała reguła (wycena,
netto -> brutto, przejazdy, zamiana na obsady silnika) siedzi w liściu
`manual_charge_rules`; tutaj tylko baza, odległości i trasy.

GDZIE TO WCHODZI - trzy mosty, każdy w jednym miejscu:
  - `manual_assignments` - dokładane w `province_settlements._assignments`,
    czyli w JEDYNYM miejscu, z którego biorą obsady: zestawienie miesiąca,
    PDF-y (ekwiwalenty, przejazdy), „Moje rozliczenia" sędziego, siatka
    miesięcy i przebieg panelu klubów. KUP i podatek liczą się od sumy
    miesiąca jak zawsze (`settle_period`),
  - `manual_charges_for` - w `province_clubs.load_clubs`: z tych samych,
    już przeliczonych obsad robi wiersze obciążeń klubu (saldo, lista meczów,
    suma sezonu, szablon Excela i alerty liczą je same),
  - `manual_stats_rows` - w `/province/stats/me` (kubełek „district").

⚠ Nie mylić z `province_manual_matches` (dopiski EHF do statystyk bez kwot).

Zapis przechodzi przez tę samą bramkę co panel klubów (konto VIP
z uprawnieniem „Rozliczenia") - patrz `province_panel_guard`.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import date, datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, delete, insert, select, update

from app import manual_charge_rules as M
from app import settlement_buckets as SB
from app import settlement_engine as E
from app import settlement_rates as R
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import panel_write_gate

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/province/manual-charges",
    tags=["province_manual_charges"],
    dependencies=[Depends(panel_write_gate(PANEL_SETTLEMENTS, "Ręczny mecz w panelu klubów"))],
)

#: Ile par miast wolno dopytać Google w jednej wycenie - obsada to kilka osób.
GOOGLE_LIMIT = 12


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _json(raw: Any, fallback: Any) -> Any:
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            return json.loads(raw)
        except ValueError:
            return fallback
    return fallback


def _require(province: str) -> str:
    # Import w funkcji: `province_settlements` ciągnie za sobą pół rozliczeń,
    # a on sam importuje ten moduł (w funkcji) - bez tego byłby cykl.
    from app.province_settlements import require_province

    return require_province(province)


# ---------------------------------------------------------------------------
# Odczyt z bazy
# ---------------------------------------------------------------------------

async def _records(province: str, *, club_id: Optional[str] = None) -> list[dict]:
    from app.db import database, province_manual_charges as T

    query = select(T).where(T.c.province == province)
    if club_id:
        query = query.where(T.c.club_id == club_id)
    try:
        rows = await database.fetch_all(query.order_by(T.c.day.asc(), T.c.id.asc()))
    except Exception as exc:  # tabela jeszcze nie założona - rozliczenia nie mogą przez to paść
        logger.warning("[manual_charges] odczyt %s: %s", province, exc)
        return []
    return [dict(row) for row in rows]


async def _club_names(province: str, club_ids: set[str]) -> dict[str, str]:
    """Nazwa klubu do napisu przy obsadzie - z ustawień panelu albo drużyny."""
    if not club_ids:
        return {}
    from app.db import database, province_club_teams, province_clubs

    out: dict[str, str] = {}
    rows = await database.fetch_all(
        select(province_clubs.c.club_id, province_clubs.c.display_name).where(
            and_(province_clubs.c.province == province, province_clubs.c.club_id.in_(sorted(club_ids)))
        )
    )
    for row in rows:
        if _s(row["display_name"]):
            out[_s(row["club_id"])] = _s(row["display_name"])
    missing = club_ids - set(out)
    if missing:
        rows = await database.fetch_all(
            select(province_club_teams.c.club_id, province_club_teams.c.team_name).where(
                and_(
                    province_club_teams.c.province == province,
                    province_club_teams.c.club_id.in_(sorted(missing)),
                )
            )
        )
        for row in rows:
            name = _s(row["team_name"])
            club_id = _s(row["club_id"])
            if name and (club_id not in out or len(name) < len(out[club_id])):
                out[club_id] = name
    # Okręg jako płatnik (`district_payer`) nie ma drużyn - bez nazwy nadanej
    # w panelu dostaje skrót związku („ŚlZPR").
    from app import district_payer as DP

    for club_id in club_ids:
        if DP.is_district_payer(club_id) and club_id not in out:
            out[club_id] = DP.default_label(province)
    return out


# ---------------------------------------------------------------------------
# Mosty do rozliczeń i panelu klubów
# ---------------------------------------------------------------------------

async def manual_assignments(
    province: str, *, judge_ids: Optional[list[str]] = None
) -> list[E.Assignment]:
    """Obsady z ręcznych meczów - dokładane do obsad z terminarza."""
    records = await _records(province)
    if not records:
        return []
    names = await _club_names(province, {_s(r["club_id"]) for r in records})
    wanted = {_s(j) for j in judge_ids} if judge_ids else None
    out: list[E.Assignment] = []
    for record in records:
        for item in M.assignments_of(record, club_name=names.get(_s(record["club_id"]), "")):
            if wanted is None or item.judge_id in wanted:
                out.append(item)
    return out


async def manual_charges_for(
    province: str, settled: list[Any], judge_names: Optional[dict[str, str]] = None
) -> list:
    """Wiersze obciążeń z przeliczonych obsad ręcznych meczów."""
    mine = [item for item in settled if M.is_manual_key(getattr(item, "match_key", ""))]
    if not mine:
        return []
    records = await _records(province)
    names = await _club_names(province, {_s(r["club_id"]) for r in records})
    return M.charge_rows(records, mine, judge_names=judge_names, club_names=names)


async def manual_stats_rows(province: str, judge_id: str) -> list[dict]:
    """
    Ręczne mecze sędziego w kształcie wiersza `province_settlement_matches`
    - do statystyk `/province/stats/me`. Kubełek zawsze „district": to mecz,
    który okręg sam obsadził i sam rozlicza.
    """
    out: list[dict] = []
    for item in await manual_assignments(province, judge_ids=[judge_id]):
        out.append(
            {
                "match_key": item.match_key,
                "match_at": item.match_at,
                "match_code": item.match_code,
                "role": item.role,
                "origin": item.origin,
                "city": item.city,
                "hall": "",
                "teams": item.teams,
                "distance_km": item.distance_km,
                "bucket": SB.DISTRICT,
            }
        )
    return out


# ---------------------------------------------------------------------------
# Stawki, sędziowie, miasta, odległości
# ---------------------------------------------------------------------------

async def _rate_versions(province: str) -> tuple[list[dict], list[dict]]:
    from app.province_settlements import _versions

    return await _versions(province)


async def _distance_book(province: str):
    from app.db import database, okreg_distances
    from app.settlement_distances import VersionedDistanceIndex
    from app.settlement_province import spellings

    row = await database.fetch_one(
        select(okreg_distances.c.content).where(okreg_distances.c.province.in_(spellings(province)))
    )
    content = _json(row["content"], None) if row else None
    return content, VersionedDistanceIndex(content)


def _table_cities(content: Any, day: Optional[date]) -> list[str]:
    """Miasta z tabeli odległości obowiązującej w dniu meczu - do podpowiedzi."""
    from app.settlement_distances import extract_pairs, pick_distance_table

    table = pick_distance_table(content, day)
    names: dict[str, str] = {}

    def put(value: Any) -> None:
        text = " ".join(_s(value).split())
        if text:
            names.setdefault(text.lower(), text)

    if isinstance(table, dict) and isinstance(table.get("cities"), list):
        for item in table["cities"]:
            put(item.get("name") if isinstance(item, dict) else item)
    for a, b, _ in extract_pairs(table):
        put(a)
        put(b)
    return sorted(names.values(), key=lambda value: R.strip_dia(value).lower())


async def _judges(province: str) -> list[dict]:
    """
    Sędziowie okręgu z miastem domowym - to samo źródło co silnik rozliczeń:
    lista „Sędziowie i Delegaci" z przebiegu (`province_settlement_judges`),
    a gdy tam miasta nie ma - obsady meczów w API (`settlement_names.judge_cities`).
    """
    from app.db import database, province_judges, province_settlement_judges
    from app.settlement_names import judge_cities, judge_names
    from app.settlement_province import spellings

    names = await judge_names(province)
    cities: dict[str, str] = {}
    ids: set[str] = set()
    for row in await database.fetch_all(
        select(province_settlement_judges).where(province_settlement_judges.c.province == province)
    ):
        judge_id = _s(row["judge_id"])
        ids.add(judge_id)
        if _s(row["home_city"]):
            cities[judge_id] = _s(row["home_city"])
    for row in await database.fetch_all(
        select(province_judges.c.judge_id).where(province_judges.c.province.in_(spellings(province)))
    ):
        ids.add(_s(row["judge_id"]))
    missing = [judge_id for judge_id in ids if judge_id not in cities]
    if missing:
        cities.update({k: v for k, v in (await judge_cities(missing)).items() if v})
    out = [
        {"judge_id": judge_id, "name": names.get(judge_id, ""), "home_city": cities.get(judge_id, "")}
        for judge_id in ids
        if judge_id and names.get(judge_id)
    ]
    out.sort(key=lambda item: E._sort_name(item["name"]))
    return out


def _google_key() -> str:
    key = (os.getenv("GOOGLE_MAPS_API_KEY") or "").strip()
    if key:
        return key
    try:  # ten sam klucz, którym BAZA_web dopytuje brakujące pary
        from app.baza_web import _GOOGLE_MAPS_API_KEY

        return _s(_GOOGLE_MAPS_API_KEY)
    except Exception:
        return ""


async def _google_km(client: Any, origin: str, destination: str) -> Optional[float]:
    key = _google_key()
    if not key or not origin or not destination:
        return None
    try:
        response = await client.get(
            "https://maps.googleapis.com/maps/api/distancematrix/json",
            params={
                "origins": f"{origin}, Polska",
                "destinations": f"{destination}, Polska",
                "mode": "driving",
                "avoid": "tolls",
                "language": "pl",
                "region": "PL",
                "key": key,
            },
        )
        data = response.json()
        element = ((data.get("rows") or [{}])[0].get("elements") or [{}])[0]
        if data.get("status") != "OK" or element.get("status") != "OK":
            return None
        meters = (element.get("distance") or {}).get("value")
        return round(float(meters) / 1000.0, 1) if isinstance(meters, (int, float)) else None
    except Exception as exc:
        logger.info("[manual_charges] google %s -> %s: %s", origin, destination, exc)
        return None


async def _resolve_km(officials: list[dict], city: str, day: Optional[date], province: str) -> list[dict]:
    """
    Kilometry w jedną stronę dla sędziów bez ręcznie wpisanej wartości:
    najpierw tabela okręgu z dnia meczu, potem Google, a gdy i tam nic -
    `none` i pole do wpisania (nigdy zgadnięte zero).
    """
    todo = [
        item for item in officials
        if _s(item.get("km_source")) != "manual" and _s(item.get("home_city")) and city
    ]
    if not todo:
        return officials
    _, book = await _distance_book(province)
    index = book.for_day(day)
    google_left = GOOGLE_LIMIT
    client = None
    try:
        for item in todo:
            hit = index.lookup(item["home_city"], city)
            if hit is not None:
                item["km_one_way"] = float(hit)
                item["km_source"] = "same-city" if hit == 0 else "table"
                continue
            if google_left <= 0:
                item["km_one_way"], item["km_source"] = None, "none"
                continue
            if client is None:
                import httpx

                client = httpx.AsyncClient(timeout=8.0)
            google_left -= 1
            value = await _google_km(client, item["home_city"], city)
            item["km_one_way"] = value
            item["km_source"] = "google" if value is not None else "none"
    finally:
        if client is not None:
            await client.aclose()
    return officials


# ---------------------------------------------------------------------------
# Trasy
# ---------------------------------------------------------------------------

class OfficialIn(BaseModel):
    judge_id: str = ""
    name: Optional[str] = None
    role: str = M.FIELD
    home_city: Optional[str] = None
    km_one_way: Optional[float] = None
    #: "manual" = wpisane ręcznie, nie nadpisujemy przy wycenie.
    km_source: Optional[str] = None


class ManualChargeIn(BaseModel):
    province: str
    club_id: Optional[str] = None
    day: Optional[date] = None
    match_time: Optional[str] = None
    code: Optional[str] = None
    city: Optional[str] = None
    travel_enabled: bool = True
    rate_mode: str = M.MODE_GROSS
    #: Ryczałt na sędziego w trybie `rate_mode`; pusto = domyślny z tabeli okręgu.
    field_fee: Optional[float] = None
    table_fee: Optional[float] = None
    officials: list[OfficialIn] = []
    note: Optional[str] = None
    #: Dopytaj kilometry dla sędziów bez ręcznej wartości (tabela, potem Google).
    resolve_km: bool = True
    user: Optional[str] = None


async def _price(payload: ManualChargeIn, key: str) -> dict:
    """Wycena - wspólna dla podglądu i zapisu, żeby zapis nie liczył inaczej."""
    day = payload.day
    code = M.clean_code(payload.code)
    central, provincial = await _rate_versions(key)
    when = day or _now().date()
    rate = M.km_rate(code, key, when, central_versions=central, province_versions=provincial)
    defaults = {
        role: M.default_fee(code, role, when, central_versions=central, province_versions=provincial)
        for role in (M.FIELD, M.TABLE)
    }
    mode = M.MODE_NET if _s(payload.rate_mode) == M.MODE_NET else M.MODE_GROSS

    def entered(value: Optional[float], role: str) -> float:
        if value is not None and value > 0:
            return float(value)
        # Pusto = domyślna stawka brutto; w trybie netto podpowiadamy jej netto.
        gross = defaults[role][0]
        return float(M.net_of(gross)) if mode == M.MODE_NET else float(gross)

    field_in = entered(payload.field_fee, M.FIELD)
    table_in = entered(payload.table_fee, M.TABLE)
    field_gross = M.fee_gross(field_in, mode)
    table_gross = M.fee_gross(table_in, mode)

    officials = [item.model_dump() if hasattr(item, "model_dump") else item.dict() for item in payload.officials]
    city = " ".join(_s(payload.city).split())
    if payload.resolve_km:
        officials = await _resolve_km(officials, city, day, key)
    priced = M.price_officials(
        officials,
        field_fee=field_gross,
        table_fee=table_gross,
        rate=rate,
        travel_enabled=bool(payload.travel_enabled),
    )
    totals = {**M.totals_of(priced), "km_rate": rate}
    return {
        "province": key,
        "day": day.isoformat() if day else None,
        "code": code,
        "city": city,
        "rate_mode": mode,
        "travel_enabled": bool(payload.travel_enabled),
        "km_rate": rate,
        "defaults": {
            role: {"gross": value, "net": M.net_of(value), "source": source}
            for role, (value, source) in defaults.items()
        },
        "fees": {
            M.FIELD: {"entered": field_in, "gross": field_gross, "net": M.net_of(field_gross)},
            M.TABLE: {"entered": table_in, "gross": table_gross, "net": M.net_of(table_gross)},
        },
        "officials": priced,
        "totals": totals,
        "problems": M.problems(
            day=day,
            city=city,
            officials=priced,
            field_fee=field_gross,
            table_fee=table_gross,
            travel_enabled=bool(payload.travel_enabled),
        ),
    }


@router.get("/options", summary="Ręczny mecz: sędziowie, miasta, stawki domyślne")
async def options(
    province: str = Query(...),
    day: Optional[date] = Query(None),
    code: Optional[str] = Query(None),
):
    key = _require(province)
    when = day or _now().date()
    central, provincial = await _rate_versions(key)
    content, _ = await _distance_book(key)
    rate = M.km_rate(code, key, when, central_versions=central, province_versions=provincial)
    defaults = {}
    for role in (M.FIELD, M.TABLE):
        value, source = M.default_fee(code, role, when, central_versions=central, province_versions=provincial)
        defaults[role] = {"gross": value, "net": M.net_of(value), "source": source}
    return {
        "province": key,
        "day": when.isoformat(),
        "code": M.clean_code(code),
        "km_rate": rate,
        "defaults": defaults,
        "judges": await _judges(key),
        "cities": _table_cities(content, when),
    }


@router.post("/quote", summary="Ręczny mecz: wycena na żywo (bez zapisu)")
async def quote(payload: ManualChargeIn):
    key = _require(payload.province)
    return await _price(payload, key)


@router.get("", summary="Ręczne mecze klubu")
async def list_manual(
    province: str = Query(...),
    club_id: Optional[str] = Query(None),
    season: Optional[str] = Query(None),
):
    key = _require(province)
    records = await _records(key, club_id=_s(club_id) or None)
    if season:
        records = [r for r in records if _s(r.get("season")) == _s(season)]
    return {"province": key, "items": [M.record_json(r) for r in records]}


@router.get("/{record_id}", summary="Ręczny mecz - do edycji")
async def get_manual(record_id: int, province: str = Query(...)):
    key = _require(province)
    record = next((r for r in await _records(key) if int(r["id"]) == record_id), None)
    if record is None:
        raise HTTPException(404, "Nie znaleziono takiego ręcznego meczu")
    return M.record_json(record)


def _values(payload: ManualChargeIn, priced: dict) -> dict:
    return {
        "day": payload.day,
        "match_time": _s(payload.match_time) or None,
        "code": priced["code"],
        "city": priced["city"],
        "distance_source": ",".join(sorted({o["km_source"] for o in priced["officials"]})) or None,
        "travel_enabled": bool(payload.travel_enabled),
        "rate_mode": priced["rate_mode"],
        "field_fee": priced["fees"][M.FIELD]["entered"],
        "table_fee": priced["fees"][M.TABLE]["entered"],
        "officials": json.dumps(priced["officials"], ensure_ascii=False),
        "totals": json.dumps(priced["totals"], ensure_ascii=False),
        "note": _s(payload.note)[:300] or None,
        "season": M.club_season(payload.day),
    }


def _refuse(priced: dict) -> None:
    if priced["problems"]:
        # Zero cichych blokad: odmowa wymienia każdy brak.
        raise HTTPException(400, " ".join(priced["problems"]))


@router.post("", summary="Dopisz ręczny mecz (obciążenie klubu + rozliczenie sędziów)")
async def create_manual(payload: ManualChargeIn):
    from app.db import database, province_manual_charges as T

    key = _require(payload.province)
    club_id = _s(payload.club_id)
    if not club_id:
        raise HTTPException(400, "Brak klubu - ręczny mecz dopisuje się z karty klubu.")
    priced = await _price(payload, key)
    _refuse(priced)
    now = _now()
    new_id = await database.execute(
        insert(T).values(
            province=key,
            club_id=club_id,
            created_by=_s(payload.user) or None,
            created_at=now,
            updated_by=_s(payload.user) or None,
            updated_at=now,
            **_values(payload, priced),
        )
    )
    return {"success": True, "id": int(new_id), "match_key": M.match_key(new_id), **priced}


@router.put("/{record_id}", summary="Popraw ręczny mecz")
async def update_manual(record_id: int, payload: ManualChargeIn):
    from app.db import database, province_manual_charges as T

    key = _require(payload.province)
    priced = await _price(payload, key)
    _refuse(priced)
    values = _values(payload, priced)
    if _s(payload.club_id):
        values["club_id"] = _s(payload.club_id)
    await database.execute(
        update(T)
        .where(and_(T.c.id == record_id, T.c.province == key))
        .values(updated_by=_s(payload.user) or None, updated_at=_now(), **values)
    )
    # `databases` nie zawsze oddaje liczbę wierszy - sprawdzamy wprost.
    exists = await database.fetch_one(select(T.c.id).where(and_(T.c.id == record_id, T.c.province == key)))
    if not exists:
        raise HTTPException(404, "Nie znaleziono takiego ręcznego meczu")
    return {"success": True, "id": record_id, "match_key": M.match_key(record_id), **priced}


@router.delete("/{record_id}", summary="Usuń ręczny mecz")
async def delete_manual(record_id: int, province: str = Query(...)):
    from app.db import database, province_manual_charges as T

    key = _require(province)
    exists = await database.fetch_one(select(T.c.id).where(and_(T.c.id == record_id, T.c.province == key)))
    if not exists:
        raise HTTPException(404, "Nie znaleziono takiego ręcznego meczu")
    await database.execute(delete(T).where(and_(T.c.id == record_id, T.c.province == key)))
    return {"success": True}
