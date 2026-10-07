"""
Rejestr oficjalnych dokumentów rozliczeń okręgu - warstwa HTTP i baza.

Reguła (numeracja ciągła w sezonie, zajętość części puli) w liściu
`settlement_register_rules`, schemat w `settlement_register_tables`. Samo
wydanie dokumentu robią trasy PDF (`province_settlement_pdf`) - tutaj jest
przegląd rejestru, ponowne pobranie, usunięcie (numer i pozycje wracają do
puli) i „kontynuacja numeracji" w ustawieniach.

Zapisy przez bramkę panelu Rozliczeń (`province_panel_guard`), jak podział.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, delete, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import settlement_register_rules as G
from app.db import (
    database,
    province_settlement_doc_settings,
    province_settlement_register,
    province_settlement_register_settings,
)
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import panel_write_gate

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/province/settlements/register",
    tags=["province_settlements"],
    dependencies=[Depends(panel_write_gate(PANEL_SETTLEMENTS, "Rejestr dokumentów rozliczeń"))],
)

T = province_settlement_register
ST = province_settlement_register_settings
DS = province_settlement_doc_settings

#: Domyślny wygląd dokumentów - liczba meczów UKRYTA (decyzja z 07.10.2026).
DOC_DEFAULTS = {"show_matches": False}


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


def dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _kind(kind: Any) -> str:
    value = _s(kind).lower()
    if value not in G.KINDS:
        raise HTTPException(400, f"Nieznany rodzaj dokumentu: {kind!r}")
    return value


def _require(province: str) -> str:
    from app.province_settlements import require_province

    return require_province(province)


def _short(key: str) -> str:
    from app.province_settlements import province_short

    return province_short(key)


# ---------------------------------------------------------------------------
# Odczyt - wołane także z tras PDF i podziału
# ---------------------------------------------------------------------------

def _doc_json(row: Any) -> dict:
    items = _json(row["items_json"], [])
    return {
        "id": row["id"],
        "kind": row["kind"],
        "number": row["number"],
        "number_year": row["number_year"],
        #: Sezon numeracji: „2026/27" (rok początku w `number_year`).
        "season": row["number_year"],
        "season_label": G.season_label(row["number_year"]),
        "seq": row["seq"],
        "period": {
            "year": row["period_year"],
            "month": row["period_month"],
            "id": row["period_id"] or None,
            "label": row["period_label"],
            "from": row["date_from"].isoformat() if row["date_from"] else None,
            "to": row["date_to"].isoformat() if row["date_to"] else None,
        },
        "include_future": bool(row["include_future"]),
        "include_zprp": bool(row["include_zprp"]),
        "items": items,
        "judges": len({_s(i.get("judge_id")) for i in items}),
        "totals": _json(row["totals_json"], {}),
        "created_by": row["created_by"],
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
    }


async def period_documents(key: str, kind: str, year: int, month: int, period_id: str) -> list[dict]:
    """Oficjalne dokumenty jednego okresu i rodzaju."""
    rows = await database.fetch_all(
        select(T).where(
            and_(
                T.c.province == key,
                T.c.kind == kind,
                T.c.period_year == int(year),
                T.c.period_month == int(month),
                T.c.period_id == _s(period_id).lower(),
            )
        )
    )
    return [_doc_json(row) for row in rows]


async def period_taken(
    key: str, kind: str, year: int, month: int, period_id: str
) -> dict[tuple[str, str], str]:
    """(sędzia, część) -> numer - pozycje zajęte w okresie."""
    try:
        return G.taken_map(await period_documents(key, kind, year, month, period_id))
    except Exception as exc:  # pragma: no cover - brak tabeli przed pierwszym startem
        logger.warning("[register] %s %s %s/%s: odczyt rejestru: %s", key, kind, month, year, exc)
        return {}


async def season_of_period(key: str, year: int, month: int, period_id: Optional[str]) -> int:
    """Sezon numeracji dla okresu rozliczenia (rok początku sezonu)."""
    from app.province_settlements import settlement_range

    date_from, _date_to, item = await settlement_range(key, year, month, _s(period_id).lower() or None)
    return G.period_season(date_from, (item or {}).get("season")) or int(year)


async def used_seqs(key: str, kind: str, number_year: int) -> list[int]:
    rows = await database.fetch_all(
        select(T.c.seq).where(
            and_(T.c.province == key, T.c.kind == kind, T.c.number_year == int(number_year))
        )
    )
    return [int(row["seq"]) for row in rows]


async def start_after(key: str, kind: str, number_year: int) -> int:
    row = await database.fetch_one(
        select(ST.c.start_after).where(
            and_(ST.c.province == key, ST.c.kind == kind, ST.c.number_year == int(number_year))
        )
    )
    return int(row["start_after"]) if row else 0


async def suggestion(key: str, kind: str, season: int) -> dict:
    """Numer, który podpowiada ekran przed wydaniem - bez rezerwacji."""
    used = await used_seqs(key, kind, season)
    after = await start_after(key, kind, season)
    seq = G.suggest_seq(used, after)
    short = _short(key)
    return {
        "seq": seq,
        "number": G.number_text(short, season, seq, kind),
        "prefix": G.number_prefix(short, season, kind),
        "last": max(used) if used else None,
        "start_after": after,
        "season": season,
        "season_label": G.season_label(season),
    }


async def insert_document(
    key: str,
    *,
    kind: str,
    seq: int,
    number: str,
    period: dict,
    include_future: bool,
    include_zprp: bool,
    items: list[dict],
    totals: dict,
    context: dict,
    created_by: Optional[str],
) -> int:
    """Wpis w rejestrze - wołać w transakcji z blokadą (`issue_lock`)."""
    from datetime import date

    return await database.fetch_val(
        insert(T)
        .values(
            province=key,
            kind=kind,
            number_year=int(period["season"]),
            seq=int(seq),
            number=number,
            period_year=int(period["year"]),
            period_month=int(period["month"]),
            period_id=_s(period.get("id")).lower(),
            period_label=period.get("label"),
            date_from=date.fromisoformat(period["from"]) if period.get("from") else None,
            date_to=date.fromisoformat(period["to"]) if period.get("to") else None,
            include_future=bool(include_future),
            include_zprp=bool(include_zprp),
            items_json=dump(items),
            totals_json=dump(totals),
            context_json=dump(context),
            created_by=created_by,
        )
        .returning(T.c.id)
    )


def issue_lock(key: str, kind: str) -> str:
    """Klucz blokady doradczej: dwa wydania naraz nie wezmą tego samego numeru."""
    return f"settlement-register:{key}:{kind}"


# ---------------------------------------------------------------------------
# Trasy
# ---------------------------------------------------------------------------

@router.get("", summary="Rejestr oficjalnych dokumentów okręgu - jeden sezon")
async def list_register(
    province: str = Query(...),
    season: int = Query(..., description="Rok początku sezonu: 2026 = 2026/27"),
    kind: Optional[str] = Query(None),
):
    key = _require(province)
    query = select(T).where(and_(T.c.province == key, T.c.number_year == int(season)))
    if kind:
        query = query.where(T.c.kind == _kind(kind))
    rows = await database.fetch_all(query.order_by(T.c.kind, T.c.seq.desc()))
    return {
        "province": key,
        "season": int(season),
        "season_label": G.season_label(season),
        "documents": [_doc_json(row) for row in rows],
        "next": {k: await suggestion(key, k, int(season)) for k in G.KINDS},
    }


@router.get("/period", summary="Zajętość pozycji i podpowiedź numeru dla okresu")
async def period_state(
    province: str = Query(...),
    year: int = Query(...),
    month: int = Query(...),
    period_id: Optional[str] = Query(None),
):
    key = _require(province)
    pid = _s(period_id).lower()
    season = await season_of_period(key, year, month, pid)
    taken = {}
    documents = {}
    issued = {}
    for kind in G.KINDS:
        docs = await period_documents(key, kind, year, month, pid)
        documents[kind] = [
            {"id": d["id"], "number": d["number"], "created_at": d["created_at"]} for d in docs
        ]
        taken[kind] = G.judge_view(G.taken_map(docs))
        # Ile z okresu jest już na oficjalnych dokumentach - do paska wypłaty
        # (07.10.2026): zestawienia netto (przed karą, jak suma na pasku),
        # przejazdy kwotą.
        field = "net" if kind == G.ZESTAWIENIE else "amount"
        issued[kind] = {
            "amount": round(sum(float((d["totals"] or {}).get(field) or 0) for d in docs), 2),
            "documents": len(docs),
        }
    return {
        "province": key,
        "season": season,
        "season_label": G.season_label(season),
        "taken": taken,
        "documents": documents,
        "issued": issued,
        "next": {kind: await suggestion(key, kind, season) for kind in G.KINDS},
    }


class DownloadBody(BaseModel):
    province: str
    id: int


@router.post("/download", summary="Pobierz ponownie oficjalny dokument z rejestru")
async def download_document(body: DownloadBody):
    key = _require(body.province)
    row = await database.fetch_one(select(T).where(and_(T.c.province == key, T.c.id == int(body.id))))
    if not row:
        raise HTTPException(404, "Tego dokumentu nie ma w rejestrze - mógł zostać usunięty.")
    from app import province_settlement_pdf as P

    context = _json(row["context_json"], {})
    if not context:
        raise HTTPException(409, "Dokument nie ma zapisanego wydruku.")
    result = P.render_kind(key, row["kind"], context)
    return {"ok": True, "number": row["number"], "kind": row["kind"], **result}


@router.delete("", summary="Usuń dokument z rejestru - numer i pozycje wracają do puli")
async def remove_document(
    province: str = Query(...),
    id: int = Query(...),
    user: Optional[str] = Query(None),
):
    key = _require(province)
    row = await database.fetch_one(select(T).where(and_(T.c.province == key, T.c.id == int(id))))
    if not row:
        raise HTTPException(404, "Tego dokumentu nie ma już w rejestrze.")
    await database.execute(delete(T).where(T.c.id == row["id"]))
    logger.info(
        "[register] %s: usunięto %s %s (wydał %s, usunął %s)",
        key, row["kind"], row["number"], row["created_by"], user,
    )
    return {
        "ok": True,
        "message": f"Usunięto {row['number']} z rejestru - numer i pozycje są znowu wolne.",
    }


class SettingsBody(BaseModel):
    province: str
    kind: str
    #: Rok początku sezonu: 2026 = 2026/27.
    season: int
    #: Ostatni numer wydany poza systemem - 0 = numeracja od 1.
    start_after: int = 0
    user: Optional[str] = None


@router.put("/settings", summary="Kontynuacja numeracji w sezonie")
async def save_settings(body: SettingsBody):
    key = _require(body.province)
    kind = _kind(body.kind)
    if body.start_after < 0 or body.start_after > G.MAX_SEQ:
        raise HTTPException(400, f"Ostatni numer musi być między 0 a {G.MAX_SEQ}.")
    values = {"start_after": int(body.start_after), "updated_by": body.user, "updated_at": _now()}
    await database.execute(
        pg_insert(ST)
        .values(province=key, kind=kind, number_year=int(body.season), **values)
        .on_conflict_do_update(index_elements=[ST.c.province, ST.c.kind, ST.c.number_year], set_=values)
    )
    return {"ok": True, "next": await suggestion(key, kind, int(body.season))}


async def doc_settings(key: str) -> dict:
    """Wygląd dokumentów okręgu - z bazy albo domyślny (`DOC_DEFAULTS`)."""
    try:
        row = await database.fetch_one(select(DS).where(DS.c.province == key))
    except Exception as exc:  # pragma: no cover - tabela przed pierwszym startem
        logger.warning("[register] %s: ustawienia dokumentów: %s", key, exc)
        row = None
    if not row:
        return dict(DOC_DEFAULTS)
    return {"show_matches": bool(row["show_matches"])}


@router.get("/doc-settings", summary="Wygląd dokumentów okręgu (np. liczba meczów)")
async def get_doc_settings(province: str = Query(...)):
    key = _require(province)
    return {"province": key, **await doc_settings(key)}


class DocSettingsBody(BaseModel):
    province: str
    show_matches: bool = False
    user: Optional[str] = None


@router.put("/doc-settings", summary="Zapisz wygląd dokumentów okręgu")
async def save_doc_settings(body: DocSettingsBody):
    key = _require(body.province)
    values = {"show_matches": bool(body.show_matches), "updated_by": body.user, "updated_at": _now()}
    await database.execute(
        pg_insert(DS)
        .values(province=key, **values)
        .on_conflict_do_update(index_elements=[DS.c.province], set_=values)
    )
    return {"ok": True, "province": key, **await doc_settings(key)}

