"""
Stawki CENTRALNE (Tabela Ryczaltow Sedziowskich ZPRP) jako dane serwera.

Dlaczego nie plik w aplikacji: tabela zmienia sie uchwala Zarzadu (ostatnio
44/26 z 28.08.2026) i do tej pory kazda zmiana wymagala wydania BAZY ORAZ
recznego przepisania tych samych kwot do BAZA_web. Dwie kopie rozjechaly sie
juz raz - web liczy caly sezon 2026/2027 ze starej tabeli.

Model jest scisle taki sam jak `okreg_rates`, tylko bez wojewodztwa:
- kazdy wiersz to PELNA, juz scalona tabela (`content`),
- obowiazuje w oknie `valid_from`..`valid_to`,
- klient wybiera wiersz DATA MECZU, nie dzisiejsza, zeby archiwum liczylo sie
  tak, jak liczylo sie wtedy.

Klient niczego nie scala. Blok roznicowy `od_2026_09` z `calcRates.json`
zostaje w aplikacji wylacznie jako kopia offline na pierwszy start i brak sieci.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import insert, or_, select, update

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None  # type: ignore

from app.db import central_rates, database
from app.schemas import (
    CentralRateItem,
    CreateCentralRateVersionRequest,
    GetCentralRateResponse,
    ListCentralRateVersionsResponse,
    UpdateCentralRateVersionRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/central_rates", tags=["central_rates"])

SEED_PATH = os.path.join(os.path.dirname(__file__), "data", "central_rates_seed.json")


def _warsaw_today() -> date:
    try:
        if ZoneInfo is None:
            return date.today()
        return datetime.now(timezone.utc).astimezone(ZoneInfo("Europe/Warsaw")).date()
    except Exception:
        return date.today()


def _item(row) -> CentralRateItem:
    data = dict(row)
    content = data.get("content")
    # JSONB potrafi wrocic napisem - wtedy trzeba go rozpakowac, nie oddac jak jest.
    if isinstance(content, str):
        try:
            content = json.loads(content)
        except Exception:
            content = {}
    data["content"] = content
    return CentralRateItem(**data)


def _pick_best(rows: list[dict]) -> Optional[dict]:
    """Najpozniejsze `valid_from`, potem najswiezszy zapis, potem najwyzsze id."""
    if not rows:
        return None

    def key(row: dict):
        return (
            row.get("valid_from") or date.min,
            row.get("updated_at") or datetime.min,
            row.get("id") or 0,
        )

    return max(rows, key=key)


# ---------------------------------------------------------------------------
# Odczyt
# ---------------------------------------------------------------------------

@router.get("/manifest", summary="Lekki indeks zmian, bez tabel kwot")
async def get_central_rates_manifest():
    """
    To samo, co `/admin/okreg_rates/manifest`: aplikacja pyta o to co kilkanascie
    minut i sciaga pelne tabele dopiero, gdy `revision` sie zmienil.
    """
    rows = await database.fetch_all(
        select(
            central_rates.c.id,
            central_rates.c.enabled,
            central_rates.c.valid_from,
            central_rates.c.valid_to,
            central_rates.c.updated_at,
        ).order_by(central_rates.c.id.asc())
    )

    items = [
        {
            key: (value.isoformat() if hasattr(value, "isoformat") else value)
            for key, value in dict(row).items()
        }
        for row in rows
    ]

    today = _warsaw_today().isoformat()
    effective = [
        item
        for item in items
        if item["enabled"]
        and (not item["valid_from"] or item["valid_from"] <= today)
        and (not item["valid_to"] or item["valid_to"] >= today)
    ]
    active = max(
        effective,
        key=lambda item: (item["valid_from"] or "", item["updated_at"] or "", item["id"]),
        default=None,
    )

    revision = hashlib.sha256(
        json.dumps([items, active["id"] if active else None], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    return JSONResponse(
        {"schema": 1, "revision": revision, "active_id": active["id"] if active else None, "count": len(items)},
        headers={"Cache-Control": "no-store"},
    )


@router.get("/versions", response_model=ListCentralRateVersionsResponse, summary="Wszystkie wersje tabeli centralnej")
async def list_central_rate_versions():
    rows = await database.fetch_all(
        select(central_rates).order_by(central_rates.c.valid_from.asc().nullsfirst(), central_rates.c.id.asc())
    )
    return ListCentralRateVersionsResponse(files=[_item(r) for r in rows])


@router.get("", response_model=GetCentralRateResponse, summary="Tabela obowiazujaca dzisiaj")
async def get_active_central_rate():
    today = _warsaw_today()
    rows = await database.fetch_all(
        select(central_rates).where(
            central_rates.c.enabled == True,  # noqa: E712
            or_(central_rates.c.valid_from == None, central_rates.c.valid_from <= today),  # noqa: E711
            or_(central_rates.c.valid_to == None, central_rates.c.valid_to >= today),  # noqa: E711
        )
    )
    best = _pick_best([dict(r) for r in rows])
    return GetCentralRateResponse(file=_item(best) if best else None)


# ---------------------------------------------------------------------------
# Zapis
# ---------------------------------------------------------------------------

@router.post("/versions", response_model=GetCentralRateResponse, status_code=status.HTTP_201_CREATED,
             summary="Nowa wersja tabeli centralnej")
async def create_central_rate_version(req: CreateCentralRateVersionRequest):
    if not isinstance(req.content, dict) or not req.content:
        raise HTTPException(400, "content musi byc niepustym obiektem")

    valid_from = req.valid_from
    valid_to = req.valid_to
    if valid_from is None and valid_to is not None:
        valid_from = _warsaw_today()
    if valid_from is not None and valid_to is not None and valid_to < valid_from:
        raise HTTPException(400, "valid_to nie moze byc wczesniejsze niz valid_from")

    new_id = await database.fetch_val(
        insert(central_rates)
        .values(
            content=req.content,
            label=(req.label or None),
            enabled=req.enabled,
            valid_from=valid_from,
            valid_to=valid_to,
        )
        .returning(central_rates.c.id)
    )

    # Domkniecie poprzedniej otwartej wersji dzien przed startem nowej. Bez tego
    # dwie wersje obowiazywalyby jednoczesnie i o kwocie decydowalaby kolejnosc
    # wierszy, czyli przypadek.
    if valid_from is not None:
        await database.execute(
            update(central_rates)
            .where(
                central_rates.c.id != new_id,
                central_rates.c.enabled == True,  # noqa: E712
                or_(central_rates.c.valid_to == None, central_rates.c.valid_to >= valid_from),  # noqa: E711
                or_(central_rates.c.valid_from == None, central_rates.c.valid_from < valid_from),  # noqa: E711
            )
            .values(valid_to=valid_from - timedelta(days=1))
        )

    row = await database.fetch_one(select(central_rates).where(central_rates.c.id == int(new_id)))
    return GetCentralRateResponse(file=_item(row) if row else None)


@router.put("/versions/{rate_id}", response_model=GetCentralRateResponse, summary="Poprawka konkretnej wersji")
async def update_central_rate_version(rate_id: int, req: UpdateCentralRateVersionRequest):
    row = await database.fetch_one(select(central_rates).where(central_rates.c.id == rate_id))
    if not row:
        raise HTTPException(404, "Nie znaleziono wersji")

    fields = getattr(req, "model_fields_set", None)
    if fields is None:
        fields = getattr(req, "__fields_set__", set())

    values: dict[str, Any] = {}
    if "content" in fields:
        if not isinstance(req.content, dict) or not req.content:
            raise HTTPException(400, "content musi byc niepustym obiektem")
        values["content"] = req.content
    if "label" in fields:
        values["label"] = req.label or None
    if "enabled" in fields:
        values["enabled"] = bool(req.enabled)
    if "valid_from" in fields:
        values["valid_from"] = req.valid_from
    if "valid_to" in fields:
        values["valid_to"] = req.valid_to

    if values:
        await database.execute(update(central_rates).where(central_rates.c.id == rate_id).values(**values))
        row = await database.fetch_one(select(central_rates).where(central_rates.c.id == rate_id))

    return GetCentralRateResponse(file=_item(row) if row else None)


@router.delete("/versions/{rate_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Usun wersje")
async def delete_central_rate_version(rate_id: int) -> Response:
    row = await database.fetch_one(select(central_rates).where(central_rates.c.id == rate_id))
    if not row:
        raise HTTPException(404, "Nie znaleziono wersji")
    await database.execute(central_rates.delete().where(central_rates.c.id == rate_id))
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# Zasilenie
# ---------------------------------------------------------------------------

async def seed_central_rates() -> None:
    """
    Wklada wersje startowe, gdy tabela jest PUSTA.

    Nigdy nie nadpisuje istniejacych wierszy: raz poprawiona przez czlowieka
    kwota nie moze wrocic do stanu z pliku przy najblizszym restarcie.
    """
    try:
        existing = await database.fetch_val(select(central_rates.c.id).limit(1))
        if existing is not None:
            return

        with open(SEED_PATH, encoding="utf-8") as handle:
            seed = json.load(handle)

        versions = seed.get("versions") or []
        if not versions:
            logger.warning("[central_rates] seed bez wersji - pomijam")
            return

        for version in versions:
            content = version.get("content")
            if not isinstance(content, dict) or not content:
                continue
            await database.execute(
                insert(central_rates).values(
                    content=content,
                    label=version.get("label"),
                    enabled=bool(version.get("enabled", True)),
                    valid_from=(date.fromisoformat(version["valid_from"]) if version.get("valid_from") else None),
                    valid_to=(date.fromisoformat(version["valid_to"]) if version.get("valid_to") else None),
                )
            )

        logger.info("[central_rates] zasilono %s wersji z pliku", len(versions))
    except Exception as exc:  # nie blokuj startu serwera
        logger.warning("[central_rates] zasilanie nieudane: %s", exc)
