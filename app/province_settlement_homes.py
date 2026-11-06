"""
Panel okręgu: miejsce zamieszkania sędziów w rozliczeniach (06.11.2026).

  GET    /province/settlements/homes          - sędziowie z dzisiejszym miastem, wpisy historii,
                                                miasta z tabeli odległości, okresy wypłat do wyboru
  POST   /province/settlements/homes          - wpis „do dnia X mieszkał w Y" + przeliczenie
  POST   /province/settlements/homes/batch    - kilka wpisów naraz (zatwierdzenie wyników listy)
  DELETE /province/settlements/homes/{id}     - usunięcie wpisu + przeliczenie
  POST   /province/settlements/homes/scan     - wgrana lista przejazdów (PDF z BAZY): komu się zmieniło

Reguły i odczyt listy: `settlement_home_rules`; zapis i przeliczenie: `settlement_home_history`.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel

from app import settlement_home_history as HH
from app import settlement_home_rules as H
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import panel_write_gate

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/province/settlements/homes",
    tags=["province_settlements"],
    dependencies=[Depends(panel_write_gate(PANEL_SETTLEMENTS, "Miejsce zamieszkania sędziego w rozliczeniach"))],
)

#: Największy plik listy przejazdów (PDF z BAZY ma ~150 KB na 30 stron).
MAX_PDF_BYTES = 8 * 1024 * 1024


def _s(value: Any) -> str:
    return " ".join(str(value or "").split())


def require_province(province: str) -> str:
    # Import w funkcji: `app.province_settlements` łączy się z bazą przy imporcie.
    from app.province_settlements import require_province as require

    return require(province)


async def _judges(key: str) -> list[dict]:
    from app.province_manual_charges import _judges as manual_judges

    return await manual_judges(key)


async def _periods(key: str) -> list[dict]:
    """Okresy wypłat bieżącego i poprzedniego sezonu - „zmiana przed okresem X"."""
    from app import settlement_payout_ranges as P
    from app.province_settlement_periods import periods_for
    from app.season_rules import season_start_year

    today = datetime.now(timezone.utc).date()
    periods, _saved = await periods_for(key)
    out: list[dict] = []
    for season in (season_start_year(today) - 1, season_start_year(today)):
        start, end = P.season_span(season)
        for item in P.payout_ranges(periods, start, end):
            if item["from"] > today + timedelta(days=62):
                continue
            out.append({"id": item["id"], "label": item["label"], "from": item["from"].isoformat(), "to": item["to"].isoformat()})
    return out[-14:]


@router.get("", summary="Miejsce zamieszkania sędziów: dziś, historia zmian, miasta z tabeli")
async def overview(province: str = Query(...)):
    from app.province_manual_charges import _distance_book, _table_cities

    key = require_province(province)
    judges, entries = await asyncio.gather(_judges(key), HH.entries(key))
    content, _ = await _distance_book(key)
    names = {j["judge_id"]: j["name"] for j in judges}
    for entry in entries:
        entry["name"] = names.get(entry["judge_id"], entry["judge_id"])
    return {
        "province": key,
        "judges": [{"judge_id": j["judge_id"], "name": j["name"], "current": j.get("home_city") or None} for j in judges],
        "entries": entries,
        "cities": _table_cities(content, None),
        "periods": await _periods(key),
    }


class HomeEntryIn(BaseModel):
    province: str
    judge_id: str
    city: str
    until: date
    source: str = H.SOURCE_MANUAL
    ref: str | None = None
    user: str | None = None


class HomeBatchIn(BaseModel):
    province: str
    entries: list[HomeEntryIn]
    user: str | None = None


async def _apply(key: str, items: list[HomeEntryIn], user: str | None) -> dict:
    judges = {j["judge_id"]: j for j in await _judges(key)}
    clean: list[tuple[HomeEntryIn, str, date]] = []
    for item in items:
        judge_id = _s(item.judge_id)
        if judge_id not in judges:
            raise HTTPException(400, f"Sędziego nr {judge_id} nie ma na liście okręgu.")
        try:
            city, until = H.clean_entry(item.city, item.until)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        clean.append((item, city, until))
    saved: list[int] = []
    for item, city, until in clean:
        saved.append(await HH.save(key, item.judge_id, city, until, source=item.source, ref=item.ref, user=item.user or user))
    results = []
    for judge_id in dict.fromkeys(_s(item.judge_id) for item, _, _ in clean):
        results.append(await HH.recompute_judge(key, judge_id))
    return {
        "success": True,
        "ids": saved,
        "recomputed": results,
        "matches": sum(r["matches"] for r in results),
        "missing_km": sum(r["missing_km"] for r in results),
    }


@router.post("", summary="Zapisz: do dnia X sędzia mieszkał w Y (przelicza jego mecze)")
async def add_entry(payload: HomeEntryIn):
    key = require_province(payload.province)
    return await _apply(key, [payload], payload.user)


@router.post("/batch", summary="Zapisz kilka zmian miejsca zamieszkania naraz")
async def add_batch(payload: HomeBatchIn):
    key = require_province(payload.province)
    if not payload.entries:
        raise HTTPException(400, "Nie wybrano żadnej zmiany do zapisania.")
    return await _apply(key, payload.entries, payload.user)


@router.delete("/{entry_id}", summary="Usuń wpis historii miejsca zamieszkania (przelicza mecze)")
async def remove_entry(entry_id: int, province: str = Query(...)):
    key = require_province(province)
    judge_id = await HH.remove(key, entry_id)
    if judge_id is None:
        raise HTTPException(404, "Nie ma takiego wpisu.")
    result = await HH.recompute_judge(key, judge_id)
    return {"success": True, "recomputed": [result], "matches": result["matches"], "missing_km": result["missing_km"]}


def _pdf_text(data: bytes) -> str:
    import pymupdf

    with pymupdf.open(stream=data, filetype="pdf") as doc:
        return "\n".join(page.get_text() for page in doc)


@router.post("/scan", summary="Wgrana lista przejazdów: kto jeździł z innego miasta niż dziś")
async def scan(province: str = Query(...), file: UploadFile = File(...)):  # noqa: B008 - FastAPI
    key = require_province(province)
    data = await file.read(MAX_PDF_BYTES + 1)
    if len(data) > MAX_PDF_BYTES:
        raise HTTPException(413, "Plik jest za duży - lista przejazdów z BAZY ma zwykle kilkaset KB.")
    if not data.startswith(b"%PDF"):
        raise HTTPException(400, "To nie jest plik PDF. Wgraj listę przejazdów wydaną w BAZIE.")
    try:
        text = await asyncio.to_thread(_pdf_text, data)
    except Exception as exc:
        logger.info("[settlement] %s: nieczytelny PDF listy przejazdów: %s", key, exc)
        raise HTTPException(400, "Nie udało się odczytać tego PDF-u.") from exc
    parsed = H.parse_travel_list(text)
    if not parsed["judges"]:
        raise HTTPException(
            400,
            "W pliku nie znalazłem przejazdów w układzie listy z BAZY (Nazwisko, data, trasa „Dom-Hala-Dom”).",
        )
    if parsed["to"] is None:
        raise HTTPException(400, "Na liście nie ma okresu (np. „05.10.2026 - 01.11.2026”) - nie wiem, do kiedy obowiązywały stare dane.")
    judges, history = await asyncio.gather(_judges(key), HH.load(key))
    result = H.compare_list(parsed, judges, history)
    return {"province": key, "file": _s(file.filename) or None, **result}
