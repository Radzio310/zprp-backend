"""
Plik księgowej (04.11.2026) - warstwa HTTP i baza.

Do każdego zestawienia - szkicu i oficjalnego z Rejestru - BAZA wydaje
skoroszyt do wczytania ryczałtów w enova365: zakładka „Ryczałty sędziowskie"
(źródło i kontrola), „dane do importu" i „Import" jak u księgowej. Reguła
w `settlement_accounting_rules`, plik w `settlement_accounting_excel`.

Trasy:
  GET  /codes      - kody osób w enova: słownik okręgu + podpowiedzi z reguły
  PUT  /codes      - zapis (potwierdzenie) kodów; pusty kod = powrót do reguły
  POST /preview    - wiersze pliku bez pliku (ekran przed generowaniem)
  POST /xlsx       - plik: szkic (te same pola co PDF zestawienia) albo
                     dokument z Rejestru (`document_id`) - wtedy data wypłaty
                     zostaje zapamiętana przy dokumencie
  GET  /download/{token}

Zapisy przez bramkę panelu Rozliczeń, jak Rejestr.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.parse
import uuid
from datetime import date, datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import and_, delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import settlement_accounting_excel as X
from app import settlement_accounting_rules as A
from app import settlement_register_rules as G
from app.db import database, province_accounting_codes, province_settlement_register
from app.deps import get_optional_jwt_payload
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import panel_write_gate

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/province/settlements/accounting",
    tags=["province_settlements"],
    dependencies=[Depends(panel_write_gate(PANEL_SETTLEMENTS, "Plik księgowej"))],
)

C = province_accounting_codes
T = province_settlement_register
DOWNLOAD_DIR = "/tmp/province_accounting_downloads"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


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
    from app.province_settlements import require_province

    return require_province(province)


# ---------------------------------------------------------------------------
# Kody osób
# ---------------------------------------------------------------------------

async def saved_codes(key: str) -> dict[str, dict]:
    rows = await database.fetch_all(select(C).where(C.c.province == key))
    return {
        _s(row["judge_id"]): {
            "code": _s(row["code"]),
            "name": row["name"],
            "updated_by": row["updated_by"],
            "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
        }
        for row in rows
    }


async def province_people(key: str, extra: Optional[dict[str, str]] = None) -> dict[str, str]:
    """Sędziowie okręgu (numer -> „NAZWISKO Imię") - tło reguły zbieżnych nazwisk."""
    from app.province_settlements import _judge_names, _province_judge_ids
    from app.settlement_engine import display_judge_name

    names = await _judge_names(key)
    ids = await _province_judge_ids(key)
    people = {judge_id: display_judge_name(names.get(judge_id) or judge_id) for judge_id in ids}
    for judge_id, name in (extra or {}).items():
        people.setdefault(judge_id, name)
    return people


async def code_picks(key: str, extra: Optional[dict[str, str]] = None) -> tuple[dict[str, A.CodePick], dict[str, str]]:
    saved = await saved_codes(key)
    people = await province_people(key, extra)
    for judge_id, item in saved.items():
        people.setdefault(judge_id, item.get("name") or judge_id)
    picks = A.suggest_codes(people.items(), {j: v["code"] for j, v in saved.items()})
    return picks, people


@router.get("/codes", summary="Kody osób w enova księgowej - słownik okręgu z podpowiedziami")
async def get_codes(province: str = Query(...)):
    key = _require(province)
    picks, people = await code_picks(key)
    saved = await saved_codes(key)
    # Sama reguła (bez słownika) - „przywróć podpowiedź" na ekranie.
    rule = A.suggest_codes(people.items(), {})
    rows = []
    for judge_id, name in people.items():
        pick = picks[judge_id]
        rows.append(
            {
                "judge_id": judge_id,
                "name": name,
                "code": pick.code,
                "source": pick.source,
                "suggested": rule[judge_id].code,
                "conflict_with": [{"judge_id": o, "name": people.get(o, o)} for o in pick.conflict_with],
                "updated_by": (saved.get(judge_id) or {}).get("updated_by"),
                "updated_at": (saved.get(judge_id) or {}).get("updated_at"),
            }
        )
    rows.sort(key=lambda r: (not r["conflict_with"], r["name"]))
    return {
        "province": key,
        "codes": rows,
        "counts": {
            "all": len(rows),
            "saved": sum(1 for r in rows if r["source"] == "saved"),
            "conflicts": sum(1 for r in rows if r["conflict_with"]),
        },
    }


class CodeItem(BaseModel):
    judge_id: str
    code: str = ""
    name: Optional[str] = None


class CodesBody(BaseModel):
    province: str
    codes: list[CodeItem]
    user: Optional[str] = None


@router.put("/codes", summary="Zapisz kody osób w enova (pusty = wróć do reguły)")
async def save_codes(body: CodesBody):
    key = _require(body.province)
    if len(body.codes) > 2000:
        raise HTTPException(400, "Za dużo kodów naraz.")
    now = datetime.now(timezone.utc)
    saved = removed = 0
    async with database.transaction():
        for item in body.codes:
            judge_id = _s(item.judge_id)
            if not judge_id:
                continue
            code = A.normalize_code(item.code)
            if not code:
                await database.execute(delete(C).where(and_(C.c.province == key, C.c.judge_id == judge_id)))
                removed += 1
                continue
            values = {"code": code, "name": _s(item.name) or None, "updated_by": body.user, "updated_at": now}
            await database.execute(
                pg_insert(C)
                .values(province=key, judge_id=judge_id, **values)
                .on_conflict_do_update(index_elements=[C.c.province, C.c.judge_id], set_=values)
            )
            saved += 1
    logger.info("[accounting] %s: kody enova - zapisano %s, usunięto %s (%s)", key, saved, removed, body.user)
    return {"ok": True, "saved": saved, "removed": removed, **(await get_codes(key))}


# ---------------------------------------------------------------------------
# Wiersze pliku
# ---------------------------------------------------------------------------

class AccountingRequest(BaseModel):
    province: str
    #: Dokument z Rejestru - plik oficjalny. Brak = szkic z pól poniżej.
    document_id: Optional[int] = None
    #: Szkic: dokładnie te pola, co PDF zestawienia (`PdfRequest`).
    year: Optional[int] = None
    month: Optional[int] = None
    include_future: bool = False
    include_zprp: bool = False
    judge_ids: list[str] = []
    period_id: Optional[str] = None
    parts: dict[str, list[str]] = {}
    letter: Optional[str] = None
    #: „2026-11-09"; brak = zapamiętana przy dokumencie albo dziś.
    payout_date: Optional[str] = None
    created_by: Optional[str] = None


def _today() -> date:
    from zoneinfo import ZoneInfo

    return datetime.now(ZoneInfo("Europe/Warsaw")).date()


async def _period_payout(key: str, year: Any, month: Any, period_id: Any) -> Optional[date]:
    """Data wypłaty z własnego okresu rozliczeń okręgu - podpowiedź zamiast „dziś"."""
    if not _s(period_id):
        return None
    try:
        from app.province_settlements import settlement_range

        _from, _to, item = await settlement_range(key, int(year), int(month), _s(period_id).lower())
        return A.parse_day((item or {}).get("payout_date"))
    except Exception:  # noqa: BLE001 - okres usunięty: zostaje „dziś"
        return None


async def _document_job(key: str, body: AccountingRequest) -> tuple[list[dict], X.Meta, dict]:
    row = await database.fetch_one(select(T).where(and_(T.c.province == key, T.c.id == int(body.document_id))))
    if not row:
        raise HTTPException(404, "Tego dokumentu nie ma w rejestrze - mógł zostać usunięty.")
    if row["kind"] != G.ZESTAWIENIE:
        raise HTTPException(400, "Plik księgowej powstaje z zestawienia, nie z listy przejazdów.")
    context = _json(row["context_json"], {})
    accounting = _json(row["accounting_json"], {})
    items = _json(row["items_json"], [])
    payout = (
        A.parse_day(body.payout_date)
        or A.parse_day(accounting.get("payout_date"))
        or await _period_payout(key, row["period_year"], row["period_month"], row["period_id"])
        or _today()
    )
    from app.province_settlement_pdf import _org
    from app.province_settlement_register import doc_settings

    extra = (await doc_settings(key)).get("extra") or A.clean_extra({})
    meta = X.Meta(
        number=_s(row["number"]),
        draft=False,
        org_name=_s(context.get("org_name")) or _org(key)["name"],
        period_from=row["date_from"],
        period_to=row["date_to"],
        period_label=_s(row["period_label"]),
        payout_date=payout,
        # Formuła z dnia wydania - papier i plik mają te same kwoty.
        formula=A.formula_of(context.get("tax_formula")),
        enova=extra.get("enova") or {},
        list_letter=_s(context.get("list_letter")),
    )
    info = {
        "document_id": int(row["id"]),
        "number": meta.number,
        "official": True,
        "payout_saved": accounting.get("payout_date"),
    }
    return items, meta, info


async def _draft_job(key: str, body: AccountingRequest, jwt: Optional[dict]) -> tuple[list[dict], X.Meta, dict]:
    from app.province_settlement_pdf import PdfRequest, _org, zestawienie_job
    from app import province_settlement_register as REG

    if body.year is None or body.month is None:
        raise HTTPException(400, "Szkic pliku potrzebuje miesiąca rozliczenia.")
    payload = PdfRequest(
        province=key,
        year=int(body.year),
        month=int(body.month),
        include_future=body.include_future,
        include_zprp=body.include_zprp,
        judge_ids=body.judge_ids,
        created_by=body.created_by,
        period_id=body.period_id,
        official=False,
        parts=body.parts,
        letter=body.letter,
    )
    province, period, candidates, _build, extra = await zestawienie_job(payload, jwt)
    taken = await REG.period_taken(province, G.ZESTAWIENIE, period["year"], period["month"], period["id"] or "")
    items, _ = G.select_items(candidates, taken, skip_taken=False)
    if not items:
        raise HTTPException(400, "W tym okresie nie ma pozycji do zestawienia.")
    hint = await REG.suggestion(province, G.ZESTAWIENIE, period["season"])
    meta = X.Meta(
        number=_s(hint.get("number")),
        draft=True,
        org_name=_org(province)["name"],
        period_from=date.fromisoformat(period["from"]),
        period_to=date.fromisoformat(period["to"]),
        period_label=period["label"],
        payout_date=A.parse_day(body.payout_date)
        or await _period_payout(key, body.year, body.month, body.period_id)
        or _today(),
        formula=A.formula_of(extra.get("tax_formula")),
        enova=extra.get("enova") or {},
        list_letter=_s(body.letter).upper(),
    )
    taken_numbers = sorted({_s(i.get("taken_by")) for i in items if i.get("taken_by")})
    info = {"document_id": None, "number": meta.number, "official": False, "taken": taken_numbers}
    return items, meta, info


async def _job(body: AccountingRequest, jwt: Optional[dict]):
    key = _require(body.province)
    if body.document_id:
        items, meta, info = await _document_job(key, body)
    else:
        items, meta, info = await _draft_job(key, body, jwt)
    names = {_s(i.get("judge_id")): _s(i.get("name")) for i in items if i.get("judge_id")}
    picks, _people = await code_picks(key, names)
    rows = A.sheet_rows(items, picks, meta.formula)
    return key, rows, meta, info


def _preview(rows: list[A.SheetRow], meta: X.Meta, info: dict) -> dict:
    other = A.other_formula(meta.formula)
    return {
        **info,
        "draft": meta.draft,
        "period": {
            "from": meta.period_from.isoformat() if meta.period_from else None,
            "to": meta.period_to.isoformat() if meta.period_to else None,
            "label": meta.period_label,
            "text": A.period_text(meta.period_from, meta.period_to),
        },
        "doc_date": meta.period_to.isoformat() if meta.period_to else None,
        "payout_date": meta.payout_date.isoformat() if meta.payout_date else None,
        "formula": meta.formula,
        "formula_label": A.formula_label(meta.formula),
        "other_formula": other,
        "other_label": A.formula_short(other),
        "list_letter": meta.list_letter,
        "totals": A.totals(rows),
        "rows": [
            {
                "judge_id": r.judge_id,
                "name": r.name,
                "code": r.code,
                "code_source": r.code_source,
                "code_conflict": r.code_conflict,
                "part": r.part,
                "part_of": r.part_of,
                "gross": r.gross,
                "costs": r.costs,
                "taxable": r.taxable,
                "tax": r.tax,
                "net": r.net,
                "other_tax": r.other_tax,
                "differs": r.differs,
            }
            for r in rows
        ],
        "filename": A.file_name(meta.number, draft=meta.draft, period_tag=_period_tag(meta)),
    }


def _period_tag(meta: X.Meta) -> str:
    tag = meta.period_to.strftime("%m_%Y") if meta.period_to else ""
    return (f"lista_{meta.list_letter}_" if meta.list_letter else "") + tag


@router.post("/preview", summary="Wiersze pliku księgowej - bez pliku")
async def preview(body: AccountingRequest, jwt: Optional[dict] = Depends(get_optional_jwt_payload)):
    _key, rows, meta, info = await _job(body, jwt)
    return _preview(rows, meta, info)


@router.post("/xlsx", summary="Plik księgowej (.xlsx) - szkic albo dokument z Rejestru")
async def make_xlsx(body: AccountingRequest, jwt: Optional[dict] = Depends(get_optional_jwt_payload)):
    key, rows, meta, info = await _job(body, jwt)
    if not rows:
        raise HTTPException(400, "Dokument nie ma pozycji.")
    data = X.build_workbook(rows, meta)
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    token = str(uuid.uuid4())
    with open(os.path.join(DOWNLOAD_DIR, f"{token}.xlsx"), "wb") as handle:
        handle.write(data)
    result = _preview(rows, meta, info)
    if info.get("document_id") and meta.payout_date:
        # Data wypłaty zostaje przy dokumencie - następne pobranie ją podpowie.
        stored = {"payout_date": meta.payout_date.isoformat(), "updated_by": body.created_by}
        await database.execute(
            update(T)
            .where(and_(T.c.province == key, T.c.id == int(info["document_id"])))
            .values(accounting_json=json.dumps(stored, ensure_ascii=False))
        )
    logger.info(
        "[accounting] %s: plik księgowej %s (%s wierszy, %s) - %s",
        key, meta.number, len(rows), "szkic" if meta.draft else "oficjalny", body.created_by,
    )
    return {
        **result,
        "token": token,
        "download_url": (
            f"/province/settlements/accounting/download/{token}"
            f"?filename={urllib.parse.quote(result['filename'])}"
        ),
    }


@router.get("/download/{token}", summary="Pobierz plik księgowej")
async def download(token: str, filename: str = Query("ksiegowa.xlsx")):
    try:
        uuid.UUID(token)
    except ValueError:
        raise HTTPException(404, "Nie ma takiego pliku.")
    path = os.path.join(DOWNLOAD_DIR, f"{token}.xlsx")
    if not os.path.exists(path):
        raise HTTPException(404, "Plik wygasł - wygeneruj go jeszcze raz.")
    safe = os.path.basename(filename) or "ksiegowa.xlsx"
    if not safe.lower().endswith(".xlsx"):
        safe += ".xlsx"
    return FileResponse(path, media_type=XLSX, filename=safe)
