"""
PDF-y rozliczeniowe okregu: zestawienie ekwiwalentow i lista kosztow przejazdow.

Wzorzec 1:1 jak `app/beach/settlements_pdf.py` - Jinja2 + WeasyPrint, logo
wpisane w HTML jako base64, gotowy plik pod jednorazowym tokenem. Roznica jest
jedna i istotna: NUMER DOKUMENTU rezerwuje sie dopiero przy udanym wydruku.
Numer bez pliku to dziura w ksiazce, a ksiegowosc pyta wtedy, co sie stalo
z „SL/01/2026/2".
"""

from __future__ import annotations

import base64
import logging
import os
import shutil
import tempfile
import urllib.parse
import uuid
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import insert, select

from app import settlement_rates as R
from app.db import database, province_settlement_documents
from app.province_settlement_sync import module_enabled
from app.province_settlements import (
    load_settlement,
    month_range,
    province_short,
    require_province,
)
from app.settlement_province import display
from app.settlement_words import amount_in_words, money, number

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province/settlements/pdf", tags=["province_settlements"])

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
DOWNLOAD_DIR = "/tmp/province_settlement_downloads"

MONTHS_PL = (
    "", "styczeń", "luty", "marzec", "kwiecień", "maj", "czerwiec",
    "lipiec", "sierpień", "wrzesień", "październik", "listopad", "grudzień",
)

#: Dane na papierze firmowym. Okreg, ktorego tu nie ma, dostanie sama nazwe -
#: lepszy naglowek bez adresu niz cudzy adres.
ORG_DETAILS: dict[str, dict[str, str]] = {
    "SLASKIE": {
        "name": "Śląski Związek Piłki Ręcznej",
        "address": "ul. Jesionowa 15, 40-159 Katowice",
    },
}


def _province_logo_b64(province: str) -> str:
    """Logo okregu, przeskalowane - pelnowymiarowy PNG puchnie plik bez potrzeby."""
    slug = R.province_key(province).lower()
    candidates = [
        TEMPLATE_DIR / "okregi" / f"{slug}.png",
        TEMPLATE_DIR / "okregi" / f"{slug.replace('_', '')}.png",
    ]
    # „KUJAWSKOPOMORSKIE" -> „kujawsko_pomorskie" i podobne warianty z podkresleniem.
    for name in os.listdir(TEMPLATE_DIR / "okregi") if (TEMPLATE_DIR / "okregi").exists() else []:
        if name.lower().replace("_", "").replace(".png", "") == slug:
            candidates.append(TEMPLATE_DIR / "okregi" / name)

    path = next((p for p in candidates if p.exists()), None)
    if not path:
        return ""
    try:
        from PIL import Image
        import io as _io

        image = Image.open(path)
        image.thumbnail((420, 420), Image.LANCZOS)
        buffer = _io.BytesIO()
        image.save(buffer, "PNG", optimize=True)
        return base64.b64encode(buffer.getvalue()).decode()
    except Exception:
        try:
            return base64.b64encode(path.read_bytes()).decode()
        except Exception:
            return ""


def _org(province: str) -> dict[str, str]:
    key = R.province_key(province)
    hit = ORG_DETAILS.get(key)
    if hit:
        return hit
    pretty = display(province).title()
    return {"name": f"Związek Piłki Ręcznej – {pretty}", "address": ""}


def _plural(count: int, one: str, few: str, many: str) -> str:
    if count == 1:
        return one
    last_two, last = count % 100, count % 10
    if 2 <= last <= 4 and not 12 <= last_two <= 14:
        return few
    return many


def _period_label(year: int, month: int, date_to: date, *, include_future: bool) -> str:
    start, end = month_range(year, month)
    today = datetime.now(timezone.utc).date()
    # Miesiac, ktory jeszcze trwa, oznaczamy tak samo - decyzja uzytkownika -
    # ale piszemy wprost, do kiedy naliczono, zeby nikt nie szukal reszty.
    if not include_future and today < end:
        return f"{MONTHS_PL[month]} {year} (do {min(today, end).strftime('%d.%m.%Y')})"
    return f"{MONTHS_PL[month]} {year}"


def _render(template_name: str, context: dict) -> str:
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    env.filters["money"] = money
    env.filters["km"] = lambda value: f"{number(value, 1)} km"
    env.filters["rate"] = lambda value: f"{number(value, 2)} zł/km"
    return env.get_template(template_name).render(**context)


def _to_pdf(html: str, base_name: str, filename: str) -> dict:
    import weasyprint

    tmp_dir = tempfile.mkdtemp()
    try:
        html_path = os.path.join(tmp_dir, f"{base_name}.html")
        pdf_path = os.path.join(tmp_dir, f"{base_name}.pdf")
        with open(html_path, "w", encoding="utf-8") as handle:
            handle.write(html)
        weasyprint.HTML(filename=html_path).write_pdf(pdf_path)

        os.makedirs(DOWNLOAD_DIR, exist_ok=True)
        token = str(uuid.uuid4())
        shutil.copyfile(pdf_path, os.path.join(DOWNLOAD_DIR, f"{token}.pdf"))
        return {
            "token": token,
            "download_url": (
                f"/province/settlements/pdf/download/{token}"
                f"?filename={urllib.parse.quote(filename)}"
            ),
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


async def _reserve_number(
    province: str,
    *,
    kind: str,
    year: int,
    month: int,
    judge_ids: list[str],
    include_future: bool,
    totals: dict,
    created_by: Optional[str],
) -> str:
    """Numer zapada dopiero tutaj - po tym, jak plik faktycznie powstal."""
    row = await database.fetch_one(
        select(province_settlement_documents.c.seq)
        .where(province_settlement_documents.c.province == province)
        .where(province_settlement_documents.c.kind == kind)
        .where(province_settlement_documents.c.period_year == year)
        .where(province_settlement_documents.c.period_month == month)
        .order_by(province_settlement_documents.c.seq.desc())
        .limit(1)
    )
    seq = int(row["seq"]) + 1 if row else 1
    number_text = f"{province_short(province)}/{month:02d}/{year}/{seq}"
    date_from, date_to = month_range(year, month)

    await database.execute(
        insert(province_settlement_documents).values(
            province=province,
            kind=kind,
            period_year=year,
            period_month=month,
            seq=seq,
            number=number_text,
            date_from=date_from,
            date_to=date_to,
            include_future=include_future,
            judge_ids=judge_ids,
            totals_json=totals,
            created_by=created_by,
        )
    )
    return number_text


class PdfRequest(BaseModel):
    province: str
    year: int
    month: int
    include_future: bool = False
    #: Puste = wszyscy sedziowie okregu z tego miesiaca.
    judge_ids: list[str] = []
    created_by: Optional[str] = None


@router.post("/zestawienie", summary="PDF: zestawienie ekwiwalentów sędziowskich")
async def zestawienie_pdf(payload: PdfRequest):
    province = require_province(payload.province)
    if not await module_enabled(province, "settlements"):
        raise HTTPException(403, "Moduł Rozliczeń nie jest włączony w tym okręgu")

    data = await load_settlement(
        province,
        year=payload.year,
        month=payload.month,
        include_future=payload.include_future,
        judge_ids=payload.judge_ids or None,
    )
    entries = data["entries"]
    totals = data["totals"]
    _, date_to = month_range(payload.year, payload.month)

    number_text = await _reserve_number(
        province,
        kind="zestawienie",
        year=payload.year,
        month=payload.month,
        judge_ids=[e.judge_id for e in entries],
        include_future=payload.include_future,
        totals=totals,
        created_by=payload.created_by,
    )

    org = _org(province)
    html = _render(
        "okreg_zestawienie.html",
        {
            "logo": _province_logo_b64(province),
            "org_name": org["name"],
            "org_address": org["address"],
            "document_number": number_text,
            "period_label": _period_label(
                payload.year, payload.month, date_to, include_future=payload.include_future
            ),
            "generated_at": datetime.now(timezone.utc).strftime("%d.%m.%Y"),
            "include_future": payload.include_future,
            "judges_count": totals["judges"],
            "judges_word": _plural(totals["judges"], "sędzia", "sędziów", "sędziów"),
            "matches_count": totals["matches"],
            "matches_word": _plural(totals["matches"], "mecz", "mecze", "meczów"),
            "rows": [
                {
                    "judge_id": e.judge_id,
                    "name": e.judge_name,
                    "matches": e.match_count,
                    "future": e.future_count if payload.include_future else 0,
                    "gross": e.gross,
                    "costs": e.costs,
                    "taxable": e.taxable,
                    "tax": e.tax,
                    "net": e.net,
                }
                for e in entries
            ],
            "totals": totals,
            "total_in_words": amount_in_words(totals["net"]),
        },
    )

    result = _to_pdf(html, "zestawienie", f"zestawienie_{number_text.replace('/', '_')}.pdf")
    return {"success": True, "number": number_text, **result}


@router.post("/przejazdy", summary="PDF: lista kosztów przejazdów")
async def przejazdy_pdf(payload: PdfRequest):
    province = require_province(payload.province)
    if not await module_enabled(province, "settlements"):
        raise HTTPException(403, "Moduł Rozliczeń nie jest włączony w tym okręgu")

    data = await load_settlement(
        province,
        year=payload.year,
        month=payload.month,
        include_future=payload.include_future,
        judge_ids=payload.judge_ids or None,
    )
    travel = data["travel"]
    _, date_to = month_range(payload.year, payload.month)

    rows: list[dict] = []
    previous = None
    for item in travel:
        rows.append(
            {
                "judge_id": item.judge_id,
                "name": item.judge_name,
                "day_label": item.day.strftime("%d.%m.%Y") if item.day else "—",
                "route": item.route,
                "one_way_km": item.one_way_km,
                "total_km": item.total_km,
                "rate": item.rate,
                "amount": item.amount,
                "first_of_judge": item.judge_id != previous,
            }
        )
        previous = item.judge_id

    total_amount = sum(r["amount"] for r in rows)
    total_km = sum(r["total_km"] for r in rows)
    judges_count = len({r["judge_id"] for r in rows})

    number_text = await _reserve_number(
        province,
        kind="przejazdy",
        year=payload.year,
        month=payload.month,
        judge_ids=sorted({r["judge_id"] for r in rows}),
        include_future=payload.include_future,
        totals={"amount": total_amount, "km": total_km, "trips": len(rows)},
        created_by=payload.created_by,
    )

    org = _org(province)
    html = _render(
        "okreg_przejazdy.html",
        {
            "logo": _province_logo_b64(province),
            "org_name": org["name"],
            "org_address": org["address"],
            "document_number": number_text,
            "period_label": _period_label(
                payload.year, payload.month, date_to, include_future=payload.include_future
            ),
            "include_future": payload.include_future,
            "judges_count": judges_count,
            "judges_word": _plural(judges_count, "sędzia", "sędziów", "sędziów"),
            "trips_word": _plural(len(rows), "wyjazd", "wyjazdy", "wyjazdów"),
            "rows": rows,
            "total_amount": total_amount,
            "total_km": total_km,
            "total_in_words": amount_in_words(total_amount),
        },
    )

    result = _to_pdf(html, "przejazdy", f"przejazdy_{number_text.replace('/', '_')}.pdf")
    return {"success": True, "number": number_text, **result}


@router.get("/documents", summary="Wystawione dokumenty okręgu")
async def documents(
    province: str = Query(...),
    year: Optional[int] = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    query = (
        select(province_settlement_documents)
        .where(province_settlement_documents.c.province == require_province(province))
        .order_by(province_settlement_documents.c.created_at.desc())
        .limit(limit)
    )
    if year:
        query = query.where(province_settlement_documents.c.period_year == year)
    rows = await database.fetch_all(query)
    return {
        "documents": [
            {
                "id": row["id"],
                "kind": row["kind"],
                "number": row["number"],
                "year": row["period_year"],
                "month": row["period_month"],
                "include_future": row["include_future"],
                "judges": len(row["judge_ids"] or []),
                "totals": row["totals_json"],
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                "created_by": row["created_by"],
            }
            for row in rows
        ]
    }


@router.get("/download/{token}", summary="Pobierz wygenerowany PDF")
async def download(token: str, filename: str = Query("rozliczenie.pdf")):
    safe = os.path.basename(token)
    path = os.path.join(DOWNLOAD_DIR, f"{safe}.pdf")
    if not os.path.exists(path):
        raise HTTPException(404, "Plik wygasł albo nie istnieje")
    return FileResponse(path, media_type="application/pdf", filename=filename)
