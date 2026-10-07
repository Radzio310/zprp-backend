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

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select, text

from app import settlement_rates as R
from app import settlement_register_rules as G
from app.deps import get_optional_jwt_payload
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import ensure_panel_write
from app.national_lookup_rules import NATIONAL_FOOTNOTE, SOURCE_NATIONAL as NATIONAL_SOURCE
from app.db import database, province_settlement_documents
from app.province_settlement_sync import module_enabled
from app.province_settlements import (
    load_settlement,
    month_range,
    province_short,
    require_province,
)
from app.settlement_province import display
from app.settlement_engine import display_judge_name
from app.settlement_pdf_groups import group_by_judge
from app.settlement_money import money as round2
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
    return {"name": f"Związek Piłki Ręcznej - {pretty}", "address": ""}


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
    # „3 wyjazdy" w wierszu „Razem" sędziego na liście przejazdów.
    env.filters["trips"] = lambda n: f"{n} {_plural(int(n), 'wyjazd', 'wyjazdy', 'wyjazdów')}"
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


def _pl_date(value: Optional[str]) -> str:
    """„2026-10-04" -> „04.10.2026"."""
    text = str(value or "")
    return f"{text[8:10]}.{text[5:7]}.{text[0:4]}" if len(text) >= 10 else "-"


class PdfRequest(BaseModel):
    province: str
    year: int
    month: int
    include_future: bool = False
    #: Doliczyc obsady rozliczane przez ZPRP (przelacznik panelu webowego).
    include_zprp: bool = False
    #: Puste = wszyscy sedziowie okregu z tego miesiaca.
    judge_ids: list[str] = []
    created_by: Optional[str] = None
    period_id: Optional[str] = None
    #: Szkic (False) nie zuzywa numeru i nie trafia do rejestru. Oficjalny
    #: dostaje numer ciagly w sezonie i zajmuje swoje pozycje (06.10.2026).
    official: bool = False
    #: Numer kolejny wpisany recznie przed wydaniem; brak = podpowiedz rejestru.
    seq: Optional[int] = None
    #: Czesci puli sedziow z podzialem: {judge_id: ["A"]}. Sedzia, ktorego tu
    #: nie ma, idzie ze wszystkimi czesciami; pusta lista = bez tego sedziego.
    parts: dict[str, list[str]] = {}


#: Szablon kazdego rodzaju dokumentu z rejestru.
TEMPLATES = {G.ZESTAWIENIE: "okreg_zestawienie.html", G.PRZEJAZDY: "okreg_przejazdy.html"}

#: Napis w miejscu numeru na szkicu.
DRAFT_NUMBER = "SZKIC"


def render_kind(province: str, kind: str, context: dict) -> dict:
    """
    PDF z kontekstu szablonu - wspolne dla wydania i ponownego pobrania
    z rejestru (`province_settlement_register`), zeby duplikat byl tym samym
    papierem. Logo dokladamy tutaj, bo nie trzymamy go w bazie.
    """
    html = _render(TEMPLATES[kind], {**context, "logo": _province_logo_b64(province)})
    number = str(context.get("document_number") or DRAFT_NUMBER)
    if context.get("draft"):
        filename = f"{kind}_SZKIC_{context.get('file_period') or ''}.pdf".replace("__", "_")
    else:
        filename = f"{kind}_{number.replace('/', '_')}.pdf"
    return {"filename": filename, **_to_pdf(html, kind, filename)}


def _period_info(payload: PdfRequest, data: dict) -> dict:
    date_from = date.fromisoformat(data["period"]["from"])
    date_to = date.fromisoformat(data["period"]["to"])
    label = (
        f"{date_from.strftime('%d.%m.%Y')} - {date_to.strftime('%d.%m.%Y')}"
        if payload.period_id
        else _period_label(payload.year, payload.month, date_to, include_future=payload.include_future)
    )
    return {
        "year": payload.year,
        "month": payload.month,
        # Sezon numeracji (07.10.2026): sezon OKRESU, nie dnia wydania.
        "season": G.period_season(date_from, data["period"].get("season")) or payload.year,
        "id": (payload.period_id or "").strip().lower() or None,
        "label": label,
        "from": date_from.isoformat(),
        "to": date_to.isoformat(),
    }


async def _issue(
    province: str,
    kind: str,
    payload: PdfRequest,
    period: dict,
    candidates: list[dict],
    build,
) -> dict:
    """
    Szkic albo oficjalny dokument z tych samych pozycji.

    `candidates` - pozycje dokumentu w kolejnosci ({judge_id, part, ...}),
    `build(items, number, draft)` -> (kontekst szablonu, sumy do rejestru).

    Szkic bierze wszystko, a pozycje juz wydane oznacza (`taken_by`). Oficjalny
    pomija pozycje zajete na innych oficjalnych dokumentach okresu i wydaje
    reszte pod blokada - dwa wydania naraz nie wezma ani tego samego numeru,
    ani tej samej czesci. PDF powstaje PRZED wpisem do rejestru: nieudany
    wydruk cofa transakcje i numer zostaje wolny.
    """
    from app import province_settlement_register as REG

    pid = period["id"] or ""
    if not payload.official:
        taken = await REG.period_taken(province, kind, period["year"], period["month"], pid)
        items, _ = G.select_items(candidates, taken, skip_taken=False)
        if not items:
            raise HTTPException(400, "Nie wybrano żadnej pozycji do dokumentu.")
        context, _totals = build(items, DRAFT_NUMBER, True)
        result = render_kind(province, kind, context)
        return {
            "success": True,
            "official": False,
            "number": DRAFT_NUMBER,
            "taken": [
                {"judge_id": i["judge_id"], "part": i.get("part") or "", "number": i["taken_by"]}
                for i in items
                if i.get("taken_by")
            ],
            **result,
        }

    async with database.transaction():
        await database.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:k))").bindparams(k=REG.issue_lock(province, kind))
        )
        taken = await REG.period_taken(province, kind, period["year"], period["month"], pid)
        items, skipped = G.select_items(candidates, taken, skip_taken=True)
        if not items:
            numbers = sorted({s["taken_by"] for s in skipped})
            raise HTTPException(
                409,
                "Wszystkie wybrane pozycje są już na oficjalnych dokumentach"
                + (f" ({', '.join(numbers)})" if numbers else "")
                + " - nie ma czego wydać.",
            )
        used = await REG.used_seqs(province, kind, period["season"])
        seq = payload.seq or G.suggest_seq(used, await REG.start_after(province, kind, period["season"]))
        problem = G.seq_problem(seq, used)
        if problem:
            raise HTTPException(409, problem)
        number = G.number_text(province_short(province), period["season"], int(seq), kind)
        context, totals = build(items, number, False)
        result = render_kind(province, kind, context)
        doc_id = await REG.insert_document(
            province,
            kind=kind,
            seq=int(seq),
            number=number,
            period=period,
            include_future=payload.include_future,
            include_zprp=payload.include_zprp,
            items=[_register_item(i) for i in items],
            totals=totals,
            context=context,
            created_by=payload.created_by,
        )
    return {
        "success": True,
        "official": True,
        "id": doc_id,
        "number": number,
        "skipped": [
            {
                "judge_id": i["judge_id"],
                "name": i.get("name"),
                "part": i.get("part") or "",
                "number": i["taken_by"],
            }
            for i in skipped
        ],
        **result,
    }


def _register_item(item: dict) -> dict:
    """Pozycja w rejestrze - tyle, ile trzeba do zajetosci i do podgladu."""
    keep = ("judge_id", "name", "part", "part_of", "matches", "gross", "net", "payable", "amount", "km")
    return {key: item.get(key) for key in keep if key in item}


def _zestawienie_candidates(entries: list, parts: dict[str, list[str]]) -> list[dict]:
    """
    Wiersze zestawienia: sedzia bez podzialu jednym wierszem, sedzia
    z obowiazujacym podzialem - wierszem na kazda WYBRANA czesc (kazda czesc
    to osobny rachunek: koszty, podatek, netto).
    """
    wanted = {str(k): v for k, v in (parts or {}).items()}
    out: list[dict] = []
    for e in entries:
        name = display_judge_name(e.judge_name)
        split_parts = list((e.split or {}).get("parts") or [])
        if not split_parts:
            out.append(
                {
                    "judge_id": e.judge_id,
                    "name": name,
                    "part": G.WHOLE,
                    "part_of": 0,
                    "matches": e.match_count,
                    "future": e.future_count,
                    "gross": e.gross,
                    "costs": e.costs,
                    "taxable": e.taxable,
                    "tax": e.tax,
                    "net": e.net,
                    "penalty": e.penalty,
                    "penalty_left": e.penalty_left,
                    "payable": round(e.net - e.penalty, 2),
                }
            )
            continue
        letters = G.wanted_parts(
            [p["letter"] for p in split_parts], wanted.get(e.judge_id)
        )
        penalties = G.allocate_penalty(split_parts, e.penalty)
        future_keys = {m.match_key for m in e.matches if m.future}
        for part in split_parts:
            letter = part["letter"]
            # Pusta część (0 zł - sędzia „nie uwzględniony" na tej liście) nie
            # trafia na żaden dokument.
            if letter not in letters or not part["gross"]:
                continue
            penalty = penalties.get(letter, 0.0)
            out.append(
                {
                    "judge_id": e.judge_id,
                    "name": name,
                    "part": letter,
                    "part_of": len(split_parts),
                    "matches": part["match_count"],
                    "future": sum(1 for k in part.get("match_keys") or [] if k in future_keys),
                    "gross": part["gross"],
                    "costs": part["costs"],
                    "taxable": part["taxable"],
                    "tax": part["tax"],
                    "net": part["net"],
                    "penalty": penalty,
                    "penalty_left": e.penalty_left if letter == split_parts[0]["letter"] else 0,
                    "payable": round(part["net"] - penalty, 2),
                }
            )
    return out


@router.post("/zestawienie", summary="PDF: zestawienie ekwiwalentów sędziowskich (szkic albo oficjalne)")
async def zestawienie_pdf(payload: PdfRequest, jwt: Optional[dict] = Depends(get_optional_jwt_payload)):
    province = require_province(payload.province)
    if not await module_enabled(province, "settlements"):
        raise HTTPException(403, "Moduł Rozliczeń nie jest włączony w tym okręgu")
    if payload.official:
        await ensure_panel_write(
            jwt, province=province, panel=PANEL_SETTLEMENTS, action="Wydanie oficjalnego zestawienia"
        )

    data = await load_settlement(
        province,
        year=payload.year,
        month=payload.month,
        include_future=payload.include_future,
        include_zprp=payload.include_zprp,
        judge_ids=payload.judge_ids or None,
        period_id=payload.period_id,
    )
    period = _period_info(payload, data)
    outside = data["outside_district"]
    bombs = data.get("bombs") or []
    candidates = _zestawienie_candidates(data["entries"], payload.parts)
    from app.province_settlement_register import doc_settings

    look = await doc_settings(province)

    def build(items: list[dict], number: str, draft: bool) -> tuple[dict, dict]:
        judges = {item["judge_id"] for item in items}
        rows = [
            {
                **item,
                # Część puli idzie na dokument BEZ oznaczenia „część A"
                # (decyzja z 07.10.2026) - wiersz to po prostu kwota sędziego.
                "split_note": "",
                "split_applied": False,
                # Na szkicu: pozycja jest juz na oficjalnym dokumencie.
                "taken_note": f"już na {item['taken_by']}" if draft and item.get("taken_by") else "",
            }
            for item in items
        ]
        totals = {
            "judges": len(judges),
            "matches": sum(int(r["matches"] or 0) for r in rows),
            "gross": round2(sum(float(r["gross"] or 0) for r in rows)),
            "costs": round2(sum(float(r["costs"] or 0) for r in rows)),
            "taxable": round2(sum(float(r["taxable"] or 0) for r in rows)),
            "tax": sum(int(r["tax"] or 0) for r in rows),
            "net": round2(sum(float(r["net"] or 0) for r in rows)),
        }
        penalty_total = round2(sum(float(r["penalty"] or 0) for r in rows))
        payable_total = round2(totals["net"] - penalty_total)
        context = {
            "draft": draft,
            "show_matches": bool(look.get("show_matches")),
            "file_period": f"{payload.month:02d}_{payload.year}",
            "org_name": _org(province)["name"],
            "org_address": _org(province)["address"],
            "document_number": number,
            "period_label": period["label"],
            "generated_at": datetime.now(timezone.utc).strftime("%d.%m.%Y"),
            "include_future": payload.include_future,
            "include_zprp": payload.include_zprp,
            "judges_count": totals["judges"],
            "judges_word": _plural(totals["judges"], "sędzia", "sędziów", "sędziów"),
            "matches_count": totals["matches"],
            "matches_word": _plural(totals["matches"], "mecz", "mecze", "meczów"),
            "rows": rows,
            "has_penalty": penalty_total > 0,
            "penalty_total": penalty_total,
            "payable_total": payable_total,
            # Nieobecnosci z Rejestru: mecz zdjety z wyplaty (i ewentualna kara).
            "bomb_rows": [
                {
                    "name": row.get("name") or row["judge_id"],
                    "day": _pl_date(row.get("day")),
                    "code": row.get("code") or "",
                    "teams": row.get("teams") or "",
                    "role": row.get("role") or "",
                    "lost": round(float(row.get("lost_gross") or 0) + float(row.get("lost_travel") or 0), 2),
                    "penalty": float(row.get("penalty") or 0),
                }
                for row in bombs
                if row["judge_id"] in judges
            ],
            # Przypis o czesciach puli - wylaczony razem z oznaczeniem czesci.
            "split_rows": 0,
            "totals": totals,
            "total_in_words": amount_in_words(payable_total),
            "outside_rows": [
                {"judge_id": e.judge_id, "name": display_judge_name(e.judge_name),
                 "matches": e.match_count, "gross": e.gross, "net": e.net,
                 "travel": e.travel, "total": e.total}
                for e in outside["entries"]
                if e.judge_id in judges
            ],
            "outside_totals": outside["totals"],
            "outside_clubs": outside["clubs"],
        }
        register_totals = {**totals, "penalty": penalty_total, "payable": payable_total}
        return context, register_totals

    return await _issue(province, G.ZESTAWIENIE, payload, period, candidates, build)


@router.post("/przejazdy", summary="PDF: lista kosztów przejazdów (szkic albo oficjalna)")
async def przejazdy_pdf(payload: PdfRequest, jwt: Optional[dict] = Depends(get_optional_jwt_payload)):
    province = require_province(payload.province)
    if not await module_enabled(province, "settlements"):
        raise HTTPException(403, "Moduł Rozliczeń nie jest włączony w tym okręgu")
    if payload.official:
        await ensure_panel_write(
            jwt, province=province, panel=PANEL_SETTLEMENTS, action="Wydanie oficjalnej listy przejazdów"
        )

    data = await load_settlement(
        province,
        year=payload.year,
        month=payload.month,
        include_future=payload.include_future,
        include_zprp=payload.include_zprp,
        judge_ids=payload.judge_ids or None,
        period_id=payload.period_id,
    )
    period = _period_info(payload, data)
    travel = data["travel"]
    outside = data["outside_district"]
    from app.province_settlement_register import doc_settings

    look = await doc_settings(province)

    # Przejazdy ida cale - sedzia jest pozycja, bez czesci puli.
    candidates: list[dict] = []
    seen: set[str] = set()
    for item in travel:
        if item.judge_id in seen:
            continue
        seen.add(item.judge_id)
        mine = [t for t in travel if t.judge_id == item.judge_id]
        candidates.append(
            {
                "judge_id": item.judge_id,
                "name": display_judge_name(item.judge_name),
                "part": G.WHOLE,
                "amount": round2(sum(t.amount for t in mine)),
                "km": sum(t.total_km for t in mine),
            }
        )
    if not candidates:
        raise HTTPException(400, "W wybranym okresie nie ma przejazdów do rozliczenia.")

    def build(items: list[dict], number: str, draft: bool) -> tuple[dict, dict]:
        judges = {item["judge_id"] for item in items}
        taken_by = {item["judge_id"]: item.get("taken_by") for item in items}
        rows: list[dict] = []
        previous = None
        for item in travel:
            if item.judge_id not in judges:
                continue
            rows.append(
                {
                    "judge_id": item.judge_id,
                    "name": display_judge_name(item.judge_name),
                    "day_label": item.day.strftime("%d.%m.%Y") if item.day else "-",
                    "route": item.route,
                    "one_way_km": item.one_way_km,
                    "total_km": item.total_km,
                    "rate": item.rate,
                    "amount": item.amount,
                    "first_of_judge": item.judge_id != previous,
                    # Kilometry z ogolnopolskiej tabeli ZPRP - znacznik przy odleglosci.
                    "national_km": item.distance_source == NATIONAL_SOURCE,
                    "taken_note": (
                        f"już na {taken_by[item.judge_id]}"
                        if draft and taken_by.get(item.judge_id) and item.judge_id != previous
                        else ""
                    ),
                }
            )
            previous = item.judge_id

        total_amount = round(sum(r["amount"] for r in rows), 2)
        total_km = sum(r["total_km"] for r in rows)
        outside_rows = []
        previous_outside = None
        for item in outside["travel"]:
            if item.judge_id not in judges:
                continue
            outside_rows.append({
                "judge_id": item.judge_id,
                "name": display_judge_name(item.judge_name),
                "day_label": item.day.strftime("%d.%m.%Y") if item.day else "-",
                "route": item.route,
                "total_km": item.total_km,
                "amount": item.amount,
                "first_of_judge": item.judge_id != previous_outside,
                "national_km": item.distance_source == NATIONAL_SOURCE,
            })
            previous_outside = item.judge_id

        context = {
            "draft": draft,
            "show_matches": bool(look.get("show_matches")),
            "file_period": f"{payload.month:02d}_{payload.year}",
            "org_name": _org(province)["name"],
            "org_address": _org(province)["address"],
            "document_number": number,
            "period_label": period["label"],
            "include_future": payload.include_future,
            "include_zprp": payload.include_zprp,
            "judges_count": len(judges),
            "judges_word": _plural(len(judges), "sędzia", "sędziów", "sędziów"),
            "trips_word": _plural(len(rows), "wyjazd", "wyjazdy", "wyjazdów"),
            "rows": rows,
            # Wyjazdy zebrane pod sedziami, z wierszem „Razem" dla kazdego.
            "groups": group_by_judge(rows),
            "total_amount": total_amount,
            "total_km": total_km,
            "total_in_words": amount_in_words(total_amount),
            "outside_rows": outside_rows,
            "outside_groups": group_by_judge(outside_rows),
            "outside_total_amount": round(sum(r["amount"] for r in outside_rows), 2),
            "outside_total_km": sum(r["total_km"] for r in outside_rows),
            "outside_clubs": outside["clubs"],
            "national_km": any(r["national_km"] for r in rows),
            "outside_national_km": any(r["national_km"] for r in outside_rows),
            "national_footnote": NATIONAL_FOOTNOTE,
        }
        totals = {"judges": len(judges), "amount": total_amount, "km": total_km, "trips": len(rows)}
        return context, totals

    return await _issue(province, G.PRZEJAZDY, payload, period, candidates, build)


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
                # „anulowana" = numer unieważniony przy odblokowaniu podziału na listy.
                "status": row["status"],
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
