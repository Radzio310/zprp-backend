"""
Kreator raportu finansów klubów - warstwa HTTP (`/province/club-report`).

Jeden filtr (okres, kategorie, kluby) i trzy wyniki z tych samych liczb:
- `POST /preview` - podgląd na żywo (sumy, liczniki chipów, wyciąg jednego klubu),
- `POST /pdf` - wyciąg JEDNEGO klubu (WeasyPrint, plik pod jednorazowym tokenem);
  hurt składa panel: PDF po PDF-ie z prawdziwym postępem, potem `POST /zip`,
- `POST /xlsx` - zeszyt Excela: podsumowanie, kategorie, mecze, arkusz per klub.

Dane czytamy z policzonego sezonu panelu klubów (`province_clubs.load_clubs`
i `_season_clubs` z pamięci `settlement_cache`) - raport nie liczy okręgu drugi
raz i nie może rozjechać się z kartą klubu. Reguły wyciągu: `club_report_rules`.

Kluby spoza programu okręgu (`settles_via_district = False`, na ekranie
„club-off") przy „wszystkie" pomijamy domyślnie i zwracamy, ilu pominięto -
wybrany świadomie klub wchodzi zawsze, z adnotacją na wyciągu.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import urllib.parse
import uuid
from datetime import date, datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select

from app import club_charges as C
from app import club_report_rules as RR
from app import province_club_budgets as CB
from app.club_report_excel import build_report_workbook
from app.province_panel_access import PANEL_SETTLEMENTS
from app.province_panel_guard import panel_read_gate
from app.settlement_money import money_sum
from app.settlement_province import display
from app.settlement_seasons import season_of

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/province/club-report", tags=["province_clubs"])

# Finanse klubów to dane prywatne okręgu - tylko dla osób z panelem Rozliczeń.
# ZIP skleja wyłącznie pliki z tokenów wydanych za tą bramką.
_READ = Depends(panel_read_gate(PANEL_SETTLEMENTS, "Raport finansów klubów"))

#: Ile meczów i wpisów idzie w podglądzie jednego klubu - kartka na ekranie
#: pokazuje początek, a resztę mówi liczbą.
PREVIEW_MATCHES = 40
PREVIEW_ENTRIES = 20
#: Teczka ZIP: kluby okręgu mieszczą się z zapasem.
ZIP_LIMIT = 400

_CREST_CACHE: dict[str, str] = {}


class ReportFilter(BaseModel):
    province: str
    season: Optional[str] = None
    date_from: Optional[date] = None
    date_to: Optional[date] = None
    #: `None` = wszystkie kategorie; lista = tylko te klucze (`club_report_rules`).
    categories: Optional[list[str]] = None
    #: Puste = wszystkie kluby w programie okręgu.
    club_ids: list[str] = []
    #: Przy „wszystkie": dołącz też kluby spoza programu okręgu.
    include_off: bool = False
    include_future: bool = False


class PreviewRequest(ReportFilter):
    #: Klub, którego wyciąg pokazuje kartka w podglądzie.
    focus: Optional[str] = None


class PdfRequest(ReportFilter):
    club_id: str


class ZipFile(BaseModel):
    token: str
    filename: str


class ZipRequest(BaseModel):
    files: list[ZipFile]
    filename: str = "wyciagi_klubow.zip"


def _s(value: Any) -> str:
    return str(value or "").strip()


def _initials(name: str) -> str:
    words = [w for w in _s(name).replace("-", " ").split() if w[:1].isalpha()]
    skip = {"KS", "MKS", "UKS", "SPR", "KPR", "MUKS", "LKS", "AZS", "SMS", "GKS", "MTS", "KU"}
    meaningful = [w for w in words if w.upper() not in skip] or words
    return "".join(w[0] for w in meaningful[:2]).upper() or "?"


async def _scope(payload: ReportFilter) -> dict:
    """Policzony sezon, zakres dat i wybrane kluby - wspólne dla trzech wyników."""
    from app.province_clubs import _season_clubs, load_clubs, pending_invoices, season_range
    from app.province_settlements import require_province

    key = require_province(payload.province)
    season = _s(payload.season) or season_of(datetime.now(timezone.utc))
    season_from, season_to = season_range(season)
    date_from, date_to, notes = RR.clamp_range(season_from, season_to, payload.date_from, payload.date_to)

    unknown = [k for k in (payload.categories or []) if k not in RR.BY_KEY]
    if unknown:
        raise HTTPException(400, f"Nieznane kategorie raportu: {', '.join(unknown)}")

    data = await load_clubs(key, season, include_future=payload.include_future)
    merged = await CB.merged_clubs(
        key, (await _season_clubs(key, season, include_future=payload.include_future))["clubs"]
    )
    pending = await pending_invoices(key, season)

    wanted = {_s(item) for item in payload.club_ids if _s(item)}
    picked: list[dict] = []
    skipped_off = 0
    for club in merged.values():
        members = [_s(m) for m in (club.get("member_ids") or [club["club_id"]])]
        off = not bool(club.get("settles_via_district", True))
        if wanted:
            if not (set(members) & wanted):
                continue
        elif off and not payload.include_off:
            skipped_off += 1
            continue
        picked.append({**club, "member_ids": members, "off": off})
    picked.sort(key=lambda item: _s(item.get("name")).lower())
    if wanted and not picked:
        raise HTTPException(404, "Żaden z wybranych klubów nie ma danych w tym sezonie.")

    charges_by: dict[str, list] = {}
    for row in data["charges"]:
        if row.status == C.CHARGED and row.club_id:
            charges_by.setdefault(_s(row.club_id), []).append(row)
    entries_by: dict[str, list] = {}
    for row in data["entries"]:
        entries_by.setdefault(_s(row["club_id"]), []).append(row)

    return {
        "key": key,
        "season": season,
        "season_from": season_from,
        "season_to": season_to,
        "date_from": date_from,
        "date_to": date_to,
        "notes": notes,
        "clubs": picked,
        "skipped_off": skipped_off,
        "charges_by": charges_by,
        "entries_by": entries_by,
        "pending": pending,
    }


def _club_rows(ctx: dict, club: dict) -> tuple[list, list, list]:
    members = club["member_ids"]
    charges = [row for m in members for row in ctx["charges_by"].get(m, [])]
    charges.sort(key=lambda row: (row.day or date.min, row.match_key))
    entries = [row for m in members for row in ctx["entries_by"].get(m, [])]
    pending = [item for m in members for item in ctx["pending"].get(m, [])]
    return charges, entries, pending


def _statement(ctx: dict, club: dict, categories: Optional[list[str]]) -> dict:
    charges, entries, pending = _club_rows(ctx, club)
    return RR.build_statement(
        charges=charges,
        entries=entries,
        pending=pending,
        season_from=ctx["season_from"],
        date_from=ctx["date_from"],
        date_to=ctx["date_to"],
        categories=categories,
    )


def _period_label(ctx: dict) -> str:
    return f"{RR.pl_date(ctx['date_from'])} - {RR.pl_date(ctx['date_to'])}"


async def _public_info(club_ids: list[str]) -> dict[str, dict]:
    """Adres i herb z katalogu klubów ZPRP (`zprp_public_clubs`) - jeśli jest."""
    if not club_ids:
        return {}
    try:
        from app.db import database, zprp_public_clubs as T

        rows = await database.fetch_all(
            select(T.c.club_id, T.c.city, T.c.street, T.c.postal_code, T.c.logo_url).where(T.c.club_id.in_(club_ids))
        )
    except Exception:  # katalog bywa pusty w nowym okręgu - wyciąg bez herbu też jest wyciągiem
        logger.warning("club_report: katalog klubów ZPRP niedostępny", exc_info=True)
        return {}
    out = {}
    for row in rows:
        street = _s(row["street"])
        city = " ".join(x for x in [_s(row["postal_code"]), _s(row["city"])] if x)
        out[_s(row["club_id"])] = {
            "address": ", ".join(x for x in [street, city] if x),
            "logo_url": _s(row["logo_url"]) or None,
        }
    return out


async def _crest_data_uri(url: Optional[str]) -> str:
    """Herb klubu jako data URI do PDF-a. Brak herbu albo sieci = monogram, nie błąd."""
    if not url:
        return ""
    if url in _CREST_CACHE:
        return _CREST_CACHE[url]
    uri = ""
    try:
        import httpx

        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True) as client:
            response = await client.get(url)
        if response.status_code == 200 and response.content:
            kind = (response.headers.get("content-type") or "").split(";")[0].strip().lower()
            if "svg" in kind:
                uri = "data:image/svg+xml;base64," + base64.b64encode(response.content).decode()
            else:
                from PIL import Image
                import io as _io

                image = Image.open(_io.BytesIO(response.content))
                image.thumbnail((240, 240))
                buffer = _io.BytesIO()
                image.save(buffer, "PNG", optimize=True)
                uri = "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode()
    except Exception:
        logger.info("club_report: herb %s nie zszedł - monogram", url, exc_info=True)
    _CREST_CACHE[url] = uri
    return uri


def _club_json(club: dict, st: dict, info: dict) -> dict:
    return {
        "club_id": club["club_id"],
        "name": club["name"],
        "off": club["off"],
        "member_ids": club["member_ids"],
        "logo_url": (info.get(club["club_id"]) or {}).get("logo_url"),
        "opening": st["opening"],
        "closing": st["closing"],
        "charged": st["charged"],
        "charged_scope": st["charged_scope"],
        "charged_other": st["charged_other"],
        "paid_in": st["paid_in"],
        "paid_out": st["paid_out"],
        "settled": st["settled"],
        "pending_in": st["pending_in"],
        "matches": len(st["matches"]),
        "entries": len(st["entries"]),
    }


@router.get("/categories", summary="Kategorie raportu i presety chipów")
async def categories():
    return {"categories": RR.categories_json({}), "presets": RR.presets_json()}


@router.post("/preview", summary="Kreator raportu: podgląd na żywo")
async def preview(payload: PreviewRequest, _access: None = _READ):
    ctx = await _scope(payload)
    info = await _public_info([club["club_id"] for club in ctx["clubs"]])

    counts_rows = []
    clubs_out = []
    statements: dict[str, dict] = {}
    for club in ctx["clubs"]:
        charges, _, _ = _club_rows(ctx, club)
        counts_rows.extend(charges)
        st = _statement(ctx, club, payload.categories)
        statements[club["club_id"]] = st
        clubs_out.append(_club_json(club, st, info))

    focus_id = _s(payload.focus)
    focus_club = next(
        (club for club in ctx["clubs"] if focus_id and (focus_id == club["club_id"] or focus_id in club["member_ids"])),
        ctx["clubs"][0] if ctx["clubs"] else None,
    )
    focus = None
    if focus_club:
        st = statements[focus_club["club_id"]]
        focus = {
            "club": {
                **_club_json(focus_club, st, info),
                "address": (info.get(focus_club["club_id"]) or {}).get("address") or "",
                "initials": _initials(focus_club["name"]),
            },
            **{k: v for k, v in st.items() if k not in ("matches", "entries")},
            "matches": st["matches"][:PREVIEW_MATCHES],
            "matches_total": len(st["matches"]),
            "entries": st["entries"][:PREVIEW_ENTRIES],
            "entries_total": len(st["entries"]),
        }

    # Oś sezonu w kreatorze: mecze w zakresie kategorii, miesiąc po miesiącu.
    months = RR.season_months(counts_rows, ctx["season_from"], payload.categories)

    def total(field: str) -> float:
        return money_sum(item[field] for item in clubs_out)

    return {
        "province": ctx["key"],
        "display": display(ctx["key"]),
        "season": ctx["season"],
        "season_from": ctx["season_from"].isoformat(),
        "season_to": ctx["season_to"].isoformat(),
        "date_from": ctx["date_from"].isoformat(),
        "date_to": ctx["date_to"].isoformat(),
        "period_label": _period_label(ctx),
        "scope_label": RR.scope_label(payload.categories),
        "notes": ctx["notes"],
        "skipped_off": ctx["skipped_off"],
        "categories": RR.categories_json(RR.category_counts(counts_rows, ctx["date_from"], ctx["date_to"], ctx["season_from"])),
        "presets": RR.presets_json(),
        "months": months,
        "clubs": clubs_out,
        "totals": {
            "clubs": len(clubs_out),
            "matches": sum(item["matches"] for item in clubs_out),
            "opening": total("opening"),
            "closing": total("closing"),
            "charged": total("charged"),
            "charged_scope": total("charged_scope"),
            "charged_other": total("charged_other"),
            "paid_in": total("paid_in"),
            "paid_out": total("paid_out"),
            "settled": total("settled"),
            "pending_in": total("pending_in"),
            "debtors": sum(1 for item in clubs_out if item["closing"] < 0),
        },
        "focus": focus,
    }


def _plural(count: int, one: str, few: str, many: str) -> str:
    if count == 1:
        return one
    if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return few
    return many


def _render_context(ctx: dict, club: dict, st: dict, info: dict, crest: str, categories: Optional[list[str]]) -> dict:
    from app.province_settlement_pdf import _org

    org = _org(ctx["key"])
    n = len(st["matches"])
    entries_in = sum(1 for e in st["entries"] if e["kind"] == "in")
    period_label = _period_label(ctx)
    footer = f"{club['name']} · {period_label}"
    closing = st["closing"]
    return {
        "org_name": org["name"],
        "org_address": org.get("address", ""),
        "club": {
            "club_id": club["club_id"],
            "name": club["name"],
            "off": club["off"],
            "address": (info.get(club["club_id"]) or {}).get("address") or "",
            "crest": crest,
            "initials": _initials(club["name"]),
            "members": [m for m in club["member_ids"]],
        },
        "season": ctx["season"],
        "season_start_label": RR.pl_date(ctx["season_from"]),
        "period_label": period_label,
        "opening_label": RR.pl_date(ctx["date_from"]),
        "scope_label": RR.scope_label(categories),
        "generated_label": datetime.now().strftime("%d.%m.%Y, %H:%M"),
        "notes": ctx["notes"],
        "st": st,
        "match_count_label": f"{n} {_plural(n, 'mecz', 'mecze', 'meczów')}",
        "all_count_label": (
            f"{n + st['other_count']} {_plural(n + st['other_count'], 'mecz', 'mecze', 'meczów')}"
            + (f", w zakresie {n}" if st["other_count"] else "")
        ),
        "other_label": f"{st['other_count']} {_plural(st['other_count'], 'mecz', 'mecze', 'meczów')}",
        "entries_in_label": f"{entries_in} {_plural(entries_in, 'wpłata', 'wpłaty', 'wpłat')}",
        "entries_word": _plural(len(st["entries"]), "wpis", "wpisy", "wpisów"),
        "closing_hint": "do zapłaty przez klub" if closing < 0 else ("nadpłata klubu" if closing > 0 else "rozliczony"),
        # Tekst w CSS stopki - bez cudzysłowów i nawiasów, które zamknęłyby regułę.
        "footer_css": "".join(ch for ch in footer if ch not in '"\\<>{}'),
    }


def render_statement_html(context: dict) -> str:
    """HTML wyciągu - osobno, żeby test i podgląd lokalny mogły go złożyć bez WeasyPrint."""
    from app.province_settlement_pdf import _render

    return _render("klub_wyciag.html", context)


@router.post("/pdf", summary="Kreator raportu: wyciąg klubu (PDF)")
async def statement_pdf(payload: PdfRequest, _access: None = _READ):
    from app.province_settlement_pdf import _province_logo_b64, _to_pdf

    ctx = await _scope(payload.model_copy(update={"club_ids": [payload.club_id]}))
    club = ctx["clubs"][0]
    info = await _public_info([club["club_id"]])
    st = _statement(ctx, club, payload.categories)
    crest = await _crest_data_uri((info.get(club["club_id"]) or {}).get("logo_url"))
    context = _render_context(ctx, club, st, info, crest, payload.categories)
    context["logo"] = _province_logo_b64(ctx["key"])
    html = render_statement_html(context)
    filename = (
        f"wyciag_{RR.safe_file_part(club['name'])}_"
        f"{ctx['date_from'].strftime('%Y%m%d')}-{ctx['date_to'].strftime('%Y%m%d')}.pdf"
    )
    try:
        # WeasyPrint jest synchroniczny - w wątku, żeby hurt nie zatrzymał serwera.
        result = await asyncio.to_thread(_to_pdf, html, "wyciag", filename)
    except Exception as exc:
        logger.exception("club_report: PDF dla %s nie powstał", club["club_id"])
        raise HTTPException(500, f"Nie udało się złożyć PDF-a dla {club['name']}: {exc}") from exc
    return {
        **result,
        "filename": filename,
        "club_id": club["club_id"],
        "name": club["name"],
        "closing": st["closing"],
        "matches": len(st["matches"]),
    }


@router.post("/zip", summary="Kreator raportu: wyciągi hurtem w jednym ZIP-ie")
async def statements_zip(payload: ZipRequest):
    import zipfile

    from app.province_settlement_pdf import DOWNLOAD_DIR

    if not payload.files:
        raise HTTPException(400, "Teczka jest pusta - najpierw powstają wyciągi.")
    if len(payload.files) > ZIP_LIMIT:
        raise HTTPException(400, f"Za dużo plików w jednej teczce (najwyżej {ZIP_LIMIT}).")
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    token = str(uuid.uuid4())
    target = os.path.join(DOWNLOAD_DIR, f"{token}.zip")
    used: set[str] = set()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in payload.files:
            source = os.path.join(DOWNLOAD_DIR, f"{os.path.basename(item.token)}.pdf")
            if not os.path.exists(source):
                raise HTTPException(404, f"Plik {item.filename} wygasł - wygeneruj wyciągi jeszcze raz.")
            name = os.path.basename(item.filename) or f"{item.token}.pdf"
            while name in used:
                name = f"_{name}"
            used.add(name)
            archive.write(source, arcname=name)
    filename = os.path.basename(payload.filename) or "wyciagi_klubow.zip"
    return {
        "token": token,
        "filename": filename,
        "download_url": (
            f"/province/settlements/pdf/download-zip/{token}?filename={urllib.parse.quote(filename)}"
        ),
    }


@router.post("/xlsx", summary="Kreator raportu: zeszyt Excela")
async def statements_xlsx(payload: ReportFilter, _access: None = _READ):
    ctx = await _scope(payload)
    if not ctx["clubs"]:
        raise HTTPException(404, "W tym filtrze nie ma żadnego klubu.")
    clubs = [
        {"club_id": club["club_id"], "name": club["name"], "off": club["off"], "statement": _statement(ctx, club, payload.categories)}
        for club in ctx["clubs"]
    ]
    meta = {
        "title": f"Finanse klubów - {display(ctx['key'])}",
        "province": display(ctx["key"]),
        "period_label": _period_label(ctx),
        "scope_label": RR.scope_label(payload.categories),
        "generated_label": "Wygenerowano " + datetime.now().strftime("%d.%m.%Y, %H:%M") + " w panelu rozliczeń BAZA",
    }
    data = await asyncio.to_thread(build_report_workbook, meta, clubs)
    name = (
        f"finanse_klubow_{RR.safe_file_part(ctx['key'], 20)}_"
        f"{ctx['date_from'].strftime('%Y%m%d')}-{ctx['date_to'].strftime('%Y%m%d')}.xlsx"
    )
    return Response(
        content=data,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )
