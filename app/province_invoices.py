"""
Faktury PDF jako wpłaty klubów - warstwa HTTP panelu klubów (Rozliczenia).

Przebieg:
  1. `POST /province/invoices/upload` - pliki PDF (jeden albo wiele, można
     dosyłać do tej samej partii przez `batch_id`, dzięki czemu panel pokazuje
     postęp plik po pliku). Każdy plik: odczyt regułami (`invoice_parse_rules`),
     a tylko gdy reguły zawiodą - AI (`invoice_ai`). Potem propozycja klubu
     (`invoice_match_rules`): najpierw zapamiętany NIP, potem nazwa.
  2. `POST /province/invoices/batches/{id}/approve` - zaznaczone pozycje
     (z ewentualnie zmienionym klubem, kwotą, opisem, datą) stają się
     WPŁATAMI (`province_club_entries`, kind "in", source "invoice"), a NIP
     nabywcy zapisuje się przy klubie.
  3. Historia: lista partii, pozycje partii i plik PDF - z historii i z wpłaty.

Faktura = wpłata na kwotę BRUTTO („Razem do zapłaty") z dniem wystawienia.
Ta sama faktura (numer + NIP sprzedawcy) nie wejdzie drugi raz: podsumowanie
mówi to od razu, a zatwierdzenie sprawdza jeszcze raz (dwie karty naraz).
Faktura, której wpłatę ktoś potem usunął w panelu, znowu jest do wzięcia.

Pliki PDF leżą w bazie (BYTEA) - uzasadnienie w `province_invoice_tables`.
Bramka zapisu: ta sama co w panelu klubów (konto VIP z „Rozliczeniami").
Okręg przy wysyłce plików MUSI być w adresie - bramka formularzy nie rozbiera.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import time
from datetime import date, datetime, timezone
from typing import Any, Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import and_, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app import invoice_match_rules as M
from app import invoice_parse_rules as P
from app.db import (
    database,
    province_club_entries,
    province_club_nips,
    province_invoice_batches,
    province_invoice_items,
)
from app.invoice_ai import read_invoice
from app.invoice_pdf import analyze_pdf, is_pdf
from app.province_panel_access import PANEL_SETTLEMENTS
from app.deps import get_jwt_payload
from app.province_panel_guard import panel_write_gate
from app.province_settlements import require_province
from app.settlement_seasons import season_of

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/province/invoices",
    tags=["province_invoices"],
    dependencies=[Depends(panel_write_gate(PANEL_SETTLEMENTS, "Wczytywanie faktur"))],
)

#: Faktura to zwykle 30-200 KB; 8 MB mieści skan kilku stron.
MAX_FILE_BYTES = 8 * 1024 * 1024
#: Plików w jednym żądaniu i w całej partii.
MAX_FILES_PER_REQUEST = 20
MAX_FILES_PER_BATCH = 60

STATUS_PROPOSED = "proposed"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_DUPLICATE = "duplicate"
STATUS_UNREADABLE = "unreadable"

#: Kandydaci (kluby i drużyny) na chwilę - panel wysyła pliki po jednym.
_CANDIDATES: dict[tuple[str, str], tuple[float, list[dict], dict[str, str]]] = {}
_CANDIDATES_TTL = 90.0

_ITEM_COLUMNS = [c for c in province_invoice_items.c if c.name != "pdf"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _s(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _json(raw: Any) -> Any:
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            return json.loads(raw)
        except Exception:
            return {}
    return {}


# ---------------------------------------------------------------------------
# kluby, NIP-y, budżety
# ---------------------------------------------------------------------------


async def _candidates(key: str, season: str) -> tuple[list[dict], dict[str, str]]:
    """([{club_id, name, names}], {club_id: nazwa}) - kluby sezonu z drużynami."""
    cached = _CANDIDATES.get((key, season))
    if cached and time.monotonic() - cached[0] < _CANDIDATES_TTL:
        return cached[1], cached[2]

    # Import w funkcji: panel klubów to duży moduł, a potrzebne są dwa zapytania.
    from app.province_clubs import _club_name, _club_settings, _teams

    _, _, meta = await _teams(key, season)
    settings = await _club_settings(key)
    names_of: dict[str, list[str]] = {}
    for item in meta.values():
        club_id = _s(item.get("club_id"))
        if club_id:
            names_of.setdefault(club_id, []).append(_s(item.get("name")))
    # Klub bez drużyny w tym sezonie, ale z nazwą nadaną w panelu - też kandydat.
    for club_id, row in settings.items():
        if _s(row.get("display_name")):
            names_of.setdefault(club_id, [])

    names: dict[str, str] = {}
    candidates: list[dict] = []
    for club_id, team_names in names_of.items():
        name = _club_name(settings, meta, club_id)
        names[club_id] = name
        all_names = [name] + [n for n in team_names if n and n != name]
        candidates.append({"club_id": club_id, "name": name, "names": all_names})
    # Okręg jako płatnik (`district_payer`) - faktura może trafić na niego tak
    # samo jak na klub. Zawsze na liście, pod nazwą z panelu albo skrótem związku.
    from app import district_payer as DP
    from app.settlement_province import display

    district_name = _club_name(settings, meta, DP.DISTRICT_PAYER_ID, key)
    names[DP.DISTRICT_PAYER_ID] = district_name
    candidates = [item for item in candidates if item["club_id"] != DP.DISTRICT_PAYER_ID]
    candidates.append(
        {
            "club_id": DP.DISTRICT_PAYER_ID,
            "name": district_name,
            "names": list(dict.fromkeys([district_name, DP.default_label(key), f"Okręg {display(key)}"])),
        }
    )
    # Nazwy klubów spoza sezonu (np. wpłata do klubu z zeszłego roku).
    for club_id, row in settings.items():
        names.setdefault(club_id, _s(row.get("display_name")) or club_id)

    _CANDIDATES[(key, season)] = (time.monotonic(), candidates, names)
    return candidates, names


async def _known_nips(key: str) -> dict[str, str]:
    rows = await database.fetch_all(
        select(province_club_nips.c.nip, province_club_nips.c.club_id).where(province_club_nips.c.province == key)
    )
    return {_s(row["nip"]): _s(row["club_id"]) for row in rows}


async def _budget_members(key: str, season: str) -> dict[str, str]:
    """
    Członek wspólnego budżetu -> klub główny. Moduł budżetów pisze kto inny
    (kontrakt `season_budgets(province, season)`), więc import w funkcji i bez
    niego zwykłe kluby.
    """
    try:
        from app import province_club_budgets as budgets  # type: ignore
    except Exception:
        return {}
    # `budget_groups` to jedno zapytanie; `season_budgets` liczy całe salda
    # sezonu - bierzemy go tylko, gdyby lżejszej funkcji zabrakło.
    light = getattr(budgets, "budget_groups", None)
    fn = getattr(budgets, "season_budgets", None)
    if light is None and fn is None:
        return {}
    try:
        raw = light(key) if light is not None else fn(key, season)
        if inspect.isawaitable(raw):
            raw = await raw
    except Exception as exc:  # noqa: BLE001 - brak budżetów nie może blokować faktur
        logger.warning("[province_invoices] budżety niedostępne: %s", exc)
        return {}
    return M.budget_members(raw)


# ---------------------------------------------------------------------------
# duplikaty
# ---------------------------------------------------------------------------


async def _live_entries(entry_ids: list[int]) -> set[int]:
    ids = [int(item) for item in entry_ids if item]
    if not ids:
        return set()
    rows = await database.fetch_all(
        select(province_club_entries.c.id).where(province_club_entries.c.id.in_(ids))
    )
    return {int(row["id"]) for row in rows}


async def _approved_by_key(key: str, invoice_keys: list[str], *, skip_item: Optional[int] = None) -> dict[str, dict]:
    """Zatwierdzone faktury o tych kluczach, których wpłata wciąż istnieje."""
    keys = [item for item in invoice_keys if item]
    if not keys:
        return {}
    rows = await database.fetch_all(
        select(
            province_invoice_items.c.id,
            province_invoice_items.c.batch_id,
            province_invoice_items.c.invoice_key,
            province_invoice_items.c.entry_id,
            province_invoice_items.c.decided_at,
            province_invoice_items.c.club_id,
        ).where(
            and_(
                province_invoice_items.c.province == key,
                province_invoice_items.c.status == STATUS_APPROVED,
                province_invoice_items.c.invoice_key.in_(keys),
            )
        )
    )
    live = await _live_entries([row["entry_id"] for row in rows])
    out: dict[str, dict] = {}
    for row in rows:
        if skip_item and int(row["id"]) == skip_item:
            continue
        if row["entry_id"] and int(row["entry_id"]) in live:
            out[_s(row["invoice_key"])] = {
                "item_id": int(row["id"]),
                "batch_id": int(row["batch_id"]),
                "club_id": _s(row["club_id"]),
                "decided_at": row["decided_at"].isoformat() if row["decided_at"] else None,
            }
    return out


async def _approved_by_sha(key: str, sha: str) -> Optional[dict]:
    """Zatwierdzony identyczny plik (po SHA-256), którego wpłata wciąż istnieje."""
    if not sha:
        return None
    rows = await database.fetch_all(
        select(
            province_invoice_items.c.id,
            province_invoice_items.c.batch_id,
            province_invoice_items.c.entry_id,
            province_invoice_items.c.club_id,
            province_invoice_items.c.decided_at,
        ).where(
            and_(
                province_invoice_items.c.province == key,
                province_invoice_items.c.status == STATUS_APPROVED,
                province_invoice_items.c.file_sha256 == sha,
            )
        )
    )
    live = await _live_entries([row["entry_id"] for row in rows])
    for row in rows:
        if row["entry_id"] and int(row["entry_id"]) in live:
            return {
                "item_id": int(row["id"]),
                "batch_id": int(row["batch_id"]),
                "club_id": _s(row["club_id"]),
                "decided_at": row["decided_at"].isoformat() if row["decided_at"] else None,
            }
    return None


# ---------------------------------------------------------------------------
# serializacja
# ---------------------------------------------------------------------------


def _has_pdf(row: Any) -> bool:
    """Kolumna wyliczana `has_pdf` (sam plik nie wychodzi z bazy w listach)."""
    try:
        return bool(row["has_pdf"])
    except Exception:  # noqa: BLE001 - zapytanie bez tej kolumny
        return True


def _item_json(row: Any, names: dict[str, str], live: set[int]) -> dict:
    parsed = _json(row["parsed_json"]) or {}
    match = _json(row["match_json"]) or {}
    club_id = _s(row["club_id"])
    entry_id = int(row["entry_id"]) if row["entry_id"] else None
    alternatives = []
    for alt in match.get("alternatives") or []:
        alt_id = _s(alt.get("club_id"))
        alternatives.append({**alt, "name": names.get(alt_id) or _s(alt.get("name")) or alt_id})
    day = row["issue_date"]
    return {
        "id": int(row["id"]),
        "batch_id": int(row["batch_id"]),
        "file_name": _s(row["file_name"]),
        "file_size": int(row["file_size"] or 0),
        "status": _s(row["status"]),
        "method": _s(row["method"]),
        "ai": _s(row["method"]).startswith("ai"),
        "note": _s(row["note"]),
        "invoice_no": _s(row["invoice_no"]),
        "issue_date": day.isoformat() if day else None,
        "due_date": parsed.get("due_date"),
        "season": season_of(day) if day else "",
        "seller_name": _s(parsed.get("seller_name")),
        "seller_nip": _s(row["seller_nip"]),
        "buyer_name": _s(row["buyer_name"]),
        "buyer_nip": _s(row["buyer_nip"]),
        "amount": float(row["amount"]) if row["amount"] is not None else None,
        "paid": parsed.get("paid"),
        "remaining": parsed.get("remaining"),
        "currency": _s(parsed.get("currency")) or "PLN",
        "items": parsed.get("items") or [],
        "missing": parsed.get("missing") or [],
        "description": _s(row["description"]),
        "club_id": club_id,
        "club_name": names.get(club_id, club_id) if club_id else "",
        "confidence": float(row["confidence"] or 0),
        "confident": bool(match.get("confident")),
        "via": _s(match.get("via")),
        "budget_of": _s(match.get("budget_of")),
        "budget_of_name": names.get(_s(match.get("budget_of")), "") if match.get("budget_of") else "",
        "alternatives": alternatives,
        "duplicate_of": match.get("duplicate_of"),
        "entry_id": entry_id,
        "entry_missing": bool(entry_id) and entry_id not in live,
        "has_pdf": _has_pdf(row),
        "decided_by": _s(row["decided_by"]),
        "decided_at": row["decided_at"].isoformat() if row["decided_at"] else None,
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
    }


def _batch_json(row: Any) -> dict:
    return {
        "id": int(row["id"]),
        "province": _s(row["province"]),
        "season": _s(row["season"]),
        "created_by": _s(row["created_by"]),
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
        "files": int(row["files"] or 0),
        "read_ok": int(row["read_ok"] or 0),
        "ai_used": int(row["ai_used"] or 0),
        "approved": int(row["approved"] or 0),
        "duplicates": int(row["duplicates"] or 0),
        "total": round(float(row["total"] or 0), 2),
        "approved_total": round(float(row["approved_total"] or 0), 2),
    }


async def _batch_row(key: str, batch_id: int):
    row = await database.fetch_one(
        select(province_invoice_batches).where(
            and_(province_invoice_batches.c.id == batch_id, province_invoice_batches.c.province == key)
        )
    )
    if row is None:
        raise HTTPException(404, "Nie znaleziono takiej partii faktur w tym okręgu")
    return row


async def _refresh_counters(batch_id: int) -> None:
    rows = await database.fetch_all(
        select(
            province_invoice_items.c.status,
            province_invoice_items.c.method,
            province_invoice_items.c.amount,
        ).where(province_invoice_items.c.batch_id == batch_id)
    )
    files = len(rows)
    read_ok = sum(1 for row in rows if _s(row["status"]) != STATUS_UNREADABLE)
    ai_used = sum(1 for row in rows if _s(row["method"]).startswith("ai"))
    approved = [row for row in rows if _s(row["status"]) == STATUS_APPROVED]
    duplicates = sum(1 for row in rows if _s(row["status"]) == STATUS_DUPLICATE)
    total = sum(
        float(row["amount"] or 0)
        for row in rows
        if _s(row["status"]) not in (STATUS_DUPLICATE, STATUS_REJECTED)
    )
    await database.execute(
        update(province_invoice_batches)
        .where(province_invoice_batches.c.id == batch_id)
        .values(
            files=files,
            read_ok=read_ok,
            ai_used=ai_used,
            approved=len(approved),
            duplicates=duplicates,
            total=round(total, 2),
            approved_total=round(sum(float(row["amount"] or 0) for row in approved), 2),
            updated_at=_now(),
        )
    )


async def _batch_detail(key: str, batch_id: int) -> dict:
    batch = await _batch_row(key, batch_id)
    rows = await database.fetch_all(
        select(*_ITEM_COLUMNS, province_invoice_items.c.pdf.isnot(None).label("has_pdf"))
        .where(province_invoice_items.c.batch_id == batch_id)
        .order_by(province_invoice_items.c.id.asc())
    )
    season = _s(batch["season"]) or season_of(_now())
    _, names = await _candidates(key, season)
    live = await _live_entries([row["entry_id"] for row in rows])
    items = [_item_json(row, names, live) for row in rows]
    return {
        "batch": _batch_json(batch),
        "items": items,
        "summary": _summary(items),
    }


def _summary(items: list[dict]) -> dict:
    open_items = [item for item in items if item["status"] in (STATUS_PROPOSED, STATUS_UNREADABLE)]
    return {
        "files": len(items),
        "proposed": sum(1 for item in items if item["status"] == STATUS_PROPOSED),
        "confident": sum(1 for item in items if item["status"] == STATUS_PROPOSED and item["confident"]),
        "unreadable": sum(1 for item in items if item["status"] == STATUS_UNREADABLE),
        "duplicates": sum(1 for item in items if item["status"] == STATUS_DUPLICATE),
        "approved": sum(1 for item in items if item["status"] == STATUS_APPROVED),
        "rejected": sum(1 for item in items if item["status"] == STATUS_REJECTED),
        "ai": sum(1 for item in items if item["ai"]),
        "open_total": round(sum(item["amount"] or 0 for item in open_items), 2),
    }


# ---------------------------------------------------------------------------
# analiza jednego pliku
# ---------------------------------------------------------------------------


async def _analyze(data: bytes) -> tuple[dict, str, str]:
    """(pola, metoda, notatka). Metoda: rules | ai-text | ai-vision | none."""
    try:
        read = await asyncio.to_thread(analyze_pdf, data)
    except Exception as exc:  # noqa: BLE001
        return {"missing": ["gross", "buyer"], "items": []}, "none", f"PDF jest uszkodzony albo zaszyfrowany: {exc}"

    parsed = read["parsed"]
    if not P.needs_ai(parsed, has_text=read["has_text"]):
        return parsed, "rules", ""

    ai, method, reason = await read_invoice(text=read["text"], pdf_bytes=data, has_text=read["has_text"])
    if ai is None:
        why = "Skan bez warstwy tekstu." if not read["has_text"] else "Reguły nie znalazły kwoty albo nabywcy."
        return parsed, "rules" if read["has_text"] else "none", f"{why} {reason}".strip()
    merged = P.merge_ai(parsed, ai)
    return merged, method, ""


@router.post("/upload", summary="Wgraj faktury PDF i odczytaj je (partia z propozycjami wpłat)")
async def upload(
    province: str = Query(...),
    season: Optional[str] = Query(None),
    created_by: Optional[str] = Query(None),
    batch_id: Optional[int] = Query(None, description="Dosyłanie plików do istniejącej partii"),
    files: list[UploadFile] = File(...),
):
    key = require_province(province)
    season = _s(season) or season_of(_now())
    if not files:
        raise HTTPException(400, "Nie wybrano żadnego pliku")
    if len(files) > MAX_FILES_PER_REQUEST:
        raise HTTPException(400, f"Jednorazowo można wysłać najwyżej {MAX_FILES_PER_REQUEST} plików")

    if batch_id:
        batch = await _batch_row(key, batch_id)
        season = _s(batch["season"]) or season
        count = await database.fetch_val(
            select(func.count()).select_from(province_invoice_items).where(province_invoice_items.c.batch_id == batch_id)
        )
        if int(count or 0) + len(files) > MAX_FILES_PER_BATCH:
            raise HTTPException(400, f"Jedna partia mieści najwyżej {MAX_FILES_PER_BATCH} faktur - zacznij nową")
    else:
        batch_id = int(
            await database.execute(
                insert(province_invoice_batches).values(
                    province=key,
                    season=season,
                    created_by=_s(created_by) or None,
                    created_at=_now(),
                    updated_at=_now(),
                )
            )
        )

    candidates, names = await _candidates(key, season)
    known = await _known_nips(key)
    budget = await _budget_members(key, season)

    # Co już jest w tej partii - druga kopia tej samej faktury to duplikat.
    in_batch = await database.fetch_all(
        select(
            province_invoice_items.c.id,
            province_invoice_items.c.invoice_key,
            province_invoice_items.c.file_sha256,
            province_invoice_items.c.status,
        ).where(province_invoice_items.c.batch_id == batch_id)
    )
    batch_keys = {
        _s(row["invoice_key"]): int(row["id"])
        for row in in_batch
        if _s(row["invoice_key"]) and _s(row["status"]) not in (STATUS_DUPLICATE, STATUS_REJECTED)
    }
    batch_shas = {_s(row["file_sha256"]): int(row["id"]) for row in in_batch if _s(row["file_sha256"])}

    new_ids: list[int] = []
    for upload_file in files:
        name = _s(upload_file.filename) or "faktura.pdf"
        data = await upload_file.read(MAX_FILE_BYTES + 1)
        sha = hashlib.sha256(data).hexdigest() if data else ""
        values: dict[str, Any] = {
            "batch_id": batch_id,
            "province": key,
            "file_name": name[:240],
            "file_size": len(data),
            "file_sha256": sha or None,
            "created_at": _now(),
        }

        if len(data) > MAX_FILE_BYTES:
            values.update(status=STATUS_UNREADABLE, method="none", note=f"Plik większy niż {MAX_FILE_BYTES // (1024 * 1024)} MB - nie zapisano go.")
            new_ids.append(int(await database.execute(insert(province_invoice_items).values(**values))))
            continue
        if not data or not is_pdf(data):
            values.update(status=STATUS_UNREADABLE, method="none", note="To nie jest plik PDF - nie zapisano go.")
            new_ids.append(int(await database.execute(insert(province_invoice_items).values(**values))))
            continue

        values["pdf"] = data
        if sha in batch_shas:
            values.update(
                status=STATUS_DUPLICATE,
                method="none",
                note="Ten sam plik jest już w tej partii.",
                match_json=json.dumps({"duplicate_of": {"item_id": batch_shas[sha], "same_batch": True}}),
            )
            new_ids.append(int(await database.execute(insert(province_invoice_items).values(**values))))
            continue

        parsed, method, note = await _analyze(data)
        inv_key = P.invoice_key(parsed.get("invoice_no"), parsed.get("seller_nip"))
        match = M.propose(
            buyer_name=parsed.get("buyer_name"),
            buyer_nip=parsed.get("buyer_nip"),
            candidates=candidates,
            known_nips=known,
            budget_main=budget,
        )

        status = STATUS_PROPOSED if not parsed.get("missing") else STATUS_UNREADABLE
        if status == STATUS_UNREADABLE and not note:
            what = {"gross": "kwoty brutto", "buyer": "nabywcy"}
            note = "Nie odczytano " + " ani ".join(what[m] for m in parsed.get("missing") or [] if m in what) + " - uzupełnij ręcznie."

        duplicate = None
        # Faktura bez odczytanego numeru: duplikat poznajemy po identycznym pliku.
        same_file = None if inv_key else await _approved_by_sha(key, sha)
        if same_file:
            duplicate = {**same_file, "same_batch": False}
            note = f"Ten sam plik jest już wpłatą klubu {names.get(same_file['club_id'], same_file['club_id'])}."
        elif inv_key:
            done = (await _approved_by_key(key, [inv_key])).get(inv_key)
            if done:
                duplicate = {**done, "same_batch": False}
                note = f"Faktura {parsed.get('invoice_no')} jest już wpłatą klubu {names.get(done['club_id'], done['club_id'])}."
            elif inv_key in batch_keys:
                duplicate = {"item_id": batch_keys[inv_key], "same_batch": True}
                note = f"Faktura {parsed.get('invoice_no')} jest już w tej partii."
        if duplicate:
            status = STATUS_DUPLICATE
            match["duplicate_of"] = duplicate

        issue = P.parse_date(parsed.get("issue_date") or "")
        gross = parsed.get("gross")
        values.update(
            status=status,
            method=method,
            note=note or None,
            parsed_json=json.dumps(parsed, ensure_ascii=False, default=str),
            match_json=json.dumps(match, ensure_ascii=False),
            invoice_no=_s(parsed.get("invoice_no")) or None,
            invoice_key=inv_key or None,
            seller_nip=_s(parsed.get("seller_nip")) or None,
            buyer_nip=_s(parsed.get("buyer_nip")) or None,
            buyer_name=_s(parsed.get("buyer_name")) or None,
            issue_date=issue,
            amount=round(float(gross), 2) if isinstance(gross, (int, float)) and gross > 0 else None,
            description=P.describe(parsed),
            club_id=_s(match.get("club_id")) or None,
            confidence=float(match.get("confidence") or 0),
        )
        item_id = int(await database.execute(insert(province_invoice_items).values(**values)))
        new_ids.append(item_id)
        batch_shas[sha] = item_id
        if inv_key and status != STATUS_DUPLICATE:
            batch_keys[inv_key] = item_id

    await _refresh_counters(batch_id)
    detail = await _batch_detail(key, batch_id)
    detail["new_ids"] = new_ids
    return detail


# ---------------------------------------------------------------------------
# zatwierdzanie
# ---------------------------------------------------------------------------


class ApproveItem(BaseModel):
    item_id: int
    club_id: str
    amount: Optional[float] = None
    description: Optional[str] = None
    day: Optional[date] = None


class ApproveRequest(BaseModel):
    province: str
    created_by: Optional[str] = None
    items: list[ApproveItem] = []
    #: Pozycje odrzucone świadomie - znikają z „do zatwierdzenia", zostają w historii.
    reject_ids: list[int] = []


@router.post("/batches/{batch_id}/approve", summary="Zatwierdź wybrane faktury jako wpłaty klubów")
async def approve(batch_id: int, payload: ApproveRequest):
    key = require_province(payload.province)
    await _batch_row(key, batch_id)
    who = _s(payload.created_by) or None
    saved: list[dict] = []
    skipped: list[dict] = []

    for wanted in payload.items:
        row = await database.fetch_one(
            select(*_ITEM_COLUMNS).where(
                and_(
                    province_invoice_items.c.id == wanted.item_id,
                    province_invoice_items.c.batch_id == batch_id,
                )
            )
        )
        if row is None:
            skipped.append({"item_id": wanted.item_id, "reason": "Nie ma takiej pozycji w tej partii."})
            continue
        label = _s(row["invoice_no"]) or _s(row["file_name"])
        status = _s(row["status"])
        if status == STATUS_DUPLICATE:
            skipped.append({"item_id": wanted.item_id, "reason": f"{label}: duplikat - ta faktura już jest wpłatą."})
            continue
        if status == STATUS_REJECTED:
            skipped.append({"item_id": wanted.item_id, "reason": f"{label}: odrzucona - najpierw ją przywróć."})
            continue
        if status == STATUS_APPROVED and row["entry_id"] and await _live_entries([row["entry_id"]]):
            skipped.append({"item_id": wanted.item_id, "reason": f"{label}: już zatwierdzona."})
            continue
        if not row["parsed_json"] and _s(row["method"]) == "none" and status == STATUS_UNREADABLE:
            skipped.append({"item_id": wanted.item_id, "reason": f"{label}: plik nie był fakturą PDF - nie ma czego zatwierdzić."})
            continue
        club_id = _s(wanted.club_id)
        amount = round(abs(float(wanted.amount if wanted.amount is not None else (row["amount"] or 0))), 2)
        if not club_id:
            skipped.append({"item_id": wanted.item_id, "reason": f"{label}: wybierz klub."})
            continue
        if amount <= 0:
            skipped.append({"item_id": wanted.item_id, "reason": f"{label}: kwota musi być większa od zera."})
            continue
        inv_key = _s(row["invoice_key"])
        if inv_key:
            done = (await _approved_by_key(key, [inv_key], skip_item=int(row["id"]))).get(inv_key)
            if done:
                await database.execute(
                    update(province_invoice_items)
                    .where(province_invoice_items.c.id == row["id"])
                    .values(status=STATUS_DUPLICATE, note=f"Faktura {label} została w międzyczasie zatwierdzona w innej partii.")
                )
                skipped.append({"item_id": wanted.item_id, "reason": f"{label}: w międzyczasie zatwierdzona w innej partii."})
                continue

        day = wanted.day or row["issue_date"] or _now().date()
        description = (_s(wanted.description) or _s(row["description"]) or f"Faktura {label}")[:500]
        async with database.transaction():
            entry_id = int(
                await database.execute(
                    insert(province_club_entries).values(
                        province=key,
                        club_id=club_id,
                        team_id=None,
                        team_name=None,
                        season=season_of(day),
                        kind="in",
                        amount=amount,
                        description=description,
                        day=day,
                        source="invoice",
                        created_by=who,
                        created_at=_now(),
                    )
                )
            )
            await database.execute(
                update(province_invoice_items)
                .where(province_invoice_items.c.id == row["id"])
                .values(
                    status=STATUS_APPROVED,
                    club_id=club_id,
                    amount=amount,
                    description=description,
                    issue_date=day,
                    entry_id=entry_id,
                    decided_by=who,
                    decided_at=_now(),
                    note=None,
                )
            )
            nip = P.normalize_nip(row["buyer_nip"])
            if nip:
                await database.execute(
                    pg_insert(province_club_nips)
                    .values(
                        province=key,
                        nip=nip,
                        club_id=club_id,
                        buyer_name=_s(row["buyer_name"]) or None,
                        confirmed_by=who,
                        confirmed_at=_now(),
                    )
                    .on_conflict_do_update(
                        index_elements=["province", "nip"],
                        set_={
                            "club_id": club_id,
                            "buyer_name": _s(row["buyer_name"]) or None,
                            "confirmed_by": who,
                            "confirmed_at": _now(),
                        },
                    )
                )
        saved.append({"item_id": int(row["id"]), "entry_id": entry_id, "club_id": club_id, "amount": amount})

    if payload.reject_ids:
        await database.execute(
            update(province_invoice_items)
            .where(
                and_(
                    province_invoice_items.c.batch_id == batch_id,
                    province_invoice_items.c.id.in_([int(item) for item in payload.reject_ids]),
                    province_invoice_items.c.status.in_([STATUS_PROPOSED, STATUS_UNREADABLE]),
                )
            )
            .values(status=STATUS_REJECTED, decided_by=who, decided_at=_now())
        )

    await _refresh_counters(batch_id)
    _CANDIDATES.clear()
    detail = await _batch_detail(key, batch_id)
    detail["saved"] = saved
    detail["skipped"] = skipped
    detail["saved_total"] = round(sum(item["amount"] for item in saved), 2)
    return detail


class ReopenRequest(BaseModel):
    province: str
    item_ids: list[int] = []


@router.post("/batches/{batch_id}/reopen", summary="Przywróć odrzucone pozycje do zatwierdzenia")
async def reopen(batch_id: int, payload: ReopenRequest):
    key = require_province(payload.province)
    await _batch_row(key, batch_id)
    if payload.item_ids:
        rows = await database.fetch_all(
            select(province_invoice_items.c.id, province_invoice_items.c.amount, province_invoice_items.c.buyer_name)
            .where(
                and_(
                    province_invoice_items.c.batch_id == batch_id,
                    province_invoice_items.c.id.in_([int(item) for item in payload.item_ids]),
                    province_invoice_items.c.status == STATUS_REJECTED,
                )
            )
        )
        for row in rows:
            status = STATUS_PROPOSED if row["amount"] and _s(row["buyer_name"]) else STATUS_UNREADABLE
            await database.execute(
                update(province_invoice_items)
                .where(province_invoice_items.c.id == row["id"])
                .values(status=status, decided_by=None, decided_at=None)
            )
        await _refresh_counters(batch_id)
    return await _batch_detail(key, batch_id)


# ---------------------------------------------------------------------------
# historia i pliki
# ---------------------------------------------------------------------------


@router.get("/batches", summary="Historia wczytań faktur")
async def list_batches(province: str = Query(...), limit: int = Query(50, ge=1, le=200)):
    key = require_province(province)
    rows = await database.fetch_all(
        select(province_invoice_batches)
        .where(and_(province_invoice_batches.c.province == key, province_invoice_batches.c.files > 0))
        .order_by(province_invoice_batches.c.id.desc())
        .limit(limit)
    )
    return {"batches": [_batch_json(row) for row in rows]}


@router.get("/batches/{batch_id}", summary="Partia faktur: pozycje i podsumowanie")
async def batch_detail(batch_id: int, province: str = Query(...)):
    return await _batch_detail(require_province(province), batch_id)


def _pdf_response(row: Any) -> Response:
    if row is None or not row["pdf"]:
        raise HTTPException(404, "Tego pliku nie zapisano na serwerze (np. nie był PDF-em albo był za duży)")
    name = _s(row["file_name"]) or "faktura.pdf"
    ascii_name = "".join(ch for ch in P.ascii_fold(name) if 32 <= ord(ch) < 127 and ch not in '"\\') or "faktura.pdf"
    return Response(
        content=bytes(row["pdf"]),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"inline; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}",
            "Cache-Control": "private, max-age=3600",
        },
    )


async def _pdf_reader(province: str, payload: dict) -> str:
    """
    Plik faktury to dane firm (nazwy, NIP-y, konta) - czyta go tylko konto
    z uprawnieniem do Rozliczeń tego okręgu, ta sama reguła co zapis w panelu.
    Token obowiązkowy, bez okresu przejściowego: to nowa trasa.
    """
    from app.province_alerts import _refusal

    key = require_province(province)
    reason = await _refusal(payload, key)
    if reason:
        raise HTTPException(403, f"Faktura: {reason}")
    return key


@router.get("/items/{item_id}/pdf", summary="Plik PDF faktury z historii")
async def item_pdf(
    item_id: int,
    province: str = Query(...),
    payload: dict = Depends(get_jwt_payload),
):
    key = await _pdf_reader(province, payload)
    row = await database.fetch_one(
        select(province_invoice_items.c.pdf, province_invoice_items.c.file_name).where(
            and_(province_invoice_items.c.id == item_id, province_invoice_items.c.province == key)
        )
    )
    return _pdf_response(row)


@router.get("/entries/{entry_id}/pdf", summary="Plik PDF faktury, z której powstała wpłata klubu")
async def entry_pdf(
    entry_id: int,
    province: str = Query(...),
    payload: dict = Depends(get_jwt_payload),
):
    key = await _pdf_reader(province, payload)
    row = await database.fetch_one(
        select(province_invoice_items.c.pdf, province_invoice_items.c.file_name)
        .where(
            and_(
                province_invoice_items.c.entry_id == entry_id,
                province_invoice_items.c.province == key,
                province_invoice_items.c.status == STATUS_APPROVED,
            )
        )
        .order_by(province_invoice_items.c.id.desc())
        .limit(1)
    )
    return _pdf_response(row)
