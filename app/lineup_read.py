"""„Wczytaj składy" w meczach ręcznych (02.11.2026): odczyt składu z PDF-a, skanu albo zdjęcia protokołu ZPRP.

Kontrakt: `docs/mecze-wspolne-api.md` (sekcja „Wczytaj składy"). Decyzje: pamięć `wczytaj-sklady-decyzje`.

  - `POST /matches/lineup/read`        pliki (multipart `files`) -> skład, nagłówek, ostrzeżenia; NIC nie zapisuje,
  - `GET  /matches/lineup/zprp-check`  czy IdZawody istnieje w ZPRP i czy drużyny oraz data zgadzają się z meczem ręcznym.

Zalogowany sędzia (JWT aplikacji), nie admin. Plik żyje wyłącznie w pamięci, w logach są same liczby (bez nazwisk i treści).
PDF z warstwą tekstową czyta parser regułami (bez AI, luźny limit); zdjęcie i skan idą do modelu z wizją (20 na konto na dobę).
Reguły i normalizacja: `lineup_read_rules`, `lineup_pdf_parse`, `lineup_vision` (czyste moduły, testowane bez bazy).
Zapis do meczu wspólnego: `PUT /shared-matches/{id}/lineup` (`app/shared_matches.py`).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.concurrency import run_in_threadpool

from app import lineup_pdf_parse as P
from app import lineup_read_quota as Q
from app import lineup_read_rules as R
from app import lineup_vision as V
from app.mentor_panel_auth import base_actor

logger = logging.getLogger("app.lineup_read")
router = APIRouter(prefix="/matches/lineup", tags=["Wczytaj składy"])
WARSAW = ZoneInfo("Europe/Warsaw")


def _http(exc: R.LineupError, **extra: Any) -> HTTPException:
    return HTTPException(exc.status, detail={"code": exc.code, "message": exc.message, **extra})


def _deps():
    """Baza leniwie (`app/db.py` łączy się przy imporcie, więc testy reguł nie mogą jej wciągać)."""
    from app.db import database, lineup_read_usage

    return database, lineup_read_usage


class _Item:
    """Jeden wczytany plik: rodzaj, bajty, liczba stron, czy PDF ma warstwę tekstową."""

    def __init__(self, kind: str, data: bytes, pages: int, has_text: bool):
        self.kind, self.data, self.pages, self.has_text = kind, data, pages, has_text


def _pdf_info(data: bytes) -> tuple[int, bool]:
    import fitz

    try:
        doc = fitz.open(stream=data, filetype="pdf")
    except Exception as exc:  # noqa: BLE001
        raise R.LineupError(422, "PDF_UNREADABLE", "Nie udało się otworzyć PDF-a.") from exc
    with doc:
        if doc.needs_pass:
            raise R.LineupError(422, "PDF_ENCRYPTED", "PDF jest chroniony hasłem.")
        if doc.page_count < 1:
            raise R.LineupError(422, "PDF_UNREADABLE", "PDF nie ma żadnej strony.")
        chars = sum(len((doc[i].get_text() or "").strip()) for i in range(min(doc.page_count, R.MAX_PAGES)))
        return doc.page_count, chars / min(doc.page_count, R.MAX_PAGES) >= R.MIN_TEXT_CHARS


async def load_items(files: List[Any]) -> List[_Item]:
    """Walidacja wszystkich plików ZANIM cokolwiek zużyje limit: typ po bajtach, rozmiar, liczba plików i stron."""
    if not files:
        raise R.LineupError(422, "NO_FILE", "Nie wybrano żadnego pliku.")
    if len(files) > R.MAX_FILES:
        raise R.LineupError(422, "TOO_MANY_FILES", f"Najwyżej {R.MAX_FILES} pliki naraz.")
    items: List[_Item] = []
    pages = 0
    for upload in files:
        data = await upload.read(R.MAX_PDF_BYTES + 1)
        kind = R.check_upload(data)
        if kind == "pdf":
            count, has_text = await run_in_threadpool(_pdf_info, data)
        else:
            count, has_text = 1, False
        pages += count
        if pages > R.MAX_PAGES:
            raise R.LineupError(422, "TOO_MANY_PAGES", f"Najwyżej {R.MAX_PAGES} strony (zdjęcie = 1 strona).")
        items.append(_Item(kind, data, count, has_text))
    return items


async def run_read(items: List[_Item], judge_id: str, *, take=None, release=None, model=None) -> Dict[str, Any]:
    """Cała logika odczytu bez FastAPI: limity, gałąź tekstowa, gałąź z modelem, scalenie. Zależności z bazy i sieci są
    wstrzykiwane (`take(kind, limit) -> (ok, used)`, `release(kind)`, `model(images) -> dict`), co daje test bez bazy i bez OpenAI."""
    text_items = [i for i in items if i.kind == "pdf" and i.has_text]
    vision_items = [i for i in items if not (i.kind == "pdf" and i.has_text)]
    parts: List[Dict[str, Any]] = []
    failure: Optional[R.LineupError] = None

    if text_items:
        ok, _ = await take("text", R.TEXT_DAILY_LIMIT)
        if not ok:
            raise R.LineupError(429, "READ_LIMIT_REACHED", "Za dużo odczytów PDF-ów na dziś. Spróbuj jutro albo wpisz skład ręcznie.")
        for item in text_items:
            try:
                parts.append(await run_in_threadpool(P.parse_pdf, item.data, max_pages=R.MAX_PAGES))
            except R.LineupError as exc:
                if exc.code != "NOT_A_PROTOCOL":
                    raise
                # PDF z tekstem, ale bez tabel „A (nazwa)" / „B (nazwa)": inny szablon albo skan z warstwą OCR - próbujemy wizji.
                failure = exc
                vision_items.append(item)

    ai_used: Optional[int] = None
    if vision_items:
        if not V.api_key() and model is None:
            if failure is not None and not parts:
                raise failure
            raise R.LineupError(503, "AI_NOT_CONFIGURED", "Odczyt ze zdjęć jest chwilowo niedostępny (brak konfiguracji serwera). PDF z tekstem można nadal wczytać.")
        images: List[bytes] = []
        for item in vision_items:
            if item.kind == "pdf":
                images += await run_in_threadpool(V.render_pdf_pages, item.data, R.MAX_PAGES - len(images))
            else:
                images.append(await run_in_threadpool(V.shrink_image, item.data))
        images = images[: R.MAX_PAGES]
        ok, ai_used = await take("ai", R.AI_DAILY_LIMIT)
        if not ok:
            raise R.LineupError(429, "AI_LIMIT_REACHED",
                                f"Wykorzystano dzienny limit {R.AI_DAILY_LIMIT} odczytów ze zdjęć. Wczytaj PDF z tekstem albo spróbuj jutro.")
        try:
            payload = await (model or V.call_model)(images)
        except R.LineupError as exc:
            if exc.status >= 500:
                await release("ai")  # awaria po stronie dostawcy nie zjada użytkownikowi limitu
            raise
        parts.append(V.vision_to_result(payload, len(images)))
        failure = None
    if not parts and failure is not None:
        raise failure
    result = R.merge_results(parts)
    result["quota"] = {"ai_used": ai_used, "ai_limit": R.AI_DAILY_LIMIT} if ai_used is not None else None
    logger.info("[lineup_read] judge=%s source=%s pages=%d home=%d away=%d staff=%d low=%d", judge_id, result["source"], result["pages"],
                len(result["home"]["players"]), len(result["away"]["players"]),
                len(result["home"]["staff"]) + len(result["away"]["staff"]), result["low_confidence_count"])
    return result


@router.post("/read")
async def read_lineup(files: List[UploadFile] = File(..., description="PDF, JPEG albo PNG protokołu (do 4 stron)"),
                      actor=Depends(base_actor)):
    """Odczyt składu z protokołu. Nic nie zapisuje; zapis to osobne `PUT /shared-matches/{id}/lineup`."""
    database, table = _deps()
    judge_id = str(actor.judge_id)

    async def take(kind: str, limit: int):
        return await Q.take(database, table, judge_id, kind, limit)

    async def release(kind: str):
        await Q.release(database, table, judge_id, kind)

    try:
        items = await load_items(files)
        return await run_read(items, judge_id, take=take, release=release)
    except R.LineupError as exc:
        extra: Dict[str, Any] = {}
        if exc.code == "AI_LIMIT_REACHED":
            extra = {"limit": R.AI_DAILY_LIMIT, "used": R.AI_DAILY_LIMIT}
        raise _http(exc, **extra) from None


@router.get("/zprp-check")
async def zprp_check(zprp_match_id: str = Query(..., max_length=20), home_name: Optional[str] = Query(None, max_length=120),
                     away_name: Optional[str] = Query(None, max_length=120), date: Optional[str] = Query(None, max_length=10),
                     actor=Depends(base_actor)):
    """Czy mecz o tym IdZawody istnieje w ZPRP i czy drużyny oraz data zgadzają się z meczem ręcznym.

    Nic nie łączy: połączenie to zwykłe `PUT /shared-matches/{id}/zprp` po decyzji użytkownika. Werdykt:
    `match` | `swapped` (gospodarz i gość zamienieni) | `mismatch` | `not_found`. Źródła: `zprp_public_matches`, a gdy brak -
    mecze okręgowe w `province_matches` (nazwy z `state_json`)."""
    zid = R.clean_zprp_id(zprp_match_id)
    if zid is None:
        raise HTTPException(422, detail={"code": "VALIDATION", "message": "IdZawody musi być liczbą."})
    from sqlalchemy import select

    from app.db import database, province_matches, zprp_public_matches

    found = await database.fetch_one(select(zprp_public_matches).where(zprp_public_matches.c.match_id == zid))
    row = dict(found) if found is not None else None
    if row is None:
        alt = await database.fetch_one(select(province_matches).where(province_matches.c.match_id == zid).limit(1))
        if alt is not None:
            state = alt["state_json"] if isinstance(alt["state_json"], dict) else {}
            when = alt["match_at"]
            if when is not None and when.tzinfo is not None:
                when = when.astimezone(WARSAW).replace(tzinfo=None)
            row = {"match_id": zid, "home_team_name": state.get("ID_zespoly_gosp_ZespolNazwa"),
                   "away_team_name": state.get("ID_zespoly_gosc_ZespolNazwa"), "scheduled_at": when,
                   "competition_name": None, "match_code": alt["match_code"]}
    verdict = R.compare_with_zprp(row, home=home_name, away=away_name, day=date)
    logger.info("[lineup_read] zprp-check judge=%s verdict=%s", actor.judge_id, verdict["verdict"])
    return verdict
