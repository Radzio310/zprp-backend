"""Dodatkowy raport sędziów i delegata - przechowanie, złożenie PDF, adresaci.

Po co osobny magazyn: raport ma żyć poza jednym telefonem. Sędziowie opisują
czerwone kartki na podsumowaniu meczu, delegat swoje incydenty czasem dzień
później i z innego urządzenia, a każdy z nich ma widzieć to, co napisał ten
drugi. Blob ProEla się do tego nie nadaje - jedzie w całości przy każdym
zapisie meczu, a opis jednego incydentu to setki znaków.

CO TU JEST, A CZEGO NIE MA:

  • przechowanie treści (`GET`/`PUT`) - kluczowane `match_key`, nie numerem
    meczu (patrz `app/proel_match_key.py`: numer nie jest unikalny między
    sezonami);
  • złożenie PDF na żądanie (`POST .../pdf`) razem ze śladem „kto i kiedy";
  • rozwiązanie adresatów po kategorii rozgrywek.

Nie ma tu WYSYŁKI maila. Raport wychodzi z poczty sędziego, z jego adresu -
odpowiedź związku ma wrócić do niego, a nie do skrzynki aplikacji. Serwer daje
gotowy plik i podpowiada adresatów, resztę robi klient poczty na telefonie.

TOŻSAMOŚĆ. Tak samo jak w dzienniku ProEla: aktora czytamy MIĘKKO z nagłówków
i zapisujemy przy treści. Twarde sprawdzanie obsady przy każdym zapisie
wymagałoby logowania do bazy ZPRP na każde naciśnięcie klawisza; o tym, kto
widzi przycisk, rozstrzyga `utils/postMatchAuthority.ts` po stronie aplikacji,
a tu zostaje odpowiedź na pytanie „kto to napisał". Konfiguracja adresatów jest
inna - ją zmienia wyłącznie administrator i to jest sprawdzane.
"""

from __future__ import annotations

import base64
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from starlette.background import BackgroundTask

from app.db import database, extra_report_recipients, extra_reports
from app.extra_report_download import download_path_for, stash_for_download
from app.extra_report_pdf import ExtraReportError, build_extra_report_pdf
from app.proel_auth import Actor, is_admin, proel_actor

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/extra-report", tags=["Dodatkowy raport"])
admin_router = APIRouter(prefix="/admin/extra-report", tags=["Dodatkowy raport: admin"])

KINDS = ("referees", "delegate")

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+\.[^@\s]+$")


# ─────────────────────────── kształty ───────────────────────────


class ExtraReportBody(BaseModel):
    entries: List[Dict[str, Any]] = Field(default_factory=list)
    matchNumber: Optional[str] = None
    zprpMatchId: Optional[str] = None


class ExtraReportItem(BaseModel):
    kind: str
    entries: List[Dict[str, Any]]
    updatedBy: Optional[str] = None
    updatedByName: Optional[str] = None
    updatedAt: Optional[str] = None
    generatedBy: Optional[str] = None
    generatedByName: Optional[str] = None
    generatedAt: Optional[str] = None


class ExtraReportPair(BaseModel):
    matchKey: str
    referees: Optional[ExtraReportItem] = None
    delegate: Optional[ExtraReportItem] = None


class GeneratePdfBody(BaseModel):
    """Wszystko, co idzie w nagłówek formularza - liczone po stronie aplikacji.

    Serwer nie zna ani nazwisk sędziów, ani hali: to dane meczu, które aplikacja
    i tak trzyma. Przysyła je razem z żądaniem, żeby nie odpytywać ZPRP po raz
    drugi o coś, co leży na telefonie.
    """

    names: List[str] = Field(default_factory=list)
    match: str = ""
    teams: List[str] = Field(default_factory=list)
    video: bool = False
    #: Adresy PNG podpisów z protokołu - serwer je pobiera i wkleja.
    signatureUrls: List[str] = Field(default_factory=list)
    matchNumber: Optional[str] = None
    zprpMatchId: Optional[str] = None


class RecipientGroup(BaseModel):
    id: Optional[int] = None
    name: str
    categories: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)


class RecipientGroups(BaseModel):
    groups: List[RecipientGroup] = Field(default_factory=list)


# ─────────────────────────── pomocnicze ───────────────────────────


def _iso(value: Any) -> Optional[str]:
    if not value:
        return None
    if isinstance(value, str):
        return value
    try:
        return value.astimezone(timezone.utc).isoformat()
    except Exception:
        return str(value)


def _row_to_item(row: Any) -> ExtraReportItem:
    d = dict(row)
    return ExtraReportItem(
        kind=d["kind"],
        entries=d.get("entries") or [],
        updatedBy=d.get("updated_by"),
        updatedByName=d.get("updated_by_name"),
        updatedAt=_iso(d.get("updated_at")),
        generatedBy=d.get("generated_by"),
        generatedByName=d.get("generated_by_name"),
        generatedAt=_iso(d.get("generated_at")),
    )


def _check_kind(kind: str) -> str:
    if kind not in KINDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Nieznany rodzaj raportu: {kind!r}",
        )
    return kind


def normalize_emails(raw: Any) -> List[str]:
    """Adresy bez śmieci i bez powtórzeń, w kolejności wpisania.

    Kolejność ma znaczenie: pierwszy adres trafia do „Do", reszta do kopii,
    więc nie wolno tego posortować „dla porządku".
    """
    out: List[str] = []
    seen = set()
    for item in raw or []:
        email = str(item or "").strip()
        if not email or not EMAIL_RE.match(email):
            continue
        key = email.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(email)
    return out


def normalize_categories(raw: Any) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in raw or []:
        cat = str(item or "").strip()
        if not cat or cat in seen:
            continue
        seen.add(cat)
        out.append(cat)
    return out


async def _require_admin(actor: Actor) -> None:
    if not await is_admin(actor.judge_id or ""):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Adresatów raportu zmienia wyłącznie administrator.",
        )


# ─────────────────────────── treść raportu ───────────────────────────


@router.get("/{match_key}", response_model=ExtraReportPair, summary="Raporty meczu")
async def get_reports(match_key: str) -> ExtraReportPair:
    """Oba raporty jednego meczu.

    Czytanie jest wspólne świadomie: delegat ma widzieć, co napisali sędziowie,
    i odwrotnie. Pisać wolno tylko w swoim - o tym rozstrzyga aplikacja, bo to
    ona wie, w jakiej roli ktoś w tej chwili siedzi przy telefonie.
    """
    rows = await database.fetch_all(
        select(extra_reports).where(extra_reports.c.match_key == match_key)
    )
    pair = ExtraReportPair(matchKey=match_key)
    for row in rows:
        item = _row_to_item(row)
        if item.kind == "referees":
            pair.referees = item
        elif item.kind == "delegate":
            pair.delegate = item
    return pair


@router.put("/{match_key}/{kind}", response_model=ExtraReportItem, summary="Zapis raportu")
async def save_report(
    match_key: str,
    kind: str,
    body: ExtraReportBody,
    actor: Actor = Depends(proel_actor),
) -> ExtraReportItem:
    _check_kind(kind)
    now = datetime.now(timezone.utc)

    existing = await database.fetch_one(
        select(extra_reports).where(
            (extra_reports.c.match_key == match_key) & (extra_reports.c.kind == kind)
        )
    )
    values = {
        "entries": body.entries or [],
        "match_number": (body.matchNumber or "").strip() or None,
        "zprp_match_id": (body.zprpMatchId or "").strip() or None,
        "updated_by": actor.judge_id or None,
        "updated_by_name": actor.name or None,
        "updated_at": now,
    }
    if existing:
        await database.execute(
            extra_reports.update()
            .where(extra_reports.c.id == dict(existing)["id"])
            .values(**values)
        )
    else:
        await database.execute(
            extra_reports.insert().values(match_key=match_key, kind=kind, **values)
        )

    row = await database.fetch_one(
        select(extra_reports).where(
            (extra_reports.c.match_key == match_key) & (extra_reports.c.kind == kind)
        )
    )
    return _row_to_item(row)


# ─────────────────────────── PDF ───────────────────────────


@router.post("/{match_key}/{kind}/pdf", summary="Złóż PDF raportu")
async def generate_pdf(
    match_key: str,
    kind: str,
    body: GeneratePdfBody,
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    """Składa PDF z ZAPISANEJ treści i odnotowuje, kto go wygenerował.

    Treść bierzemy z bazy, nie z żądania - inaczej dałoby się wysłać do związku
    raport inny niż ten, który widzą pozostali członkowie obsady.
    """
    _check_kind(kind)

    row = await database.fetch_one(
        select(extra_reports).where(
            (extra_reports.c.match_key == match_key) & (extra_reports.c.kind == kind)
        )
    )
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Ten raport nie ma jeszcze treści.",
        )
    entries = dict(row).get("entries") or []

    # Podpisy z protokołu - te same, którymi sędziowie podpisali arkusz.
    signatures: List[bytes] = []
    if body.signatureUrls:
        from app.results import _fetch_png_bytes, _full_static_url, _trim_ink_margins

        for url in body.signatureUrls:
            data = await _fetch_png_bytes(_full_static_url(url or ""))
            signatures.append(_trim_ink_margins(data) if data else b"")

    try:
        pdf = build_extra_report_pdf(
            kind=kind,
            header={
                "names": body.names,
                "match": body.match,
                "teams": body.teams,
                "video": body.video,
            },
            entries=entries,
            signatures=signatures,
            templates_dir=TEMPLATES_DIR,
        )
    except ExtraReportError as exc:
        # Powód jest konkretny („opis nr 3 się nie mieści") i ma dojść do
        # sędziego w takiej formie, a nie jako „błąd serwera".
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    now = datetime.now(timezone.utc)
    await database.execute(
        extra_reports.update()
        .where(extra_reports.c.id == dict(row)["id"])
        .values(
            generated_by=actor.judge_id or None,
            generated_by_name=actor.name or None,
            generated_at=now,
        )
    )

    filename = _filename(kind, body.matchNumber or dict(row).get("match_number"))
    # Plik zostaje też pod tokenem - „Pobierz na telefon" otwiera ten adres
    # systemowo i raport ląduje w pobranych, jak protokół PDF.
    token = stash_for_download(pdf)
    return {
        "filename": filename,
        "pdfBase64": base64.b64encode(pdf).decode("ascii"),
        "downloadUrl": f"/extra-report/pdf/download/{token}?filename={filename}",
        "generatedAt": now.isoformat(),
        "generatedByName": actor.name or None,
    }


def _filename(kind: str, match_number: Optional[str]) -> str:
    safe = re.sub(r"[^A-Za-z0-9]+", "-", str(match_number or "mecz")).strip("-")
    label = "sedziow" if kind == "referees" else "delegata"
    return f"raport-{label}-{safe or 'mecz'}.pdf"


# ─────────────────────────── pobieranie na telefon ───────────────────────────
#
# Mechanika (token, TTL, sprzątanie) mieszka w `app/extra_report_download.py` -
# module-liściu bez `app.db`, żeby testy jednostkowe mogły go zaimportować
# bez bazy. Tu zostaje sam endpoint.


@router.get("/pdf/download/{token}", summary="Pobierz złożony raport (attachment)")
async def download_extra_report_pdf(
    token: str,
    filename: str = Query("raport.pdf"),
) -> FileResponse:
    file_path = download_path_for(token)
    if not file_path:
        raise HTTPException(status_code=404, detail="Plik wygasł lub nie istnieje")
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", filename) or "raport.pdf"
    return FileResponse(
        path=file_path,
        media_type="application/pdf",
        filename=safe_name,
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "Cache-Control": "no-store",
        },
        background=BackgroundTask(
            lambda: os.remove(file_path) if os.path.exists(file_path) else None
        ),
    )


# ─────────────────────────── adresaci ───────────────────────────


@router.get("/recipients/for-category/{category}", summary="Adresaci dla kategorii")
async def recipients_for_category(category: str) -> Dict[str, Any]:
    """Skrzynki przypisane do kategorii rozgrywek.

    Kategorię liczy aplikacja z numeru meczu - ta sama funkcja, z której żyją
    kolorowe plakietki na kaflach (`utils/matchCategoryColor.ts`). Serwer nie
    powtarza tego rozpoznania, żeby nie było dwóch odpowiedzi na jedno pytanie.
    """
    cat = (category or "").strip()
    rows = await database.fetch_all(
        select(extra_report_recipients).order_by(extra_report_recipients.c.order_index)
    )
    emails: List[str] = []
    groups: List[str] = []
    for row in rows:
        d = dict(row)
        if cat and cat in (d.get("categories") or []):
            groups.append(d.get("name") or "")
            emails.extend(d.get("emails") or [])
    return {"category": cat, "groups": groups, "emails": normalize_emails(emails)}


@admin_router.get("/recipients", response_model=RecipientGroups, summary="Grupy adresatów")
async def list_recipients(actor: Actor = Depends(proel_actor)) -> RecipientGroups:
    await _require_admin(actor)
    rows = await database.fetch_all(
        select(extra_report_recipients).order_by(extra_report_recipients.c.order_index)
    )
    return RecipientGroups(
        groups=[
            RecipientGroup(
                id=dict(r)["id"],
                name=dict(r).get("name") or "",
                categories=dict(r).get("categories") or [],
                emails=dict(r).get("emails") or [],
            )
            for r in rows
        ]
    )


@admin_router.put("/recipients", response_model=RecipientGroups, summary="Zapis grup adresatów")
async def save_recipients(
    body: RecipientGroups,
    actor: Actor = Depends(proel_actor),
) -> RecipientGroups:
    """Nadpisuje CAŁĄ konfigurację - panel edytuje ją jako jedną całość.

    Zapis wiersz po wierszu wymagałby śledzenia usunięć po stronie aplikacji,
    a grup jest kilkanaście, nie kilkanaście tysięcy.
    """
    await _require_admin(actor)

    now = datetime.now(timezone.utc)
    async with database.transaction():
        await database.execute(extra_report_recipients.delete())
        for index, group in enumerate(body.groups):
            name = (group.name or "").strip()
            if not name:
                continue
            await database.execute(
                extra_report_recipients.insert().values(
                    name=name,
                    categories=normalize_categories(group.categories),
                    emails=normalize_emails(group.emails),
                    order_index=index,
                    updated_at=now,
                )
            )

    return await list_recipients(actor)  # type: ignore[arg-type]
