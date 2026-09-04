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
  • opcjonalna kopia PDF przez webhook Discord przypisany grupie lub okręgowi.

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

# `app.db` wchodzi LENIWIE, wewnątrz funkcji (konwencja jak w proel_journal):
# import na górze buduje cały schemat przy imporcie modułu, a to wywraca
# testy czystych helperów (_clean_signatures, _row_to_item) bez Postgresa.
from app.extra_report_download import download_path_for, stash_for_download
from app.extra_report_discord import normalize_webhook_url, report_payload, send_report_copies
from app.extra_report_pdf import ExtraReportError, build_extra_report_pdf
from app.extra_report_scope import fetch_match_province, is_province_scoped
from app.proel_auth import Actor, is_admin, proel_actor
from app.zprp_accounts import normalize_province

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
    #: Podpisy złożone POD RAPORTEM - ścieżki PNG z /signatures/upload,
    #: w stałej kolejności (sędziowie [ref1, ref2], delegat [delegat]).
    #: `None` = nie ruszaj zapisanych: autozapis treści leci bez tego pola
    #: i nie może skasować podpisu złożonego wcześniej.
    signatures: Optional[List[str]] = None


class ExtraReportItem(BaseModel):
    kind: str
    entries: List[Dict[str, Any]]
    signatures: List[str] = Field(default_factory=list)
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
    #: Treść wprost w żądaniu - dla MECZU TESTOWEGO, którego raportu nie ma
    #: w bazie (isTest blokuje zapis). Używana WYŁĄCZNIE, gdy pod kluczem nic
    #: nie leży - przy prawdziwym meczu treść zapisana wygrywa zawsze, żeby
    #: nie dało się wysłać do związku raportu innego niż ten, który widzi
    #: reszta obsady.
    entries: Optional[List[Dict[str, Any]]] = None
    #: Kategoria z tej samej funkcji klienta co przy rozwiązywaniu adresatów.
    #: Brak w starszej aplikacji = bez automatycznej wysyłki Discord.
    category: str = ""
    localOnly: bool = False


class RecipientGroup(BaseModel):
    id: Optional[int] = None
    name: str
    categories: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    #: None = zachowaj konfigurację przy zapisie ze starszej aplikacji.
    #: Pusty napis = świadome wyłączenie wysyłki.
    discordWebhookUrl: Optional[str] = Field(None, max_length=512)


class RecipientGroups(BaseModel):
    groups: List[RecipientGroup] = Field(default_factory=list)


class ProvinceRecipients(BaseModel):
    #: Slug bez ogonków - `SLASKIE`. Nazwa i herb powstają z niego w aplikacji.
    province: str
    emails: List[str] = Field(default_factory=list)
    discordWebhookUrl: Optional[str] = Field(None, max_length=512)


class ProvinceRecipientList(BaseModel):
    provinces: List[ProvinceRecipients] = Field(default_factory=list)


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


def _clean_signatures(raw: Any) -> List[str]:
    """Lista podpisów z bazy/żądania - same napisy, przycięte, bez None."""
    if not isinstance(raw, list):
        return []
    return [str(s or "").strip() for s in raw]


def _row_to_item(row: Any) -> ExtraReportItem:
    d = dict(row)
    return ExtraReportItem(
        kind=d["kind"],
        entries=d.get("entries") or [],
        signatures=_clean_signatures(d.get("signatures")),
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


def _webhook_for_save(value: Optional[str], previous: Any = "") -> str:
    try:
        return normalize_webhook_url(previous if value is None else value)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


# ─────────────────────────── treść raportu ───────────────────────────


@router.get("/{match_key}", response_model=ExtraReportPair, summary="Raporty meczu")
async def get_reports(match_key: str) -> ExtraReportPair:
    """Oba raporty jednego meczu.

    Czytanie jest wspólne świadomie: delegat ma widzieć, co napisali sędziowie,
    i odwrotnie. Pisać wolno tylko w swoim - o tym rozstrzyga aplikacja, bo to
    ona wie, w jakiej roli ktoś w tej chwili siedzi przy telefonie.
    """
    from app.db import database, extra_reports

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
    from app.db import database, extra_reports

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
    # Podpisy raportowe nadpisujemy TYLKO, gdy żądanie je niesie - autozapis
    # treści (bez pola) nie może skasować podpisu złożonego wcześniej.
    # W drugą stronę te podpisy nie idą nigdy: blob meczu ich nie widzi.
    if body.signatures is not None:
        values["signatures"] = _clean_signatures(body.signatures)
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
    raport inny niż ten, który widzą pozostali członkowie obsady. Jedyny
    wyjątek: klucz, pod którym NIC nie leży, może dostać treść w żądaniu -
    tak składa raport MECZ TESTOWY, którego zapis jest zablokowany (isTest).
    Plik powstaje naprawdę, w bazie nie zostaje nic - jak protokół ćwiczeniowy.
    """
    from app.db import database, extra_reports

    _check_kind(kind)

    row = await database.fetch_one(
        select(extra_reports).where(
            (extra_reports.c.match_key == match_key) & (extra_reports.c.kind == kind)
        )
    )
    if not row and not body.entries:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Ten raport nie ma jeszcze treści.",
        )
    entries = (dict(row).get("entries") or []) if row else (body.entries or [])

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
    # Ślad „kto wygenerował" tylko przy raporcie ZAPISANYM - mecz testowy
    # (treść z żądania, bez wiersza) świadomie nie zostawia w bazie niczego.
    if row:
        await database.execute(
            extra_reports.update()
            .where(extra_reports.c.id == dict(row)["id"])
            .values(
                generated_by=actor.judge_id or None,
                generated_by_name=actor.name or None,
                generated_at=now,
            )
        )

    filename = _filename(
        kind, body.matchNumber or (dict(row).get("match_number") if row else None)
    )
    # Plik zostaje też pod tokenem - „Pobierz na telefon" otwiera ten adres
    # systemowo i raport ląduje w pobranych, jak protokół PDF.
    token = stash_for_download(pdf)
    discord: Dict[str, Any] = {"status": "skipped", "deliveries": []}
    # Tylko zapisany raport, nowy klient z kategorią i prawdziwy mecz.
    # Inline/test pozostaje generowaniem pliku bez wysyłki do osób trzecich.
    if row and body.category.strip() and not body.localOnly and body.entries is None:
        try:
            stored = dict(row)
            mid = stored.get("zprp_match_id") or (match_key if match_key.isdigit() else None)
            recipients = await _resolve_recipients(body.category, mid)
            discord = await send_report_copies(
                targets=recipients["_discordTargets"], pdf=pdf, filename=filename,
                payload=report_payload(
                    kind=kind, match_number=stored.get("match_number") or body.matchNumber or "",
                    names=body.names, teams=body.teams, generated_at=now.isoformat(),
                    filename=filename,
                ),
            )
            if recipients["discordProvinceUnresolved"]:
                discord["warning"] = "Nie ustalono okręgu — kopia okręgowa nie została wysłana."
        except Exception:
            # Awaria konfiguracji lub transportu nie zabiera gotowego PDF.
            # Nie logujemy wyjątku: URL webhooka zawiera sekret.
            logger.warning("Extra report Discord dispatch failed")
            discord = {"status": "failed", "deliveries": [],
                       "warning": "Nie udało się wysłać kopii do Discorda."}
    return {
        "filename": filename,
        "pdfBase64": base64.b64encode(pdf).decode("ascii"),
        "downloadUrl": f"/extra-report/pdf/download/{token}?filename={filename}",
        "generatedAt": now.isoformat(),
        "generatedByName": actor.name or None,
        "discord": discord,
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
async def recipients_for_category(
    category: str,
    match_id: Optional[str] = Query(
        None,
        description=(
            "IdZawody - pozwala dołożyć adresatów OKRĘGU prowadzącego te "
            "rozgrywki. Bez niego odpowiedź jest taka jak dawniej."
        ),
    ),
) -> Dict[str, Any]:
    """Skrzynki, do których ma trafić raport z tego meczu.

    Kategorię liczy aplikacja z numeru meczu - ta sama funkcja, z której żyją
    kolorowe plakietki na kaflach (`utils/matchCategoryColor.ts`). Serwer nie
    powtarza tego rozpoznania, żeby nie było dwóch odpowiedzi na jedno pytanie.

    DWIE WARSTWY, ŚWIADOMIE SUMOWANE. Grupy kategorii odpowiadają na pytanie
    „kto czyta tę rozgrywkę w kraju", adresaci okręgu - „kto czyta ją tutaj".
    Rozgrywki od II ligi w dół prowadzą związki wojewódzkie, więc bez drugiej
    warstwy raport z meczu młodzieżowego jechał tam, gdzie ktoś wpisał adres
    pierwszy. Suma, a nie zastąpienie: związek bywa umawiany na kopię, a to
    była dotąd jedyna droga, którą raport w ogóle wychodził.

    `match_id` jest OPCJONALNY i musi taki zostać: starsze wersje aplikacji go
    nie wysyłają, a odpowiedź bez niego ma być dokładnie tą, którą znały.
    """
    resolved = await _resolve_recipients(category, match_id)
    # Sekrety trafiają tylko do endpointów admina i serwerowego transportu.
    resolved.pop("_discordTargets")
    return resolved


async def _resolve_recipients(category: str, match_id: Optional[str]) -> Dict[str, Any]:
    from app.db import database, extra_report_province_recipients, extra_report_recipients

    cat = (category or "").strip()
    rows = await database.fetch_all(
        select(extra_report_recipients).order_by(extra_report_recipients.c.order_index)
    )
    emails: List[str] = []
    groups: List[str] = []
    targets: List[Dict[str, str]] = []
    for row in rows:
        d = dict(row)
        if cat and cat in (d.get("categories") or []):
            groups.append(d.get("name") or "")
            emails.extend(d.get("emails") or [])
            if d.get("discord_webhook_url"):
                targets.append({"name": d.get("name") or "Grupa ligowa", "url": d["discord_webhook_url"]})

    province = ""
    province_unresolved = False
    if match_id and is_province_scoped(cat):
        province = await fetch_match_province(match_id)
        if province:
            row = await database.fetch_one(
                select(extra_report_province_recipients).where(
                    extra_report_province_recipients.c.province == province
                )
            )
            if row is not None:
                emails.extend(dict(row).get("emails") or [])
                if dict(row).get("discord_webhook_url"):
                    targets.append({"name": province, "url": dict(row)["discord_webhook_url"]})

    if is_province_scoped(cat) and not province:
        # Bez skonfigurowanych webhooków funkcja jest wyłączona, więc brak
        # okręgu nie powinien dokładać ostrzeżenia o nieużywanej wysyłce.
        province_unresolved = await database.fetch_one(
            select(extra_report_province_recipients.c.province)
            .where(extra_report_province_recipients.c.discord_webhook_url.isnot(None))
            .where(extra_report_province_recipients.c.discord_webhook_url != "")
            .limit(1)
        ) is not None

    return {
        "category": cat,
        "groups": groups,
        "emails": normalize_emails(emails),
        # Pusty, gdy okręg nie ma tu nic do rzeczy albo gdy ZPRP nie
        # odpowiedziało. Aplikacja pokazuje to sędziemu, zamiast milczeć.
        "province": province,
        "provinceScoped": is_province_scoped(cat),
        "discordDestinations": [t["name"] for t in targets],
        "discordProvinceUnresolved": province_unresolved,
        "_discordTargets": targets,
    }


@admin_router.get("/recipients", response_model=RecipientGroups, summary="Grupy adresatów")
async def list_recipients(actor: Actor = Depends(proel_actor)) -> RecipientGroups:
    from app.db import database, extra_report_recipients

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
                discordWebhookUrl=dict(r).get("discord_webhook_url") or "",
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
    from app.db import database, extra_report_recipients

    await _require_admin(actor)

    now = datetime.now(timezone.utc)
    async with database.transaction():
        existing = [dict(r) for r in await database.fetch_all(select(extra_report_recipients))]
        by_id = {r["id"]: r for r in existing}
        # Zgodność ze starszym klientem, który wysyła maile bez pola webhooka.
        prepared = []
        for group in body.groups:
            previous = by_id.get(group.id, {})
            url = _webhook_for_save(group.discordWebhookUrl, previous.get("discord_webhook_url"))
            prepared.append((group, url))
        await database.execute(extra_report_recipients.delete())
        for index, (group, url) in enumerate(prepared):
            name = (group.name or "").strip()
            if not name:
                continue
            await database.execute(
                extra_report_recipients.insert().values(
                    name=name,
                    categories=normalize_categories(group.categories),
                    emails=normalize_emails(group.emails),
                    discord_webhook_url=url or None,
                    order_index=index,
                    updated_at=now,
                )
            )

    return await list_recipients(actor)  # type: ignore[arg-type]


# ────────────────────── adresaci per okręg ──────────────────────


@admin_router.get(
    "/province-recipients",
    response_model=ProvinceRecipientList,
    summary="Adresaci per okręg",
)
async def list_province_recipients(
    actor: Actor = Depends(proel_actor),
) -> ProvinceRecipientList:
    from app.db import database, extra_report_province_recipients

    await _require_admin(actor)
    rows = await database.fetch_all(
        select(extra_report_province_recipients).order_by(
            extra_report_province_recipients.c.province
        )
    )
    return ProvinceRecipientList(
        provinces=[
            ProvinceRecipients(
                province=dict(r)["province"],
                emails=dict(r).get("emails") or [],
                discordWebhookUrl=dict(r).get("discord_webhook_url") or "",
            )
            for r in rows
        ]
    )


@admin_router.put(
    "/province-recipients",
    response_model=ProvinceRecipientList,
    summary="Zapis adresatów per okręg",
)
async def save_province_recipients(
    body: ProvinceRecipientList,
    actor: Actor = Depends(proel_actor),
) -> ProvinceRecipientList:
    """Nadpisuje CAŁĄ konfigurację, tak samo jak grupy kategorii.

    Okręg bez adresów i webhooka nie zostaje pustym wierszem - znika. Pusty wiersz i brak
    wiersza znaczą dokładnie to samo („nikt tu nie czyta"), a dwa zapisy tego
    samego stanu to dwa miejsca, w których panel może pokazać co innego.

    Nazwę województwa sprowadzamy do sluga tą samą funkcją, co reszta serwera.
    Nieznana nazwa wypada - lepiej stracić literówkę przy zapisie niż trzymać
    w bazie okręg, którego nikt nigdy nie odnajdzie.
    """
    from app.db import database, extra_report_province_recipients

    await _require_admin(actor)

    now = datetime.now(timezone.utc)
    async with database.transaction():
        existing = {
            dict(r)["province"]: dict(r)
            for r in await database.fetch_all(select(extra_report_province_recipients))
        }
        prepared = []
        included = set()
        for entry in body.provinces:
            province = normalize_province(entry.province)
            if not province or province in included:
                continue
            included.add(province)
            url = _webhook_for_save(
                entry.discordWebhookUrl, existing.get(province, {}).get("discord_webhook_url"),
            )
            prepared.append((province, normalize_emails(entry.emails), url))
        # Starszy panel pomija okręgi bez maili. Takie pominięcie nie wyłącza
        # webhooka; nowy panel wysyła jawne "" przy usunięciu jego adresu.
        for province, previous in existing.items():
            if province not in included and previous.get("discord_webhook_url"):
                prepared.append((province, [], previous["discord_webhook_url"]))
        await database.execute(extra_report_province_recipients.delete())
        for province, emails, url in prepared:
            if not emails and not url:
                continue
            await database.execute(
                extra_report_province_recipients.insert().values(
                    province=province,
                    emails=emails,
                    discord_webhook_url=url or None,
                    updated_at=now,
                )
            )

    return await list_province_recipients(actor)  # type: ignore[arg-type]
