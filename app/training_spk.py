# app/training_spk.py
#
# Szkolenie stałe na meczu Superpucharu (SPK/1) - wzorzec, podejścia, wyniki.
#
# CZYM TO SIĘ RÓŻNI OD KURSOKONFERENCJI (`app/training_runs.py`). Tamto jest
# wydarzeniem: ma okno czasowe, wiele meczów i punkt odniesienia w konsensusie
# grupy, bo w chwili ćwiczenia nikt jeszcze nie zna prawdy. To jest sprawdzian
# stały na JEDNYM meczu, który już się odbył - więc prawda istnieje i da się z
# nią porównać zdarzenie po zdarzeniu. Inne pytanie, inne tabele, inne progi.
#
# WZORZEC NIE JEST ZASZYTY W KODZIE. Powstaje z oficjalnego protokołu tego
# meczu, zaimportowanego z ProEla jedną akcją w panelu. Paczka w repozytorium
# znaczyłaby, że poprawka wzorca wymaga wdrożenia serwera, a ktoś musiałby
# pamiętać o złożeniu PDF-a od nowa. Tu poprawia się w jednym miejscu i
# wszystko - ocena, slajdy, PDF - idzie za tym samo.
#
# ZAPIS PODEJŚCIA JEST OTWARTY, tak jak zapis ćwiczenia z kursokonferencji i z
# tego samego powodu: sędzia w hali nie ma tokenu administratora, a JWT żyje 15
# minut. Tożsamość przychodzi w nagłówkach aktora i służy do PODPISANIA wpisu,
# nie do wpuszczenia go. Odczyt cudzych wyników jest już wyłącznie dla
# administratora - taka była decyzja: autor widzi swoje, admin wszystkie.

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select

from app.db import database, saved_matches, spk_reference, spk_run, spk_settings
from app.proel_admin_guard import proel_admin_guard
from app.proel_auth import Actor, is_admin, proel_actor
from app.spk_pdf_link import create_pdf_token, token_expires_at, verify_pdf_token
from app.spk_province_gate import (
    create_province_token,
    generate_password,
    normalize_password,
    passwords_match,
    token_expires_at as province_token_expires_at,
    verify_province_token,
)
from app.training_spk_score import grade, score_run
from app.training_spk_pdf import SpkPdfError, build_report_pdf, build_slides_pdf
from app.training_spk_ai import AI_MODEL, ai_messages, clean_ai_summary
from app.training_spk_entries import entered_players
from app.training_spk_halftime import state_after_first_half
from app.training_spk_meta import meta_from_blob
from app.training_spk_report import report_context
from app.training_spk_shootout import shootout_shots
from app.training_spk_slides import action_text, format_clock, slides_from_timeline
from app.training_spk_video import video_clock
from app.zprp_accounts import PROVINCE_ENV_SUFFIXES, normalize_province

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/training/spk", tags=["Szkolenie: Superpuchar"])
# Bramka na CAŁYM routerze: numer admina z nagłówka musi być czymś dowiedziony
# (app/proel_admin_guard.py). Adres podpisany `/training/spk/slides.pdf` stoi
# na `router`, więc menedżer pobierania bez nagłówków dalej go dostaje.
admin_router = APIRouter(
    prefix="/admin/training/spk",
    tags=["Szkolenie: Superpuchar (admin)"],
    dependencies=[Depends(proel_admin_guard)],
)

#: Mecz, na którym stoi to szkolenie. Klucz w ProElu jest zapisany wielkimi
#: literami (`proelMatchKey` w aplikacji), więc szukamy dokładnie tak.
SPK_MATCH_NUMBER = "SPK/1"

#: Powyżej tego rozmiaru pełny stan meczu nie jest już stanem meczu, tylko
#: pomyłką - ta sama granica co przy kursokonferencji.
MAX_STATE_BYTES = 2_000_000


# ─────────────────────────── tożsamość ───────────────────────────


async def _identity(actor: Actor) -> Dict[str, str]:
    """Kto podchodzi: numer, nazwisko, okręg i rodzaj konta.

    WOJEWÓDZTWO ZAWSZE Z KONTA, nigdy z pytania na ekranie. Konto BAZY ma je w
    `login_records`, konto ProEl we własnej tabeli - więc nie ma powodu, żeby
    ktokolwiek wpadał w zestawieniu do worka „nieznane". Gdy jednak wpadnie
    (profil lokalny bez konta), zostaje pusto i panel mówi to wprost, zamiast
    zgadywać.
    """
    judge_id = str(actor.judge_id or "").strip()
    kind = "device"
    province = ""
    name = str(actor.name or "").strip()

    if judge_id.startswith("proel:"):
        kind = "proel"
        try:
            from app.db import proel_users

            row = await database.fetch_one(
                select(proel_users).where(
                    proel_users.c.id == int(judge_id.split(":", 1)[1])
                )
            )
            if row is not None:
                data = dict(row)
                province = normalize_province(data.get("province"))
                name = name or str(data.get("full_name") or "").strip()
                # Konto z POTWIERDZONYM numerem sędziego podpisujemy numerem:
                # ten sam człowiek podchodzący raz z BAZY, raz z konta ProEl ma
                # być w zestawieniu jedną osobą, a nie dwiema.
                if data.get("judge_id_verified_at") and data.get("judge_id"):
                    judge_id = str(data["judge_id"]).strip()
                    kind = "baza"
        except Exception:  # noqa: BLE001 — brak konta nie może zablokować zapisu
            logger.warning("SPK: nie udało się odczytać konta ProEl", exc_info=True)
    elif judge_id and not judge_id.startswith("inst:"):
        kind = "baza"

    if kind == "baza" and not province:
        try:
            from app.db import login_records

            row = await database.fetch_one(
                select(login_records.c.province, login_records.c.full_name).where(
                    login_records.c.judge_id == judge_id
                )
            )
            if row is not None:
                data = dict(row)
                province = normalize_province(data.get("province"))
                name = name or str(data.get("full_name") or "").strip()
        except Exception:  # noqa: BLE001
            logger.warning("SPK: nie udało się odczytać okręgu sędziego", exc_info=True)

    return {
        "judge_id": judge_id,
        "judge_name": name,
        "province": province,
        "account_kind": kind,
    }


async def _require_admin(actor: Actor) -> None:
    if not await is_admin(actor.judge_id):
        raise HTTPException(403, "Ta lista jest dla administratora.")


# ─────────────────────────── wzorzec ───────────────────────────


async def _current_reference() -> Optional[Dict[str, Any]]:
    row = await database.fetch_one(
        select(spk_reference)
        .where(spk_reference.c.match_number == SPK_MATCH_NUMBER)
        .order_by(desc(spk_reference.c.updated_at))
        .limit(1)
    )
    if row is None:
        return None
    ref = dict(row)
    # Meta liczymy z dokumentu meczu NA ŻYWO, a nie z kolumny zapisanej przy
    # imporcie. Zapisana meta zamarza w kształcie z tamtego dnia i każde jej
    # ulepszenie (medyk, wynik do przerwy) czekałoby na ponowny import wzorca -
    # a dokument, z którego się ją liczy, leży w wierszu obok.
    blob = ref.get("blob")
    if isinstance(blob, dict) and blob:
        ref["meta"] = meta_from_blob(blob)
    return ref


class ReferenceImportResult(BaseModel):
    ok: bool
    found: bool
    events: int = 0
    message: str = ""
    meta: Dict[str, Any] = Field(default_factory=dict)


@admin_router.post(
    "/reference/import",
    response_model=ReferenceImportResult,
    summary="Wczytaj wzorzec z protokołu ProEl",
)
async def import_reference(
    actor: Actor = Depends(proel_actor),
) -> ReferenceImportResult:
    """Bierze oficjalny protokół SPK/1 z ProEla i zapisuje go jako wzorzec.

    ODPOWIADA WPROST, GDY GO NIE MA. Milczenie przy braku protokołu byłoby tu
    najgorszą możliwą odpowiedzią: szkolenie wyglądałoby na gotowe, a każde
    podejście dostawałoby zero punktów za „pominięcie" wszystkiego.
    """
    await _require_admin(actor)

    row = await database.fetch_one(
        select(saved_matches).where(
            saved_matches.c.match_number == SPK_MATCH_NUMBER
        )
    )
    if row is None:
        return ReferenceImportResult(
            ok=False,
            found=False,
            message=(
                "W ProElu nie ma protokołu meczu SPK/1. Wzorzec musi skądś "
                "powstać - albo mecz trzeba wgrać do ProEla, albo wpisać oś "
                "czasu ręcznie."
            ),
        )

    blob = dict(row).get("data_json") or {}
    if not isinstance(blob, dict):
        return ReferenceImportResult(
            ok=False, found=True, message="Dokument meczu ma nieoczekiwany kształt."
        )

    timeline = blob.get("protocol")
    if not isinstance(timeline, list) or not timeline:
        return ReferenceImportResult(
            ok=False,
            found=True,
            message=(
                "Protokół SPK/1 jest w ProElu, ale nie ma w nim żadnych zdarzeń. "
                "Bez osi czasu nie ma czego porównywać."
            ),
        )

    meta = meta_from_blob(blob)
    await database.execute(
        spk_reference.insert().values(
            match_number=SPK_MATCH_NUMBER,
            zprp_match_id=meta.get("zprpMatchId") or None,
            timeline=timeline,
            meta=meta,
            blob=blob,
            source="proel",
            updated_by=str(actor.name or actor.judge_id or "").strip() or None,
            updated_at=datetime.now(timezone.utc),
        )
    )
    return ReferenceImportResult(
        ok=True,
        found=True,
        events=len(timeline),
        meta=meta,
        message=f"Wzorzec wczytany: {len(timeline)} zdarzeń.",
    )


@admin_router.get("/reference", summary="Obowiązujący wzorzec")
async def get_reference(actor: Actor = Depends(proel_actor)) -> Dict[str, Any]:
    await _require_admin(actor)
    ref = await _current_reference()
    if ref is None:
        return {"ok": True, "hasReference": False}
    return {
        "ok": True,
        "hasReference": True,
        "matchNumber": ref["match_number"],
        "events": len(ref["timeline"] or []),
        # Liczba SLAJDÓW to nie liczba zdarzeń: akcje z tej samej sekundy
        # („bramka i kara") składają się w jedno polecenie. Panel pokazuje
        # przy materiale, ile stron naprawdę z tego wyjdzie.
        "slides": len(
            slides_from_timeline(
                ref["timeline"] or [],
                shootout=shootout_shots(
                    ref["blob"] if isinstance(ref["blob"], dict) else {}
                ),
            )
        ),
        "meta": ref["meta"] or {},
        "source": ref["source"],
        "updatedBy": ref["updated_by"],
        "updatedAt": ref["updated_at"].isoformat() if ref["updated_at"] else None,
        "timeline": ref["timeline"] or [],
    }


# ─────────────────────────── wejście sędziego ───────────────────────────


@router.get("/brief", summary="Dane meczu szkoleniowego")
async def brief(
    mode: str = Query(
        "video", description="video, condensed, slides albo guided"
    ),
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    """Co telefon musi wiedzieć, zanim sędzia zacznie.

    OŚ CZASU WYCHODZI STĄD TYLKO W TRYBIE PREZENTACJI - bo tam JEST ćwiczeniem:
    sędzia czyta z niej polecenia. Przy nagraniu byłaby kluczem odpowiedzi
    leżącym w pamięci telefonu, więc jej nie wysyłamy. Ocenę i tak liczy serwer,
    aplikacja nie ma po co znać wzorca wcześniej.

    STAN NA PRZERWIE WYCHODZI TYLKO PRZY SKRÓCONYM NAGRANIU. Zawiera pierwszą
    połowę wzorca, więc jest częścią klucza odpowiedzi - ale tam pierwsza
    połowa nie jest oceniana ani przez sędziego prowadzona, tylko wczytana.
    Wysłanie go w pozostałych trybach oddawałoby połowę meczu za darmo.
    """
    ref = await _current_reference()
    if ref is None:
        return {"ok": True, "available": False}

    who = await _identity(actor)
    mine = await database.fetch_val(
        select(func.count())
        .select_from(spk_run)
        .where(spk_run.c.judge_id == who["judge_id"])
    )

    out: Dict[str, Any] = {
        "ok": True,
        "available": True,
        "matchNumber": ref["match_number"],
        "meta": ref["meta"] or {},
        "attempts": int(mine or 0),
    }
    blob = ref["blob"] if isinstance(ref["blob"], dict) else {}
    if mode in ("slides", "guided"):
        # Tryb prowadzony w aplikacji to prezentacja z wykrywaniem wykonania -
        # klucz odpowiedzi i tak jest wtedy na ekranie, więc slajdy lecą tak
        # samo jak przy zwykłej prezentacji.
        out["slides"] = slides_from_timeline(
            ref["timeline"] or [],
            ref["meta"] or {},
            shootout=shootout_shots(blob),
        )
    if mode == "guided":
        # Kto naprawdę wszedł na boisko. TYLKO w prowadzeniu za rękę: w
        # pozostałych trybach rubryka wejścia jest częścią ćwiczenia i jej
        # gotowa lista byłaby oddaniem punktów za darmo. Tutaj cały wzorzec
        # i tak stoi na ekranie, a bez tej listy ćwiczący kończył mecz z
        # pustymi wejściami zawodników, którzy nic nie przeskrobali.
        out["entries"] = entered_players(blob)
    if mode == "condensed":
        if not blob:
            # Wzorzec wczytany starszym wydaniem serwera nie ma przy sobie
            # dokumentu meczu. Mówimy o tym wprost - inaczej sędzia dostałby
            # pusty mecz i zaczynał drugą połowę od 0:0.
            out["startState"] = None
            out["startStateReason"] = (
                "Ten wzorzec został wczytany bez pełnego dokumentu meczu. "
                "Wczytaj wzorzec ponownie w panelu, żeby ćwiczenie od drugiej "
                "połowy miało od czego zacząć."
            )
        else:
            out["startState"] = state_after_first_half(blob)
        # Kotwice zegara: same pary czasów, bez treści zdarzeń - patrz
        # `training_spk_video.py`. Czasy są w arkuszu plansz co do sekundy,
        # więc wzorzec nie jest już do niczego potrzebny.
        out["videoClock"] = video_clock()
    # Adresy nagrań nie są kluczem odpowiedzi - idą w każdym trybie, a
    # ekran startowy pokazuje ten właściwy dla wybranej drogi.
    out["videoLinks"] = await video_links()
    return out


# ─────────────────────────── nagrania ───────────────────────────

#: Adres skrótu z chwili wdrożenia. Zmienia go administrator w panelu;
#: ten wpis obowiązuje tylko dopóki w bazie nic nie ma.
DEFAULT_VIDEO_LINKS: Dict[str, str] = {
    "full": "",
    # Nagranie Z PLANSZAMI - po każdej sytuacji 15-sekundowy opis. Kotwice
    # w `training_spk_video.py` są zmierzone w TYM nagraniu, więc podmiana
    # adresu bez podmiany kotwic rozjedzie zegar.
    "condensed": "https://iframe.mediadelivery.net/play/431457/2183341f-9116-4969-9aa1-1c7a05d0934d",
}


async def video_links() -> Dict[str, str]:
    """Adresy nagrań: z bazy, a gdy jej brak - domyślne."""
    links = dict(DEFAULT_VIDEO_LINKS)
    try:
        row = await database.fetch_one(
            select(spk_settings.c.payload).order_by(spk_settings.c.id.desc()).limit(1)
        )
    except Exception:  # noqa: BLE001 - brak tabeli nie może zabrać briefu
        logger.warning("spk_settings: odczyt nieudany", exc_info=True)
        return links
    payload = (dict(row).get("payload") if row else None) or {}
    stored = payload.get("videoLinks") if isinstance(payload, dict) else None
    if isinstance(stored, dict):
        for key in ("full", "condensed"):
            if key in stored:
                links[key] = str(stored.get(key) or "").strip()
    return links


class VideoLinksIn(BaseModel):
    full: str = ""
    condensed: str = ""


def _clean_link(value: str, label: str) -> str:
    text = (value or "").strip()
    if text and not (text.startswith("https://") or text.startswith("http://")):
        raise HTTPException(400, f"Adres nagrania ({label}) musi zaczynać się od https://.")
    return text


@router.get("/video-links", summary="Adresy nagrań sprawdzianu")
async def get_video_links(actor: Actor = Depends(proel_actor)) -> Dict[str, Any]:
    return {"ok": True, "links": await video_links()}


@admin_router.put("/video-links", summary="Zapis adresów nagrań (administrator)")
async def put_video_links(
    body: VideoLinksIn, actor: Actor = Depends(proel_actor)
) -> Dict[str, Any]:
    await _require_admin(actor)
    links = {
        "full": _clean_link(body.full, "cały mecz"),
        "condensed": _clean_link(body.condensed, "skrót"),
    }
    existing = await database.fetch_one(
        select(spk_settings.c.id, spk_settings.c.payload)
        .order_by(spk_settings.c.id.desc())
        .limit(1)
    )
    if existing:
        row = dict(existing)
        payload = dict(row.get("payload") or {})
        payload["videoLinks"] = links
        await database.execute(
            spk_settings.update()
            .where(spk_settings.c.id == row["id"])
            .values(payload=payload, updated_by=actor.judge_id)
        )
    else:
        await database.execute(
            spk_settings.insert().values(
                payload={"videoLinks": links}, updated_by=actor.judge_id
            )
        )
    return {"ok": True, "links": links}


class RunIn(BaseModel):
    runId: str
    #: "video", "condensed", "slides" albo "guided" (nauka w aplikacji).
    mode: str = "video"
    appVersion: Optional[str] = None
    #: Pełny stan meczu - ten sam kształt, co dokument ProEla.
    dataJson: Dict[str, Any] = Field(default_factory=dict)


@router.post("/run", summary="Zapisz podejście i policz wynik")
async def save_run(
    body: RunIn,
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    ref = await _current_reference()
    if ref is None:
        raise HTTPException(
            409,
            detail={
                "code": "NO_REFERENCE",
                "message": "Wzorzec tego szkolenia nie został jeszcze wczytany.",
            },
        )

    blob = body.dataJson if isinstance(body.dataJson, dict) else {}
    mine_meta = meta_from_blob(blob)
    # Tryb rozstrzyga o CAŁEJ ocenie, więc nieznana wartość nie ma prawa przejść
    # dalej jako ona sama - wpada na najostrzejszy tryb, nie na najłagodniejszy.
    mode = body.mode if body.mode in ("slides", "condensed", "guided") else "video"

    report = score_run(
        ref["timeline"] or [],
        blob.get("protocol"),
        # Nauka w aplikacji liczy się jak prezentacja (kolejność i numery, bez
        # czasu) - własnego trybu w silniku nie ma, bo różni się WYŁĄCZNIE tym,
        # że sędzia był prowadzony. To rozróżnienie niesie zapisany `mode`.
        mode="slides" if mode == "guided" else mode,
        reference_meta=ref["meta"] or {},
        attempt_meta=mine_meta,
    )
    report["grade"] = grade(report["score"])
    report["mode"] = mode

    who = await _identity(actor)
    previous = await database.fetch_val(
        select(func.count())
        .select_from(spk_run)
        .where(spk_run.c.judge_id == who["judge_id"])
    )

    now = datetime.now(timezone.utc)
    values = {
        "judge_id": who["judge_id"] or None,
        "judge_name": who["judge_name"] or None,
        "province": who["province"] or None,
        "account_kind": who["account_kind"],
        "install_id": actor.installation_id or None,
        "attempt": int(previous or 0) + 1,
        "mode": mode,
        "score": report["score"],
        "score_json": report,
        "data_json": blob,
        "app_version": body.appVersion,
        "ended_at": now,
        "updated_at": now,
    }

    existing = await database.fetch_one(
        select(spk_run.c.id, spk_run.c.attempt).where(spk_run.c.run_id == body.runId)
    )
    if existing is None:
        await database.execute(spk_run.insert().values(run_id=body.runId, **values))
    else:
        # Ponowny zapis TEGO SAMEGO podejścia nie jest nowym podejściem -
        # telefon dosyła stan po odzyskaniu zasięgu. Numer porządkowy zostaje
        # ten, który wpis dostał za pierwszym razem.
        values["attempt"] = dict(existing)["attempt"]
        await database.execute(
            spk_run.update().where(spk_run.c.run_id == body.runId).values(**values)
        )

    # Ocena słowna pisze się W TLE - OpenAI potrafi myśleć dziesięć sekund i
    # miewa gorsze dni, a sędzia stoi przed ekranem wyniku i czeka na liczbę.
    # Liczba wychodzi od razu; tekst dojedzie, a klient o niego dopyta.
    asyncio.create_task(_write_ai_summary(body.runId, report))

    return {"ok": True, "runId": body.runId, "report": report}


async def _write_ai_summary(run_id: str, report: Dict[str, Any]) -> None:
    """Dopisuje ocenę modelu do zapisanego podejścia. Porażka = brak, nie błąd."""
    try:
        import openai

        client = openai.AsyncOpenAI()
        resp = await client.chat.completions.create(
            model=AI_MODEL,
            messages=ai_messages(report),
            max_tokens=320,
            temperature=0.5,
        )
        summary = clean_ai_summary(resp.choices[0].message.content)
        if not summary:
            return
        await database.execute(
            spk_run.update()
            .where(spk_run.c.run_id == run_id)
            .values(
                ai_json={
                    "summary": summary,
                    "model": AI_MODEL,
                    "generatedAt": datetime.now(timezone.utc).isoformat(),
                }
            )
        )
    except Exception:  # noqa: BLE001 — ocena słowna jest dodatkiem, nie warunkiem
        logger.warning("SPK: ocena AI dla %s nie powstała", run_id, exc_info=True)


@router.get("/run-ai", summary="Ocena AI mojego podejścia")
async def run_ai(
    runId: str = Query(..., min_length=4),
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    """Tekst oceny, gdy już jest - klient dopytuje po zapisie.

    Tylko WŁASNE podejście: wpis musi się zgadzać z tożsamością pytającego
    (numer sędziego albo urządzenie). Cudze oceny są w panelu administratora.
    """
    row = await database.fetch_one(select(spk_run).where(spk_run.c.run_id == runId))
    if row is None:
        raise HTTPException(404, "Nie ma takiego podejścia.")
    data = dict(row)
    who = await _identity(actor)
    mine = (
        (who["judge_id"] and data.get("judge_id") == who["judge_id"])
        or (
            actor.installation_id
            and data.get("install_id") == actor.installation_id
        )
    )
    if not mine and not await is_admin(actor.judge_id):
        raise HTTPException(403, "To podejście należy do kogoś innego.")
    ai = data.get("ai_json") if isinstance(data.get("ai_json"), dict) else None
    return {
        "ok": True,
        "status": "ready" if ai and ai.get("summary") else "pending",
        "summary": (ai or {}).get("summary", ""),
    }


@router.get("/runs/mine", summary="Moje podejścia")
async def my_runs(actor: Actor = Depends(proel_actor)) -> Dict[str, Any]:
    who = await _identity(actor)
    if not who["judge_id"]:
        return {"ok": True, "runs": []}
    rows = await database.fetch_all(
        select(
            spk_run.c.run_id,
            spk_run.c.attempt,
            spk_run.c.mode,
            spk_run.c.score,
            spk_run.c.score_json,
            spk_run.c.ended_at,
        )
        .where(spk_run.c.judge_id == who["judge_id"])
        .order_by(desc(spk_run.c.ended_at))
        .limit(50)
    )
    return {
        "ok": True,
        "runs": [
            {
                "runId": d["run_id"],
                "attempt": d["attempt"],
                "mode": d["mode"],
                "score": float(d["score"]) if d["score"] is not None else None,
                "report": d["score_json"],
                "endedAt": d["ended_at"].isoformat() if d["ended_at"] else None,
            }
            for d in (dict(r) for r in rows)
        ],
    }


# ─────────────────────────── panel administratora ───────────────────────────


@admin_router.get("/runs", summary="Wszystkie podejścia")
async def list_runs(
    limit: int = Query(500, ge=1, le=2000),
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    """Surowe wiersze plus jedno zestawienie po okręgach.

    Liczby liczymy TUTAJ, nie w panelu: średnia i mediana okręgu to rzeczy, o
    które ktoś zapyta „a z czego to wyszło", i muszą dać się pokazać w teście.
    Panel dostaje gotowe wartości i rysuje.
    """
    await _require_admin(actor)
    rows = await database.fetch_all(
        select(spk_run).order_by(desc(spk_run.c.ended_at)).limit(limit)
    )
    runs = [
        {
            "runId": d["run_id"],
            "judgeId": d["judge_id"],
            "judgeName": d["judge_name"],
            "province": d["province"],
            "accountKind": d["account_kind"],
            "attempt": d["attempt"],
            "mode": d["mode"],
            "score": float(d["score"]) if d["score"] is not None else None,
            "counts": (d["score_json"] or {}).get("counts") if d["score_json"] else None,
            "parts": (d["score_json"] or {}).get("parts") if d["score_json"] else None,
            "endedAt": d["ended_at"].isoformat() if d["ended_at"] else None,
        }
        for d in (dict(r) for r in rows)
    ]
    return {"ok": True, "runs": runs, "byProvince": summarize_by_province(runs)}


def summarize_by_province(runs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Zestawienie po okręgach - z NAJLEPSZEGO podejścia każdego sędziego.

    Ze średniej po WSZYSTKICH podejściach wychodziłaby nieprawda: kto ćwiczy
    wytrwale, ma więcej słabych pierwszych prób i wypada gorzej od kogoś, kto
    podszedł raz i przestał. Szkolenie ma nagradzać powtarzanie, a nie karać za
    nie, więc liczymy to, co sędzia ostatecznie umie.
    """
    best: Dict[str, Dict[str, Any]] = {}
    for run in runs:
        if run.get("score") is None:
            continue
        # Nauka w aplikacji prowadzi za rękę, więc gwarantuje niemal komplet
        # zdarzeń - w zestawieniu mówiłaby nieprawdę. Widać ją na liście
        # podejść, do średnich nie wchodzi.
        if run.get("mode") == "guided":
            continue
        key = str(run.get("judgeId") or run.get("runId"))
        current = best.get(key)
        if current is None or run["score"] > current["score"]:
            best[key] = run

    grouped: Dict[str, List[float]] = {}
    for run in best.values():
        grouped.setdefault(str(run.get("province") or ""), []).append(run["score"])

    out: List[Dict[str, Any]] = []
    for province, scores in grouped.items():
        ordered = sorted(scores)
        middle = len(ordered) // 2
        median = (
            ordered[middle]
            if len(ordered) % 2 == 1
            else round((ordered[middle - 1] + ordered[middle]) / 2, 1)
        )
        out.append(
            {
                "province": province,
                "judges": len(ordered),
                "avg": round(sum(ordered) / len(ordered), 1),
                "median": median,
                "best": ordered[-1],
                "worst": ordered[0],
            }
        )
    out.sort(key=lambda x: (-x["avg"], x["province"]))
    return out


async def _slides_response() -> Response:
    """Prezentacja złożona z obowiązującego wzorca - jedna akcja na stronę.

    Składana NA ŻĄDANIE, a nie trzymana jako plik. Poprawka jednej akcji ma iść
    w materiał sama; plik w repozytorium wymagałby pamiętania o złożeniu go od
    nowa, a o tym się zapomina dokładnie raz.
    """
    ref = await _current_reference()
    if ref is None:
        raise HTTPException(404, "Wzorzec nie został jeszcze wczytany.")
    try:
        blob = ref["blob"] if isinstance(ref["blob"], dict) else {}
        data = build_slides_pdf(
            ref["timeline"] or [],
            ref["meta"] or {},
            shootout=shootout_shots(blob),
        )
    except SpkPdfError as exc:
        raise HTTPException(409, str(exc))
    return Response(
        content=data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="prezentacja-SPK1.pdf"'
        },
    )


class SlidesLink(BaseModel):
    ok: bool = True
    #: Ścieżka z podpisem - adres publiczny składa aplikacja, bo to ONA go zna.
    path: str
    expiresAt: int


@admin_router.post("/slides-link", response_model=SlidesLink, summary="Adres materiału")
async def slides_link(actor: Actor = Depends(proel_actor)) -> SlidesLink:
    """Podpisany adres, pod którym menedżer pobierania weźmie prezentację.

    PO CO OSOBNY ADRES, skoro trasa poniżej istnieje. Bo tamta sprawdza
    nagłówki aktora, a systemowy menedżer pobierania żadnych nie niesie -
    dostałby 403. Reszta aplikacji pobiera PDF-y właśnie przez adres (protokół
    meczu w `MatchSummaryScreen`), więc materiał ma to robić tak samo: plik
    ląduje w Pobranych, bez pytania o katalog.

    ADRES ZWRACAMY JAKO ŚCIEŻKĘ, nie jako pełny URL. Serwer stoi za proxy i
    jego własne wyobrażenie o swoim adresie bywa nieprawdziwe (schemat http
    zamiast https); aplikacja zna adres backendu na pewno, bo się z nim łączy.

    Sprawdzamy TU, że wzorzec w ogóle jest - inaczej sędzia dostałby adres,
    który po naciśnięciu otwiera pustą stronę z błędem gdzieś w przeglądarce,
    zamiast zdania na ekranie.
    """
    await _require_admin(actor)
    if await _current_reference() is None:
        raise HTTPException(404, "Wzorzec nie został jeszcze wczytany.")
    token = create_pdf_token(str(actor.judge_id or ""))
    return SlidesLink(
        path="/training/spk/slides.pdf?t=" + token,
        expiresAt=token_expires_at(token),
    )


@router.get("/slides.pdf", summary="Materiał szkoleniowy (adres podpisany)")
async def slides_pdf_signed(t: str = Query("", description="Podpis z /slides-link")) -> Response:
    """Trasa dla menedżera pobierania - uprawnienie siedzi w adresie.

    Token jest tu CAŁYM uprawnieniem, więc wygasły to odmowa, a nie zejście na
    inną ścieżkę. Żyje minuty i otwiera wyłącznie ten jeden materiał.
    """
    payload = verify_pdf_token(t)
    if payload is None or payload.get("doc", "slides") != "slides":
        raise HTTPException(403, "Adres materiału wygasł. Poproś o nowy w panelu.")
    return await _slides_response()


@admin_router.get("/slides.pdf", summary="Materiał szkoleniowy (nagłówki aktora)")
async def slides_pdf(actor: Actor = Depends(proel_actor)) -> Response:
    """To samo, ale dla wywołania z nagłówkami - zostaje do diagnostyki."""
    await _require_admin(actor)
    return await _slides_response()


# ─────────────────────────── podgląd podejścia ───────────────────────────


async def _run_detail_payload(run_id: str) -> Dict[str, Any]:
    """Wszystko, co panel pokaże o jednym podejściu - „co kto klikał".

    Trzy warstwy: pełny raport oceny (różnice zdarzenie po zdarzeniu), ocena
    słowna AI i PRZEBIEG WPISÓW sędziego - jego protokół zamieniony na zdania
    tym samym modułem, którym mówią slajdy. Panel niczego nie składa sam, bo
    wtedy to samo zdarzenie brzmiałoby inaczej w prezentacji i w podglądzie.

    OSOBNA FUNKCJA, BO CZYTELNIKÓW JEST DWÓCH: administrator (trasa niżej) i
    sędzia, który otworzył wyniki swojego okręgu hasłem. Mają zobaczyć dokładnie
    to samo - dwa podobne składania znaczyłyby, że przy pierwszej poprawce
    zaczną mówić co innego. Uprawnienie sprawdza wołający, nie ta funkcja.
    """
    row = await database.fetch_one(select(spk_run).where(spk_run.c.run_id == run_id))
    if row is None:
        raise HTTPException(404, "Nie ma takiego podejścia.")
    data = dict(row)

    blob = data.get("data_json") if isinstance(data.get("data_json"), dict) else {}
    clicks: List[Dict[str, Any]] = []
    for event in blob.get("protocol") or []:
        if not isinstance(event, dict):
            continue
        text = action_text(event)
        if not text:
            continue
        clicks.append(
            {
                "clock": format_clock(event.get("time")),
                "half": int(event.get("half") or 1),
                "shootout": bool(event.get("shootout")),
                "text": text,
            }
        )
        if len(clicks) >= 400:
            break

    ai = data.get("ai_json") if isinstance(data.get("ai_json"), dict) else None
    return {
        "ok": True,
        "run": {
            "runId": data["run_id"],
            "judgeId": data["judge_id"],
            "judgeName": data["judge_name"],
            "province": data["province"],
            "accountKind": data["account_kind"],
            "attempt": data["attempt"],
            "mode": data["mode"],
            "score": float(data["score"]) if data["score"] is not None else None,
            "report": data.get("score_json") or None,
            "ai": (ai or {}).get("summary", ""),
            "appVersion": data.get("app_version"),
            "endedAt": data["ended_at"].isoformat() if data["ended_at"] else None,
            "clicks": clicks,
        },
    }


async def _run_state_payload(run_id: str) -> Dict[str, Any]:
    """Pełny dokument meczu z tego podejścia - do podglądu w panelu.

    OSOBNA TRASA, bo to setki kilobajtów: lista podejść i karta szczegółów mają
    być lekkie, a stan meczu schodzi dopiero wtedy, gdy administrator naprawdę
    chce zobaczyć protokół. Kształt jest ten sam, co dokument ProEla, więc
    panel podaje go wprost do `MatchSummaryScreen` - tak samo jak przy podglądzie
    zapisu w zakładce protokołów.
    """
    row = await database.fetch_one(
        select(spk_run.c.run_id, spk_run.c.data_json).where(spk_run.c.run_id == run_id)
    )
    if row is None:
        raise HTTPException(404, "Nie ma takiego podejścia.")
    data = dict(row)
    blob = data.get("data_json") if isinstance(data.get("data_json"), dict) else {}
    if not blob:
        raise HTTPException(
            409,
            "To podejście zapisało się bez dokumentu meczu - nie ma czego pokazać.",
        )
    return {"ok": True, "runId": data["run_id"], "dataJson": blob}


@admin_router.get("/runs/{run_id}", summary="Jedno podejście w szczegółach")
async def run_detail(
    run_id: str,
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    await _require_admin(actor)
    return await _run_detail_payload(run_id)


@admin_router.get("/runs/{run_id}/state", summary="Protokół podejścia")
async def run_state(
    run_id: str,
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    await _require_admin(actor)
    return await _run_state_payload(run_id)


# ─────────────────────────── raport wyników PDF ───────────────────────────


class ReportLinkIn(BaseModel):
    #: Pusto = raport ogólnopolski; nazwa okręgu = raport jednego okręgu.
    province: str = ""


@admin_router.post(
    "/report-link", response_model=SlidesLink, summary="Adres raportu wyników"
)
async def report_link(
    body: ReportLinkIn,
    actor: Actor = Depends(proel_actor),
) -> SlidesLink:
    """Podpisany adres raportu - ta sama droga, którą jedzie prezentacja.

    Okręg siedzi W TOKENIE, nie w parametrze adresu: podpisanego linku nie da
    się wtedy przepisać na inny okręg. Osobny `doc`, bo adres prezentacji jest
    do pokazania sali, a raport niesie nazwiska i wyniki sędziów.
    """
    await _require_admin(actor)
    token = create_pdf_token(
        str(actor.judge_id or ""),
        doc="report",
        province=normalize_province(body.province) or body.province.strip().upper(),
    )
    return SlidesLink(
        path="/training/spk/report.pdf?t=" + token,
        expiresAt=token_expires_at(token),
    )


async def _report_response(province: str, issued_by: str) -> Response:
    rows = await database.fetch_all(
        select(spk_run).order_by(desc(spk_run.c.ended_at)).limit(5000)
    )
    runs = [
        {
            "runId": d["run_id"],
            "judgeId": d["judge_id"],
            "judgeName": d["judge_name"],
            "province": d["province"],
            "attempt": d["attempt"],
            "mode": d["mode"],
            "score": float(d["score"]) if d["score"] is not None else None,
        }
        for d in (dict(r) for r in rows)
    ]
    context = report_context(runs, province=province, generated_by=issued_by)
    try:
        data = build_report_pdf(context)
    except Exception as exc:  # noqa: BLE001 — WeasyPrint mówi po swojemu
        logger.warning("SPK: raport PDF nie powstał", exc_info=True)
        raise HTTPException(500, "Nie udało się złożyć raportu.") from exc
    scope = (province or "POLSKA").replace(" ", "-")
    return Response(
        content=data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="raport-SPK1-{scope}.pdf"'
        },
    )


@router.get("/report.pdf", summary="Raport wyników (adres podpisany)")
async def report_pdf_signed(
    t: str = Query("", description="Podpis z /report-link"),
) -> Response:
    payload = verify_pdf_token(t)
    if payload is None or payload.get("doc") != "report":
        raise HTTPException(403, "Adres raportu wygasł. Poproś o nowy w panelu.")
    return await _report_response(
        str(payload.get("prov") or ""), str(payload.get("by") or "")
    )


# ───────────────── dostęp okręgu do własnych wyników ─────────────────
#
# DO TEJ PORY WYNIKI WIDZIAŁ TYLKO ADMINISTRATOR i to była świadoma decyzja:
# lista niesie nazwiska i liczby, które czyta się jak ranking. Okręgi jednak
# pytają o nie same - to ich sędziowie i ich szkolenie. Odpowiedź jest
# pośrednia: administrator otwiera okręg po okręgu, a hasło rozstrzyga, czy
# przed wynikami stoi ktoś, komu je podano. Reguły hasła siedzą w
# `app/spk_province_gate.py`, tutaj jest tylko rozmowa z bazą i z aplikacją.
#
# SĘDZIA WIDZI TO SAMO CO ADMINISTRATOR, taka była decyzja - z podejściami
# kolegów z okręgu włącznie. Dlatego trasy niżej wołają DOKŁADNIE te same
# funkcje (`_run_detail_payload`, `_run_state_payload`, `summarize_by_province`),
# a nie własne, podobne składania.

#: Klucz rygli w jedynym wierszu `spk_settings` - obok `videoLinks`.
PROVINCE_ACCESS_KEY = "provinceAccess"


def _access_entry(raw: Any) -> Dict[str, Any]:
    """Jeden rygiel sprowadzony do kształtu, na który można liczyć."""
    data = raw if isinstance(raw, dict) else {}
    return {
        "enabled": bool(data.get("enabled")),
        "password": normalize_password(data.get("password")),
        "updatedAt": str(data.get("updatedAt") or "") or None,
        "updatedBy": str(data.get("updatedBy") or "") or None,
    }


async def province_access_map() -> Dict[str, Dict[str, Any]]:
    """Rygle wszystkich okręgów z bazy. Brak wiersza = nikt nic nie otworzył."""
    try:
        row = await database.fetch_one(
            select(spk_settings.c.payload).order_by(spk_settings.c.id.desc()).limit(1)
        )
    except Exception:  # noqa: BLE001 - brak tabeli nie może wywrócić ekranu
        logger.warning("spk_settings: odczyt rygli nieudany", exc_info=True)
        return {}
    payload = (dict(row).get("payload") if row else None) or {}
    stored = payload.get(PROVINCE_ACCESS_KEY) if isinstance(payload, dict) else None
    if not isinstance(stored, dict):
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    for key, value in stored.items():
        province = normalize_province(key)
        if province:
            out[province] = _access_entry(value)
    return out


async def _save_province_access(
    province: str, enabled: bool, password: str, by: str
) -> Dict[str, Any]:
    """Zapis jednego rygla. Reszta okręgów zostaje nietknięta."""
    entry = {
        "enabled": bool(enabled),
        "password": normalize_password(password),
        "updatedAt": datetime.now(timezone.utc).isoformat(),
        "updatedBy": str(by or "").strip() or None,
    }
    existing = await database.fetch_one(
        select(spk_settings.c.id, spk_settings.c.payload)
        .order_by(spk_settings.c.id.desc())
        .limit(1)
    )
    if existing:
        row = dict(existing)
        payload = dict(row.get("payload") or {})
        access = dict(payload.get(PROVINCE_ACCESS_KEY) or {})
        access[province] = entry
        payload[PROVINCE_ACCESS_KEY] = access
        await database.execute(
            spk_settings.update()
            .where(spk_settings.c.id == row["id"])
            .values(payload=payload, updated_by=by)
        )
    else:
        await database.execute(
            spk_settings.insert().values(
                payload={PROVINCE_ACCESS_KEY: {province: entry}}, updated_by=by
            )
        )
    return entry


class ProvinceAccessIn(BaseModel):
    province: str
    enabled: bool = False
    #: Puste przy włączaniu = wylosuj nowe. Podane = to jest hasło okręgu.
    password: str = ""


@admin_router.get("/province-access", summary="Rygle wyników okręgów")
async def admin_province_access(actor: Actor = Depends(proel_actor)) -> Dict[str, Any]:
    """Wszystkie szesnaście okręgów, z hasłami.

    HASŁA JAWNIE, i to jest właściwa odpowiedź: administrator ma je komuś
    podać. Skrót kryptograficzny dawałby tu pole „nie do odczytania" i zmuszał
    do losowania nowego hasła za każdym razem, gdy ktoś zapyta, jakie jest
    obecne. Ta lista stoi już za bramką numeru administratora.
    """
    await _require_admin(actor)
    access = await province_access_map()
    return {
        "ok": True,
        "provinces": [
            {"province": province, **(access.get(province) or _access_entry(None))}
            for province in sorted(PROVINCE_ENV_SUFFIXES)
        ],
    }


@admin_router.put("/province-access", summary="Zapis rygla okręgu")
async def admin_save_province_access(
    body: ProvinceAccessIn, actor: Actor = Depends(proel_actor)
) -> Dict[str, Any]:
    await _require_admin(actor)
    province = normalize_province(body.province)
    if not province:
        raise HTTPException(400, "Nie znam takiego okręgu.")
    password = normalize_password(body.password)
    # Włączenie bez hasła musi COŚ znaczyć, a jedyne sensowne znaczenie to
    # „wylosuj". Pusty rygiel z zapalonym światłem byłby drzwiami bez zamka.
    if body.enabled and not password:
        password = generate_password()
    entry = await _save_province_access(
        province, body.enabled, password, str(actor.judge_id or "")
    )
    return {"ok": True, "province": province, **entry}


@router.get("/province-gate", summary="Czy mój okręg udostępnia wyniki")
async def province_gate(actor: Actor = Depends(proel_actor)) -> Dict[str, Any]:
    """Co aplikacja ma zrobić z kaflem „wyniki mojego okręgu".

    OKRĘG BIERZEMY Z KONTA, nie z pytania na ekranie - konto BAZY ma go w
    `login_records`, konto ProEl we własnej tabeli (patrz `_identity`). Pusty
    okręg to profil lokalny bez konta: wtedy aplikacja pyta, o który okręg
    chodzi, i rozstrzyga samo hasło.

    HASŁA TU NIE MA i nie będzie - ta trasa jest otwarta dla każdego, kto ma
    aplikację. Oddajemy jego DŁUGOŚĆ, bo z niej aplikacja buduje pole na hasło
    (sześć okienek zamiast jednej kreski). Przy haśle losowym z trzydziestu
    dwóch znaków sama długość nie zbliża nikogo do odgadnięcia.
    """
    who = await _identity(actor)
    access = await province_access_map()
    mine = who["province"]
    mine_entry = (access.get(mine) or {}) if mine else {}
    return {
        "ok": True,
        "province": mine,
        "enabled": bool(mine_entry.get("enabled")),
        "passwordLength": len(str(mine_entry.get("password") or "")),
        #: Okręgi z otwartymi wynikami - do wyboru z listy herbów, gdy konto
        #: nie mówi, skąd jest sędzia.
        "openProvinces": [
            {
                "province": province,
                "passwordLength": len(str(entry.get("password") or "")),
            }
            for province, entry in sorted(access.items())
            if entry.get("enabled")
        ],
    }


class ProvinceUnlockIn(BaseModel):
    #: Pusto = mój okręg z konta.
    province: str = ""
    password: str = ""


class ProvinceUnlocked(BaseModel):
    ok: bool = True
    province: str
    token: str
    expiresAt: int


@router.post(
    "/province-unlock",
    response_model=ProvinceUnlocked,
    summary="Otwórz wyniki okręgu hasłem",
)
async def province_unlock(
    body: ProvinceUnlockIn, actor: Actor = Depends(proel_actor)
) -> ProvinceUnlocked:
    """Hasło w zamian za token okręgu - patrz `app/spk_province_gate.py`.

    TYLKO SWÓJ OKRĘG, gdy konto mówi, który to jest. Hasło krąży po grupie
    okręgowej i prędzej czy później wypłynie dalej; wtedy jedyne, co je
    powstrzyma przed otwarciem cudzych wyników, to ten warunek. Gdy konta nie
    ma (profil lokalny), okręgu nie ma z czym porównać i rozstrzyga samo hasło -
    to świadomie słabszy przypadek, nie przeoczenie.

    ODMOWA MÓWI, CZEGO DOTYCZY: inny okręg, zamknięte wyniki i złe hasło to
    trzy różne zdania. Jedno „brak dostępu" na wszystko kazałoby sędziemu
    zgadywać, czy pomylił się w haśle, czy jego okręg jeszcze nic nie otworzył.
    """
    who = await _identity(actor)
    mine = who["province"]
    wanted = normalize_province(body.province) or mine
    if not wanted:
        raise HTTPException(400, "Nie wiem, o który okręg pytasz.")
    if mine and wanted != mine:
        raise HTTPException(403, "Wyniki otwiera się tylko we własnym okręgu.")

    access = await province_access_map()
    entry = access.get(wanted) or {}
    if not entry.get("enabled"):
        raise HTTPException(403, "Ten okręg nie udostępnia jeszcze swoich wyników.")
    if not passwords_match(body.password, entry.get("password")):
        raise HTTPException(403, "Hasło nie pasuje do tego okręgu.")

    token = create_province_token(wanted, str(actor.judge_id or ""))
    return ProvinceUnlocked(
        province=wanted, token=token, expiresAt=province_token_expires_at(token)
    )


def _province_from_token(token: str) -> str:
    """Okręg z podpisanego tokenu albo odmowa. Nic pośredniego."""
    payload = verify_province_token(token)
    if payload is None:
        raise HTTPException(403, "Dostęp do wyników wygasł. Wpisz hasło jeszcze raz.")
    province = normalize_province(payload.get("prov"))
    if not province:
        raise HTTPException(403, "Ten dostęp nie wskazuje żadnego okręgu.")
    return province


@router.get("/province/runs", summary="Wyniki okręgu (po haśle)")
async def province_runs(
    t: str = Query("", description="Token z /province-unlock"),
    limit: int = Query(500, ge=1, le=2000),
) -> Dict[str, Any]:
    """Podejścia jednego okręgu plus jego wiersz zestawienia.

    Zestawienie liczy `summarize_by_province` - ta sama funkcja, co w panelu.
    Druga arytmetyka znaczyłaby, że średnia okręgu w aplikacji i w panelu
    rozjadą się przy pierwszej zmianie reguły.
    """
    province = _province_from_token(t)
    rows = await database.fetch_all(
        select(spk_run)
        .where(spk_run.c.province == province)
        .order_by(desc(spk_run.c.ended_at))
        .limit(limit)
    )
    runs = [
        {
            "runId": d["run_id"],
            "judgeId": d["judge_id"],
            "judgeName": d["judge_name"],
            "province": d["province"],
            "accountKind": d["account_kind"],
            "attempt": d["attempt"],
            "mode": d["mode"],
            "score": float(d["score"]) if d["score"] is not None else None,
            "counts": (d["score_json"] or {}).get("counts") if d["score_json"] else None,
            "parts": (d["score_json"] or {}).get("parts") if d["score_json"] else None,
            "endedAt": d["ended_at"].isoformat() if d["ended_at"] else None,
        }
        for d in (dict(r) for r in rows)
    ]
    summary = next(
        (row for row in summarize_by_province(runs) if row["province"] == province),
        None,
    )
    return {"ok": True, "province": province, "runs": runs, "summary": summary}


@router.get("/province/runs/{run_id}", summary="Podejście z mojego okręgu")
async def province_run_detail(
    run_id: str,
    t: str = Query("", description="Token z /province-unlock"),
) -> Dict[str, Any]:
    """Szczegóły podejścia - wyłącznie z okręgu, który token otwiera.

    Warunek okręgu sprawdzamy PO odczytaniu wiersza, a nie ufamy temu, że
    aplikacja poda numer z własnej listy: numer podejścia jest jawny w jej
    pamięci, więc bez tego warunku token jednego okręgu otwierałby cudze
    podejścia przez sam podmieniony adres.
    """
    province = _province_from_token(t)
    payload = await _run_detail_payload(run_id)
    if normalize_province(payload["run"].get("province")) != province:
        raise HTTPException(403, "To podejście jest z innego okręgu.")
    return payload


@router.get("/province/runs/{run_id}/state", summary="Protokół podejścia z okręgu")
async def province_run_state(
    run_id: str,
    t: str = Query("", description="Token z /province-unlock"),
) -> Dict[str, Any]:
    province = _province_from_token(t)
    row = await database.fetch_one(
        select(spk_run.c.province).where(spk_run.c.run_id == run_id)
    )
    if row is None:
        raise HTTPException(404, "Nie ma takiego podejścia.")
    if normalize_province(dict(row).get("province")) != province:
        raise HTTPException(403, "To podejście jest z innego okręgu.")
    return await _run_state_payload(run_id)


class ProvinceReportIn(BaseModel):
    token: str = ""


@router.post(
    "/province/report-link",
    response_model=SlidesLink,
    summary="Adres raportu mojego okręgu",
)
async def province_report_link(
    body: ProvinceReportIn, actor: Actor = Depends(proel_actor)
) -> SlidesLink:
    """Raport PDF okręgu dla sędziego, który otworzył wyniki hasłem.

    Okręg przepisujemy Z TOKENU do podpisu PDF-a, a nie z ciała zapytania -
    inaczej ktokolwiek z ważnym dostępem do własnego okręgu wyprosiłby raport
    dowolnego innego.
    """
    province = _province_from_token(body.token)
    token = create_pdf_token(
        str(actor.judge_id or ""), doc="report", province=province
    )
    return SlidesLink(
        path="/training/spk/report.pdf?t=" + token,
        expiresAt=token_expires_at(token),
    )
