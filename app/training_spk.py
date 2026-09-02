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

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select

from app.db import database, saved_matches, spk_reference, spk_run
from app.proel_auth import Actor, is_admin, proel_actor
from app.training_spk_score import grade, score_run
from app.training_spk_pdf import SpkPdfError, build_slides_pdf
from app.training_spk_meta import meta_from_blob
from app.training_spk_slides import slides_from_timeline
from app.zprp_accounts import normalize_province

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/training/spk", tags=["Szkolenie: Superpuchar"])
admin_router = APIRouter(
    prefix="/admin/training/spk", tags=["Szkolenie: Superpuchar (admin)"]
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
    return dict(row) if row is not None else None


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
        "slides": len(slides_from_timeline(ref["timeline"] or [])),
        "meta": ref["meta"] or {},
        "source": ref["source"],
        "updatedBy": ref["updated_by"],
        "updatedAt": ref["updated_at"].isoformat() if ref["updated_at"] else None,
        "timeline": ref["timeline"] or [],
    }


# ─────────────────────────── wejście sędziego ───────────────────────────


@router.get("/brief", summary="Dane meczu szkoleniowego")
async def brief(
    mode: str = Query("video", description="video albo slides"),
    actor: Actor = Depends(proel_actor),
) -> Dict[str, Any]:
    """Co telefon musi wiedzieć, zanim sędzia zacznie.

    OŚ CZASU WYCHODZI STĄD TYLKO W TRYBIE PREZENTACJI - bo tam JEST ćwiczeniem:
    sędzia czyta z niej polecenia. Przy nagraniu byłaby kluczem odpowiedzi
    leżącym w pamięci telefonu, więc jej nie wysyłamy. Ocenę i tak liczy serwer,
    aplikacja nie ma po co znać wzorca wcześniej.
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
    if mode == "slides":
        out["slides"] = slides_from_timeline(ref["timeline"] or [], ref["meta"] or {})
    return out


class RunIn(BaseModel):
    runId: str
    #: "video" albo "slides".
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
    mode = "slides" if body.mode == "slides" else "video"

    report = score_run(
        ref["timeline"] or [],
        blob.get("protocol"),
        mode=mode,
        reference_meta=ref["meta"] or {},
        attempt_meta=mine_meta,
    )
    report["grade"] = grade(report["score"])

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

    return {"ok": True, "runId": body.runId, "report": report}


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


@admin_router.get("/slides.pdf", summary="Materiał szkoleniowy jako prezentacja")
async def slides_pdf(actor: Actor = Depends(proel_actor)) -> Response:
    """Prezentacja do wyświetlenia grupie - jedna akcja na stronę.

    Składana NA ŻĄDANIE z obowiązującego wzorca, a nie trzymana jako plik.
    Poprawka jednej akcji ma iść w materiał sama; plik w repozytorium wymagałby
    pamiętania o złożeniu go od nowa, a o tym się zapomina dokładnie raz.
    """
    await _require_admin(actor)
    ref = await _current_reference()
    if ref is None:
        raise HTTPException(404, "Wzorzec nie został jeszcze wczytany.")
    try:
        data = build_slides_pdf(ref["timeline"] or [], ref["meta"] or {})
    except SpkPdfError as exc:
        raise HTTPException(409, str(exc))
    return Response(
        content=data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="szkolenie-spk1.pdf"'
        },
    )
