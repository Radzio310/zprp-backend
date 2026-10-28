"""Zadania klipów Bastionu - trwała kolejka (etap 4: zapis, worker, rewizje, resolver odtwarzania).

Zasady (handoff 10.3, 10.4, 10.6, 6.3):
  - zadanie i jego odcisk zapisujemy PRZED jakimkolwiek zewnętrznym zapisem; jedna operacja na rewizję klipu
    (`mentor_clips.media_rev`); zdalne id zapisujemy natychmiast po odpowiedzi connectora,
  - worker żyje w bazie (dzierżawa `lease_until` + `worker_id`, przejęcie przez zgodne UPDATE), więc restart i wiele
    procesów nie dają równoległych duplikatów; stan jest w tabeli, nie w pamięci procesu,
  - zlecenie idzie do connectora z odciskiem: ten sam odcisk = ten sam wynik, więc ponowienie po utraconej odpowiedzi
    nie tworzy drugiego klipu; niepewny wynik to `needs_reconciliation` (zero automatycznych ponowień),
  - po utracie sesji zadanie czeka (`waiting_for_auth`) i wraca TYLKO przy tym samym koncie zewnętrznym,
  - błąd magazynu (R2) nie zleca cięcia drugi raz: zdalne id zostaje, ponawiamy pobranie i zapis,
  - `ready` dopiero po uploadzie, kontroli i zapisie metadanych; spóźniony wynik starej rewizji ani usuniętego klipu
    niczego nie nadpisuje (sprzątamy to, co wgraliśmy).
Importy bazy w funkcjach (`app.db` łączy się przy imporcie).
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import socket
import tempfile
from datetime import timedelta
from typing import Any, Dict, List, Optional

from app import mentor_bastion_media as BM
from app import mentor_bastion_rules as BR

logger = logging.getLogger("app.mentor_bastion")

_wake_event: Optional[asyncio.Event] = None
_last_release = 0.0


def wake_worker() -> None:
    if _wake_event is not None:
        _wake_event.set()


# ─── Zapis zadania ──────────────────────────────────────────────────────────


async def enqueue_clip_job(*, clip: Dict[str, Any], bunny_item_id: int, revision: int, requested_by: str,
                           acted_as: Optional[str] = None, connection: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Dodaje zadanie dla klipu (`mentor_clips`) i rewizji. Ten sam klip + rewizja = to samo zadanie (bez duplikatu).
    Rzuca `BR.ClipRangeError`, gdy zakres nie mieści się w limitach Bastionu."""
    from sqlalchemy import select

    from app import mentor_panel_core as C
    from app import mentor_panel_rules as R
    from app.db import database, mentor_bastion_clip_jobs as J

    rng = BR.bastion_clip_range(float(clip["start_s"]), float(clip["end_s"]))
    fingerprint = BR.clip_fingerprint(clip_id=clip["id"], revision=revision, bunny_item_id=bunny_item_id,
                                      start_s=rng["start_s"], end_s=rng["end_s"])
    existing = await C.one(select(J).where(J.c.clip_id == clip["id"]).where(J.c.clip_revision == int(revision)))
    if existing:
        return existing
    stamp = C.now()
    row = {
        "id": R.new_id(), "clip_id": clip["id"], "pair_id": clip["pair_id"], "match_id": clip["match_id"],
        "source_video_id": clip["video_id"], "source_bunny_item_id": int(bunny_item_id),
        "requested_by_real_judge_id": str(requested_by), "acted_as_judge_id": acted_as or None,
        "connection_id": (connection or {}).get("id"), "external_identity_id": (connection or {}).get("external_identity_id"),
        "clip_revision": int(revision), "start_s": rng["start_s"], "end_s": rng["end_s"],
        "idempotency_key": fingerprint, "request_fingerprint": fingerprint, "state": "queued", "attempts": 0,
        "created_at": stamp, "updated_at": stamp,
    }
    try:
        await database.execute(J.insert().values(**row))
    except Exception:  # noqa: BLE001 - wyścig dwóch zapisów tej samej rewizji kończy się jednym zadaniem
        again = await C.one(select(J).where(J.c.clip_id == clip["id"]).where(J.c.clip_revision == int(revision)))
        if not again:
            raise
        return again
    return row


async def hold_jobs_for_connection(connection_id: str, error_code: str = "BASTION_AUTH_REQUIRED") -> int:
    """Utrata/odłączenie sesji: aktywne zadania tego połączenia czekają na to samo konto (zdalne id zostaje)."""
    from sqlalchemy import update

    from app import mentor_panel_core as C
    from app.db import database, mentor_bastion_clip_jobs as J

    waiting = [s for s in BR.JOB_ACTIVE if s not in ("waiting_for_auth", "needs_reconciliation", "uploading")]
    res = await database.execute(update(J).where(J.c.connection_id == connection_id).where(J.c.state.in_(waiting))
                                 .values(state="waiting_for_auth", last_error_code=error_code, last_error_message=None,
                                         updated_at=C.now(), lease_until=None, worker_id=None))
    return int(res or 0)


def real_judge_of(actor: Any) -> str:
    """Prawdziwy użytkownik: przy `act_as` administrator (`acted_by`), nigdy odgrywany mentor."""
    return str(getattr(actor, "acted_by", None) or actor.judge_id)


async def pick_connection(real_judge_id: str) -> Optional[Dict[str, Any]]:
    """Połączenie dla nowego zadania: domyślne, potem własne osobiste użytkownika (tylko gotowe)."""
    from sqlalchemy import select

    from app import mentor_panel_core as C
    from app.db import mentor_bastion_connections as CONN

    flags = BR.load_flags()
    for scope in BR.candidate_scopes(flags):
        key = BR.connection_key(scope, real_judge_id if scope == "personal" else None)
        row = await C.one(select(CONN).where(CONN.c.connection_key == key))
        if row and row.get("status") == "ready":
            return row
    return None


def bastion_item_of(video: Optional[Dict[str, Any]]) -> Optional[int]:
    if not video or video.get("provider") != BR.PROVIDER:
        return None
    return BR.parse_game_url(video.get("url"))


async def supersede_jobs(clip_id: str, keep_revision: int) -> None:
    """Zmiana zakresu: aktywne zadania starszych rewizji są anulowane (ich wynik i tak nic nie nadpisze)."""
    from sqlalchemy import update

    from app import mentor_panel_core as C
    from app.db import database, mentor_bastion_clip_jobs as J

    await database.execute(update(J).where(J.c.clip_id == clip_id).where(J.c.clip_revision < int(keep_revision))
                           .where(J.c.state.in_(BR.JOB_ACTIVE)).values(state="cancelled", updated_at=C.now(),
                                                                       lease_until=None, worker_id=None, finished_at=C.now()))


async def after_clip_saved(clip: Dict[str, Any], video: Optional[Dict[str, Any]], actor: Any, *,
                           want_mp4: bool = False) -> Optional[Dict[str, Any]]:
    """Wołane w tej samej operacji co zapis klipu (utworzenie, ze znacznika, zmiana zakresu). MP4 NIE powstaje samo:
    zadanie zakładamy tylko przy `want_mp4` (wybór użytkownika w dialogu zapisu, albo klip miał już MP4 i zmienia zakres).
    Zmiana zakresu zawsze anuluje zadania starszych rewizji. Klip wirtualny zostaje wirtualny.
    Zwraca zadanie albo None (inne źródło, flaga, brak zamówienia, zakres poza limitem Bastionu). Awaria zapisu zadania
    nie psuje zapisu klipu (zamówienie MP4 można powtórzyć trasą `mp4`)."""
    rev = int(clip.get("media_rev") or 1)
    if rev > 1:
        try:
            await supersede_jobs(clip["id"], rev)
        except Exception:  # noqa: BLE001
            logger.warning("bastion: anulowanie starych zadań nieudane", exc_info=True)
    if not want_mp4 or not BR.load_flags().enabled:
        return None
    item = bastion_item_of(video)
    if not item:
        return None
    try:
        real = real_judge_of(actor)
        conn = await pick_connection(real)
        job = await enqueue_clip_job(clip=clip, bunny_item_id=item, revision=rev, requested_by=real,
                                     acted_as=actor.judge_id if getattr(actor, "acted_by", None) else None, connection=conn)
        if job.get("state") == "cancelled":
            job = await requeue_cancelled(job, conn)
        elif conn is None and job.get("state") == "queued":
            await _hold_unbound(job)
            job = {**job, "state": "waiting_for_auth", "last_error_code": "BASTION_AUTH_REQUIRED"}
    except BR.ClipRangeError:
        return None
    except Exception:  # noqa: BLE001
        logger.warning("bastion: zapis zadania klipu nieudany (klip zapisany, zamów MP4 ponownie)", exc_info=True)
        return None
    wake_worker()
    return job


async def requeue_cancelled(job: Dict[str, Any], conn: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Świadome ponowne zamówienie po anulowaniu: zadanie bieżącej rewizji wraca do kolejki (bez poprzednich śladów)."""
    from sqlalchemy import select, update

    from app import mentor_panel_core as C
    from app.db import database, mentor_bastion_clip_jobs as J

    values: Dict[str, Any] = {"state": "queued" if conn else "waiting_for_auth", "attempts": 0, "poll_count": 0, "next_attempt_at": None,
                              "last_error_code": None if conn else "BASTION_AUTH_REQUIRED", "last_error_message": None,
                              "lease_until": None, "worker_id": None, "finished_at": None, "updated_at": C.now(),
                              "connection_id": (conn or {}).get("id"), "external_identity_id": (conn or {}).get("external_identity_id")}
    if job.get("remote_clip_id") is None:
        values["submitted_at"] = None
    await database.execute(update(J).where(J.c.id == job["id"]).values(**values))
    return await C.one(select(J).where(J.c.id == job["id"]))


async def cancel_clip_media(clip: Dict[str, Any]) -> Dict[str, Any]:
    """Anulowanie zamówienia MP4, gdy nic jeszcze nie poszło do Bastionu (albo zadanie już leży w błędzie). Klip wraca do
    stanu wirtualnego. Zlecenie, które Bastion już przyjął, anulować się nie da (409)."""
    from sqlalchemy import update

    from app import mentor_panel_core as C
    from app.db import database, mentor_bastion_clip_jobs as J

    job = await current_job(clip)
    if not job or job["state"] == "cancelled":
        return {"cancelled": False, "job": job}
    if not BR.can_cancel_job(job):
        raise C.err(409, "MP4_CANCEL_TOO_LATE", "Bastion już przygotowuje ten klip - nie da się anulować. Poczekaj na plik.")
    await database.execute(update(J).where(J.c.id == job["id"]).where(J.c.state == job["state"])
                           .values(state="cancelled", lease_until=None, worker_id=None, finished_at=C.now(), updated_at=C.now()))
    again = await current_job(clip)
    return {"cancelled": again is not None and again["state"] == "cancelled", "job": again}


async def mp4_offer(clip: Dict[str, Any], video: Optional[Dict[str, Any]], actor: Any) -> Optional[Dict[str, Any]]:
    """Dane do dialogu „Zapisz też jako MP4”: przewidywany czas, limit, czy połączenie działa i którym kontem.
    None = to nagranie nie jest z Bastionu albo integracja jest wyłączona (dialog się nie pokazuje)."""
    flags = BR.load_flags()
    if not flags.enabled or not bastion_item_of(video):
        return None
    try:
        BR.bastion_clip_range(float(clip["start_s"]), float(clip["end_s"]))
        reason = None
    except BR.ClipRangeError as exc:
        reason = str(exc)
    conn = await pick_connection(real_judge_of(actor))
    if conn:
        label = conn.get("external_identity_label") or ("Twoje konto" if conn["scope"] == "personal" else "Połączenie domyślne")
        connection = {"ok": True, "scope": conn["scope"], "account_label": label}
    else:
        connection = {"ok": False, "scope": None, "account_label": None}
    return {"estimated_s": BR.ESTIMATED_CUT_S, "min_s": BR.MIN_CLIP_S, "max_s": BR.MAX_CLIP_S, "eligible": reason is None,
            "reason": reason, "connection": connection}


async def _hold_unbound(job: Dict[str, Any]) -> None:
    from sqlalchemy import update

    from app import mentor_panel_core as C
    from app.db import database, mentor_bastion_clip_jobs as J

    await database.execute(update(J).where(J.c.id == job["id"]).where(J.c.state == "queued")
                           .values(state="waiting_for_auth", last_error_code="BASTION_AUTH_REQUIRED", updated_at=C.now()))


async def discard_clip_media(clip_id: str) -> None:
    """Usunięty klip: zadania anulowane, pliki (wszystkich rewizji) skasowane. Soft-delete klipu zostaje bez zmian."""
    from sqlalchemy import select, update

    from app import mentor_panel_core as C
    from app.db import database, mentor_bastion_clip_jobs as J, mentor_clip_assets as A

    await database.execute(update(J).where(J.c.clip_id == clip_id).where(J.c.state.in_(BR.JOB_ACTIVE))
                           .values(state="cancelled", updated_at=C.now(), lease_until=None, worker_id=None, finished_at=C.now()))
    found = await C.rows(select(A).where(A.c.clip_id == clip_id))
    if found:
        from app import mentor_panel_media as M

        M.forget_object(*[k for r in found for k in (r.get("storage_key"), r.get("poster_key"))])
        await database.execute(A.delete().where(A.c.clip_id == clip_id))


# ─── Resolver odtwarzania i stan w kształcie klipu ──────────────────────────


async def media_for_clips(clip_rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """`{clip_id: media}` dla klipów z nagrań Bastion (inne źródła nie mają bloku `media`: standardowy zakres oryginału).
    To JEDEN resolver (`BR.resolve_clip_playback`) - ten sam wynik w pokoju, bibliotece, kinie, kolejkach, zestawieniach
    i publicznym klipie. Bez adresów URL."""
    from sqlalchemy import select

    from app import mentor_panel_core as C
    from app.db import mentor_bastion_clip_jobs as J, mentor_clip_assets as A, mentor_match_videos as V

    if not clip_rows:
        return {}
    video_ids = sorted({r["video_id"] for r in clip_rows})
    videos = {v["id"]: v for v in await C.rows(select(V.c.id, V.c.provider, V.c.url).where(V.c.id.in_(video_ids)))}
    mine = [r for r in clip_rows if (videos.get(r["video_id"]) or {}).get("provider") == BR.PROVIDER]
    if not mine:
        return {}
    ids = [r["id"] for r in mine]
    jobs: Dict[str, Dict[str, Any]] = {}
    for j in await C.rows(select(J).where(J.c.clip_id.in_(ids))):
        clip = next(r for r in mine if r["id"] == j["clip_id"])
        if int(j["clip_revision"]) == int(clip.get("media_rev") or 1) and j["state"] != "cancelled":
            jobs[j["clip_id"]] = j
    assets: Dict[str, Dict[str, Any]] = {}
    for a in await C.rows(select(A).where(A.c.clip_id.in_(ids))):
        clip = next(r for r in mine if r["id"] == a["clip_id"])
        if int(a["revision"]) == int(clip.get("media_rev") or 1):
            assets[a["clip_id"]] = a
    out: Dict[str, Dict[str, Any]] = {}
    for r in mine:
        try:
            BR.bastion_clip_range(float(r["start_s"]), float(r["end_s"]))
            eligible = True
        except BR.ClipRangeError:
            eligible = False
        media = BR.resolve_clip_playback(clip=r, asset=assets.get(r["id"]), job=jobs.get(r["id"]),
                                         video_provider=BR.PROVIDER, eligible=eligible)
        out[r["id"]] = media
    return out


def mp4_status_of(media: Optional[Dict[str, Any]], stored: str) -> str:
    """Stary `mp4_status` dla klientów sprzed etapu 4, wyprowadzony z `media`."""
    if not media:
        return stored
    if media["mode"] == "asset":
        return "ready"
    stage = media.get("stage")
    if stage == "failed":
        return "failed"
    if stage in ("saved", "bastion_cutting", "storing", "waiting_for_auth"):
        return "working"
    return "none"


def signed_urls(clip: Dict[str, Any], asset: Dict[str, Any], filename: str) -> Dict[str, Any]:
    """Podpisane adresy gotowego pliku (R2 obsługuje Range): odtwarzanie inline i pobranie z nazwą pliku."""
    from app import mentor_panel_media as M

    play = M.presign_get(asset.get("storage_key"), M.PLAY_URL_TTL)
    return {"play_url": play, "poster_url": M.presign_get(asset.get("poster_key"), M.PLAY_URL_TTL) if asset.get("poster_key") else None,
            "download_url": M.presign_get(asset.get("storage_key"), M.DOWNLOAD_TTL, filename), "filename": filename,
            "play_expires_in": M.PLAY_URL_TTL, "download_expires_in": M.DOWNLOAD_TTL}


async def current_asset(clip: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    from sqlalchemy import select

    from app import mentor_panel_core as C
    from app.db import mentor_clip_assets as A

    return await C.one(select(A).where(A.c.clip_id == clip["id"]).where(A.c.revision == int(clip.get("media_rev") or 1))
                       .where(A.c.status == "ready"))


async def current_job(clip: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    from sqlalchemy import select

    from app import mentor_panel_core as C
    from app.db import mentor_bastion_clip_jobs as J

    return await C.one(select(J).where(J.c.clip_id == clip["id"]).where(J.c.clip_revision == int(clip.get("media_rev") or 1)))


async def had_mp4(clip: Dict[str, Any]) -> bool:
    """Klip „z MP4”: ma zadanie bieżącej rewizji (poza anulowanym) albo gotowy plik."""
    job = await current_job(clip)
    if job and job["state"] != "cancelled":
        return True
    return await current_asset(clip) is not None


async def public_media(clip: Dict[str, Any]) -> Dict[str, Any]:
    """Publiczny klip: tylko gotowy plik tego klipu (adresy podpisane), inaczej stan oczekiwania. Zero sesji i embedu."""
    asset = await current_asset(clip)
    if not asset:
        return {"mode": "waiting", "status": "no_file", "kind": "virtual"}
    media = BR.resolve_clip_playback(clip=clip, asset=asset, video_provider=BR.PROVIDER, eligible=True)
    urls = signed_urls(clip, asset, "klip.mp4")
    return {**media, "play_url": urls["play_url"], "poster_url": urls["poster_url"]}


# ─── Wznowienie ręczne ──────────────────────────────────────────────────────


async def resume_clip_media(clip: Dict[str, Any], video: Optional[Dict[str, Any]], actor: Any) -> Optional[Dict[str, Any]]:
    """„Wznów”: czeka na połączenie / niepowodzenie / niepewny wynik -> kolejka. Zasady:
      - zadanie ze zdalnym id wraca na TO SAMO połączenie i to samo konto zewnętrzne (inne = 409 BASTION_WRONG_ACCOUNT),
      - połączenie osobiste innej osoby nie jest pożyczane (wznawia ta osoba),
      - zadanie, które nigdy nic nie wysłało, może zostać przypięte do połączenia wznawiającego,
      - niepewny wynik (`needs_reconciliation`) albo klip usunięty w Bastionie dostają NOWY odcisk (świadoma decyzja
        człowieka; może powstać drugi, prywatny klip).
    Zwraca zadanie po zmianie. Błędy jako HTTPException BAZY."""
    from sqlalchemy import select, update

    from app import mentor_panel_core as C
    from app import mentor_panel_rules as R
    from app.db import database, mentor_bastion_clip_jobs as J, mentor_bastion_connections as CONN

    item = bastion_item_of(video)
    if not item:
        raise C.err(409, "MP4_LINK_VIDEO", "Plik MP4 z Bastionu robimy tylko z nagrań z Handball Bastion.")
    real = real_judge_of(actor)
    job = await current_job(clip)
    if job is None:
        job = await enqueue_clip_job(clip=clip, bunny_item_id=item, revision=int(clip.get("media_rev") or 1), requested_by=real,
                                     acted_as=actor.judge_id if getattr(actor, "acted_by", None) else None, connection=None)
        await _hold_unbound(job)
        job = await current_job(clip)
    if job["state"] == "cancelled":
        job = await requeue_cancelled(job, await pick_connection(real))
        wake_worker()
        return job
    if not BR.can_resume_job(job["state"]):
        return job  # w toku: nic do wznawiania
    # Wybór połączenia
    bound = None
    if job.get("connection_id"):
        bound = await C.one(select(CONN).where(CONN.c.id == job["connection_id"]))
    if bound and bound.get("scope") == "personal" and bound.get("owner_judge_id") != real:
        raise C.err(403, "BASTION_CONNECTION_FORBIDDEN", "Klip zlecono z konta innej osoby. Poproś ją o wznowienie.")
    never_sent = job.get("submitted_at") is None and not job.get("remote_clip_id")
    target = bound
    if never_sent and (target is None or target.get("status") != "ready"):
        target = await pick_connection(real) or target
    if target is None or target.get("status") != "ready":
        raise C.err(409, "BASTION_AUTH_REQUIRED", BR.MSG_AUTH_REQUIRED)
    if not never_sent and not BR.may_resume_with(job.get("external_identity_id"), target.get("external_identity_id")):
        await database.execute(update(J).where(J.c.id == job["id"]).values(last_error_code="BASTION_WRONG_ACCOUNT", updated_at=C.now()))
        raise C.err(409, "BASTION_WRONG_ACCOUNT", BR.MSG_WRONG_ACCOUNT)
    values: Dict[str, Any] = {"state": "queued", "attempts": 0, "poll_count": 0, "next_attempt_at": None, "last_error_code": None,
                              "last_error_message": None, "lease_until": None, "worker_id": None, "finished_at": None,
                              "connection_id": target["id"], "updated_at": C.now()}
    if never_sent or not job.get("external_identity_id"):
        values["external_identity_id"] = target.get("external_identity_id")
    reconcile = job["state"] == "needs_reconciliation" or job.get("last_error_code") == "BASTION_CLIP_NOT_FOUND"
    if reconcile:
        values.update(remote_clip_id=None, remote_clip_code=None, submitted_at=None,
                      request_fingerprint=BR.clip_fingerprint(clip_id=f"{clip['id']}:{R.new_id()}", revision=job["clip_revision"],
                                                              bunny_item_id=job["source_bunny_item_id"], start_s=job["start_s"],
                                                              end_s=job["end_s"]))
    await database.execute(update(J).where(J.c.id == job["id"]).values(**values))
    wake_worker()
    return await current_job(clip)


async def _pin_unbound_jobs(connection_id: Optional[str] = None) -> int:
    """Zamówienie MP4 bez połączenia (offline) czeka bez `connection_id`. Gdy połączenie staje się gotowe, przypinamy je
    do pierwszego połączenia, którego ZLECAJĄCY może użyć (`pick_connection`: domyślne, potem jego własne; cudzego
    osobistego nigdy). Zadania z wysłanym klipem mają już połączenie, więc zasady konta (BASTION_WRONG_ACCOUNT) zostają."""
    from sqlalchemy import select, update

    from app import mentor_panel_core as C
    from app.db import database, mentor_bastion_clip_jobs as J

    query = (select(J).where(J.c.state == "waiting_for_auth").where(J.c.connection_id.is_(None))
             .where(J.c.remote_clip_id.is_(None)).where(J.c.submitted_at.is_(None)))
    pinned = 0
    for job in await C.rows(query.limit(200)):
        conn = await pick_connection(job["requested_by_real_judge_id"])
        if not conn or (connection_id and conn["id"] != connection_id):
            continue
        await database.execute(update(J).where(J.c.id == job["id"]).where(J.c.state == "waiting_for_auth")
                               .where(J.c.connection_id.is_(None))
                               .values(connection_id=conn["id"], external_identity_id=conn.get("external_identity_id"),
                                       updated_at=C.now()))
        pinned += 1
    return pinned


async def release_waiting_jobs(connection_id: Optional[str] = None) -> int:
    """Zadania `waiting_for_auth` wracają do kolejki, gdy ich połączenie znów działa NA TYM SAMYM KONCIE. Inne konto
    zostawia je w oczekiwaniu (`BASTION_WRONG_ACCOUNT`)."""
    from sqlalchemy import select, update

    from app import mentor_panel_core as C
    from app.db import database, mentor_bastion_clip_jobs as J, mentor_bastion_connections as CONN

    await _pin_unbound_jobs(connection_id)
    query = select(J).where(J.c.state == "waiting_for_auth").where(J.c.connection_id.isnot(None))
    if connection_id:
        query = query.where(J.c.connection_id == connection_id)
    released = 0
    conns: Dict[str, Optional[Dict[str, Any]]] = {}
    for job in await C.rows(query.limit(200)):
        cid = job["connection_id"]
        if cid not in conns:
            conns[cid] = await C.one(select(CONN).where(CONN.c.id == cid))
        conn = conns[cid]
        if not conn or conn.get("status") != "ready":
            continue
        if not BR.may_resume_with(job.get("external_identity_id"), conn.get("external_identity_id")):
            if job.get("last_error_code") != "BASTION_WRONG_ACCOUNT":
                await database.execute(update(J).where(J.c.id == job["id"]).values(last_error_code="BASTION_WRONG_ACCOUNT",
                                                                                   updated_at=C.now()))
            continue
        values: Dict[str, Any] = {"state": "queued", "last_error_code": None, "last_error_message": None, "updated_at": C.now()}
        if not job.get("external_identity_id") and conn.get("external_identity_id"):
            values["external_identity_id"] = conn["external_identity_id"]
        await database.execute(update(J).where(J.c.id == job["id"]).where(J.c.state == "waiting_for_auth").values(**values))
        released += 1
    if released:
        wake_worker()
    return released


# ─── Dzierżawa ──────────────────────────────────────────────────────────────


async def claim_next(worker_id: str, *, lease_s: int = BR.LEASE_S, now: Any = None) -> Optional[Dict[str, Any]]:
    """Przejmuje jedno zadanie do wykonania. Bezpieczne przy wielu workerach: UPDATE ma w WHERE warunek wolnej
    dzierżawy, więc po wyścigu dokładnie jeden worker widzi swój `worker_id`."""
    from sqlalchemy import or_, select, update

    from app import mentor_panel_core as C
    from app import mentor_panel_rules as R
    from app.db import database, mentor_bastion_clip_jobs as J

    now = now or C.now()
    for job in await C.rows(select(J).where(J.c.state.in_(BR.JOB_RUNNABLE)).order_by(J.c.created_at.asc()).limit(100)):
        due = R.aware(job["next_attempt_at"]) if job.get("next_attempt_at") else None
        held = R.aware(job["lease_until"]) if job.get("lease_until") else None
        if (due and due > now) or (held and held > now):
            continue
        await database.execute(
            update(J).where(J.c.id == job["id"]).where(J.c.state == job["state"])
            .where(or_(J.c.lease_until.is_(None), J.c.lease_until < now))
            .values(worker_id=worker_id, lease_until=now + timedelta(seconds=lease_s), updated_at=now))
        again = await C.one(select(J).where(J.c.id == job["id"]))
        if again and again.get("worker_id") == worker_id and again["state"] == job["state"]:
            return again
    return None


async def _heartbeat(job_id: str, worker_id: str, lease_s: int) -> None:
    from sqlalchemy import update

    from app import mentor_panel_core as C
    from app.db import database, mentor_bastion_clip_jobs as J

    while True:
        await asyncio.sleep(max(0.05, lease_s / 3))
        await database.execute(update(J).where(J.c.id == job_id).where(J.c.worker_id == worker_id)
                               .values(lease_until=C.now() + timedelta(seconds=lease_s)))


# ─── Zapisy stanu zadania (tylko właściciel dzierżawy) ──────────────────────


async def _save(job: Dict[str, Any], owner_id: str, /, **values: Any) -> None:
    from sqlalchemy import update

    from app import mentor_panel_core as C
    from app.db import database, mentor_bastion_clip_jobs as J

    values["updated_at"] = C.now()
    await database.execute(update(J).where(J.c.id == job["id"]).where(J.c.worker_id == owner_id).values(**values))
    job.update(values)


async def _touch(job: Dict[str, Any], action: str) -> None:
    from app import mentor_panel_core as C

    try:
        await C.touch(job["pair_id"], job["requested_by_real_judge_id"], action, "clips", job["match_id"], {"id": job["clip_id"]})
    except Exception:  # noqa: BLE001
        logger.warning("bastion: touch po zmianie stanu klipu nieudany", exc_info=True)


async def _release(job: Dict[str, Any], worker_id: str, state: str, *, notify: Optional[str] = None, **values: Any) -> None:
    await _save(job, worker_id, state=state, lease_until=None, worker_id=None, **values)
    if notify:
        await _touch(job, notify)


async def _fail(job: Dict[str, Any], wid: str, code: str) -> None:
    from app import mentor_panel_core as C

    await _release(job, wid, "failed", notify="clip_media_failed", last_error_code=code,
                   last_error_message=BR.ERROR_MESSAGES.get(code), finished_at=C.now())


async def _retry(job: Dict[str, Any], wid: str, code: str, *, delay: Optional[float] = None) -> None:
    from app import mentor_panel_core as C

    attempts = int(job.get("attempts") or 0) + 1
    if attempts >= BR.MAX_ATTEMPTS:
        await _fail(job, wid, "BASTION_RETRIES_EXHAUSTED")
        return
    wait = delay if delay is not None else BR.backoff_s(attempts)
    await _release(job, wid, "retryable_failed", attempts=attempts, last_error_code=code,
                   last_error_message=BR.ERROR_MESSAGES.get(code), next_attempt_at=C.now() + timedelta(seconds=wait))


async def _wait_auth(job: Dict[str, Any], wid: str, code: str = "BASTION_AUTH_REQUIRED") -> None:
    await _release(job, wid, "waiting_for_auth", notify="clip_media_waiting", last_error_code=code, last_error_message=None)


async def _park(job: Dict[str, Any], wid: str) -> bool:
    """Plik jeszcze niegotowy po stronie Bastionu: sprawdzimy za chwilę (backoff z jitterem). False = limit pytań."""
    from app import mentor_panel_core as C

    polls = int(job.get("poll_count") or 0) + 1
    if polls > BR.MAX_POLLS:
        await _fail(job, wid, "BASTION_REMOTE_TIMEOUT")
        return False
    await _release(job, wid, "waiting_for_remote", poll_count=polls, attempts=0, last_error_code=None, last_error_message=None,
                   next_attempt_at=C.now() + timedelta(seconds=BR.poll_delay_s(polls)))
    return True


async def _mark_connection(conn: Dict[str, Any], kind: str) -> None:
    """401 portalu przy zleceniu: zapis w metadanych połączenia (best effort)."""
    try:
        from app import mentor_bastion as B

        await B.apply_verdict(conn["scope"], conn.get("owner_judge_id"), BR.PlaybackVerdict(kind, "BASTION_AUTH_REQUIRED"))
    except Exception:  # noqa: BLE001
        logger.warning("bastion: zapis stanu połączenia po błędzie klipu nieudany", exc_info=True)


# ─── Przebieg jednego zadania ───────────────────────────────────────────────


def _code(body: Dict[str, Any]) -> str:
    return str(body.get("error") or body.get("code") or "")


AUTH_CODES = ("BASTION_AUTH_REQUIRED", "BASTION_NOT_CONNECTED", "BASTION_STATE_INVALID")


async def process_job(job: Dict[str, Any], worker_id: str, *, client: Any = None) -> None:
    """Jeden przebieg: zlecenie (gdy brak zdalnego id) -> sprawdzenie gotowości -> pobranie i zapis. Każdy krok zapisuje
    stan w bazie, więc restart w dowolnym miejscu wznawia od właściwego kroku (zdalne id raz zapisane nie wraca do cięcia)."""
    from sqlalchemy import select

    from app import mentor_bastion_client as CL
    from app import mentor_panel_core as C
    from app.db import mentor_bastion_connections as CONN, mentor_clips as K

    clip = await C.one(select(K).where(K.c.id == job["clip_id"]))
    if not clip or clip.get("deleted_at") is not None or int(clip.get("media_rev") or 1) != int(job["clip_revision"]):
        # Usunięty klip albo nowsza rewizja: ten wynik niczego nie nadpisze.
        await _release(job, worker_id, "cancelled", finished_at=C.now())
        return
    conn = await C.one(select(CONN).where(CONN.c.id == job["connection_id"])) if job.get("connection_id") else None
    if not conn or conn.get("status") != "ready":
        await _wait_auth(job, worker_id)
        return
    if not BR.may_resume_with(job.get("external_identity_id"), conn.get("external_identity_id")):
        await _wait_auth(job, worker_id, "BASTION_WRONG_ACCOUNT")
        return
    scope, owner = conn["scope"], conn.get("owner_judge_id")
    try:
        client = client or CL.get_client()
        if not job.get("remote_clip_id"):
            if not await _submit(job, worker_id, client, conn, scope, owner):
                return
        if not await _check_ready(job, worker_id, client, conn, scope, owner):
            return
        await _store(job, clip, worker_id, client, conn, scope, owner)
    except CL.ConnectorUnavailable:
        await _retry(job, worker_id, "BASTION_UNAVAILABLE")


def _as_auth(code: str, status: int) -> bool:
    return code in AUTH_CODES or (status == 409 and code in ("", "BASTION_AUTH_REQUIRED"))


async def _submit(job, wid, client, conn, scope, owner) -> bool:
    from app import mentor_panel_core as C

    if job.get("submitted_at") is None:
        await _save(job, wid, state="submitting", submitted_at=C.now())  # PRZED pierwszym wysłaniem (rebind później zabroniony)
    else:
        await _save(job, wid, state="submitting")
    if not job.get("external_identity_id") and conn.get("external_identity_id"):
        await _save(job, wid, external_identity_id=conn["external_identity_id"])
    reply = await client.create_clip(scope, owner, job["source_bunny_item_id"], job["start_s"], job["end_s"],
                                     job["request_fingerprint"], job["id"])
    body, code = reply.body, _code(reply.body)
    if reply.status == 200 and body.get("remote_id"):
        await _save(job, wid, state="submitted", remote_clip_id=str(body["remote_id"]), remote_clip_code=body.get("clip_code"),
                    attempts=0, last_error_code=None, last_error_message=None)
        await _touch(job, "clip_media_cutting")
        return True
    if reply.status == 202 or (reply.status == 200 and not body.get("remote_id")):
        await _release(job, wid, "needs_reconciliation", notify="clip_media_failed", last_error_code="NEEDS_RECONCILIATION",
                       last_error_message=BR.MSG_RECONCILE)
        return False
    if _as_auth(code, reply.status):
        await _wait_auth(job, wid)
        await _mark_connection(conn, "auth_required")
    elif reply.status == 403:
        await _fail(job, wid, "BASTION_RESOURCE_FORBIDDEN")
    elif reply.status in (400, 422) or code == "FINGERPRINT_MISMATCH":
        await _fail(job, wid, "BASTION_SUBMIT_REJECTED")
    elif code == "CLIP_SUBMIT_IN_PROGRESS":
        await _retry(job, wid, "BASTION_UNAVAILABLE", delay=20.0)
    elif reply.status == 429:
        await _retry(job, wid, "BASTION_RATE_LIMITED")
    else:
        await _retry(job, wid, "BASTION_UNAVAILABLE")
    return False


async def _check_ready(job, wid, client, conn, scope, owner) -> bool:
    reply = await client.clip_state(scope, owner, job["remote_clip_id"])
    body, code = reply.body, _code(reply.body)
    if reply.status == 200:
        if body.get("ready") or body.get("download_available"):
            return True
        await _park(job, wid)
        return False
    if _as_auth(code, reply.status):
        await _wait_auth(job, wid)
        await _mark_connection(conn, "auth_required")
    elif reply.status == 403:
        await _fail(job, wid, "BASTION_RESOURCE_FORBIDDEN")
    elif code == "CLIP_UNKNOWN":  # connector zgubił księgę: nie wiemy, co się stało ze zleceniem
        await _release(job, wid, "needs_reconciliation", notify="clip_media_failed", last_error_code="NEEDS_RECONCILIATION",
                       last_error_message=BR.MSG_RECONCILE)
    elif code == "BASTION_CLIP_NOT_FOUND":
        await _fail(job, wid, "BASTION_CLIP_NOT_FOUND")
    elif reply.status == 429:
        await _retry(job, wid, "BASTION_RATE_LIMITED")
    else:
        await _retry(job, wid, "BASTION_UNAVAILABLE")
    return False


def put_and_verify(path: str, key: str, content_type: str) -> int:
    """Upload do R2 (wątek) i kontrola rozmiaru obiektu. Wynik: rozmiar. Osobna funkcja, żeby testy mogły ją podmienić."""
    from app import mentor_panel_media as M

    size = M.put_file(path, key, content_type)
    config = M.storage_config()
    head = M.s3_client(config).head_object(Bucket=config["bucket"], Key=key)
    if int(head.get("ContentLength", -1)) != size:
        raise OSError("rozmiar obiektu w magazynie różni się od lokalnego")
    return size


def _tmpdir() -> str:
    return tempfile.mkdtemp(prefix="bastion-clip-", dir=os.getenv("MENTOR_MEDIA_TMP") or None)


async def _delete_objects(keys: List[Optional[str]]) -> None:
    from app import mentor_panel_media as M

    wanted = [k for k in keys if k]
    if wanted:
        await asyncio.to_thread(M.delete_objects, wanted)


async def _store(job, clip, wid, client, conn, scope, owner) -> None:
    """Pobranie (bez ciasteczek), kontrola, miniatura, upload, zapis metadanych i `ready`."""
    from sqlalchemy import select, update

    from app import mentor_panel_core as C
    from app import mentor_panel_media as M
    from app import mentor_panel_rules as R
    from app.db import database, mentor_bastion_clip_jobs as J, mentor_clip_assets as A, mentor_clips as K

    if not M.storage_ready():
        await _retry(job, wid, "STORAGE_OFF")
        return
    await _save(job, wid, state="downloading")
    reply = await client.clip_download_url(scope, owner, job["remote_clip_id"])
    body, code = reply.body, _code(reply.body)
    if reply.status != 200 or not body.get("url"):
        if code == "BASTION_DOWNLOAD_NOT_READY":
            await _park(job, wid)
        elif _as_auth(code, reply.status):
            await _wait_auth(job, wid)
            await _mark_connection(conn, "auth_required")
        elif reply.status == 403:
            await _fail(job, wid, "BASTION_RESOURCE_FORBIDDEN")
        elif code in ("DOWNLOAD_HOST_NOT_ALLOWED", "DOWNLOAD_ADDRESS_NOT_PUBLIC"):
            await _fail(job, wid, code)
        elif reply.status == 429:
            await _retry(job, wid, "BASTION_RATE_LIMITED")
        else:
            await _retry(job, wid, "BASTION_UNAVAILABLE")
        return
    url = body["url"]  # sekret: tylko w tej zmiennej
    rev = int(job["clip_revision"])
    folder = await asyncio.to_thread(_tmpdir)
    uploaded: List[str] = []
    try:
        try:
            dl = await BM.download_signed(url, folder)
        except BM.MediaError as exc:
            if exc.retryable:
                await _retry(job, wid, "BASTION_UNAVAILABLE")
            else:
                await _fail(job, wid, exc.code)
            return
        finally:
            url = None
        try:
            probe = await asyncio.to_thread(BM.ffprobe_file, dl.path)
        except BM.MediaError as exc:
            if exc.retryable:
                await _retry(job, wid, "BASTION_UNAVAILABLE")
            else:
                await _fail(job, wid, exc.code)
            return
        bad = BR.verify_media(probe, dl.size, job["end_s"] - job["start_s"])
        if bad:
            await _fail(job, wid, bad)
            return
        poster_path = os.path.join(folder, "poster.jpg")
        has_poster = await asyncio.to_thread(BM.make_thumbnail, dl.path, poster_path, probe.get("duration_s"))
        await _save(job, wid, state="uploading")
        prefix = M.storage_config()["prefix"]
        key = BR.asset_key(prefix, clip["pair_id"], clip["id"], rev, "mp4")
        poster_key = BR.asset_key(prefix, clip["pair_id"], clip["id"], rev, "jpg") if has_poster else None
        size = None
        for attempt in range(3):  # R2: ponawiamy upload z lokalnego pliku, bez ponownego cięcia i pobierania
            try:
                uploaded.append(key)
                size = await asyncio.to_thread(put_and_verify, dl.path, key, "video/mp4")
                if poster_key:
                    uploaded.append(poster_key)
                    await asyncio.to_thread(put_and_verify, poster_path, poster_key, "image/jpeg")
                break
            except Exception:  # noqa: BLE001
                logger.warning("bastion: upload klipu do R2 nieudany (próba %s)", attempt + 1, exc_info=True)
                if not os.getenv("BASTION_FAST_RETRY"):
                    await asyncio.sleep(min(5.0, 1.0 + attempt * 2.0))
        if size is None:
            await _delete_objects(uploaded)
            uploaded = []
            await _retry(job, wid, "STORAGE_UPLOAD_FAILED")
            return
        # Czy wciąż jesteśmy właścicielem zadania i czy rewizja jest aktualna? (restart, usunięcie, zmiana zakresu)
        mine = await C.one(select(J).where(J.c.id == job["id"]))
        fresh = await C.one(select(K).where(K.c.id == clip["id"]))
        if (not mine or mine.get("worker_id") != wid or mine["state"] == "cancelled" or not fresh
                or fresh.get("deleted_at") is not None or int(fresh.get("media_rev") or 1) != rev):
            await _delete_objects(uploaded)
            uploaded = []
            if mine and mine.get("worker_id") == wid:
                await _release(job, wid, "cancelled", finished_at=C.now())
            return
        stamp = C.now()
        asset_id = R.new_id()
        await database.execute(A.delete().where(A.c.clip_id == clip["id"]).where(A.c.revision == rev))
        await database.execute(A.insert().values(
            id=asset_id, clip_id=clip["id"], revision=rev, status="ready", storage_key=key, size=size, sha256=dl.sha256,
            duration_s=probe.get("duration_s"), width=probe.get("width"), height=probe.get("height"), poster_key=poster_key,
            origin_provider=BR.PROVIDER, remote_clip_id=job["remote_clip_id"], source_video_id=job["source_video_id"],
            source_start_s=float(job["start_s"]), source_end_s=float(job["end_s"]), created_at=stamp, updated_at=stamp))
        await database.execute(update(K).where(K.c.id == clip["id"]).where(K.c.media_rev == rev).where(K.c.deleted_at.is_(None))
                               .values(mp4_status="ready", mp4_key=key, mp4_size=size))
        after = await C.one(select(K).where(K.c.id == clip["id"]))
        if not after or after.get("deleted_at") is not None or int(after.get("media_rev") or 1) != rev or after.get("mp4_key") != key:
            # Wyścig z usunięciem / zmianą zakresu tuż przed zapisem: wycofujemy własny wynik.
            await database.execute(A.delete().where(A.c.id == asset_id))
            await _delete_objects(uploaded)
            uploaded = []
            await _release(job, wid, "cancelled", finished_at=C.now())
            return
        await _release(job, wid, "ready", notify="clip_media_ready", asset_id=asset_id, finished_at=stamp, attempts=0,
                       last_error_code=None, last_error_message=None)
        uploaded = []
        await notify_clip_ready(job, {**clip, **(after or {})}, probe.get("duration_s"), probe.get("height"))
        # Poprzednie rewizje (jeśli były) służyły do czasu sukcesu nowej: teraz je sprzątamy.
        older = await C.rows(select(A).where(A.c.clip_id == clip["id"]).where(A.c.revision < rev))
        if older:
            await database.execute(A.delete().where(A.c.clip_id == clip["id"]).where(A.c.revision < rev))
            await _delete_objects([k for r in older for k in (r.get("storage_key"), r.get("poster_key"))])
    finally:
        if uploaded:  # wyjątek po uploadzie, a przed zapisem metadanych: nie zostawiamy sierot
            await _delete_objects(uploaded)
        await asyncio.to_thread(shutil.rmtree, folder, True)


# ─── Push „Klip gotowy” ─────────────────────────────────────────────────────


def clip_ready_text(title: Any, duration_s: Any, height: Any) -> tuple[str, str]:
    """Tytuł i treść cichego pushu: nazwa klipu + pieczęć pliku (jak na karcie „Ciemni”)."""
    name = str(title or "").strip() or "Klip"
    if len(name) > 60:
        name = name[:57] + "..."
    stamp = ["MP4"]
    try:
        if duration_s is not None and float(duration_s) > 0:
            stamp.append(f"{float(duration_s):.1f}".replace(".", ",") + " s")
    except (TypeError, ValueError):
        pass
    try:
        if height and int(height) > 0:
            stamp.append(f"{int(height)}p")
    except (TypeError, ValueError):
        pass
    return "Klip gotowy", f"„{name}” wywołał się: {' · '.join(stamp)}. Gra z pliku BAZY, także w zwolnieniu."


async def notify_clip_ready(job: Dict[str, Any], clip: Dict[str, Any], duration_s: Any = None, height: Any = None) -> None:
    """Jeden cichy push do osoby, która zamówiła MP4 (zwykle autor klipu), z celem `clip` -> kino klipu w aplikacji.
    Wzorem pushy Mentora (`mentor_panel_notify.push_data`, ten sam dispatcher i przełącznik `mentorPanel`), ale bez
    e-maila: to tylko znak, że plik czeka. Tag per klip skleja ewentualny drugi push tej samej rzeczy w jeden kafelek.
    Wysyłka nigdy nie cofa stanu `ready` - błąd kończy się wpisem w logu."""
    try:
        from app.mentor_panel_notify import PREFERENCE_KEY, match_image, push_data
        from app.push.push import send_push_to_judges_report

        who = str(job.get("requested_by_real_judge_id") or clip.get("author_id") or "").strip()
        if not who:
            return
        title, body = clip_ready_text(clip.get("title"), duration_s, height)
        data = push_data(clip.get("pair_id") or job.get("pair_id"), target="clip", match_id=clip.get("match_id") or job.get("match_id"),
                         clip_id=clip.get("id") or job.get("clip_id"), tag=f"mentor-clip-{clip.get('id') or job.get('clip_id')}",
                         quiet=True, image=await match_image(clip.get("match_id") or job.get("match_id")))
        await send_push_to_judges_report([who], title, body, data, app_variant="baza", preference_key=PREFERENCE_KEY)
    except Exception:  # noqa: BLE001
        logger.warning("bastion: push „Klip gotowy” nieudany", exc_info=True)


# ─── Pętla workera ──────────────────────────────────────────────────────────


def new_worker_id(n: int = 1) -> str:
    from app import mentor_panel_rules as R

    return f"{socket.gethostname()}-{os.getpid()}-{n}-{R.new_id()[:6]}"


async def run_once(worker_id: str, *, lease_s: int = BR.LEASE_S, client: Any = None) -> bool:
    """Jedno przejęcie i wykonanie zadania. True = coś zrobiono (pętla nie śpi)."""
    global _last_release
    import time

    if not BR.load_flags().enabled:
        return False
    if time.monotonic() - _last_release > 10:
        _last_release = time.monotonic()
        try:
            await release_waiting_jobs()
        except Exception:  # noqa: BLE001
            logger.warning("bastion: wznawianie zadań po odnowieniu sesji nieudane", exc_info=True)
    job = await claim_next(worker_id, lease_s=lease_s)
    if not job:
        return False
    beat = asyncio.create_task(_heartbeat(job["id"], worker_id, lease_s))
    try:
        await process_job(job, worker_id, client=client)
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 - jedno złe zadanie nie zatrzymuje kolejki
        logger.exception("bastion: przebieg zadania %s nieudany", job["id"])
        try:
            await _retry(job, worker_id, "BASTION_UNAVAILABLE")
        except Exception:  # noqa: BLE001
            logger.warning("bastion: zapis błędu zadania nieudany", exc_info=True)
    finally:
        beat.cancel()
    return True


async def repair_legacy_links() -> int:
    """Linki Bastionu dodane przed włączeniem flagi leżą jako zwykły link (provider inny niż bastion) z tytułem
    podglądu z przekierowania na logowanie Discorda. Przy starcie z włączoną flagą przestawiamy je na Bastion
    i czyścimy obcy podgląd. Adres zostaje bez zmian (unikalność normalized_url w meczu)."""
    from sqlalchemy import select, update

    from app.db import database, mentor_match_videos as V

    rows = await database.fetch_all(select(V.c.id, V.c.url, V.c.provider).where(V.c.url.like("%handball-bastion.pl/game%")))
    fixed = 0
    for r in rows:
        item = BR.parse_game_url(r["url"])
        if not item or r["provider"] == BR.PROVIDER:
            continue
        await database.execute(update(V).where(V.c.id == r["id"]).values(
            provider=BR.PROVIDER, external_id=str(item), title=None, thumbnail_url=None, site_name=None, duration_s=None))
        fixed += 1
    if fixed:
        logger.info("Mentor Bastion: %s starych linków przestawionych na Bastion", fixed)
    return fixed


async def run_bastion_worker(n: int = 1) -> None:
    """Pętla w tle (start w `main.py`, także na Railway: jeden proces uvicorn, stan w bazie, lease chroni przed dublami
    przy większej liczbie replik). Budzi ją zapis zadania, inaczej sprawdza co 15 s."""
    global _wake_event
    if _wake_event is None:
        _wake_event = asyncio.Event()
    worker_id = new_worker_id(n)
    await asyncio.sleep(25)
    while True:
        try:
            busy = await run_once(worker_id)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("bastion: przebieg kolejki nieudany")
            busy = False
        if busy:
            continue
        _wake_event.clear()
        try:
            await asyncio.wait_for(_wake_event.wait(), timeout=15)
        except asyncio.TimeoutError:
            pass
