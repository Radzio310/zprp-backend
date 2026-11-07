"""Automatyczna kopia transmisji YouTube na serwer (07.11.2026) - uzbrajanie, harmonogram, sygnał z ProEla.

Reguły i stany: `app/mentor_live_copy_rules.py`. Kopię robi ten sam worker co „Zrób kopię na serwer”
(`app/mentor_youtube_copy.py`): automat tylko zakłada zamówienie (`status = 'downloading'` + `wake_worker()`)
albo odświeżenie gotowej kopii (`mentor_uploads.refresh_at`), a wynik dostaje z powrotem przez `after_success`
i `after_failure`.

  - uzbrojenie: `arm_new_link` przy dodaniu linku (`mentor_evaluations.insert_link_video`, także automat nagrań) -
    gdy YouTube mówi, że to transmisja trwająca albo zapowiedziana;
  - pętla `run_live_copy_loop` (co 60 s, start w `main.py`): stan transmisji w YouTube (API `videos.list` zbiorczo
    co 2 min, bez klucza strona filmu co 5 min), dociągnięcie `sync.stream_start_ms`, terminy prób;
  - `kick_on_proel_status`: koniec meczu w ProElu (`app/proel.py`). Koniec meczu = pierwszy sygnał (YouTube albo
    ProEl); próby co 5 minut przez 30 minut (+5 ... +30), a gdy żadna nie wyszła - jedna po 60 minutach.

Wyłączniki: `MENTOR_YT_COPY=0` (całe kopie), `MENTOR_LIVE_COPY=0` (sam automat). W testach (`ENVIRONMENT=test`)
automat jest domyślnie wyłączony - test włącza go jawnie (`MENTOR_LIVE_COPY=1`).
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import func, or_, select, update

from app import mentor_live_copy_rules as L
from app import mentor_panel_rules as R
from app import mentor_youtube_copy_rules as Y

logger = logging.getLogger("app.mentor_live_copy")

TICK_S = 60
API_EVERY_S = 120
PAGE_EVERY_S = 300
PAGE_PER_TICK = 8
ARM_TIMEOUT_S = 6.0
PAIR_CACHE_S = 600

_api_at = 0.0
_page_at: Dict[str, float] = {}
_pairs: Dict[str, Any] = {}


def enabled() -> bool:
    """Automat (pętla, uzbrajanie, sygnał z ProEla). W testach domyślnie wyłączony - bez sieci w tle."""
    if not Y.enabled():
        return False
    default = "0" if os.getenv("ENVIRONMENT", "").strip().lower() == "test" else "1"
    return os.getenv("MENTOR_LIVE_COPY", default).strip().lower() in ("1", "true", "yes", "on")


def _db():
    """Baza i panel brane przy wywołaniu, nie przy imporcie (sygnał z ProEla ładuje ten moduł wcześnie, a testy
    podmieniają `app.db` w `sys.modules`)."""
    return importlib.import_module("app.db")


def _core():
    return importlib.import_module("app.mentor_panel_core")


def _copy():
    YC = importlib.import_module("app.mentor_youtube_copy")  # leniwie: worker importuje ten moduł

    return YC


async def _save(row: Dict[str, Any], values: Dict[str, Any]) -> bool:
    if not values:
        return False
    await _db().database.execute(update(_db().mentor_match_videos).where(_db().mentor_match_videos.c.id == row["id"]).values(**values))
    row.update(values)
    return True


async def pair_id_for(pair_key: Any) -> Optional[str]:
    """Para panelu po kluczu `101|102` (posortowane numery sędziów). Trwająca para przed zakończoną."""
    key = R.s(pair_key)
    hit = _pairs.get(key)
    if hit and time.monotonic() - hit[0] < PAIR_CACHE_S:
        return hit[1]
    mentoring_pairs = _db().mentoring_pairs
    want = sorted(k for k in key.split("|") if k)
    found: Optional[str] = None
    for row in await _core().rows(select(mentoring_pairs.c.id, mentoring_pairs.c.judge_ids, mentoring_pairs.c.ended_at)):
        ids = sorted(R.s(j) for j in R.json_value(row.get("judge_ids"), []))
        if ids != want:
            continue
        if row.get("ended_at") is None:
            found = R.s(row["id"])
            break
        found = found or R.s(row["id"])
    if found:
        _pairs[key] = (time.monotonic(), found)
    return found


async def _touch(row: Dict[str, Any], action: str = "copy_auto") -> None:
    """Otwarte pokoje meczu dowiadują się o zmianie (rev pary). Nigdy nie psuje automatu."""
    try:
        pair_id = await pair_id_for(row.get("pair_key"))
        if pair_id:
            await _core().touch(pair_id, R.s(row.get("added_by")), action, "videos", R.s(row.get("match_id")),
                          {"id": row.get("id"), "auto": L.state_of(row)})
    except Exception:  # noqa: BLE001
        logger.warning("mentor: zapis zmiany automatu kopii nieudany", exc_info=True)


# ─── Stan transmisji ────────────────────────────────────────────────────────


async def _api_infos(ids: List[str]) -> Dict[str, Dict[str, Any]]:
    key = os.getenv("YOUTUBE_API_KEY", "").strip()
    if not key or not ids:
        return {}
    from app.streams import net, store

    out: Dict[str, Dict[str, Any]] = {}
    for item in await net.YouTube(store.quota_take, key).videos(ids):
        out[item["video_id"]] = L.api_live_info(item)
    return out


async def _page_info(vid: str) -> Optional[Dict[str, Any]]:
    from app.streams import net

    body = await net.fetch_text(f"https://www.youtube.com/watch?v={vid}", cookies=net.YT_CONSENT)
    return await asyncio.to_thread(L.page_live_info, body) if body else None


async def fetch_infos(ids: Iterable[str], *, use_api: bool = True, page_ids: Optional[Iterable[str]] = None) -> Dict[str, Dict[str, Any]]:
    """Stan transmisji: {id filmu: {state, started_ms, ended_at}}. Najpierw API (zbiorczo), brakujące ze strony filmu.
    `page_ids` = które wolno sprawdzić stroną (domyślnie wszystkie brakujące). Nigdy nie rzuca."""
    wanted = list(dict.fromkeys(i for i in ids if i))
    out: Dict[str, Dict[str, Any]] = {}
    if use_api:
        try:
            out.update(await _api_infos(wanted))
        except Exception:  # noqa: BLE001 - klucz wyczerpany albo sieć: zostaje strona filmu
            logger.info("mentor: stan transmisji z API YouTube nieczytelny", exc_info=True)
    allowed = set(wanted if page_ids is None else page_ids)
    for vid in wanted:
        if vid in out or vid not in allowed:
            continue
        try:
            info = await _page_info(vid)
        except Exception:  # noqa: BLE001
            info = None
        if info:
            out[vid] = info
    return out


async def live_info(url: Any) -> Optional[Dict[str, Any]]:
    vid = Y.youtube_video_id(url)
    if not vid:
        return None
    return (await fetch_infos([vid])).get(vid)


def _has_start(row: Dict[str, Any]) -> bool:
    return bool(R.json_value(row.get("sync_json"), {}).get("stream_start_ms"))


async def _fill_stream_start(row: Dict[str, Any], info: Optional[Dict[str, Any]]) -> bool:
    """Link dodany przed startem transmisji: godzina sekundy 0:00 dochodzi, gdy YouTube poda `actualStartTime`."""
    ms = (info or {}).get("started_ms")
    if not ms or _has_start(row):
        return False
    from app.mentor_evaluations import store_stream_start

    stored = await store_stream_start(row, int(ms))
    if stored:
        fresh = await _core().one(select(_db().mentor_match_videos.c.sync_json).where(_db().mentor_match_videos.c.id == row["id"]))
        row["sync_json"] = (fresh or {}).get("sync_json")
    return stored


# ─── Uzbrajanie ─────────────────────────────────────────────────────────────


async def arm_new_link(row: Dict[str, Any], stream_start_ms: Optional[int] = None) -> Dict[str, Any]:
    """Świeżo dodany link YouTube: transmisja trwająca albo zapowiedziana = automatyczna kopia po jej końcu.
    Zwraca wiersz (uzupełniony o kolumny automatu). Nigdy nie rzuca i nie czeka dłużej niż kilka sekund."""
    try:
        if not enabled() or (row.get("kind") or "link") == "upload" or R.s(row.get("provider")) != "youtube":
            return row
        if not Y.watch_url(row.get("url")) or not _copy().available():
            return row
        if not await pair_id_for(row.get("pair_key")):
            return row  # galeria bez pary panelu: kopii i tak nie byłoby gdzie trzymać
        try:
            info = await asyncio.wait_for(live_info(row.get("url")), ARM_TIMEOUT_S)
        except asyncio.TimeoutError:
            info = None
        if not L.live_now(info) and not (info is None and stream_start_ms):
            return row  # zwykły film albo zakończona transmisja - kopię zamawia się ręcznie, jak dotąd
        now = _core().now()
        await _save(row, L.arm_values(now))
        await _fill_stream_start(row, info)
        logger.info("mentor: transmisja %s uzbrojona (%s)", row.get("id"), row.get("auto_copy_state"))
    except Exception:  # noqa: BLE001 - dodanie linku działa i bez automatu
        logger.warning("mentor: uzbrojenie automatycznej kopii nieudane", exc_info=True)
    return row


async def disarm(video: Optional[Dict[str, Any]]) -> None:
    """Ręczne anulowanie kopii (albo kopia do kosza) wyłącza automat tego filmu."""
    if video and L.armed(video):
        await _save(video, L.off_values())


async def note_manual(video: Dict[str, Any], refresh: bool) -> None:
    """Ręczne „Zrób kopię” / „Odśwież kopię” na uzbrojonym filmie PO końcu meczu (między próbami) liczy się jako próba
    automatu - wynik wraca tu i harmonogram biegnie dalej. Przed końcem meczu ręczna kopia jest zwykłą kopią."""
    state = L.state_of(video)
    if state in ("scheduled", "last_try"):
        await _save(video, L.on_start(video, _core().now(), refresh))


# ─── Wynik próby (worker) ───────────────────────────────────────────────────


async def _source_of(upload_id: Any) -> Optional[Dict[str, Any]]:
    return await _core().one(select(_db().mentor_match_videos).where(_db().mentor_match_videos.c.mirror_upload_id == R.s(upload_id)))


async def after_success(upload: Dict[str, Any], refresh: bool) -> None:
    video = await _source_of(upload.get("id"))
    if video and L.running(video) and await _save(video, L.on_success(video, _core().now())):
        await _touch(video)


async def after_failure(upload: Dict[str, Any], code: str, message: str, refresh: bool) -> Optional[str]:
    """Nieudana próba. Zwraca błąd do zapisania w kopii (`mirror.error` / `mirror.refresh.error`) albo None.
    Próba automatu: None, dopóki harmonogram biegnie (kopia bez dobrej wersji czeka: `status = 'waiting'`, dla API
    `working`/`queued`; dobra kopia zostaje nietknięta) - błąd dostaje tylko `gave_up` (powód po polsku)."""
    video = await _source_of(upload.get("id"))
    if not video or not L.running(video):
        return message
    changes = L.on_failure(video, _core().now(), code, message, refresh)
    if not changes:
        return message
    if not refresh and changes.get("auto_copy_state") in ("scheduled", "last_try"):
        db = _db()
        await db.database.execute(update(db.mentor_uploads).where(db.mentor_uploads.c.id == upload["id"])
                                  .where(db.mentor_uploads.c.status == "downloading").values(status="waiting", error=None))
    await _save(video, changes)
    await _touch(video)
    return changes.get("auto_reason") if changes.get("auto_copy_state") == "gave_up" else None


# ─── Sygnał z ProEla ────────────────────────────────────────────────────────


async def match_ids_for_proel(match_number: Any, zprp_match_id: Any) -> List[str]:
    """Wiersz ProEla -> identyfikatory meczów w nagraniach: ID ZPRP, ręczne podpięcia (`mentor_proel_links`, także
    kluczy szkoleniowych przeniesionych do tego `promoted_to`) i mecze wspólne (`my:<id>`, klucz `M-<tuleja>/<numer>`)."""
    db = _db()
    mentor_proel_links, saved_matches, shared_matches = db.mentor_proel_links, db.saved_matches, db.shared_matches
    from app.proel_match_key import is_shared_key, number_of_key, shared_key_of, stem_of_row

    key = R.s(match_number)
    ids: List[str] = []

    def add(value: Any) -> None:
        text = R.s(value)
        if text and text not in ("0", "None") and text not in ids:
            ids.append(text)

    add(zprp_match_id)
    if not key:
        return ids
    keys = {key}
    for row in await _core().rows(select(saved_matches.c.match_number).where(saved_matches.c.promoted_to == key)):
        keys.add(R.s(row["match_number"]))
    for row in await _core().rows(select(mentor_proel_links.c.match_id).where(mentor_proel_links.c.proel_key.in_(sorted(keys)))):
        add(row["match_id"])
    if is_shared_key(key):
        upper = key.upper()
        number = number_of_key(key)
        found = await _core().rows(select(shared_matches).where(or_(func.upper(shared_matches.c.proel_key) == upper,
                                                               func.upper(shared_matches.c.code) == number.upper())))
        for row in found:
            if R.s(row.get("proel_key")).upper() == upper or shared_key_of(stem_of_row(row), row.get("code")) == upper:
                add(f"my:{row['id']}")
                add(row.get("zprp_match_id"))
    return ids


async def mark_proel_finished(match_number: Any, zprp_match_id: Any, now: Optional[datetime] = None) -> int:
    """Koniec meczu w ProElu: uzbrojone nagrania tego meczu (gdy YouTube nie był pierwszy) dostają pierwszą próbę za 5 minut. Zwraca liczbę nagrań."""
    now = now or _core().now()
    ids = await match_ids_for_proel(match_number, zprp_match_id)
    if not ids:
        return 0
    rows = await _core().rows(select(_db().mentor_match_videos).where(_db().mentor_match_videos.c.match_id.in_(ids)).where(_db().mentor_match_videos.c.auto_copy_state.in_(L.ACTIVE))
                        .where(_db().mentor_match_videos.c.deleted_at.is_(None)))
    done = 0
    for row in rows:
        if await _save(row, L.on_proel_finished(row, now)):
            done += 1
            await _touch(row)
    return done


async def _proel_task(match_number: Any, zprp_match_id: Any) -> None:
    try:
        count = await mark_proel_finished(match_number, zprp_match_id)
        if count:
            logger.info("mentor: koniec meczu %s w ProElu - %s transmisji czeka na kopię", match_number, count)
    except Exception:  # noqa: BLE001
        logger.warning("mentor: sygnał końca meczu dla automatu kopii nieudany", exc_info=True)


def kick_on_proel_status(match_number: Any, zprp_match_id: Any, previous: Optional[str], final: Optional[str]) -> bool:
    """`app/proel.py`: przejście statusu meczu. Koniec (finished/approved z innego stanu) = zadanie w tle.
    Nigdy nie rzuca; False = nic nie zaplanowano (inny status, automat wyłączony, brak pętli zdarzeń)."""
    try:
        if final not in ("finished", "approved") or previous in ("finished", "approved") or not enabled():
            return False
        asyncio.get_running_loop().create_task(_proel_task(match_number, zprp_match_id))
        return True
    except Exception:  # noqa: BLE001
        return False


# ─── Przegląd (co minutę) ───────────────────────────────────────────────────


async def _watch(rows: List[Dict[str, Any]], now: datetime, *, force: bool = False) -> None:
    """YouTube: koniec transmisji (= koniec meczu, gdy ProEl nie był pierwszy) i godzina startu transmisji."""
    global _api_at
    need = [r for r in rows if (L.state_of(r) == "waiting_end" and not r.get("live_ended_at"))
            or (L.state_of(r) in ("waiting_end", "scheduled") and not _has_start(r))]
    if not need:
        return
    by_vid: Dict[str, List[Dict[str, Any]]] = {}
    for row in need:
        vid = Y.youtube_video_id(row.get("url"))
        if vid:
            by_vid.setdefault(vid, []).append(row)
    mono = time.monotonic()
    use_api = force or mono - _api_at >= API_EVERY_S
    if use_api:
        _api_at = mono
    pages = [v for v in by_vid if force or mono - _page_at.get(v, 0.0) >= PAGE_EVERY_S][:PAGE_PER_TICK]
    infos = await fetch_infos(list(by_vid), use_api=use_api, page_ids=pages)
    for vid in pages:
        _page_at[vid] = mono
    for vid, group in by_vid.items():
        info = infos.get(vid)
        if not info:
            continue
        for row in group:
            changed = await _save(row, L.on_live_info(row, info, now))
            filled = await _fill_stream_start(row, info)
            if changed or filled:
                await _touch(row)


def _has_copy(upload: Optional[Dict[str, Any]]) -> bool:
    return bool(upload and upload.get("status") == "ready" and upload.get("play_key"))


async def _reconcile(row: Dict[str, Any], now: datetime) -> None:
    """Próba w toku po restarcie albo po zgubionym wyniku: stan automatu dogania stan kopii."""
    if not L.running(row):
        return
    upload = await _copy()._mirror_row(row)
    status = R.s((upload or {}).get("status"))
    if status == "downloading" or (status == "ready" and (upload or {}).get("refresh_at")):
        return  # worker jeszcze pracuje (po restarcie podejmie wiersz sam)
    if not upload or status in ("removed", "expired"):
        await _save(row, L.off_values())
    elif _has_copy(upload):
        await _save(row, L.on_success(row, now))
    elif status == "failed":
        await _save(row, {"auto_copy_state": "gave_up", "auto_next_at": None,
                          "auto_reason": R.s(upload.get("error")) or Y.MESSAGES["FAILED"]})
    else:  # `waiting` bez zapisanego wyniku: jak nieudana próba
        await _save(row, L.on_failure(row, now, "FAILED", Y.MESSAGES["FAILED"], False))


async def queue_attempt(row: Dict[str, Any], now: datetime) -> None:
    """Próba automatu: pierwsza kopia (to samo zamówienie co „Zrób kopię na serwer”) albo NADPISANIE gotowej kopii
    (ten sam wiersz, te same klucze R2, to samo nagranie-kopia). Kopia usunięta przez parę = koniec, bez wskrzeszania."""
    YC = _copy()
    upload = await YC._mirror_row(row)
    status = R.s((upload or {}).get("status"))
    if status == "downloading" or (status == "ready" and (upload or {}).get("refresh_at")):
        await _save(row, L.on_start(row, now, status == "ready"))  # ręczne zamówienie już w drodze
        return
    if not YC.available():
        await _save(row, L.on_failure(row, now, "NO_TOOL", Y.MESSAGES["NO_TOOL"], _has_copy(upload)))
        return
    if _has_copy(upload):
        copy = await YC._copy_video(dict(upload))
        if copy is not None and copy.get("deleted_at") is not None:
            await _save(row, {"auto_copy_state": "done", "auto_next_at": None, "auto_reason": None})
            return
        await YC.enqueue_refresh(upload)
        await _save(row, L.on_start(row, now, True))
        await _touch(row, "copy_refresh_started")
        return
    pair_id = R.s((upload or {}).get("pair_id")) or await pair_id_for(row.get("pair_key"))
    if not pair_id:
        await _save(row, {"auto_copy_state": "gave_up", "auto_next_at": None, "auto_reason": L.REASONS["NO_PAIR"]})
        return
    await YC.enqueue_copy(row, pair_id, R.s(row.get("added_by")), upload)
    await _save(row, L.on_start(row, now, False))
    await _touch(row, "copy_started")


async def tick(now: Optional[datetime] = None, *, check_live: bool = True, force: bool = False) -> int:
    """Jeden przegląd uzbrojonych filmów. Zwraca liczbę zamówionych prób."""
    now = now or _core().now()
    trashed = await _core().rows(select(_db().mentor_match_videos).where(_db().mentor_match_videos.c.auto_copy_state.in_(L.ACTIVE)).where(_db().mentor_match_videos.c.deleted_at.is_not(None)))
    for row in trashed:  # film YouTube w koszu: automat milknie (przywrócenie nie wznawia - kopię zamówi się ręcznie)
        await _save(row, L.off_values())
    rows = await _core().rows(select(_db().mentor_match_videos).where(_db().mentor_match_videos.c.auto_copy_state.in_(L.ACTIVE)).where(_db().mentor_match_videos.c.deleted_at.is_(None))
                        .order_by(_db().mentor_match_videos.c.created_at.asc()))
    if check_live:
        try:
            await _watch(rows, now, force=force)
        except Exception:  # noqa: BLE001 - bez YouTube zostaje ProEl i terminy
            logger.warning("mentor: sprawdzanie transmisji nieudane", exc_info=True)
    queued = 0
    for row in rows:
        try:
            if await _save(row, L.housekeeping(row, now)):
                await _touch(row)
            await _reconcile(row, now)
            if L.due(row, now):
                await queue_attempt(row, now)
                queued += 1
        except Exception:  # noqa: BLE001 - jeden zły film nie zatrzymuje reszty
            logger.warning("mentor: automat kopii dla %s nieudany", row.get("id"), exc_info=True)
    return queued


async def run_live_copy_loop() -> None:
    """Pętla w tle (start w `main.py`): co minutę przegląd uzbrojonych transmisji."""
    if not enabled():
        return
    await asyncio.sleep(40)
    while True:
        try:
            await tick()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("mentor: przegląd automatycznych kopii nieudany")
        await asyncio.sleep(TICK_S)
