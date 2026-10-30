"""Automat nagrań w dniu meczu (30.10.2026). Kontrakt: `docs/mentor-panel.md`, § "Automat nagrań".

W dniu meczu pary z włączonym panelem mentora serwer sam szuka nagrania (Bastion + YouTube, ta sama logika co Trybuna /
"Szukaj w Bastionie": `score_game`, `query_score`, `merge_ranked`) o godzinie startu z obsady ZPRP, start + 30 min i start + 2 h
(okno spóźnienia 15 min). Pewne trafienie (jeden kandydat) dodaje do meczu zwykłą ścieżką dodawania nagrania z pieczątką
`auto_added` (cofnięcie = kosz nagrań), niepewne zapisuje jako sugestie. Jeden push po meczu (start + 2 h), nigdy w trakcie gry.

Limity Bastionu: mecze idą JEDEN PO DRUGIM (zapytania do connectora nie nakładają się), każde szukanie to najwyżej 3 zapytania,
wyniki siedzą w pamięci Meczoteki ~10 min (te same zapytania przy kolejnej próbie i innej parze nie wychodzą do portalu), a limit
120 zapytań / 5 min liczy się też automatowi. Przy 429 / awarii próba nie jest zużywana, dopóki jej okno jest otwarte.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional

from fastapi import APIRouter, Depends, Header, Response
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app import mentor_auto_found_rules as U
from app import mentor_panel_core as C
from app import mentor_panel_rules as R
from app.db import database, mentor_auto_found, mentor_auto_found_seen, mentor_match_videos, mentor_panels, mentoring_assignments, mentoring_pairs
from app.mentor_panel_auth import mentor_actor

logger = logging.getLogger("app.mentor_panel")

router = APIRouter(prefix="/mentor-panel", tags=["Mentor automat nagran"])
Actor = C.MentorActor
F = mentor_auto_found
SEEN = mentor_auto_found_seen

#: Co ile sekund pętla sprawdza mecze (okno spóźnienia próby to 15 min, więc próba ma 3 szanse).
LOOP_S = 300
#: Mecz wchodzi do przeglądu od startu do start + 2 h 15 min (+ zapas).
SCAN_BACK_MIN = U.SLOT_MINUTES[-1] + U.LATE_MIN + 10
#: Najwięcej szukań w jednym przebiegu pętli i przerwa między nimi (łagodzi Bastion).
MAX_ATTEMPTS_PER_LOOP = 30
PAUSE_BETWEEN_S = 1.0
SYSTEM_ID = "0"

AUTO_BY = "auto-found"
Searcher = Callable[[Mapping[str, Any], Mapping[str, Any]], Awaitable[Dict[str, Any]]]
_locks: Dict[tuple, asyncio.Lock] = {}


def _lock(pair_id: str, match_id: str) -> asyncio.Lock:
    key = (pair_id, match_id)
    if key not in _locks:
        if len(_locks) > 2000:
            _locks.clear()
        _locks[key] = asyncio.Lock()
    return _locks[key]


# --- Zapis ------------------------------------------------------------------


async def get_row(pair_id: str, match_id: str) -> Optional[Dict[str, Any]]:
    return await C.one(select(F).where(F.c.pair_id == pair_id).where(F.c.match_id == match_id))


async def save_row(pair_id: str, match_id: str, values: Dict[str, Any], start_at: Optional[datetime] = None) -> None:
    exists = await C.one(select(F.c.pair_id).where(F.c.pair_id == pair_id).where(F.c.match_id == match_id))
    values = {**values, "updated_at": C.now()}
    if exists:
        await database.execute(update(F).where(F.c.pair_id == pair_id).where(F.c.match_id == match_id).values(**values))
        return
    try:
        await database.execute(F.insert().values(pair_id=pair_id, match_id=match_id, start_at=start_at or C.now(), created_at=C.now(), **values))
    except Exception:  # noqa: BLE001 - wyścig dwóch zapisów: drugi robi aktualizację
        await database.execute(update(F).where(F.c.pair_id == pair_id).where(F.c.match_id == match_id).values(**values))


def attempts_of(row: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    return U.loads((row or {}).get("attempts_json"), [])


def done_slots(row: Optional[Mapping[str, Any]]) -> List[int]:
    return [int(a["slot"]) for a in attempts_of(row) if isinstance(a, dict) and a.get("slot") is not None]


# --- Widok ------------------------------------------------------------------


async def alive_videos(pair_key: str, match_ids: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    if not match_ids:
        return out
    V = mentor_match_videos
    for v in await C.rows(select(V).where(V.c.match_id.in_(match_ids)).where(V.c.pair_key == pair_key).where(V.c.deleted_at.is_(None))):
        out.setdefault(R.s(v["match_id"]), []).append(v)
    return out


def _unseen(row: Mapping[str, Any], seen_at: Any) -> bool:
    if row.get("state") not in ("added", "suggested") or not row.get("found_at"):
        return False
    seen = U.aware(seen_at)
    return seen is None or seen < U.aware(row["found_at"])


def effective(row: Mapping[str, Any], videos: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Stan do pokazania: dodane samo, ale usunięte ręcznie (kosz) nie jest już "added" - jego kandydat wraca na początek sugestii."""
    state = row.get("state") or "searching"
    added = U.loads(row.get("added_json"), {})
    cands = U.loads(row.get("candidates_json"), [])
    if state == "added":
        alive = next((v for v in videos if v["id"] == added.get("video_id")), None)
        if alive is None:
            lost = added.get("candidate")
            cands = [lost, *[c for c in cands if c.get("key") != lost.get("key")]] if lost else cands
            state = "suggested" if cands else "none"
            added = {}
    return {"state": state, "added": added or None, "candidates": cands}


def list_shape(row: Mapping[str, Any], seen_at: Any, videos: List[Dict[str, Any]], now: datetime) -> Dict[str, Any]:
    eff = effective(row, videos)
    start = U.aware(row.get("start_at"))
    nxt = None
    if eff["state"] == "searching" and start and not row.get("finished") and not row.get("locked"):
        nxt = U.next_attempt(start, now, done_slots(row))
    unseen = _unseen({**row, "state": eff["state"]}, seen_at)
    return {"state": eff["state"], "unseen": unseen, "found_at": row.get("found_at"), "next_attempt_at": nxt}


async def list_for(ctx: Dict[str, Any], match_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """`auto_found` na kartach meczów pary (jedno zapytanie o wiersze, jedno o "widziałem", jedno o nagrania). Nigdy nie psuje listy."""
    if not match_ids:
        return {}
    try:
        rows = await C.rows(select(F).where(F.c.pair_id == ctx["pair_id"]).where(F.c.match_id.in_(match_ids)))
        if not rows:
            return {}
        ids = [R.s(r["match_id"]) for r in rows]
        seen = {R.s(r["match_id"]): r["seen_at"] for r in await C.rows(
            select(SEEN).where(SEEN.c.pair_id == ctx["pair_id"]).where(SEEN.c.judge_id == ctx["actor"].judge_id).where(SEEN.c.match_id.in_(ids)))}
        videos = await alive_videos(ctx["pair_key"], [R.s(r["match_id"]) for r in rows if r.get("state") == "added"])
        now = C.now()
        return {R.s(r["match_id"]): list_shape(r, seen.get(R.s(r["match_id"])), videos.get(R.s(r["match_id"]), []), now) for r in rows}
    except Exception:  # noqa: BLE001 - dodatek listy nie zabiera listy
        logger.warning("mentor: auto_found na liście meczów nieczytelne", exc_info=True)
        return {}


def attempt_view(a: Mapping[str, Any]) -> Dict[str, Any]:
    return {"at": a.get("at"), "result": a.get("result")}


async def detail(ctx: Dict[str, Any], match_id: str) -> Dict[str, Any]:
    row = await get_row(ctx["pair_id"], match_id)
    if not row:
        return {"state": "none", "unseen": False, "found_at": None, "attempts": [], "added": None, "candidates": [], "bastion_error": None}
    videos = (await alive_videos(ctx["pair_key"], [match_id])).get(match_id, [])
    eff = effective(row, videos)
    seen = await C.one(select(SEEN.c.seen_at).where(SEEN.c.pair_id == ctx["pair_id"]).where(SEEN.c.match_id == match_id)
                       .where(SEEN.c.judge_id == ctx["actor"].judge_id))
    added = eff["added"]
    if added:
        added = {k: added.get(k) for k in ("video_id", "source", "title", "thumbnail_url")}
    return {"state": eff["state"], "unseen": _unseen({**row, "state": eff["state"]}, (seen or {}).get("seen_at")),
            "found_at": row.get("found_at"), "attempts": [attempt_view(a) for a in attempts_of(row)],
            "added": added, "candidates": eff["candidates"], "bastion_error": row.get("bastion_error")}


# --- Szukanie ---------------------------------------------------------------

_ERROR_CODE = (("rate_limited", "BASTION_RATE_LIMITED"), ("unavailable", "BASTION_UNAVAILABLE"),
               ("forbidden", "BASTION_RESOURCE_FORBIDDEN"), ("auth_required", "BASTION_AUTH_REQUIRED"))
TRANSIENT = {"BASTION_RATE_LIMITED", "BASTION_UNAVAILABLE"}


def _stop_code(stop: Any) -> str:
    kinds = [v.kind for _, v in stop.verdicts]
    return next((code for kind, code in _ERROR_CODE if kind in kinds), "BASTION_AUTH_REQUIRED")


async def _bastion_games(card: Mapping[str, Any], pair: Mapping[str, Any]) -> Dict[str, Any]:
    """Kasety z Meczoteki dla meczu: połączenie domyślne, potem własne osób z pary (jak przy ręcznym szukaniu)."""
    from app import mentor_bastion_client as CL
    from app import mentor_bastion_rules as BR
    from app import mentor_bastion_search as S

    flags = BR.load_flags()
    if not flags.enabled:
        return {"games": [], "error": "BASTION_DISABLED"}
    scopes = BR.candidate_scopes(flags)
    if not scopes or not flags.configured:
        return {"games": [], "error": "BASTION_UNAVAILABLE"}
    try:
        client = CL.get_client()
    except CL.ConnectorUnavailable:
        return {"games": [], "error": "BASTION_UNAVAILABLE"}
    tries: List[tuple] = []
    if "default" in scopes:
        tries.append((["default"], C.MentorActor(SYSTEM_ID, display_name="Automat nagrań")))
    if "personal" in scopes:
        for jid in pair.get("judge_ids") or []:
            tries.append((["personal"], await C.load_actor(R.s(jid), via="jwt")))
    error: Optional[str] = None
    for scope_list, actor in tries:
        mz = S.Meczoteka(client, scope_list, actor)
        try:
            games, _ = await S.find_for_card(mz, card, [])
        except S._Stop as stop:
            error = _stop_code(stop)
            if error in TRANSIENT:
                break
            continue
        try:
            await S.enrich_media(actor, mz.scope, games)
        except Exception:  # noqa: BLE001 - miniatura to dodatek
            logger.warning("mentor: miniatury automatu nieudane", exc_info=True)
        return {"games": games, "error": None}
    return {"games": [], "error": error or "BASTION_AUTH_REQUIRED"}


async def search_card(card: Mapping[str, Any], pair: Mapping[str, Any]) -> Dict[str, Any]:
    """Ta sama logika co `trybuna/search`: kasety (`score_game`) i filmy YouTube (`query_score`) jako wpisy rankingu.
    Zwraca `{entries, bastion_error}`; brak sesji Bastionu = tylko YouTube."""
    from app import mentor_bastion_search as S
    from app import mentor_trybuna_rank as RK

    bastion = await _bastion_games(card, pair)
    entries: List[Dict[str, Any]] = []
    for g in bastion["games"]:
        if int(g.get("confidence") or 0) < RK.RANK_MIN:
            continue
        entries.append({"source": "bastion", "key": f"bastion:{g['bunny_item_id']}", "confidence": g["confidence"], "sure": bool(g["sure"]),
                        "signals": g["signals"], "title": g.get("title"), "date": g.get("date"), "home": g.get("home"), "away": g.get("away"),
                        "code": g.get("code"), "thumbnail_url": g.get("thumbnail_url"), "state": "video", "video_state": g.get("video_state"),
                        "url": g.get("url"), "ref": {"bunny_item_id": g["bunny_item_id"], "game_id": None}})
    try:
        from app.mentor_trybuna_feed import youtube_results

        home, away = (card.get("home") or {}).get("name"), (card.get("away") or {}).get("name")
        q = R.s(card.get("match_code")) or " ".join(x for x in (home, away) if x)
        day = S.card_day(card)
        if q and day:
            for y in await youtube_results([dict(card)], q, day, day, None, None, limit=10):
                if y["confidence"] < RK.RANK_MIN:
                    continue
                entries.append({"source": "youtube", "key": f"yt:{y['video_id']}", "confidence": y["confidence"], "sure": y["sure"], "signals": y["signals"],
                                "title": y["title"], "date": y["date"], "match_day": y.get("match_day"), "home": y["home"], "away": y["away"],
                                "code": y["code"], "thumbnail_url": y["thumbnail_url"], "official": y["official"],
                                "ref": {"video_id": y["video_id"], "url": y["url"]}, "url": y["url"]})
    except Exception:  # noqa: BLE001 - YouTube nie zabiera Bastionu i odwrotnie
        logger.warning("mentor: YouTube w automacie nagrań nieczytelny", exc_info=True)
    return {"entries": entries, "bastion_error": bastion["error"]}


# --- Dodawanie nagrania -----------------------------------------------------


async def add_video(pair_id: str, pair_key: str, match_id: str, url: str, added_by: str, idem: Optional[str], auto: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Zwykła ścieżka dodawania nagrania meczu pary (`insert_link_video`, jak `POST .../videos`); `auto` = pieczątka `auto_added`."""
    from app import mentor_video_trash as trash
    from app.mentor_evaluation_request_rules import normalized_video_url
    from app.mentor_evaluations import insert_link_video

    norm = normalized_video_url(url)
    if not norm:
        raise C.err(422, "VIDEO_URL", "Podaj link do nagrania.")
    row, created = await insert_link_video(match_id, pair_key, norm, added_by, idem)
    if row.get("deleted_at") is not None and trash.in_trash(row):  # powtórka klucza po cofnięciu: nagranie wraca z kosza
        await trash.restore(row)
    stamp = U.dumps(auto) if auto else None
    await database.execute(update(mentor_match_videos).where(mentor_match_videos.c.id == row["id"]).values(auto_added_json=stamp))
    if created:
        await C.touch(pair_id, added_by, "video_added", "videos", match_id, {"id": row["id"], "auto": bool(auto)})
    return row


# --- Przebieg ---------------------------------------------------------------


async def enabled_pairs() -> List[Dict[str, Any]]:
    ids = [R.s(r["pair_id"]) for r in await C.rows(select(mentor_panels.c.pair_id).where(mentor_panels.c.enabled.is_(True)))]
    if not ids:
        return []
    pairs = await C.rows(select(mentoring_pairs).where(mentoring_pairs.c.id.in_(ids)).where(mentoring_pairs.c.ended_at.is_(None)))
    for p in pairs:
        p["judge_ids"] = [R.s(j) for j in R.json_value(p.get("judge_ids"), [])]
    return [p for p in pairs if len(p["judge_ids"]) == 2]


async def attempt(pair: Mapping[str, Any], card: Mapping[str, Any], start: datetime, slot: int, row: Optional[Mapping[str, Any]],
                  now: datetime, searcher: Searcher, missed: List[int]) -> str:
    """Jedna próba: szukanie, decyzja, zapis. Zwraca wynik (`added|suggested|none|retry`)."""
    from app import mentor_bastion_search as S
    from app import mentor_trybuna_rank as RK

    pair_id, match_id = R.s(pair["id"]), R.s(card["match_id"])
    pair_key = "|".join(sorted(pair["judge_ids"]))
    res = await searcher(card, pair)
    error = res.get("bastion_error")
    dismissed = set(U.loads((row or {}).get("dismissed_json"), []))
    members = {e["key"]: e for e in res["entries"] if e["key"] not in dismissed}
    merged = RK.merge_ranked(list(members.values())) if members else []
    decision = U.decide(merged, members, start)
    # Awaria Bastionu bez pewnego trafienia w oknie, które jeszcze potrwa: próby nie zużywamy (kolejny przebieg ją powtórzy).
    if decision["action"] != "add" and error in TRANSIENT and now + timedelta(seconds=LOOP_S) < U.window_end(start, slot):
        return "retry"

    old_cands = U.loads((row or {}).get("candidates_json"), [])
    log = attempts_of(row) + [{"at": now, "slot": s, "result": "missed"} for s in missed if s not in done_slots(row)]
    values: Dict[str, Any] = {"bastion_error": error}
    result = "none"

    if decision["action"] == "add":
        pick, group = decision["pick"], decision["group"]
        cand = U.candidate(pick, group)
        try:
            await S.attach_crests([cand])
            video = await add_video(pair_id, pair_key, match_id, cand["url"] or "", AUTO_BY, U.idempotency(match_id, pick["key"]),
                                    {"at": now, "source": pick["source"]})
            added = {"video_id": video["id"], "source": pick["source"], "title": video.get("title") or cand.get("title"),
                     "thumbnail_url": video.get("thumbnail_url") or cand.get("thumbnail_url"), "candidate": cand}
            others = [U.candidate(representative_of(g, members, start), g) for g in decision["groups"]]
            cands, _ = U.merge_candidates([], others, dismissed)
            values.update(state="added", found_at=now, added_json=U.dumps(added), candidates_json=U.dumps(cands), finished=True)
            result = "added"
        except Exception:  # noqa: BLE001 - dodanie nieudane: pewny kandydat idzie do sugestii, człowiek zdecyduje
            logger.warning("mentor: automatyczne dodanie nagrania nieudane (%s/%s)", pair_id, match_id, exc_info=True)
            decision = {"action": "suggest", "groups": [group, *decision["groups"]]}
            result = "error"
    if decision["action"] in ("suggest",):
        new = [U.candidate(representative_of(g, members, start), g) for g in decision["groups"]]
        await S.attach_crests(new)
        cands, fresh = U.merge_candidates(old_cands, new, dismissed)
        if cands:
            was = (row or {}).get("state")
            values.update(candidates_json=U.dumps(cands))
            if was != "suggested" or fresh:
                values.update(found_at=now)
            values.update(state="suggested")
            result = "error" if result == "error" else "suggested"
    log.append({"at": now, "slot": slot, "result": result})
    values["attempts_json"] = U.dumps(log)
    await save_row(pair_id, match_id, values, start_at=start)
    if values.get("state") in ("added", "suggested"):
        await C.touch(pair_id, AUTO_BY, "auto_found", "videos", match_id, {"state": values["state"]})
    return result


def representative_of(group: Mapping[str, Any], members: Mapping[str, Mapping[str, Any]], start: datetime) -> Dict[str, Any]:
    return U.representative(group, members, start)


async def run_once(now: Optional[datetime] = None, searcher: Optional[Searcher] = None) -> Dict[str, int]:
    """Jeden przebieg pętli: próby dla meczów w oknie, domknięcie i push. Do testów można podać własny `searcher`."""
    counts = {"matches": 0, "attempts": 0, "added": 0, "suggested": 0, "retry": 0, "pushed": 0}
    now = now or C.now()
    searcher = searcher or search_card
    budget = MAX_ATTEMPTS_PER_LOOP
    for pair in await enabled_pairs():
        key = "|".join(sorted(pair["judge_ids"]))
        try:
            cards = await C.pair_match_cards(pair["judge_ids"])
        except Exception:  # noqa: BLE001
            logger.warning("mentor: mecze pary %s nieczytelne dla automatu", pair["id"], exc_info=True)
            continue
        due = []
        for card in cards:
            start = U.start_of(card)
            if start is not None and start <= now <= start + timedelta(minutes=SCAN_BACK_MIN):
                due.append((card, start))
        if not due:
            continue
        videos = await alive_videos(key, [R.s(c["match_id"]) for c, _ in due])
        for card, start in due:
            match_id = R.s(card["match_id"])
            counts["matches"] += 1
            if budget <= 0:
                break
            async with _lock(R.s(pair["id"]), match_id):
                row = await get_row(R.s(pair["id"]), match_id)
                if row and (row.get("locked") or row.get("state") == "added" or row.get("finished")):
                    continue
                if any(not v.get("auto_added_json") for v in videos.get(match_id, [])):
                    continue  # para ma już swoje nagranie - automat nie dokłada
                p = U.plan(start, now, done_slots(row))
                if p["run"] is None:
                    if p["missed"]:
                        log = attempts_of(row) + [{"at": now, "slot": s, "result": "missed"} for s in p["missed"]]
                        await save_row(R.s(pair["id"]), match_id, {"attempts_json": U.dumps(log)}, start_at=start)
                    continue
                budget -= 1
                try:
                    result = await attempt(pair, card, start, p["run"], row, now, searcher, p["missed"])
                except Exception:  # noqa: BLE001 - jedna para nie zatrzymuje reszty
                    logger.exception("mentor: próba automatu nagrań nieudana (%s/%s)", pair["id"], match_id)
                    continue
                if result == "retry":
                    counts["retry"] += 1
                else:
                    counts["attempts"] += 1
                    if result in ("added", "suggested"):
                        counts[result] += 1
            await asyncio.sleep(PAUSE_BETWEEN_S if searcher is search_card else 0)
    counts["pushed"] = await close_and_push(now)
    return counts


async def close_and_push(now: datetime) -> int:
    """Domyka mecze po ostatniej próbie (bez znaleziska = `none`) i wysyła JEDEN push na mecz po start + 2 h."""
    pushed = 0
    since = now - timedelta(days=2)
    for row in await C.rows(select(F).where(F.c.start_at >= since).where(F.c.pushed_at.is_(None))):
        start = U.aware(row["start_at"])
        pair_id, match_id = R.s(row["pair_id"]), R.s(row["match_id"])
        if start is None:
            continue
        if not row.get("finished") and now > U.window_end(start, len(U.SLOT_MINUTES) - 1):
            await save_row(pair_id, match_id, {"finished": True, **({"state": "none"} if row.get("state") == "searching" else {})})
            row = {**row, "finished": True, "state": "none" if row.get("state") == "searching" else row.get("state")}
        if row.get("state") not in ("added", "suggested") or not U.push_due(start, now):
            continue
        if row.get("locked"):
            await save_row(pair_id, match_id, {"pushed_at": now})  # człowiek już zdecydował: nie przypominamy
            continue
        async with _lock(pair_id, match_id):
            fresh = await get_row(pair_id, match_id)
            if not fresh or fresh.get("pushed_at") is not None:
                continue
            await save_row(pair_id, match_id, {"pushed_at": now})  # ślad PRZED wysyłką: błąd pusha nie powtarza go co 5 minut
            try:
                if await send_push(row):
                    pushed += 1
            except Exception:  # noqa: BLE001
                logger.warning("mentor: push automatu nagrań nieudany (%s/%s)", pair_id, match_id, exc_info=True)
    return pushed


async def send_push(row: Mapping[str, Any]) -> bool:
    from app.mentor_panel_notify import PREFERENCE_KEY, push_data
    from app.push.push import send_push_to_judges_report

    pair_id, match_id = R.s(row["pair_id"]), R.s(row["match_id"])
    pair = await C.one(select(mentoring_pairs).where(mentoring_pairs.c.id == pair_id))
    if not pair:
        return False
    judges = [R.s(j) for j in R.json_value(pair.get("judge_ids"), [])]
    mentors = [R.s(r["mentor_id"]) for r in await C.rows(select(mentoring_assignments.c.mentor_id)
                                                         .where(mentoring_assignments.c.pair_id == pair_id).where(mentoring_assignments.c.ended_at.is_(None)))]
    recipients = sorted({j for j in [*judges, *mentors] if j})
    card = next((c for c in await C.pair_match_cards(judges) if R.s(c["match_id"]) == match_id), {})
    title, body = U.push_text(row["state"], card)
    data = push_data(pair_id, target="match", match_id=match_id, tag=f"mentor-auto-found-{match_id}", extra={"autoFound": "1"})
    await send_push_to_judges_report(recipients, title, body, data, app_variant="baza", preference_key=PREFERENCE_KEY)
    return True


async def run_auto_found() -> None:
    """Pętla w tle (co 5 min). Wyłączenie: zmienna `MENTOR_AUTO_FOUND=0`."""
    if os.getenv("MENTOR_AUTO_FOUND", "1") == "0":
        logger.info("mentor: automat nagrań wyłączony (MENTOR_AUTO_FOUND=0)")
        return
    await asyncio.sleep(150)
    while True:
        try:
            counts = await run_once()
            if counts["attempts"] or counts["pushed"]:
                logger.info("mentor: automat nagrań %s", counts)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("mentor: automat nagrań nieudany")
        await asyncio.sleep(LOOP_S)


# --- Trasy ------------------------------------------------------------------


async def _context(pair_id: str, match_id: str, actor: Actor, action: str) -> Dict[str, Any]:
    ctx = await C.pair_context(pair_id, actor, action=action)
    await C.match_card(ctx, match_id)
    return ctx


@router.get("/pairs/{pair_id}/matches/{match_id}/auto-found")
async def get_auto_found(pair_id: str, match_id: str, response: Response, actor: Actor = Depends(mentor_actor)):
    response.headers["Cache-Control"] = "no-store"
    ctx = await _context(pair_id, match_id, actor, "view")
    return await detail(ctx, match_id)


async def mark_seen(pair_id: str, match_id: str, judge_id: str) -> None:
    exists = await C.one(select(SEEN.c.seen_at).where(SEEN.c.pair_id == pair_id).where(SEEN.c.match_id == match_id).where(SEEN.c.judge_id == judge_id))
    if exists:
        await database.execute(update(SEEN).where(SEEN.c.pair_id == pair_id).where(SEEN.c.match_id == match_id)
                               .where(SEEN.c.judge_id == judge_id).values(seen_at=C.now()))
        return
    try:
        await database.execute(SEEN.insert().values(pair_id=pair_id, match_id=match_id, judge_id=judge_id, seen_at=C.now()))
    except Exception:  # noqa: BLE001 - wyścig dwóch wejść
        pass


@router.post("/pairs/{pair_id}/matches/{match_id}/auto-found/seen", status_code=204)
async def seen_auto_found(pair_id: str, match_id: str, actor: Actor = Depends(mentor_actor)):
    """Wyłącza podświetlenie dla tego użytkownika (per użytkownik; bez wiersza automatu nic nie robi)."""
    ctx = await _context(pair_id, match_id, actor, "view")
    if await get_row(ctx["pair_id"], match_id):
        await mark_seen(ctx["pair_id"], match_id, actor.judge_id)
    return Response(status_code=204)


class AcceptBody(BaseModel):
    index: int = Field(ge=0, le=20)


class DismissBody(BaseModel):
    index: Optional[int] = Field(default=None, ge=0, le=20)


async def _effective(ctx: Dict[str, Any], row: Mapping[str, Any]) -> Dict[str, Any]:
    videos = (await alive_videos(ctx["pair_key"], [R.s(row["match_id"])])).get(R.s(row["match_id"]), [])
    return effective(row, videos)


async def _candidates(ctx: Dict[str, Any], row: Mapping[str, Any]) -> List[Dict[str, Any]]:
    return (await _effective(ctx, row))["candidates"]


async def _row_or_404(ctx: Dict[str, Any], match_id: str) -> Dict[str, Any]:
    row = await get_row(ctx["pair_id"], match_id)
    if not row:
        raise C.err(404, "AUTO_FOUND_NOT_FOUND", "Dla tego meczu automat niczego nie znalazł.")
    return row


@router.post("/pairs/{pair_id}/matches/{match_id}/auto-found/accept")
async def accept_auto_found(pair_id: str, match_id: str, body: AcceptBody, actor: Actor = Depends(mentor_actor),
                            idempotency_header: Optional[str] = Header(default=None, alias="Idempotency-Key")):
    """"To ten": dodaje kandydata o numerze `index` (z `candidates`) jako zwykłe nagranie meczu. Zwraca `{video_id}`."""
    from app.mentor_panel_media import idempotency_key

    ctx = await _context(pair_id, match_id, actor, "video")
    key = idempotency_key(idempotency_header)
    async with _lock(ctx["pair_id"], match_id):
        row = await _row_or_404(ctx, match_id)
        cands = await _candidates(ctx, row)
        if body.index >= len(cands):
            raise C.err(404, "CANDIDATE_NOT_FOUND", "Nie ma takiej propozycji - lista mogła się zmienić.")
        pick = cands[body.index]
        if not pick.get("url"):
            raise C.err(422, "VIDEO_URL", "Ta propozycja nie ma adresu nagrania.")
        video = await add_video(ctx["pair_id"], ctx["pair_key"], match_id, pick["url"], actor.judge_id, key, None)
        await save_row(ctx["pair_id"], match_id, {"state": "none", "candidates_json": "[]", "added_json": None, "locked": True, "finished": True})
        await mark_seen(ctx["pair_id"], match_id, actor.judge_id)
    return {"video_id": video["id"]}


@router.post("/pairs/{pair_id}/matches/{match_id}/auto-found/dismiss")
async def dismiss_auto_found(pair_id: str, match_id: str, body: Optional[DismissBody] = None, actor: Actor = Depends(mentor_actor)):
    """"Odrzuć": jedna propozycja (`index`) albo wszystkie. Odrzuconych automat już nie proponuje."""
    ctx = await _context(pair_id, match_id, actor, "video")
    async with _lock(ctx["pair_id"], match_id):
        row = await _row_or_404(ctx, match_id)
        cands = await _candidates(ctx, row)
        dismissed = U.loads(row.get("dismissed_json"), [])
        index = (body or DismissBody()).index
        if index is not None and index >= len(cands):
            raise C.err(404, "CANDIDATE_NOT_FOUND", "Nie ma takiej propozycji - lista mogła się zmienić.")
        gone = cands if index is None else [cands[index]]
        dismissed += [c["key"] for c in gone if c.get("key") and c["key"] not in dismissed]
        left = [] if index is None else [c for i, c in enumerate(cands) if i != index]
        state = (await _effective(ctx, row))["state"]
        if state == "suggested":
            state = "suggested" if left else "none"
        await save_row(ctx["pair_id"], match_id, {"candidates_json": U.dumps(left), "dismissed_json": U.dumps(dismissed), "state": state, "locked": True})
        await mark_seen(ctx["pair_id"], match_id, actor.judge_id)
    await C.touch(ctx, actor.judge_id, "auto_found_dismissed", "videos", match_id, {"count": len(gone)})
    return {"ok": True, "state": state, "candidates": left}


@router.post("/pairs/{pair_id}/matches/{match_id}/auto-found/undo")
async def undo_auto_found(pair_id: str, match_id: str, actor: Actor = Depends(mentor_actor)):
    """"Cofnij": nagranie dodane przez automat idzie do kosza (zwykłe usunięcie, 30 dni), a kandydat wraca jako sugestia."""
    from app import mentor_video_trash as trash

    ctx = await _context(pair_id, match_id, actor, "video")
    async with _lock(ctx["pair_id"], match_id):
        row = await _row_or_404(ctx, match_id)
        added = U.loads(row.get("added_json"), {})
        video = await C.one(select(mentor_match_videos).where(mentor_match_videos.c.id == added.get("video_id")))
        if row.get("state") != "added" or not video or video.get("deleted_at") is not None or not video.get("auto_added_json"):
            raise C.err(409, "AUTO_FOUND_NOT_ADDED", "Automat nie dodał tu nagrania, które można cofnąć.")
        await trash.move_to_trash(ctx, video, actor.judge_id)
        cand = added.get("candidate") or {}
        cands = [cand, *[c for c in U.loads(row.get("candidates_json"), []) if c.get("key") != cand.get("key")]] if cand else U.loads(row.get("candidates_json"), [])
        await save_row(ctx["pair_id"], match_id, {"state": "suggested" if cands else "none", "added_json": None, "candidates_json": U.dumps(cands), "locked": True})
        await mark_seen(ctx["pair_id"], match_id, actor.judge_id)
    await C.touch(ctx, actor.judge_id, "video_trashed", "videos", match_id, {"id": video["id"], "auto": True})
    return {"ok": True, "state": "suggested" if cands else "none", "candidates": cands}
