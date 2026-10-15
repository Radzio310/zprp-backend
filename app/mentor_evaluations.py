"""
Oceny mentora (29.09.2026) - arkusz we wzorze arkusza delegata ZPRP,
wypełniany w aplikacji przez mentora pary.

Trasy (prefiks `/mentor-evaluations`):
  GET  /match/{match_id}          czy mogę ocenić + moja ocena + opublikowane,
  PUT  /match/{match_id}          szkic (zapis w tle z telefonu),
  POST /match/{match_id}/publish  publikacja - para widzi ocenę od tej chwili,
  GET  /province/{province}       opublikowane oceny okręgu (komisja, admin).
  POST /match/{match_id}/requests prośba pary o ocenę (push, e-mail, SMS),
  POST/PATCH/DELETE /match/{match_id}/videos[/{id}]  galeria nagrań meczu:
                                  podgląd linku, synchronizacja, znaczniki,
  GET  /match/{match_id}/timeline oś meczu z protokołu ProEla (do znaczników),
  GET  /link-preview?url=         podgląd dowolnego linku (SSRF: `app/link_preview_rules.py`).

Status prośby (wysłano / przeczytane / ocenił) i znaczniki nagrań - liść
`app/mentor_video_rules.py`.

Reguły kto/kiedy/co w liściu `app/mentor_evaluation_rules.py`.
"""

from __future__ import annotations

import json
import html
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db import (
    database,
    json_files,
    login_records,
    mentor_evaluation_versions as versions,
    mentor_evaluations as evaluations,
    mentor_evaluation_requests as requests,
    mentor_match_videos as match_videos,
    mentoring_assignments as assignments,
    mentoring_pairs as mentoring_pairs,
    province_judges,
    province_matches,
    province_mentor_pairs,
    push_tokens,
)
from app.match_market import Actor, market_actor
from app.mentor_evaluation_rules import (
    can_view_published,
    clean_sheet,
    delegate_shape,
    eligibility,
    json_list,
    pair_key,
    pair_of,
    sheet_points,
)
from app.mentor_evaluation_request_rules import (
    REQUEST_COOLDOWN,
    cooldown_hours,
    normalized_video_url,
    request_target_error,
    video_provider,
    youtube_thumbnail,
)
from app.mentor_video_rules import clean_markers, clean_sync, mentor_states, should_mark_read, timeline_from_blob
from app.settlement_province import display as province_display, spellings

router = APIRouter(prefix="/mentor-evaluations", tags=["Mentor evaluations"])

MAX_SHEET_BYTES = 120_000
REQUEST_CHANNELS = {"push", "email", "sms"}


def now():
    return datetime.now(timezone.utc)


class SaveRequest(BaseModel):
    sheet: Dict[str, Any] = Field(default_factory=dict)
    together: bool = False
    co_author_id: Optional[str] = Field(default=None, max_length=40)


class EvaluationRequest(BaseModel):
    mentor_ids: List[str] = Field(min_length=1, max_length=30)
    video_url: Optional[str] = Field(default=None, max_length=2048)
    channels: List[Literal["push", "email", "sms"]] = Field(min_length=1, max_length=3)


class MatchVideoRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)


class MatchVideoPatch(BaseModel):
    sync: Optional[Dict[str, Any]] = None
    markers: Optional[List[Dict[str, Any]]] = Field(default=None, max_length=200)


# ─── Dane z bazy ────────────────────────────────────────────────────────────


async def match_state(match_id: str) -> Dict[str, Any]:
    """Najświeższy stan meczu z list okręgów (mecz może leżeć w kilku)."""
    row = await database.fetch_one(
        select(province_matches.c.province, province_matches.c.season, province_matches.c.match_at, province_matches.c.state_json)
        .where(province_matches.c.match_id == str(match_id))
        .order_by(province_matches.c.active.desc(), province_matches.c.updated_at.desc())
        .limit(1)
    )
    if not row:
        raise HTTPException(404, "Nie znam tego meczu - odśwież listę meczów i spróbuj ponownie.")
    state = row["state_json"]
    if isinstance(state, str):
        try:
            state = json.loads(state)
        except ValueError:
            state = {}
    return {"province": row["province"], "season": row["season"], "match_at": row["match_at"], "state": state or {}}


async def mentors_of(pair: tuple, province: str) -> Dict[str, set]:
    """Mentorzy pary w obu systemach: program Mentoring i pary mentorskie Obsady."""
    wanted = set(pair)
    mentoring: set = set()
    rows = await database.fetch_all(
        select(mentoring_pairs.c.id, mentoring_pairs.c.judge_ids).where(mentoring_pairs.c.ended_at.is_(None))
    )
    pair_ids = [r["id"] for r in rows if set(json_list(r["judge_ids"])) == wanted]
    if pair_ids:
        links = await database.fetch_all(
            select(assignments.c.mentor_id)
            .where(assignments.c.pair_id.in_(pair_ids))
            .where(assignments.c.ended_at.is_(None))
        )
        mentoring = {str(r["mentor_id"]).strip() for r in links}
    obsada: set = set()
    board = await database.fetch_all(
        select(province_mentor_pairs.c.mentor_ids)
        .where(province_mentor_pairs.c.pair_key == pair_key(pair))
        .where(province_mentor_pairs.c.province.in_(spellings(province_display(province))))
    )
    for r in board:
        obsada |= set(json_list(r["mentor_ids"]))
    return {"mentoring": mentoring, "obsada": obsada}


async def people(ids) -> Dict[str, Dict[str, Any]]:
    ids = {str(i).strip() for i in ids if str(i or "").strip()}
    if not ids:
        return {}
    rows = await database.fetch_all(
        select(province_judges.c.judge_id, province_judges.c.full_name, province_judges.c.photo_url).where(
            province_judges.c.judge_id.in_(ids)
        )
    )
    found = {str(r["judge_id"]): {"judge_id": str(r["judge_id"]), "full_name": r["full_name"], "photo_url": r["photo_url"]} for r in rows}
    return {i: found.get(i, {"judge_id": i, "full_name": f"Sędzia {i}", "photo_url": None}) for i in ids}


async def province_access(actor: Actor, province: str) -> bool:
    """Komisja / admin / VIP z dostępem do ocen okręgu - ta sama reguła co u delegatów."""
    if actor.is_admin:
        return True
    try:
        from app.delegate_evaluations import _access

        return bool((await _access(actor.judge_id, province)).get("stats"))
    except Exception:
        return False


def _loads(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}


def _json_list(value: Any) -> List[str]:
    parsed = value
    if isinstance(value, str):
        try:
            parsed = json.loads(value or "[]")
        except (TypeError, ValueError):
            parsed = []
    return [str(item) for item in parsed] if isinstance(parsed, list) else []


def _request_shape(row: Dict[str, Any]) -> Dict[str, Any]:
    last_sent = row.get("last_sent_at")
    cooldown_until = last_sent + REQUEST_COOLDOWN if last_sent else None
    return {
        "id": row["id"],
        "mentor_id": row["mentor_id"],
        "requested_by": row["requested_by"],
        "video_url": row.get("video_url"),
        "channels": _json_list(row.get("channels_json")),
        "delivery": _loads(row.get("delivery_json")),
        "send_count": int(row.get("send_count") or 0),
        "created_at": row.get("created_at"),
        "last_sent_at": last_sent,
        "cooldown_until": cooldown_until,
        "fulfilled_at": row.get("fulfilled_at"),
        "read_at": row.get("read_at"),
    }


def _video_shape(row: Dict[str, Any], names: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    url = str(row.get("url") or "")
    author_id = str(row.get("added_by") or "")
    markers_raw = row.get("markers_json")
    sync_raw = row.get("sync_json")
    return {
        "id": row["id"],
        "url": url,
        "provider": row.get("provider") or video_provider(url),
        "thumbnail_url": row.get("thumbnail_url") or youtube_thumbnail(url),
        "title": row.get("title") or "",
        "site_name": row.get("site_name") or "",
        "duration_s": row.get("duration_s"),
        "sync": clean_sync(_loads(sync_raw)) if sync_raw else None,
        "markers": clean_markers(json.loads(markers_raw)) if _is_json_list(markers_raw) else [],
        "added_by": names.get(author_id, {"judge_id": author_id, "full_name": f"Sędzia {author_id}"}),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


def _is_json_list(value: Any) -> bool:
    if not value:
        return False
    try:
        return isinstance(json.loads(value), list)
    except (TypeError, ValueError):
        return False


def _err(status: int, code: str, message: str) -> HTTPException:
    return HTTPException(status, detail={"code": code, "message": message})


def _valid_video_url(value: Optional[str]) -> str:
    try:
        return normalized_video_url(value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


def _phones_in(value: Any) -> List[str]:
    values = value if isinstance(value, list) else re.split(r"[;,]", str(value or ""))
    out: List[str] = []
    for item in values:
        raw = str(item or "").strip()
        digits = re.sub(r"\D", "", raw)
        if len(digits) < 9:
            continue
        phone = f"+{digits}" if raw.startswith("+") else digits
        if phone not in out:
            out.append(phone)
    return out


async def _mentor_contacts(province: str, mentor_ids: List[str], names: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, str]]:
    """Resolve contact data conservatively; ambiguous contact rows are ignored."""
    from app.district_alerts import _judge_email_detail
    from app.official_roster import person_key

    labels = {mentor_id: str(names.get(mentor_id, {}).get("full_name") or "") for mentor_id in mentor_ids}
    emails = await _judge_email_detail(province, mentor_ids, labels)
    rows = [dict(row) for row in await database.fetch_all(select(login_records).where(login_records.c.judge_id.in_(mentor_ids)))]
    phones: Dict[str, str] = {}
    for row in rows:
        config = row.get("config_json") or {}
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except ValueError:
                config = {}
        candidates = []
        for key in ("phone", "telephone", "contact_phone", "user_phone"):
            candidates += _phones_in(config.get(key) if isinstance(config, dict) else None)
        for nest in ("profile", "contact", "user", "account"):
            inner = config.get(nest) if isinstance(config, dict) else None
            if isinstance(inner, dict):
                for key in ("phone", "telephone", "contact_phone", "user_phone"):
                    candidates += _phones_in(inner.get(key))
        if candidates:
            phones[str(row["judge_id"])] = candidates[0]

    contact_row = await database.fetch_one(select(json_files.c.content).where(json_files.c.key == "kontakty"))
    contacts = contact_row["content"] if contact_row else []
    if isinstance(contacts, str):
        try:
            contacts = json.loads(contacts)
        except ValueError:
            contacts = []
    by_name: Dict[str, Optional[str]] = {}
    for contact in contacts if isinstance(contacts, list) else []:
        if not isinstance(contact, dict) or contact.get("isTeam") is True:
            continue
        key = person_key(f"{contact.get('name', '')} {contact.get('surname', '')}")
        found = _phones_in(contact.get("phone") or contact.get("phones"))
        if not key or not found:
            continue
        if key in by_name and by_name[key] != found[0]:
            by_name[key] = None
        else:
            by_name.setdefault(key, found[0])
    for mentor_id, label in labels.items():
        if mentor_id not in phones:
            phone = by_name.get(person_key(label))
            if phone:
                phones[mentor_id] = phone
    return {
        mentor_id: {
            "email": emails.get(mentor_id, ("", ""))[0],
            "phone": phones.get(mentor_id, ""),
        }
        for mentor_id in mentor_ids
    }


def shape(row: Dict[str, Any], names: Dict[str, Dict[str, Any]], *, working: bool) -> Dict[str, Any]:
    co = json_list(row["co_author_ids"])
    return {
        "id": row["id"],
        "match_id": row["match_id"],
        "status": row["status"],
        "source": row["source"],
        "author": names.get(row["author_id"], {"judge_id": row["author_id"], "full_name": row["author_id"]}),
        "co_authors": [names.get(c, {"judge_id": c, "full_name": c}) for c in co],
        "together": bool(co),
        # Autor dostaje wersję roboczą, reszta tylko opublikowaną.
        "sheet": _loads(row["sheet_json"] if working else row["published_json"]),
        "points": row["points"],
        "letter": row["letter"],
        "updated_at": row["updated_at"],
        "published_at": row["published_at"],
    }


async def context(match_id: str, actor: Actor) -> Dict[str, Any]:
    match = await match_state(match_id)
    state = match["state"]
    pair = pair_of(state)
    mentors = await mentors_of(pair, match["province"]) if pair else {"mentoring": set(), "obsada": set()}
    me = str(actor.judge_id)
    verdict = eligibility(
        actor_id=me,
        state=state,
        mentoring_mentor=me in mentors["mentoring"],
        obsada_mentor=me in mentors["obsada"],
    )
    co_mentors = sorted((mentors["mentoring"] | mentors["obsada"]) - {me})
    return {"match": match, "pair": pair, "mentors": mentors, "verdict": verdict, "co_mentors": co_mentors}


async def my_row(match_id: str, me: str) -> Optional[Dict[str, Any]]:
    rows = await database.fetch_all(select(evaluations).where(evaluations.c.match_id == str(match_id)))
    for r in rows:
        if r["author_id"] == me or me in json_list(r["co_author_ids"]):
            return dict(r)
    return None


# ─── Trasy ──────────────────────────────────────────────────────────────────


@router.get("/match/{match_id}")
async def for_match(match_id: str, actor: Actor = Depends(market_actor)):
    ctx = await context(match_id, actor)
    me = str(actor.judge_id)
    pair = ctx["pair"] or ()
    rows = [dict(r) for r in await database.fetch_all(select(evaluations).where(evaluations.c.match_id == str(match_id)))]
    mine = next((r for r in rows if r["author_id"] == me or me in json_list(r["co_author_ids"])), None)
    is_pair_mentor = me in ctx["mentors"]["mentoring"] or me in ctx["mentors"]["obsada"]
    access = None
    published = []
    for r in rows:
        if r["status"] != "published" or not r["published_json"]:
            continue
        authors = [r["author_id"], *json_list(r["co_author_ids"])]
        if not can_view_published(actor_id=me, pair=pair, authors=authors, is_pair_mentor=is_pair_mentor, province_access=False):
            if access is None:
                access = await province_access(actor, ctx["match"]["province"])
            if not access:
                continue
        published.append(r)
    may_view_videos = me in pair or is_pair_mentor or actor.is_admin
    video_rows = [
        dict(row)
        for row in await database.fetch_all(
            select(match_videos)
            .where(match_videos.c.match_id == str(match_id))
            .order_by(match_videos.c.created_at.asc())
        )
    ] if may_view_videos else []
    ids = set(pair) | set(ctx["co_mentors"]) | {str(row["added_by"]) for row in video_rows}
    for r in rows:
        ids |= {r["author_id"], *json_list(r["co_author_ids"])}
    names = await people(ids)
    request_rows = [
        dict(row)
        for row in await database.fetch_all(select(requests).where(requests.c.match_id == str(match_id)))
    ]
    # Mentor otworzył mecz, o którego ocenę go poproszono = „przeczytane".
    # Robi to serwer, więc działa w każdej wersji aplikacji mentora.
    for row in request_rows:
        if should_mark_read(actor_id=me, request=row):
            stamp = now()
            try:
                await database.execute(
                    update(requests)
                    .where(requests.c.id == row["id"])
                    .where(requests.c.read_at.is_(None))
                    .values(read_at=stamp)
                )
                row["read_at"] = stamp
            except Exception:  # noqa: BLE001 - potwierdzenie nie może zepsuć podglądu
                import logging

                logging.getLogger(__name__).warning("prośba o ocenę: zapis przeczytania nieudany", exc_info=True)
    assigned = sorted(ctx["mentors"]["mentoring"] | ctx["mentors"]["obsada"])
    published_authors = {
        author
        for row in rows
        if row["status"] == "published"
        for author in [row["author_id"], *json_list(row["co_author_ids"])]
    }
    drafting_authors = {
        author
        for row in rows
        if row["status"] != "published" and row.get("points") is not None
        for author in [row["author_id"], *json_list(row["co_author_ids"])]
    }
    states = mentor_states(
        assigned=assigned,
        requests=request_rows,
        published_authors=published_authors,
        drafting_authors=drafting_authors,
    ) if me in pair else {}
    return {
        "can_rate": ctx["verdict"]["can_rate"] or mine is not None,
        "source": ctx["verdict"]["source"] or (mine["source"] if mine else None),
        "reason": ctx["verdict"]["reason"],
        "pair": [names[p] for p in pair],
        "co_mentors": [names[c] for c in ctx["co_mentors"]],
        "mine": shape(mine, names, working=True) if mine else None,
        "published": [shape(r, names, working=False) for r in published],
        "requestable_mentors": [names[mentor_id] for mentor_id in assigned if mentor_id in names and mentor_id not in published_authors]
        if me in pair
        else [],
        "requests": [_request_shape(row) for row in request_rows]
        if me in pair or me in assigned or actor.is_admin
        else [],
        "videos": [_video_shape(row, names) for row in video_rows],
        # Wszyscy mentorzy pary ze stanem prośby - także ci, którzy już ocenili.
        "mentor_status": [
            {**names.get(mentor_id, {"judge_id": mentor_id, "full_name": f"Sędzia {mentor_id}", "photo_url": None}), **state}
            for mentor_id, state in states.items()
        ],
    }


@router.post("/match/{match_id}/videos")
async def add_match_video(match_id: str, body: MatchVideoRequest, actor: Actor = Depends(market_actor)):
    ctx = await context(match_id, actor)
    me = str(actor.judge_id)
    pair = tuple(ctx["pair"] or ())
    if me not in pair:
        raise HTTPException(403, "Tylko sędziowie tej pary mogą dodawać nagrania meczu.")
    url = _valid_video_url(body.url)
    existing = await database.fetch_one(
        select(match_videos).where(
            match_videos.c.match_id == str(match_id),
            match_videos.c.normalized_url == url,
        )
    )
    if existing:
        names = await people([existing["added_by"]])
        return {"ok": True, "created": False, "video": _video_shape(dict(existing), names)}
    from app.link_preview import preview_or_instant

    preview = await preview_or_instant(url)
    duration = preview.get("duration_s")
    row = {
        "id": uuid4().hex,
        "match_id": str(match_id),
        "pair_key": pair_key(pair),
        "url": url,
        "normalized_url": url,
        "provider": video_provider(url),
        "added_by": me,
        "created_at": now(),
        "title": str(preview.get("title") or "")[:200] or None,
        "thumbnail_url": str(preview.get("thumbnail_url") or "")[:2048] or None,
        "site_name": str(preview.get("site_name") or "")[:80] or None,
        "duration_s": int(duration) if isinstance(duration, (int, float)) and 0 < duration < 86400 else None,
    }
    created = True
    try:
        await database.execute(match_videos.insert().values(**row))
    except Exception:
        # Wyścig obu sędziów dodających ten sam adres kończy się jednym kaflem.
        existing = await database.fetch_one(
            select(match_videos).where(
                match_videos.c.match_id == str(match_id),
                match_videos.c.normalized_url == url,
            )
        )
        if not existing:
            raise
        row = dict(existing)
        created = False
    names = await people([row["added_by"]])
    return {"ok": True, "created": created, "video": _video_shape(row, names)}


@router.patch("/match/{match_id}/videos/{video_id}")
async def update_match_video(match_id: str, video_id: str, body: MatchVideoPatch, actor: Actor = Depends(market_actor)):
    """Synchronizacja z zegarem meczu i znaczniki akcji - zmienia para."""
    ctx = await context(match_id, actor)
    me = str(actor.judge_id)
    if me not in set(ctx["pair"] or ()):
        raise _err(403, "PAIR_ONLY", "Znaczniki nagrania ustawiają sędziowie tej pary.")
    row = await database.fetch_one(
        select(match_videos).where(match_videos.c.id == video_id, match_videos.c.match_id == str(match_id))
    )
    if not row:
        raise _err(404, "VIDEO_NOT_FOUND", "Nie znaleziono tego nagrania - mogło zostać usunięte.")
    values: Dict[str, Any] = {"updated_at": now()}
    if body.sync is not None:
        values["sync_json"] = json.dumps(clean_sync(body.sync))
    if body.markers is not None:
        values["markers_json"] = json.dumps(clean_markers(body.markers), ensure_ascii=False)
    await database.execute(update(match_videos).where(match_videos.c.id == video_id).values(**values))
    fresh = dict(await database.fetch_one(select(match_videos).where(match_videos.c.id == video_id)))
    names = await people([fresh["added_by"]])
    return {"ok": True, "video": _video_shape(fresh, names)}


@router.get("/match/{match_id}/timeline")
async def match_timeline(match_id: str, actor: Actor = Depends(market_actor)):
    """Zdarzenia z protokołu ProEla do zaimportowania jako znaczniki nagrania."""
    ctx = await context(match_id, actor)
    me = str(actor.judge_id)
    pair = set(ctx["pair"] or ())
    is_mentor = me in ctx["mentors"]["mentoring"] or me in ctx["mentors"]["obsada"]
    if me not in pair and not is_mentor and not actor.is_admin:
        raise _err(403, "NO_ACCESS", "Oś meczu widzą sędziowie pary i ich mentorzy.")
    code = str(ctx["match"]["state"].get("RozgrywkiCode") or "").strip()
    empty = {"available": False, "half_minutes": 30, "break_minutes": 10, "teams": {}, "events": []}
    if not code:
        return empty
    from app.db import saved_matches

    stored = await database.fetch_one(
        select(saved_matches.c.data_json, saved_matches.c.zprp_match_id).where(saved_matches.c.match_number == code)
    )
    if not stored:
        return empty
    # Numer meczu nie jest kluczem między sezonami - zapis innego meczu
    # o tym samym numerze nie może podsunąć cudzych zdarzeń.
    stored_id = str(stored["zprp_match_id"] or "").strip()
    if stored_id and stored_id != str(match_id):
        return empty
    blob = stored["data_json"]
    if isinstance(blob, str):
        try:
            blob = json.loads(blob)
        except ValueError:
            blob = {}
    return timeline_from_blob(blob)


@router.get("/link-preview")
async def link_preview(url: str = Query(..., min_length=8, max_length=2048), actor: Actor = Depends(market_actor)):
    """Podgląd linku: YouTube/Vimeo z oEmbed, reszta z `og:*` (z ochroną SSRF)."""
    from app.link_preview import fetch_preview
    from app.link_preview_rules import UnsafeUrl

    try:
        return {"ok": True, "preview": await fetch_preview(url)}
    except UnsafeUrl as exc:
        raise _err(422, "UNSAFE_URL", str(exc)) from exc


@router.delete("/match/{match_id}/videos/{video_id}")
async def remove_match_video(match_id: str, video_id: str, actor: Actor = Depends(market_actor)):
    ctx = await context(match_id, actor)
    me = str(actor.judge_id)
    if me not in set(ctx["pair"] or ()):
        raise HTTPException(403, "Tylko sędziowie tej pary mogą usuwać nagrania meczu.")
    row = await database.fetch_one(
        select(match_videos.c.id).where(
            match_videos.c.id == video_id,
            match_videos.c.match_id == str(match_id),
        )
    )
    if not row:
        raise HTTPException(404, "Nie znaleziono tego nagrania.")
    await database.execute(
        match_videos.delete().where(
            match_videos.c.id == video_id,
            match_videos.c.match_id == str(match_id),
        )
    )
    return {"ok": True}


def _request_message(match: Dict[str, Any], requester: str, video_url: str) -> tuple[str, str]:
    state = match["state"]
    code = str(state.get("RozgrywkiCode") or "meczu").strip()
    teams = " - ".join(
        value
        for value in (
            str(state.get("ID_zespoly_gosp_ZespolNazwa") or "").strip(),
            str(state.get("ID_zespoly_gosc_ZespolNazwa") or "").strip(),
        )
        if value
    )
    title = "Prośba o ocenę mentorską"
    body = f"{requester} prosi o ocenę meczu {code}"
    if teams:
        body += f" · {teams}"
    when = str(state.get("data_fakt") or state.get("data_prop") or "").strip().replace("T", " ")[:16]
    place = str(state.get("Hala_miasto") or state.get("Hala_nazwa") or "").strip()
    if when:
        body += f" · {when}"
    if place:
        body += f" · {place}"
    if video_url:
        body += " · dołączono nagranie"
    return title, body


async def _send_request_email(email: str, title: str, body: str, match_id: str, video_url: str) -> str:
    from app.province_alert_emails import send_alert_email

    app_link = f"refhandballapp://match?matchId={match_id}"
    video_line = f"\nNagranie: {video_url}" if video_url else ""
    text_body = f"{body}\n\nOtwórz mecz w BAZIE: {app_link}{video_line}"
    html_body = (
        '<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:24px;color:#1f2937">'
        f'<h2 style="color:#6d4ccf">{html.escape(title)}</h2><p>{html.escape(body)}</p>'
        f'<p><a href="{html.escape(app_link, quote=True)}" style="display:inline-block;padding:12px 18px;background:#a78bfa;color:#1b1230;text-decoration:none;border-radius:10px;font-weight:bold">Otwórz mecz w BAZIE</a></p>'
        + (f'<p><a href="{html.escape(video_url, quote=True)}">Otwórz nagranie meczu</a></p>' if video_url else "")
        + "</div>"
    )
    return await send_alert_email([email], title, html_body, text_body, sender="BAZA · Mentoring", tag="mentor-evaluation-request")


@router.post("/match/{match_id}/requests")
async def request_evaluation(match_id: str, req: EvaluationRequest, actor: Actor = Depends(market_actor)):
    ctx = await context(match_id, actor)
    me = str(actor.judge_id)
    pair = tuple(ctx["pair"] or ())
    mentor_ids = list(dict.fromkeys(str(value).strip() for value in req.mentor_ids if str(value).strip()))
    assigned = ctx["mentors"]["mentoring"] | ctx["mentors"]["obsada"]
    channels = list(dict.fromkeys(req.channels))
    if not channels or any(channel not in REQUEST_CHANNELS for channel in channels):
        raise HTTPException(422, "Wybierz przynajmniej jeden kanał wysyłki.")
    video_url = _valid_video_url(req.video_url)
    if not video_url:
        first_video = await database.fetch_one(
            select(match_videos.c.url)
            .where(match_videos.c.match_id == str(match_id))
            .order_by(match_videos.c.created_at.asc())
            .limit(1)
        )
        video_url = str(first_video["url"] or "") if first_video else ""
    published_rows = await database.fetch_all(
        select(evaluations.c.author_id, evaluations.c.co_author_ids)
        .where(evaluations.c.match_id == str(match_id))
        .where(evaluations.c.status == "published")
    )
    completed = {
        author
        for row in published_rows
        for author in [row["author_id"], *json_list(row["co_author_ids"])]
    }
    target_error = request_target_error(
        actor_id=me,
        pair=pair,
        assigned_mentors=assigned,
        requested_mentors=mentor_ids,
        completed_mentors=completed,
    )
    if target_error:
        raise HTTPException(*target_error)
    stamp = now()

    names = await people(set(pair) | set(mentor_ids))
    requester = names.get(me, {}).get("full_name") or "Sędziowie meczu"
    title, body = _request_message(ctx["match"], requester, video_url)
    try:
        contacts = await _mentor_contacts(ctx["match"]["province"], mentor_ids, names)
    except Exception:  # brak/awaria kontaktów nie może skasować trwałej prośby ani pushu
        import logging

        logging.getLogger(__name__).warning("prośba o ocenę: odczyt kontaktów nieudany", exc_info=True)
        contacts = {mentor_id: {"email": "", "phone": ""} for mentor_id in mentor_ids}
    outcomes: List[Dict[str, Any]] = []
    for mentor_id in mentor_ids:
        request_id = uuid4().hex
        values = {
            "id": request_id,
            "match_id": str(match_id),
            "province": province_display(ctx["match"]["province"]),
            "pair_key": pair_key(pair),
            "mentor_id": mentor_id,
            "requested_by": me,
            "video_url": video_url or None,
            "channels_json": json.dumps(channels),
            "created_at": stamp,
            "last_sent_at": stamp,
            "fulfilled_at": None,
            # Ponowiona prośba wraca do stanu „wysłano".
            "read_at": None,
            "delivery_json": "{}",
            "send_count": 1,
        }
        update_values = {key: value for key, value in values.items() if key not in {"id", "match_id", "mentor_id", "created_at", "send_count"}}
        claimed = await database.fetch_one(
            pg_insert(requests)
            .values(**values)
            .on_conflict_do_update(
                index_elements=[requests.c.match_id, requests.c.mentor_id],
                set_={**update_values, "send_count": requests.c.send_count + 1},
                where=or_(
                    requests.c.fulfilled_at.is_not(None),
                    requests.c.last_sent_at <= stamp - REQUEST_COOLDOWN,
                ),
            )
            .returning(requests.c.id)
        )
        if not claimed:
            existing = await database.fetch_one(
                select(requests.c.id, requests.c.last_sent_at, requests.c.fulfilled_at)
                .where(requests.c.match_id == str(match_id))
                .where(requests.c.mentor_id == mentor_id)
            )
            hours = cooldown_hours(
                last_sent_at=existing["last_sent_at"] if existing else stamp,
                now=stamp,
                fulfilled_at=existing["fulfilled_at"] if existing else None,
            )
            outcomes.append(
                {
                    "request_id": existing["id"] if existing else request_id,
                    "mentor": names[mentor_id],
                    "delivery": {channel: {"status": "cooldown", "hours": hours or 72} for channel in channels},
                    "sms_phone": "",
                    "sms_body": "",
                }
            )
            continue
        request_id = claimed["id"]
        delivery: Dict[str, Any] = {}
        if "push" in channels:
            try:
                from app.push.push import send_push_to_judges_report

                delivery["push"] = await send_push_to_judges_report(
                    [mentor_id],
                    title,
                    body,
                    {
                        "type": "match_change",
                        "kind": "mentor_evaluation_request",
                        "matchId": str(match_id),
                        "matchNumber": str(ctx["match"]["state"].get("RozgrywkiCode") or ""),
                        "videoUrl": video_url,
                    },
                    app_variant="baza",
                    preference_key="mentorEvaluations",
                )
            except Exception as exc:  # jeden kanał nie blokuje pozostałych
                delivery["push"] = {"status": "failed", "reason": type(exc).__name__}
        contact = contacts.get(mentor_id, {})
        if "email" in channels:
            if contact.get("email"):
                try:
                    delivery["email"] = {"status": "accepted", "message_id": await _send_request_email(contact["email"], title, body, str(match_id), video_url)}
                except Exception as exc:  # noqa: BLE001 - one channel cannot cancel the request
                    delivery["email"] = {"status": "failed", "reason": type(exc).__name__}
            else:
                delivery["email"] = {"status": "unavailable"}
        if "sms" in channels:
            delivery["sms"] = {"status": "ready" if contact.get("phone") else "unavailable"}
        await database.execute(
            update(requests).where(requests.c.id == request_id).values(delivery_json=json.dumps(delivery))
        )
        outcomes.append(
            {
                "request_id": request_id,
                "mentor": names[mentor_id],
                "delivery": delivery,
                "sms_phone": contact.get("phone") if "sms" in channels else "",
                "sms_body": f"{body}. Otwórz mecz w aplikacji BAZA.{f' Nagranie: {video_url}' if video_url else ''}",
            }
        )
    return {"ok": True, "items": outcomes}


@router.post("/requests/{request_id}/sms-opened")
async def mark_request_sms_opened(request_id: str, actor: Actor = Depends(market_actor)):
    row = await database.fetch_one(select(requests).where(requests.c.id == request_id))
    if not row:
        raise HTTPException(404, "Nie znaleziono prośby o ocenę.")
    stored = dict(row)
    ctx = await context(stored["match_id"], actor)
    if str(actor.judge_id) not in set(ctx["pair"] or ()):
        raise HTTPException(403, "Tylko sędziowie tej pary mogą aktualizować status SMS.")
    delivery = _loads(stored.get("delivery_json"))
    if "sms" not in _json_list(stored.get("channels_json")):
        raise HTTPException(409, "SMS nie był wybranym kanałem tej prośby.")
    delivery["sms"] = {"status": "opened", "opened_at": now().isoformat()}
    await database.execute(
        update(requests).where(requests.c.id == request_id).values(delivery_json=json.dumps(delivery))
    )
    return {"ok": True, "status": "opened"}


@router.get("/requests/inbox")
async def request_inbox(installation_id: str = Query(...), limit: int = Query(100, ge=1, le=200)):
    device = await database.fetch_one(
        select(push_tokens.c.judge_id, push_tokens.c.app_id).where(push_tokens.c.installation_id == installation_id)
    )
    if not device or not str(device["judge_id"] or "").strip():
        return {"items": []}
    from app.push.device_policy import dev_pushes_enabled, device_allowed

    if not device_allowed(device, await dev_pushes_enabled()):
        return {"items": []}
    mentor_id = str(device["judge_id"]).strip()
    rows = await database.fetch_all(
        select(requests)
        .where(requests.c.mentor_id == mentor_id)
        .where(requests.c.fulfilled_at.is_(None))
        .order_by(requests.c.last_sent_at.desc())
        .limit(limit)
    )
    items = []
    for raw in rows:
        row = dict(raw)
        try:
            match = await match_state(row["match_id"])
            code = str(match["state"].get("RozgrywkiCode") or "")
        except HTTPException:
            code = ""
        items.append(
            {
                "id": f"mentor-request:{row['id']}",
                "event_id": 0,
                "title": "Prośba o ocenę mentorską",
                "body": f"Sędziowie proszą o ocenę meczu {code or row['match_id']}",
                "data_json": {
                    "type": "match_change",
                    "kind": "mentor_evaluation_request",
                    "matchId": row["match_id"],
                    "matchNumber": code,
                    "videoUrl": row.get("video_url") or "",
                },
                "status": "stored",
                "created_at": row["last_sent_at"],
                "sent_at": row["last_sent_at"],
                "match_code": code,
                "event_type": "mentor_evaluation_request",
            }
        )
    return {"items": items}


async def save(match_id: str, req: SaveRequest, actor: Actor, publish: bool) -> Dict[str, Any]:
    raw = json.dumps(req.sheet, ensure_ascii=False)
    if len(raw.encode("utf-8")) > MAX_SHEET_BYTES:
        raise HTTPException(413, "Arkusz jest za duży - skróć opisy.")
    ctx = await context(match_id, actor)
    me = str(actor.judge_id)
    existing = await my_row(match_id, me)
    if not existing and not ctx["verdict"]["can_rate"]:
        raise HTTPException(403, ctx["verdict"]["reason"] or "Nie możesz ocenić tego meczu.")
    sheet = clean_sheet(req.sheet)
    points, letter = sheet_points(sheet)
    if publish and points is None:
        raise HTTPException(422, "Oceń przynajmniej jedną sekcję - ocena ogólna liczy się z liter sekcji.")
    co_ids: List[str] = []
    if req.together and req.co_author_id:
        if req.co_author_id not in ctx["co_mentors"]:
            raise HTTPException(422, "Wspólnie możesz oceniać tylko z innym mentorem tej pary.")
        co_ids = [req.co_author_id]
    body = json.dumps(sheet, ensure_ascii=False)
    stamp = now()
    match = ctx["match"]
    async with database.transaction():
        if existing:
            # Współautor nie zmienia składu autorów - robi to tylko zakładający.
            values: Dict[str, Any] = {"sheet_json": body, "points": points, "letter": letter, "updated_at": stamp}
            if existing["author_id"] == me:
                values["co_author_ids"] = json.dumps(co_ids)
            if publish:
                values.update(status="published", published_json=body, published_at=existing["published_at"] or stamp)
            await database.execute(update(evaluations).where(evaluations.c.id == existing["id"]).values(**values))
            evaluation_id = existing["id"]
        else:
            evaluation_id = uuid4().hex
            await database.execute(
                evaluations.insert().values(
                    id=evaluation_id,
                    match_id=str(match_id),
                    province=province_display(match["province"]),
                    season=match["season"] or str(match["state"].get("season") or "") or None,
                    match_number=str(match["state"].get("RozgrywkiCode") or ""),
                    match_at=match["match_at"],
                    pair_key=pair_key(ctx["pair"]),
                    author_id=me,
                    co_author_ids=json.dumps(co_ids),
                    source=ctx["verdict"]["source"],
                    status="published" if publish else "draft",
                    sheet_json=body,
                    published_json=body if publish else None,
                    points=points,
                    letter=letter,
                    created_at=stamp,
                    updated_at=stamp,
                    published_at=stamp if publish else None,
                )
            )
        if publish:
            await database.execute(
                versions.insert().values(
                    evaluation_id=evaluation_id, saved_by=me, sheet_json=body, points=points, letter=letter, saved_at=stamp
                )
            )
    first_publish = publish and not (existing and existing["status"] == "published")
    if first_publish:
        authors = [existing["author_id"], *json_list(existing["co_author_ids"])] if existing else [me, *co_ids]
        await database.execute(
            update(requests)
            .where(requests.c.match_id == str(match_id))
            .where(requests.c.mentor_id.in_(authors))
            .where(requests.c.fulfilled_at.is_(None))
            .values(fulfilled_at=stamp)
        )
        await notify_pair(match_id, ctx["pair"], authors, str(match["state"].get("RozgrywkiCode") or ""), letter, points)
    return {"ok": True, "id": evaluation_id, "points": points, "letter": letter, "status": "published" if publish or (existing and existing["status"] == "published") else "draft"}


@router.put("/match/{match_id}")
async def save_draft(match_id: str, req: SaveRequest, actor: Actor = Depends(market_actor)):
    return await save(match_id, req, actor, publish=False)


@router.post("/match/{match_id}/publish")
async def publish(match_id: str, req: SaveRequest, actor: Actor = Depends(market_actor)):
    return await save(match_id, req, actor, publish=True)


@router.get("/province/{province}")
async def for_province(province: str, season: Optional[str] = Query(default=None), actor: Actor = Depends(market_actor)):
    """Opublikowane oceny okręgu - do ekranu „Oceny delegatów i mentorów"."""
    if not await province_access(actor, province):
        raise HTTPException(403, "Brak dostępu do ocen tego okręgu.")
    query = (
        select(evaluations)
        .where(evaluations.c.province.in_(spellings(province_display(province))))
        .where(evaluations.c.status == "published")
        .order_by(evaluations.c.match_at.desc())
    )
    if season:
        query = query.where(evaluations.c.season == season)
    rows = [dict(r) for r in await database.fetch_all(query)]
    ids = set()
    for r in rows:
        ids |= {r["author_id"], *json_list(r["co_author_ids"]), *r["pair_key"].split("|")}
    names = await people(ids)
    out = []
    for r in rows:
        item = shape(r, names, working=False)
        item["pair"] = [names[p] for p in r["pair_key"].split("|") if p in names]
        item["match_number"] = r["match_number"]
        item["match_at"] = r["match_at"]
        out.append(item)
    return {"evaluations": out}


# ─── Oceny mentora w ekranie „Oceny delegatów i mentorów" ───────────────────


def _match_date(value: Any) -> str:
    if not value:
        return ""
    try:
        from zoneinfo import ZoneInfo

        return value.astimezone(ZoneInfo("Europe/Warsaw")).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(value)[:16]


async def mentor_form_rows(
    actor_id: str,
    province: str = "",
    season: str = "",
    *,
    all_provinces: bool = False,
) -> List[Dict[str, Any]]:
    """Opublikowane oceny mentora w kształcie wiersza `delegate_evaluations`.

    Z okręgiem - wszystkie oceny okręgu (dostęp sprawdza wołający). Bez okręgu -
    tylko oceny par, w których `actor_id` sędziował (jak „moje" arkusze delegata).
    """
    query = select(evaluations).where(evaluations.c.status == "published").where(evaluations.c.published_json.isnot(None))
    if province:
        query = query.where(evaluations.c.province.in_(spellings(province_display(province))))
    if season:
        query = query.where(evaluations.c.season == season)
    rows = [dict(r) for r in await database.fetch_all(query.order_by(evaluations.c.match_at.desc()))]
    if not province and not all_provinces:
        rows = [r for r in rows if actor_id in r["pair_key"].split("|")]
    ids = set()
    for r in rows:
        ids |= {r["author_id"], *json_list(r["co_author_ids"]), *r["pair_key"].split("|")}
    names = await people(ids)
    out = []
    for r in rows:
        pair = r["pair_key"].split("|")
        authors = [r["author_id"], *json_list(r["co_author_ids"])]
        author_names = " + ".join(names[a]["full_name"] for a in authors if a in names)
        out.append(
            {
                "id": f"mentor:{r['id']}",
                "kind": "mentor",
                "match_id": r["match_id"],
                "season": r["season"] or "",
                "province": r["province"],
                "match_number": r["match_number"] or "",
                "match_date": _match_date(r["match_at"]),
                "referee_ids": pair,
                "referee_names": [names[p]["full_name"] for p in pair if p in names],
                "delegate_name": author_names,
                "mentor_names": [names[a]["full_name"] for a in authors if a in names],
                "source_kind": "mentor",
                "evaluation_json": delegate_shape(_loads(r["published_json"])),
                "points": r["points"],
                "letter": r["letter"],
                "published_at": r["published_at"],
            }
        )
    return out


async def notify_pair(match_id: str, pair: tuple, authors: List[str], match_code: str, letter: Optional[str], points: Optional[float]) -> None:
    """Push do ocenianej pary po PIERWSZEJ publikacji. Awaria wysyłki nie cofa zapisu.

    Ładunek `type: "match_change"` + numer i `IdZawody` otwiera szczegóły tego
    meczu także w starszych wersjach aplikacji - tam para widzi kartę ocen.
    """
    try:
        from app.push.push import send_push_to_judges

        names = await people(authors)
        who = " i ".join(names[a]["full_name"] for a in authors if a in names) or "Mentor"
        score = f" · {letter} ({points:.2f})".replace(".", ",") if letter and points is not None else ""
        await send_push_to_judges(
            sorted(set(pair)),
            "Ocena mentora",
            f"{who} ocenił{'i' if len(authors) > 1 else ''} Wasz mecz {match_code}{score}".strip(),
            {"type": "match_change", "kind": "mentor_evaluation", "matchId": str(match_id), "matchNumber": match_code},
        )
    except Exception:  # noqa: BLE001
        import logging

        logging.getLogger(__name__).warning("ocena mentora: powiadomienie nieudane", exc_info=True)
