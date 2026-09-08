"""Fan-out into the existing durable match notification queue."""
from sqlalchemy import select, update
from datetime import datetime, timezone, timedelta
from sqlalchemy.dialects.postgresql import insert as pg_insert
from app.db import (database, mentoring_pairs as pairs, mentoring_assignments as assignments,
    province_matches, province_match_events, province_match_notifications, push_tokens,
    mentoring_members, province_judges)
from app.mentoring_rules import pair_matches, season_bounds, json_value


async def monitored_judges(province):
    rows = await database.fetch_all(select(mentoring_members.c.judge_id).select_from(mentoring_members.join(province_judges, mentoring_members.c.judge_id == province_judges.c.judge_id)).where(province_judges.c.province == province))
    return [r["judge_id"] for r in rows]


async def baseline_seen(judge_id):
    moment = datetime.now(timezone.utc)
    row = await database.fetch_one(select(mentoring_members).where(mentoring_members.c.judge_id == judge_id))
    if not row:
        return
    await database.execute(update(mentoring_members).where(mentoring_members.c.judge_id == judge_id).values(seen_at=moment))
    unseen = await database.fetch_one(select(mentoring_members).where(mentoring_members.c.pair_id == row["pair_id"]).where(mentoring_members.c.seen_at.is_(None)))
    if not unseen:
        await database.execute(update(pairs).where(pairs.c.id == row["pair_id"]).where(pairs.c.baseline_at.is_(None)).values(baseline_at=moment))


async def enqueue_recent_assignments(province, match_id):
    # Assignment events can precede the detailed match snapshot in the existing monitor.
    rows = await database.fetch_all(select(province_match_events.c.id).where(province_match_events.c.province == province).where(province_match_events.c.match_id == match_id).where(province_match_events.c.created_at >= datetime.now(timezone.utc) - timedelta(minutes=20)))
    for row in rows:
        await enqueue(row["id"])


async def enqueue(event_id, previous_state=None):
    event = await database.fetch_one(select(province_match_events).where(province_match_events.c.id == event_id))
    if not event:
        return
    previous_refs = json_value(event["data_json"], {}).get("mentoring_previous_refs") or []
    if previous_state is None and len(previous_refs) == 2:
        previous_state = dict(zip(("NrSedzia_pierwszy", "NrSedzia_drugi"), previous_refs))
    match = await database.fetch_one(select(province_matches).where(province_matches.c.province == event["province"]).where(province_matches.c.match_id == event["match_id"]))
    start, end = season_bounds()
    if not match or not match["match_at"] or not start <= match["match_at"] < end:
        return
    # Never notify about a past fixture when a new relationship is created.
    if match["match_at"] < event["created_at"]:
        return
    state = json_value(match["state_json"], {})
    links = await database.fetch_all(select(pairs.c.id, pairs.c.judge_ids, assignments.c.mentor_id).select_from(pairs.join(assignments, pairs.c.id == assignments.c.pair_id)).where(pairs.c.ended_at.is_(None)).where(pairs.c.baseline_at < event["created_at"]).where(assignments.c.ended_at.is_(None)).where(assignments.c.notify.is_(True)).where(assignments.c.started_at < event["created_at"]))
    recipients = {}
    for link in links:
        if not (pair_matches(link["judge_ids"], state) or pair_matches(link["judge_ids"], previous_state or {})):
            continue
        # Native assignment notification wins; never send a second mentor copy.
        crew_ids = {str(state.get(k) or "") for k in ("NrSedzia_pierwszy", "NrSedzia_drugi", "NrSedzia_sekretarz", "NrSedzia_czas", "NrSedzia_delegat", "NrSedzia_delegat2")}
        if link["mentor_id"] in json_value(event["target_judge_ids"], []) or link["mentor_id"] in crew_ids:
            continue
        recipients.setdefault(link["mentor_id"], []).append(link["id"])
    if not recipients:
        return
    devices = await database.fetch_all(select(push_tokens).where(push_tokens.c.judge_id.in_(recipients)).where(push_tokens.c.app_variant == "baza"))
    from app.province_match_monitor import _prefs_allow
    for device in devices:
        data = {**json_value(event["data_json"], {}), "kind": "mentoring_match_change", "mentoring_pair_ids": recipients[device["judge_id"]], "mentoring_mentor_id": device["judge_id"], "judgeId": device["judge_id"], "mentoring_event_at": event["created_at"].isoformat()}
        await database.execute(pg_insert(province_match_notifications).values(event_id=event_id, installation_id=device["installation_id"], judge_id=device["judge_id"], title="Podopieczni · " + event["title"], body=event["body"], data_json=data, status="pending" if _prefs_allow(device["notification_prefs"], event["event_type"]) else "suppressed").on_conflict_do_nothing(constraint="uq_province_match_notification_event_installation"))


async def delivery_allowed(data, token_row):
    data = json_value(data, {})
    if data.get("kind") != "mentoring_match_change":
        return True
    mentor_id = data.get("mentoring_mentor_id")
    if not token_row or token_row["judge_id"] != mentor_id:
        return False
    try:
        event_at = datetime.fromisoformat(data["mentoring_event_at"])
    except (KeyError, ValueError, TypeError):
        return False
    return bool(await database.fetch_one(select(assignments.c.pair_id).select_from(assignments.join(pairs, pairs.c.id == assignments.c.pair_id)).where(assignments.c.pair_id.in_(data.get("mentoring_pair_ids") or [])).where(assignments.c.mentor_id == mentor_id).where(assignments.c.started_at < event_at).where(assignments.c.ended_at.is_(None)).where(assignments.c.notify.is_(True)).where(pairs.c.ended_at.is_(None))))
