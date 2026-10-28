"""Panel "Mentor" - usuwanie nagrania meczu do kosza na 30 dni, przywracanie, sprzątanie, link z Discorda."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.mentor_evaluation_request_rules import normalized_video_url
from tests.mentor_panel_support import COMMITTEE, JUDGES, MENTOR, PAIR, STRANGER, Env


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


async def code_of(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.status_code
    raise AssertionError("oczekiwano odmowy")


async def table(env, name, key="id", value="deleted_at"):
    return {r[key]: r[value] for r in await env.db.fetch_all(select(env.T[name]))}


async def seed_trash_case(env):
    """v1 (m1): klip wirtualny c1 z watkiem, klip z MP4 c2, komentarze zakotwiczone w v1 i jeden bez kotwicy."""
    now = datetime.now(timezone.utc)
    await env.ins("mentor_clips", id="c1", pair_id=PAIR, match_id="m1", video_id="v1", start_s=10, end_s=20, author_id=JUDGES[0])
    await env.ins("mentor_clips", id="c2", pair_id=PAIR, match_id="m1", video_id="v1", start_s=30, end_s=40, author_id=JUDGES[0],
                  mp4_status="ready", mp4_key="k/c2.mp4")
    await env.ins("mentor_clip_assets", id="a2", clip_id="c2", revision=1, status="ready", storage_key="k/c2.mp4")
    await env.ins("mentor_threads", id="t1", pair_id=PAIR, target_kind="clip", target_id="c1", match_id="m1", created_by=JUDGES[0])
    await env.ins("mentor_comments", id="k1", thread_id="t1", author_id=JUDGES[0], body="Klip", created_at=now)
    await env.ins("mentor_threads", id="t2", pair_id=PAIR, target_kind="match", target_id="m1", match_id="m1", created_by=MENTOR)
    await env.ins("mentor_comments", id="k2", thread_id="t2", author_id=MENTOR, body="Z kotwica", video_id="v1", video_s=50, created_at=now)
    await env.ins("mentor_threads", id="t3", pair_id=PAIR, target_kind="match", target_id="m1", match_id="m1", created_by=MENTOR)
    await env.ins("mentor_comments", id="k3", thread_id="t3", author_id=MENTOR, body="Zostaje", created_at=now)
    await env.ins("mentor_comments", id="k4", thread_id="t3", author_id=MENTOR, body="Tez kotwica", video_id="v1", video_s=60, created_at=now)
    await env.ins("mentor_threads", id="t4", pair_id=PAIR, target_kind="clip", target_id="c2", match_id="m1", created_by=JUDGES[0])
    await env.ins("mentor_comments", id="k5", thread_id="t4", author_id=JUDGES[0], body="Przy MP4", video_id="v1", video_s=35, created_at=now)


def test_ostrzezenie_liczy_skutki(env):
    async def go():
        await seed_trash_case(env)
        pair = await env.actor(JUDGES[0])
        return await env.media.video_delete_impact(PAIR, "m1", "v1", pair)

    got = env.run(go)
    assert (got["virtual_clips"], got["kept_clips"], got["comments"], got["threads"]) == (1, 1, 3, 2)
    assert got["restorable"] and got["retention_days"] == 30


def test_usuniecie_i_przywrocenie(env):
    async def go():
        await seed_trash_case(env)
        pair = await env.actor(JUDGES[0])
        out = await env.media.delete_video(PAIR, "m1", "v1", pair)
        room = await env.panel.match_room(PAIR, "m1", pair)
        clips = await table(env, "mentor_clips")
        threads = set(await table(env, "mentor_threads", value="id"))
        comments = await table(env, "mentor_comments")
        again = await code_of(env.media.update_video(PAIR, "m1", "v1", env.media.VideoPatch(title="x"), pair))
        back = await env.media.restore_video(PAIR, "m1", "v1", pair)
        room2 = await env.panel.match_room(PAIR, "m1", pair)
        after = (set(await table(env, "mentor_threads", value="id")), await table(env, "mentor_comments"), await table(env, "mentor_clips"))
        twice = await code_of(env.media.restore_video(PAIR, "m1", "v1", pair))
        return out, room, clips, threads, comments, again, back, room2, after, twice

    out, room, clips, threads, comments, again, back, room2, after, twice = env.run(go)
    assert out["trashed"] and out["virtual_clips"] == 1 and out["kept_clips"] == 1
    assert room["videos"] == [] and [v["id"] for v in room["trashed_videos"]] == ["v1"]
    assert room["trashed_videos"][0]["kept_clips"] == 1
    assert [c["id"] for c in room["clips"]] == []  # klip z MP4 jedzie do Biblioteki, nie do pokoju
    assert clips["c1"] is not None and clips["c2"] is None
    assert threads == {"t3", "t4"}  # t1 i t2 opustoszaly, t3 ma jeszcze komentarz bez kotwicy
    assert comments["k1"] and comments["k2"] and comments["k4"] and comments["k3"] is None and comments["k5"] is None
    assert again == 404
    assert back["clips"] == 1 and back["video"]["id"] == "v1"
    assert [v["id"] for v in room2["videos"]] == ["v1"] and room2["trashed_videos"] == []
    assert after[0] == {"t1", "t2", "t3", "t4"}
    assert all(v is None for v in after[1].values()) and all(v is None for v in after[2].values())
    assert twice == 409


def test_prawa_do_usuwania(env):
    async def go():
        await seed_trash_case(env)
        res = {}
        for name, who in (("obcy", STRANGER), ("komisja", COMMITTEE)):
            actor = await env.actor(who)
            res[name] = await code_of(env.media.delete_video(PAIR, "m1", "v1", actor))
        mentor = await env.actor(MENTOR)
        res["mentor"] = (await env.media.delete_video(PAIR, "m1", "v1", mentor))["trashed"]
        return res

    got = env.run(go)
    assert got["obcy"] in (403, 404) and got["komisja"] == 403
    assert got["mentor"] is True


def test_dodanie_tego_samego_adresu_przywraca(env):
    async def go():
        await seed_trash_case(env)
        pair = await env.actor(JUDGES[0])
        await env.media.delete_video(PAIR, "m1", "v1", pair)
        from app.mentor_evaluations import insert_link_video

        row, created = await insert_link_video("m1", "|".join(sorted(JUDGES)), "https://youtu.be/abcdefghijk", JUDGES[0])
        return row["id"], created, row["deleted_at"], await table(env, "mentor_clips")

    vid, created, deleted_at, clips = env.run(go)
    assert vid == "v1" and created and deleted_at is None and clips["c1"] is None


def test_sprzatanie_po_30_dniach(env):
    async def go():
        await seed_trash_case(env)
        pair = await env.actor(JUDGES[0])
        await env.media.delete_video(PAIR, "m1", "v1", pair)
        soon = await env.media.retention_once(datetime.now(timezone.utc) + timedelta(days=29))
        left = await env.db.fetch_one(select(env.T["mentor_match_videos"]).where(env.T["mentor_match_videos"].c.id == "v1"))
        late = await env.media.retention_once(datetime.now(timezone.utc) + timedelta(days=31))
        tomb = await env.db.fetch_one(select(env.T["mentor_match_videos"]).where(env.T["mentor_match_videos"].c.id == "v1"))
        room = await env.panel.match_room(PAIR, "m1", pair)
        code = await code_of(env.media.restore_video(PAIR, "m1", "v1", pair))
        return soon, left, late, tomb, room, code

    soon, left, late, tomb, room, code = env.run(go)
    assert "trash" not in soon and left is not None
    assert late["trash"] == 1 and tomb is not None  # nagrobek: trzyma klip z MP4
    assert room["trashed_videos"] == [] and code == 409


def test_usun_na_zawsze_z_kosza(env):
    async def go():
        await seed_trash_case(env)
        pair = await env.actor(JUDGES[0])
        not_in_trash = await code_of(env.media.purge_video(PAIR, "m1", "v1", pair))  # jeszcze nie w koszu
        await env.media.delete_video(PAIR, "m1", "v1", pair)
        komisja = await code_of(env.media.purge_video(PAIR, "m1", "v1", await env.actor(COMMITTEE)))
        out = await env.media.purge_video(PAIR, "m1", "v1", pair)
        tomb = await env.db.fetch_one(select(env.T["mentor_match_videos"]).where(env.T["mentor_match_videos"].c.id == "v1"))
        room = await env.panel.match_room(PAIR, "m1", pair)
        again = await code_of(env.media.purge_video(PAIR, "m1", "v1", pair))
        return not_in_trash, komisja, out, tomb, room, again

    not_in_trash, komisja, out, tomb, room, again = env.run(go)
    assert not_in_trash == 409 and komisja == 403 and again == 409
    assert out["purged"] and out["tombstone"] and (out["virtual_clips"], out["kept_clips"], out["comments"]) == (1, 1, 3)
    assert tomb is not None and room["trashed_videos"] == []  # nagrobek trzyma klip z MP4, kosz pusty


def test_discord_to_nie_nagranie():
    for url in ("https://discord.com/channels/1/2/3", "https://discordapp.com/channels/1/2", "https://discord.gg/abc"):
        with pytest.raises(ValueError, match="Discordzie"):
            normalized_video_url(url)
    assert normalized_video_url("https://youtu.be/abcdefghijk")
