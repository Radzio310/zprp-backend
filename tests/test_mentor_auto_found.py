"""Automat nagrań w dniu meczu: próby (godziny, zatrzymanie po pewnym, brak dubli), próg pewności, sugestie, trasy i push.
Szukanie podmieniane atrapą (`searcher`); jedna próba z prawdziwym `search_card` na atrapie connectora."""

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import HTTPException, Response
from starlette.requests import Request

from tests.mentor_panel_support import JUDGES, MENTOR, PAIR, STRANGER, Env
from tests.test_mentor_bastion_search import Meczoteka, fresh

A, B = JUDGES
UTC = timezone.utc
CODE = "IMB/49"


def at(minutes):
    return timedelta(minutes=minutes)


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    for k, v in {"BASTION_ENABLED": "true", "BASTION_DEFAULT_ENABLED": "true", "BASTION_PERSONAL_ENABLED": "true",
                 "BASTION_STATUS_CACHE_S": "0", "BASTION_CONNECTOR_URL": "http://connector", "BASTION_CONNECTOR_TOKEN": "t" * 40}.items():
        monkeypatch.setenv(k, v)
    e.search = fresh(monkeypatch)
    e.fake = Meczoteka()
    e.client = e.bastion_client.ConnectorClient("http://connector", "t" * 40, transport=httpx.MockTransport(e.fake.handler),
                                                breaker=e.bastion_client.Breaker(threshold=99))
    monkeypatch.setattr(e.bastion_client, "get_client", lambda: e.client)

    async def no_preview(url):
        return {}

    async def no_stream(url):
        return None

    import app.link_preview as lp
    import app.mentor_evaluations as me

    monkeypatch.setattr(lp, "preview_or_instant", no_preview)
    monkeypatch.setattr(me, "_stream_start_or_none", no_stream)
    e.mp = monkeypatch
    e.pushes = []

    async def fake_push(row):
        e.pushes.append((row["match_id"], row["state"]))
        return True

    monkeypatch.setattr(e.auto_found, "send_push", fake_push)

    async def no_sleep(_s):
        return None

    monkeypatch.setattr(e.auto_found.asyncio, "sleep", no_sleep)
    return e


async def seed_match(env, match_id="m9", code=CODE):
    """Mecz pary rozpoczęty 3 h temu (czas polski), żeby czasy próbne nie wybiegały poza prawdziwy zegar."""
    from zoneinfo import ZoneInfo

    local = (datetime.now(ZoneInfo("Europe/Warsaw")) - timedelta(hours=3)).replace(minute=7, second=0, microsecond=0, tzinfo=None)
    await env.ins("zprp_public_matches", match_id=match_id, season_id="S1", competition_id="K1", competition_name="I liga mężczyzn",
                  match_code=code, home_team_name="SPR Gliwice", away_team_name="KS Opole", home_club_id="c1",
                  scheduled_at=local, referee_1_id=A, referee_2_id=B, source_hash="h", source_json={})
    env.core._match_cache.clear()
    cards = await env.core.pair_match_cards([A, B])
    card = next(c for c in cards if c["match_id"] == match_id)
    return card, env.auto_rules.start_of(card), local


def bastion_entry(item, local, *, sure=True, conf=100, code=CODE, teams="both", day="same", home="SPR Gliwice", away="KS Opole",
                  hour=None, ccode=True):
    when = local if hour is None else local.replace(hour=hour, minute=0)
    return {"source": "bastion", "key": f"bastion:{item}", "confidence": conf, "sure": sure,
            "signals": {"code": ccode if code else None, "teams": teams, "date": day, "category": None},
            "title": f"{home} - {away}", "date": when.strftime("%Y-%m-%d %H:%M:%S"), "home": home, "away": away, "code": code,
            "thumbnail_url": None, "state": "video", "video_state": "video", "url": f"https://portal.handball-bastion.pl/game?bunny_item_id={item}",
            "ref": {"bunny_item_id": item, "game_id": None}}


def yt_entry(vid, local, *, conf=60, sure=False, teams="both", day="same", code=None):
    return {"source": "youtube", "key": f"yt:{vid}", "confidence": conf, "sure": sure,
            "signals": {"code": None, "teams": teams, "date": day}, "title": "Transmisja", "date": local.strftime("%Y-%m-%dT%H:%M:%S+01:00"),
            "match_day": local.date().isoformat(), "home": "SPR Gliwice", "away": "KS Opole", "code": code, "thumbnail_url": None,
            "official": False, "ref": {"video_id": vid, "url": f"https://www.youtube.com/watch?v={vid}"}, "url": f"https://www.youtube.com/watch?v={vid}"}


class Script:
    """Atrapa szukania: odpowiedzi z kolejki, licznik wywołań."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = 0

    async def __call__(self, card, pair):
        self.calls += 1
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        return {"entries": list(answer.get("entries", [])), "bastion_error": answer.get("error")}


async def actor_for(env, judge):
    async def decode(_request, _token):
        return {"judge_id": judge}

    env.mp.setattr(env.auth, "_decode_bearer", decode)
    r = Request({"type": "http", "method": "POST", "headers": [(b"authorization", b"Bearer x")], "query_string": b"", "path": "/"})
    return await env.auth.mentor_actor(r)


async def row_of(env, match_id="m9"):
    return await env.auto_found.get_row(PAIR, match_id)


# --- Reguły czyste ----------------------------------------------------------


def test_plan_hours_and_window(env):
    r = env.auto_rules
    t = datetime(2026, 10, 31, 14, 0, tzinfo=UTC)
    assert r.plan(t, t - at(1), [])["run"] is None
    assert r.plan(t, t, [])["run"] == 0
    assert r.plan(t, t + at(14), [])["run"] == 0
    p = r.plan(t, t + at(16), [])
    assert p["run"] is None and p["missed"] == [0] and p["finished"] is False
    assert r.plan(t, t + at(5), [0])["run"] is None
    assert r.plan(t, t + at(31), [0])["run"] == 1
    assert r.plan(t, t + at(120), [0, 1])["run"] == 2
    p = r.plan(t, t + at(136), [0, 1])
    assert p["run"] is None and p["missed"] == [2] and p["finished"] is True
    # restart po 40 min: próba startowa przepadła, ale +30 min jeszcze się liczy
    p = r.plan(t, t + at(40), [])
    assert p["missed"] == [0] and p["run"] == 1


def test_start_of_needs_a_time_and_next_attempt(env):
    r = env.auto_rules
    assert r.start_of({"scheduled_at": datetime(2026, 10, 30, 23, 0, tzinfo=UTC)}) is None  # 00:00 czasu polskiego = tylko dzień
    assert r.start_of({"scheduled_at": datetime(2026, 10, 31, 14, 0, tzinfo=UTC)}) == datetime(2026, 10, 31, 14, 0, tzinfo=UTC)
    t = datetime(2026, 10, 31, 14, 0, tzinfo=UTC)
    assert r.next_attempt(t, t - at(60), []) == t
    assert r.next_attempt(t, t + at(20), [0]) == t + at(30)
    assert r.next_attempt(t, t + at(200), [0, 1]) is None
    assert r.push_due(t, t + at(119)) is False and r.push_due(t, t + at(120)) is True


def test_auto_sure_threshold(env):
    r = env.auto_rules
    t = datetime(2026, 10, 31, 14, 0, tzinfo=UTC)  # 15:00 w Warszawie
    local = datetime(2026, 10, 31, 15, 0)
    assert r.auto_sure(bastion_entry(1, local), t) is True
    # bez kodu: obie drużyny + dzień + godzina w 90 min
    near = bastion_entry(2, local, sure=False, conf=80, code=None, ccode=None)
    assert r.auto_sure(near, t) is True
    far = bastion_entry(3, local, sure=False, conf=80, code=None, ccode=None, hour=9)
    assert r.auto_sure(far, t) is False
    one_team = bastion_entry(4, local, sure=False, conf=55, code=None, ccode=None, teams="one")
    assert r.auto_sure(one_team, t) is False
    # kod sprzeczny albo inna kategoria zabija pewność
    assert r.auto_sure(bastion_entry(5, local, sure=False, ccode=False), t) is False
    other = bastion_entry(6, local)
    other["signals"]["category"] = "diff"
    assert r.auto_sure(other, t) is False


def test_decide_adds_only_one_sure(env):
    from app import mentor_trybuna_rank as RK

    r = env.auto_rules
    t = datetime(2026, 10, 31, 14, 0, tzinfo=UTC)
    local = datetime(2026, 10, 31, 15, 0)
    sure = bastion_entry(1, local)
    yt = yt_entry("abc", local, conf=70, sure=True, code=CODE)
    weak = bastion_entry(9, local, sure=False, conf=50, code="XYZ/1", teams="one", ccode=False, home="Inni", away="Obcy")
    members = {e["key"]: e for e in (sure, yt, weak)}
    merged = RK.merge_ranked(list(members.values()))
    d = r.decide(merged, members, t)
    assert d["action"] == "add" and d["pick"]["source"] == "bastion"  # kaseta przed filmem, ten sam mecz = jeden kandydat
    # dwa różne pewne mecze = brak automatu, sugestie
    other = bastion_entry(2, local, code="ZZZ/2", home="A", away="B")
    members = {e["key"]: e for e in (sure, other)}
    d2 = r.decide(RK.merge_ranked(list(members.values())), members, t)
    assert d2["action"] == "suggest" and len(d2["groups"]) == 2
    # same słabe poniżej progu = nic
    junk = bastion_entry(7, local, sure=False, conf=30, code=None, ccode=None, teams="one", day="near")
    members = {junk["key"]: junk}
    assert r.decide(RK.merge_ranked([junk]), members, t)["action"] == "none"


def test_merge_candidates_dismissed_and_limit(env):
    r = env.auto_rules
    mk = lambda k, c: {"key": k, "confidence": c, "sure": False}  # noqa: E731
    out, fresh_flag = r.merge_candidates([mk("a", 50)], [mk("b", 60), mk("c", 55)], {"c"})
    assert [c["key"] for c in out] == ["b", "a"] and fresh_flag is True
    out2, fresh2 = r.merge_candidates(out, [mk("a", 52)], set())
    assert fresh2 is False and len(out2) == 2
    many, _ = r.merge_candidates([], [mk(str(i), i) for i in range(10)], set())
    assert len(many) == r.SUGGEST_MAX


# --- Pętla ------------------------------------------------------------------


def test_sure_hit_adds_video_and_stops_retrying(env):
    async def go():
        card, start, local = await seed_match(env)
        search = Script({"entries": [bastion_entry(777, local)]})
        counts = await env.auto_found.run_once(start + at(1), search)
        assert counts["attempts"] == 1 and counts["added"] == 1
        row = await row_of(env)
        assert row["state"] == "added" and row["finished"] is True
        videos = await env.db.fetch_all(env.T["mentor_match_videos"].select().where(env.T["mentor_match_videos"].c.match_id == "m9"))
        assert len(videos) == 1 and videos[0]["auto_added_json"] and "bastion" in videos[0]["auto_added_json"]
        # kolejne próby (start + 30 min, + 2 h) już nie szukają i nie dublują
        await env.auto_found.run_once(start + at(31), search)
        await env.auto_found.run_once(start + at(121), search)
        assert search.calls == 1
        videos = await env.db.fetch_all(env.T["mentor_match_videos"].select().where(env.T["mentor_match_videos"].c.match_id == "m9"))
        assert len(videos) == 1
        # nagranie w pokoju ma pieczątkę auto_added
        ctx = await env.core.pair_context(PAIR, await actor_for(env, A))
        listed, _ = await env.media.video_list(ctx, "m9")
        assert listed[0]["auto_added"]["source"] == "bastion" and listed[0]["auto_added"]["at"]

    env.run(go)


def test_attempts_at_start_30_and_120_and_no_double_runs(env):
    async def go():
        card, start, local = await seed_match(env)
        search = Script({"entries": []})
        await env.auto_found.run_once(start - at(5), search)
        assert search.calls == 0
        await env.auto_found.run_once(start + at(2), search)
        await env.auto_found.run_once(start + at(7), search)  # ta sama próba w oknie spóźnienia: bez dubla
        assert search.calls == 1
        await env.auto_found.run_once(start + at(20), search)  # między próbami: nic
        assert search.calls == 1
        await env.auto_found.run_once(start + at(32), search)
        await env.auto_found.run_once(start + at(80), search)
        assert search.calls == 2
        await env.auto_found.run_once(start + at(121), search)
        assert search.calls == 3
        row = await row_of(env)
        assert [a["slot"] for a in env.auto_found.attempts_of(row)] == [0, 1, 2]
        # po ostatniej próbie: koniec, brak znaleziska = none, bez pusha
        await env.auto_found.run_once(start + at(140), search)
        row = await row_of(env)
        assert row["state"] == "none" and row["finished"] is True and env.pushes == []

    env.run(go)


def test_missed_slots_are_recorded_after_restart(env):
    async def go():
        card, start, local = await seed_match(env)
        search = Script({"entries": []})
        await env.auto_found.run_once(start + at(40), search)  # serwer wstał po 40 minutach
        row = await row_of(env)
        results = {a["slot"]: a["result"] for a in env.auto_found.attempts_of(row)}
        assert results == {0: "missed", 1: "none"}

    env.run(go)


def test_suggestions_then_sure_hit_and_single_push_after_two_hours(env):
    async def go():
        card, start, local = await seed_match(env)
        weak = yt_entry("zzz", local, conf=60, teams="one")
        search = Script({"entries": [weak]}, {"entries": [weak, bastion_entry(5, local, sure=False, conf=70, code=None, ccode=None, teams="one")]},
                        {"entries": [bastion_entry(777, local)]})
        await env.auto_found.run_once(start + at(1), search)
        row = await row_of(env)
        assert row["state"] == "suggested" and len(env.auto_found.U.loads(row["candidates_json"], [])) == 1
        first_found = row["found_at"]
        await env.auto_found.run_once(start + at(31), search)
        row = await row_of(env)
        assert len(env.auto_found.U.loads(row["candidates_json"], [])) == 2 and row["found_at"] != first_found
        # w trakcie gry (przed start + 2 h) push nie wychodzi
        assert env.pushes == []
        await env.auto_found.run_once(start + at(121), search)
        row = await row_of(env)
        assert row["state"] == "added"
        assert env.pushes == [("m9", "added")]
        # push dokładnie raz
        await env.auto_found.run_once(start + at(125), search)
        await env.auto_found.run_once(start + at(300), search)
        assert env.pushes == [("m9", "added")]

    env.run(go)


def test_sure_early_pushes_only_after_two_hours(env):
    async def go():
        card, start, local = await seed_match(env)
        search = Script({"entries": [bastion_entry(777, local)]})
        await env.auto_found.run_once(start + at(1), search)
        await env.auto_found.run_once(start + at(60), search)
        assert env.pushes == []
        await env.auto_found.run_once(start + at(121), search)
        assert env.pushes == [("m9", "added")]

    env.run(go)


def test_suggested_only_gets_suggested_push(env):
    async def go():
        card, start, local = await seed_match(env)
        search = Script({"entries": [yt_entry("zzz", local, conf=60, teams="one")]})
        await env.auto_found.run_once(start + at(1), search)
        await env.auto_found.run_once(start + at(122), search)
        assert env.pushes == [("m9", "suggested")]

    env.run(go)


def test_transient_bastion_error_does_not_burn_the_attempt(env):
    async def go():
        card, start, local = await seed_match(env)
        search = Script({"entries": [], "error": "BASTION_RATE_LIMITED"})
        counts = await env.auto_found.run_once(start + at(1), search)
        assert counts["retry"] == 1 and await row_of(env) is None
        # ostatnie minuty okna: próba zużyta, błąd zapisany
        await env.auto_found.run_once(start + at(13), search)
        row = await row_of(env)
        assert [a["slot"] for a in env.auto_found.attempts_of(row)] == [0] and row["bastion_error"] == "BASTION_RATE_LIMITED"

    env.run(go)


def test_manual_video_or_disabled_panel_skips(env):
    async def go():
        card, start, local = await seed_match(env)
        await env.ins("mentor_match_videos", id="vm", match_id="m9", pair_key="|".join(sorted(JUDGES)), url="https://youtu.be/manual00001",
                      normalized_url="https://youtu.be/manual00001", provider="youtube", added_by=A, created_at=datetime.now(UTC), kind="link")
        search = Script({"entries": [bastion_entry(777, local)]})
        await env.auto_found.run_once(start + at(1), search)
        assert search.calls == 0
        await env.db.execute(env.T["mentor_match_videos"].delete().where(env.T["mentor_match_videos"].c.id == "vm"))
        await env.db.execute(env.T["mentor_panels"].update().values(enabled=False))
        await env.auto_found.run_once(start + at(1), search)
        assert search.calls == 0

    env.run(go)


def test_match_without_time_is_skipped(env):
    async def go():
        await env.ins("zprp_public_matches", match_id="m8", season_id="S1", competition_id="K1", competition_name="I liga",
                      match_code="X/1", home_team_name="A", away_team_name="B", scheduled_at=datetime.now().replace(hour=0, minute=0, second=0, microsecond=0),
                      referee_1_id=A, referee_2_id=B, source_hash="h", source_json={})
        env.core._match_cache.clear()
        search = Script({"entries": []})
        await env.auto_found.run_once(datetime.now(UTC), search)
        assert search.calls == 0

    env.run(go)


# --- Prawdziwe szukanie (atrapa connectora) ---------------------------------


def test_search_card_uses_bastion_rank_and_reports_missing_session(env):
    async def go():
        card, start, local = await seed_match(env)
        day = local.date().isoformat()
        env.fake.games["default"] = (200, {"games": [
            {"bunny_item_id": 21, "code": CODE, "home": "SPR Gliwice", "away": "KS Opole", "date": f"{day} {local.strftime('%H:%M:%S')}"}],
            "total": 1, "has_more": False})
        pair = {"id": PAIR, "judge_ids": [A, B]}
        res = await env.auto_found.search_card(card, pair)
        assert res["bastion_error"] is None
        top = next(e for e in res["entries"] if e["source"] == "bastion")
        assert top["key"] == "bastion:21" and top["sure"] is True
        # pełny przebieg na prawdziwym szukaniu: pewna kaseta -> nagranie dodane samo
        counts = await env.auto_found.run_once(start + at(1))
        assert counts["added"] == 1
        # brak sesji Bastionu: szukanie nie pada, zapis bastion_error
        calls = len(env.fake.calls)
        await env.auto_found.search_card(card, pair)
        assert len(env.fake.calls) == calls  # te same zapytania stoją w pamięci wyników (10 min): nie wychodzą do portalu
        env.search.forget_search_cache()
        env.fake.games.clear()
        res = await env.auto_found.search_card(card, pair)
        assert res["bastion_error"] == "BASTION_AUTH_REQUIRED"

    env.run(go)


# --- Trasy ------------------------------------------------------------------


def test_routes_list_detail_seen_accept_dismiss(env):
    async def go():
        card, start, local = await seed_match(env)
        search = Script({"entries": [yt_entry("aaa", local, conf=60, teams="one"), bastion_entry(5, local, sure=False, conf=55, code=None, ccode=None, teams="one", home="Inni", away="Obcy")]})
        await env.auto_found.run_once(start + at(1), search)
        a_actor, b_actor = await actor_for(env, A), await actor_for(env, B)
        ctx = await env.core.pair_context(PAIR, a_actor)
        listed = next(c for c in await env.core.enrich_cards(ctx, await env.core.pair_match_cards(ctx["judge_ids"])) if c["match_id"] == "m9")
        assert listed["auto_found"]["state"] == "suggested" and listed["auto_found"]["unseen"] is True
        other = next(c for c in await env.core.enrich_cards(ctx, await env.core.pair_match_cards(ctx["judge_ids"])) if c["match_id"] == "m1")
        assert other["auto_found"] is None

        detail = await env.auto_found.get_auto_found(PAIR, "m9", Response(), a_actor)
        assert detail["state"] == "suggested" and len(detail["candidates"]) == 2 and detail["attempts"][0]["result"] == "suggested"
        assert detail["added"] is None and detail["bastion_error"] is None
        # "widziałem" jest per użytkownik
        resp = await env.auto_found.seen_auto_found(PAIR, "m9", a_actor)
        assert resp.status_code == 204
        assert (await env.auto_found.get_auto_found(PAIR, "m9", Response(), a_actor))["unseen"] is False
        assert (await env.auto_found.get_auto_found(PAIR, "m9", Response(), b_actor))["unseen"] is True
        # odrzucenie jednej, potem przyjęcie drugiej
        out = await env.auto_found.dismiss_auto_found(PAIR, "m9", env.auto_found.DismissBody(index=0), a_actor)
        assert out["state"] == "suggested" and len(out["candidates"]) == 1
        key = out["candidates"][0]["key"]
        got = await env.auto_found.accept_auto_found(PAIR, "m9", env.auto_found.AcceptBody(index=0), a_actor, None)
        assert got["video_id"]
        detail = await env.auto_found.get_auto_found(PAIR, "m9", Response(), a_actor)
        assert detail["state"] == "none" and detail["candidates"] == []
        vid = await env.db.fetch_one(env.T["mentor_match_videos"].select().where(env.T["mentor_match_videos"].c.id == got["video_id"]))
        assert vid["auto_added_json"] is None and key.startswith("bastion:")
        # po decyzji człowieka automat niczego już nie dokłada
        await env.auto_found.run_once(start + at(31), search)
        assert search.calls == 1

    env.run(go)


def test_routes_undo_moves_to_trash_and_back_to_suggestion(env):
    async def go():
        card, start, local = await seed_match(env)
        search = Script({"entries": [bastion_entry(777, local)]})
        await env.auto_found.run_once(start + at(1), search)
        actor = await actor_for(env, A)
        detail = await env.auto_found.get_auto_found(PAIR, "m9", Response(), actor)
        assert detail["state"] == "added" and detail["added"]["video_id"] and detail["added"]["source"] == "bastion"
        out = await env.auto_found.undo_auto_found(PAIR, "m9", actor)
        assert out["state"] == "suggested" and out["candidates"][0]["key"] == "bastion:777"
        video = await env.db.fetch_one(env.T["mentor_match_videos"].select().where(env.T["mentor_match_videos"].c.id == detail["added"]["video_id"]))
        assert video["deleted_at"] is not None
        # ponowne cofnięcie = 409
        with pytest.raises(HTTPException) as exc:
            await env.auto_found.undo_auto_found(PAIR, "m9", actor)
        assert exc.value.status_code == 409
        # przyjęcie kandydata przywraca nagranie z kosza (bez pieczątki)
        got = await env.auto_found.accept_auto_found(PAIR, "m9", env.auto_found.AcceptBody(index=0), actor, None)
        assert got["video_id"] == detail["added"]["video_id"]
        video = await env.db.fetch_one(env.T["mentor_match_videos"].select().where(env.T["mentor_match_videos"].c.id == got["video_id"]))
        assert video["deleted_at"] is None and video["auto_added_json"] is None

    env.run(go)


def test_manual_delete_of_auto_video_shows_suggestion_and_access(env):
    async def go():
        card, start, local = await seed_match(env)
        search = Script({"entries": [bastion_entry(777, local)]})
        await env.auto_found.run_once(start + at(1), search)
        actor = await actor_for(env, A)
        row = await row_of(env)
        vid = env.auto_found.U.loads(row["added_json"], {})["video_id"]
        await env.db.execute(env.T["mentor_match_videos"].update().where(env.T["mentor_match_videos"].c.id == vid).values(deleted_at=datetime.now(UTC)))
        detail = await env.auto_found.get_auto_found(PAIR, "m9", Response(), actor)
        assert detail["state"] == "suggested" and detail["added"] is None
        # obcy sędzia nie ma dostępu; mecz spoza pary = 404; brak wiersza = stan none
        stranger = await actor_for(env, STRANGER)
        with pytest.raises(HTTPException) as exc:
            await env.auto_found.get_auto_found(PAIR, "m9", Response(), stranger)
        assert exc.value.status_code == 403
        with pytest.raises(HTTPException) as exc:
            await env.auto_found.get_auto_found(PAIR, "nie-ma", Response(), actor)
        assert exc.value.status_code == 404
        assert (await env.auto_found.get_auto_found(PAIR, "m1", Response(), actor))["state"] == "none"
        with pytest.raises(HTTPException) as exc:
            await env.auto_found.accept_auto_found(PAIR, "m1", env.auto_found.AcceptBody(index=0), actor, None)
        assert exc.value.status_code == 404

    env.run(go)
