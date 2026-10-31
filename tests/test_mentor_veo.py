"""Nagrania Veo w Mentorze: rozpoznanie linku, stan (publiczne, prywatne, usunięte, 5xx), bezpieczeństwo adresów,
migracja providera, TTL i klipy MP4. Atrapa Veo na `httpx.MockTransport` - żadnego prawdziwego wywołania sieci."""

import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select, text

from app import mentor_veo_rules as V
from app.mentor_evaluation_tables import VEO_PROVIDER_MIGRATION
from tests.mentor_panel_support import PAIR
from tests.test_mentor_clip_download import A, PAIR_KEY, actor_for, add_clip, clip_row, d, failure, plan_of, seed  # noqa: F401

SLUG = "20261018-untitled-recording-2026-10-18_18-58-20-vbbdc38e"
LINK = f"https://app.veo.co/matches/{SLUG}/"
CANON = f"https://app.veo.co/matches/{SLUG}"
MP4 = "https://c.veocdn.com/abc/standard/video.mp4"
MP4_NEW = "https://c.veocdn.com/zzz/standard/video.mp4"
SYNC_VEO = {"match_start_s": 60, "second_half_s": 3000}


def match_json(**over):
    return {"title": "Wolsztyniak - MJO", "thumbnail": "https://c.veocdn.com/abc/thumb.jpg", "duration": "5400", "privacy": "public",
            "is_accessible": True, **over}


def videos_json(url=MP4):
    return [
        {"availability": "available", "render_type": "panorama", "mime_type": "video/mp4", "width": 3840, "height": 2160, "url": "https://c.veocdn.com/p/video.mp4"},
        {"availability": "available", "render_type": "standard", "mime_type": "video/mp4", "width": 1280, "height": 720, "url": "https://c.veocdn.com/h/video.mp4"},
        {"availability": "available", "render_type": "standard", "mime_type": "video/mp4", "width": 1920, "height": 1080, "url": url,
         "thumbnail": "https://c.veocdn.com/abc/vt.jpg"},
        {"availability": "available", "render_type": "standard", "mime_type": "video/mp4", "width": 3840, "height": 2160, "url": "https://c.veocdn.com/u/video.mp4"},
    ]


class FakeVeo:
    """Programowalna atrapa: odpowiedzi dla /matches/<slug>/ i /videos/, plik CDN i dziennik zapytań."""

    def __init__(self):
        self.match = (200, match_json())
        self.videos = (200, videos_json())
        self.cdn = (206, None)
        self.redirect_cdn = None
        self.calls = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, str(request.url), dict(request.headers).get("range")))
        host, path = request.url.host, request.url.path
        if host == "app.veo.co" and path.endswith("/videos/"):
            code, body = self.videos
        elif host == "app.veo.co":
            code, body = self.match
        elif host == "c.veocdn.com":
            if self.redirect_cdn:
                return httpx.Response(302, headers={"location": self.redirect_cdn})
            return httpx.Response(self.cdn[0], content=b"x")
        else:  # nic poza hostami Veo nie ma prawa się odezwać
            raise AssertionError(f"zapytanie do obcego hosta: {request.url}")
        if isinstance(body, str):
            return httpx.Response(code, content=body.encode(), headers={"location": body} if 300 <= code < 400 else {})
        return httpx.Response(code, json=body)

    def api_calls(self):
        return [c for c in self.calls if "app.veo.co/api" in c[1]]


@pytest.fixture
def v(d):  # noqa: F811
    fake = FakeVeo()
    d.fake = fake
    d.mp.setattr(d.veo, "_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(fake.handler), follow_redirects=False))
    return d


async def add_veo(e, url=LINK):
    actor = await actor_for(e)
    return await e.media.add_video(PAIR, "m1", e.media.VideoBody(url=url), actor)


async def veo_row(e, video_id="vv", state=None, provider="veo", url=CANON):
    await e.ins("mentor_match_videos", id=video_id, match_id="m1", pair_key=PAIR_KEY, url=url, normalized_url=url, provider=provider,
                added_by=A, created_at=datetime.now(timezone.utc), kind="link", sync_json=json.dumps(SYNC_VEO),
                veo_json=json.dumps(state) if state else None)


def ok_state(checked_ago_h=0.0, play=MP4):
    at = (datetime.now(timezone.utc) - timedelta(hours=checked_ago_h)).isoformat()
    return {"slug": SLUG, "status": "ok", "play_url": play, "checked_at": at, "attempt_at": at, "title": "Wolsztyniak", "duration_s": 5400}


# ─── Reguły czyste ──────────────────────────────────────────────────────────


def test_slug_scisly_wzorzec_i_host():
    assert V.parse_slug(LINK) == SLUG and V.parse_slug(CANON + "?utm=1") == SLUG
    assert V.canonical_url(SLUG) == CANON
    for bad in ("https://app.veo.co/matches/ab/", "https://app.veo.co/matches/../etc/passwd", "https://app.veo.co/matches/a b c d e f/",
                f"https://app.veo.co/matches/{SLUG}/extra", "https://evil.example/matches/" + SLUG, "https://app.veo.co.evil.example/matches/" + SLUG,
                f"https://user@app.veo.co/matches/{SLUG}", "https://app.veo.co/other/" + SLUG, "", None, "https://app.veo.co/matches/" + "a" * 130):
        assert V.parse_slug(bad) is None, bad
    with pytest.raises(ValueError):
        V.match_api_url("../x")


def test_adresy_api_i_pliku_tylko_z_hostow_veo():
    assert V.api_url_ok("https://app.veo.co/api/app/matches/x/") and not V.api_url_ok("http://app.veo.co/api") and not V.api_url_ok("https://c.veocdn.com/a")
    assert V.cdn_url_ok(MP4) and not V.cdn_url_ok("http://c.veocdn.com/a.mp4") and not V.cdn_url_ok("https://c.veocdn.com.evil.net/a.mp4")
    assert not V.cdn_url_ok("https://evil.example/c.veocdn.com/a.mp4") and not V.cdn_url_ok("https://u@c.veocdn.com/a.mp4")


def test_parser_wybiera_1080p_standard_i_znosi_braki_pol():
    got = V.parse_videos(videos_json())
    assert got["play_url"] == MP4 and got["height"] == 1080
    assert V.parse_videos([{"url": MP4}])["play_url"] == MP4  # tylko url
    assert V.parse_videos({"results": videos_json()})["play_url"] == MP4
    assert V.parse_videos([{"url": "https://c.veocdn.com/a/v.mp4", "height": 2160}, {"url": "https://c.veocdn.com/b/v.mp4", "height": 1440}])["play_url"].startswith("https://c.veocdn.com/b")
    for junk in (None, "x", 5, {}, [None, 1, "a"], [{"url": 5}], [{"url": "https://evil.example/v.mp4"}], [{"url": MP4, "mime_type": "video/webm"}]):
        assert V.parse_videos(junk)["play_url"] is None
    assert V.parse_videos([{"availability": "processing", "url": MP4}])["processing"] is True
    info = V.parse_match({"duration": "abc", "thumbnail": 5, "title": None})
    assert info["duration_s"] is None and info["thumbnail_url"] is None and info["accessible"] is None and V.parse_match(None)["title"] is None


def test_klasyfikacja_stanow_i_blad_nie_zmienia_dobrego_stanu():
    ok = V.classify(200, match_json(), 200, videos_json())
    assert ok["status"] == "ok" and ok["play_url"] == MP4 and ok["duration_s"] == 5400
    assert V.classify(404, None, None, None)["status"] == "gone"
    assert V.classify(403, None, None, None)["status"] == "private" and V.classify(401, None, None, None)["status"] == "private"
    assert V.classify(200, match_json(is_accessible=False), 200, [])["status"] == "private"
    assert V.classify(200, match_json(privacy="private"), 200, [])["status"] == "private"
    assert V.classify(200, match_json(), 404, None)["status"] == "gone"
    assert V.classify(200, match_json(), 200, [{"availability": "processing", "url": MP4}])["status"] == "processing"
    for res in (V.classify(503, None, None, None), V.classify(None, None, None, None), V.classify(200, "zly", 200, []),
                V.classify(200, match_json(), 502, None), V.classify(200, match_json(), None, None), V.classify(429, None, None, None)):
        assert res["kind"] == "error"
    now = datetime.now(timezone.utc)
    good = V.merge_state(None, ok, now, SLUG)
    kept = V.merge_state(good, V.classify(503, None, None, None), now + timedelta(hours=7), SLUG)
    assert kept["status"] == "ok" and kept["play_url"] == MP4 and kept["checked_at"] == good["checked_at"]
    first = V.merge_state(None, {"kind": "error", "status": "unavailable"}, now, SLUG)
    assert first["status"] == "unavailable" and first["checked_at"] is None


def test_ttl_i_odstep_miedzy_probami():
    now = datetime.now(timezone.utc)
    iso = lambda delta: (now - delta).isoformat()  # noqa: E731
    assert V.needs_refresh(None, now) and V.needs_refresh({}, now)
    assert not V.needs_refresh({"status": "ok", "checked_at": iso(timedelta(hours=5, minutes=59))}, now)
    assert V.needs_refresh({"status": "ok", "checked_at": iso(timedelta(hours=6, minutes=1))}, now)
    assert not V.needs_refresh({"status": "ok", "checked_at": iso(timedelta(hours=7)), "attempt_at": iso(timedelta(minutes=2))}, now)
    assert V.needs_refresh({"status": "ok", "checked_at": iso(timedelta(hours=7)), "attempt_at": iso(timedelta(minutes=6))}, now)


# ─── Dodanie linku i odczyt ─────────────────────────────────────────────────


def test_dodanie_linku_veo_daje_provider_veo_i_odtwarzalny_obiekt(v):
    async def go():
        one = await add_veo(v)
        two = await add_veo(v, "http://app.veo.co/matches/" + SLUG + "/?x=1")  # ten sam mecz: jeden kafel
        return one, two

    one, two = v.run(go)
    assert one["id"] == two["id"] and one["url"] == CANON
    assert one["provider"] == "veo" and one["kind"] == "link" and one["playable"] is True
    assert one["play_url"] == MP4 and one["veo_status"] == "ok" and one["veo_checked_at"]
    assert one["thumbnail_url"] == "https://c.veocdn.com/abc/thumb.jpg" and one["duration_s"] == 5400 and one["title"] == "Wolsztyniak - MJO"
    assert one["veo_message"] is None
    assert len(v.fake.api_calls()) == 2  # drugie dodanie nie woła Veo (zapis świeży)


def test_lista_nagran_czyta_zapis_i_nie_woła_veo_w_ttl(v):
    async def go():
        await veo_row(v, state=ok_state(1))
        actor = await actor_for(v)
        ctx = await v.core.pair_context(PAIR, actor)
        shaped, _ = await v.media.video_list(ctx, "m1")
        return shaped

    shaped = v.run(go)
    got = next(x for x in shaped if x["id"] == "vv")
    assert got["provider"] == "veo" and got["play_url"] == MP4 and got["playable"] is True and v.fake.calls == []
    yt = next(x for x in shaped if x["id"] == "v1")
    assert yt["provider"] == "youtube" and yt["veo_status"] is None and yt["play_url"] is None


def test_po_ttl_lista_oddaje_zapis_od_razu_a_odswiezenie_idzie_w_tle(v):
    v.fake.videos = (200, videos_json(MP4_NEW))

    async def go():
        await veo_row(v, state=ok_state(7))
        actor = await actor_for(v)
        ctx = await v.core.pair_context(PAIR, actor)
        shaped, _ = await v.media.video_list(ctx, "m1")
        immediately = next(x for x in shaped if x["id"] == "vv")["play_url"]
        for _ in range(50):
            await asyncio.sleep(0.02)
            if v.fake.api_calls():
                break
        await asyncio.sleep(0.1)
        again, _ = await v.media.video_list(ctx, "m1")
        return immediately, next(x for x in again if x["id"] == "vv")["play_url"]

    immediately, later = v.run(go)
    assert immediately == MP4 and later == MP4_NEW


def test_stan_prywatny_usuniety_i_blad_5xx(v):
    counter = iter(range(100))

    async def one(match, videos=(200, [])):
        v.fake.match, v.fake.videos = match, videos
        return await add_veo(v, f"https://app.veo.co/matches/nagranie-testowe-{next(counter):04d}/")

    async def go():
        out = {}
        out["403"] = await one((403, {}))
        out["404"] = await one((404, {}))
        out["priv"] = await one((200, match_json(is_accessible=False)))
        out["privacy"] = await one((200, match_json(privacy="private")))
        out["5xx"] = await one((503, {}))
        return out

    got = v.run(go)
    assert got["403"]["veo_status"] == "private" and got["403"]["playable"] is False and got["403"]["play_url"] is None
    assert "prywatne" in got["403"]["veo_message"]
    assert got["404"]["veo_status"] == "gone" and "usunięte" in got["404"]["veo_message"]
    assert got["priv"]["veo_status"] == "private" and got["privacy"]["veo_status"] == "private"
    assert got["5xx"]["veo_status"] == "unavailable" and got["5xx"]["veo_checked_at"] is None and got["5xx"]["provider"] == "veo"


def test_blad_sieci_i_5xx_nie_zmieniaja_dobrego_stanu_na_gone(v):
    async def go():
        await veo_row(v, state=ok_state(8))
        row = await v.core.one(select(v.T["mentor_match_videos"]).where(v.T["mentor_match_videos"].c.id == "vv"))
        out = []
        for scenario in ((503, {}), (500, {}), (200, "zle")):
            v.fake.match = scenario
            row = await v.veo.check({**row, "veo_json": row["veo_json"]})
            out.append(json.loads(row["veo_json"]))
        # sieć: wyjątek transportu
        def boom(request):
            raise httpx.ConnectError("nie ma sieci")

        v.mp.setattr(v.veo, "_client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(boom)))
        row = await v.veo.check(row)
        out.append(json.loads(row["veo_json"]))
        return out

    for state in v.run(go):
        assert state["status"] == "ok" and state["play_url"] == MP4
    # po prawdziwym 404 dopiero gone


def test_404_po_dobrym_stanie_to_gone(v):
    async def go():
        await veo_row(v, state=ok_state(8))
        v.fake.match = (404, {})
        row = await v.core.one(select(v.T["mentor_match_videos"]).where(v.T["mentor_match_videos"].c.id == "vv"))
        return json.loads((await v.veo.check(row))["veo_json"])

    state = v.run(go)
    assert state["status"] == "gone" and state["play_url"] is None


def test_zly_slug_nie_jest_veo_i_nie_wola_sieci(v):
    async def go():
        a = await add_veo(v, "https://app.veo.co/matches/ab/")
        b = await add_veo(v, "https://app.veo.co/matches/../../admin/")
        c = await add_veo(v, "https://app.veo.co.evil.example/matches/" + SLUG)
        return a, b, c

    a, b, c = v.run(go)
    assert {x["provider"] for x in (a, b, c)} == {"video"} and all(x["veo_status"] is None for x in (a, b, c))
    assert v.fake.calls == []


def test_przekierowanie_api_na_obca_domene_jest_odrzucone(v):
    v.fake.match = (302, "https://evil.example/steal")

    async def go():
        return await add_veo(v)

    got = v.run(go)
    assert got["veo_status"] == "unavailable" and got["playable"] is False
    assert all("evil.example" not in c[1] for c in v.fake.calls)


def test_obca_domena_pliku_nie_daje_play_url(v):
    v.fake.videos = (200, [{"availability": "available", "render_type": "standard", "mime_type": "video/mp4", "height": 1080,
                            "url": "https://evil.example/video.mp4"}, {"render_type": "standard", "height": 1080, "url": "http://c.veocdn.com/a.mp4"}])

    async def go():
        return await add_veo(v)

    got = v.run(go)
    assert got["play_url"] is None and got["playable"] is False and got["veo_status"] == "unavailable"


def test_odpowiedz_json_ponad_limit_jest_bledem(v):
    v.fake.match = (200, {"title": "x" * (V.MAX_JSON_BYTES + 10)})

    async def go():
        return await add_veo(v)

    assert v.run(go)["veo_status"] == "unavailable"


# ─── Migracja ───────────────────────────────────────────────────────────────


def test_migracja_providera_jest_idempotentna(v):
    async def go():
        await veo_row(v, "m_video", provider="video", url="https://app.veo.co/matches/" + SLUG)
        await veo_row(v, "m_other", provider="other", url="https://app.veo.co/matches/inne-nagranie-12345678")
        await veo_row(v, "m_fake", provider="video", url="https://app.veo.co.evil.example/matches/" + SLUG)
        await veo_row(v, "m_yt", provider="youtube", url="https://youtu.be/zzzzzzzzzzz")
        import sqlalchemy

        engine = sqlalchemy.create_engine(v.url)  # produkcyjnie ta sama instrukcja idzie przez `conn.execute(text(...))`
        for _ in range(2):
            with engine.begin() as conn:
                conn.execute(text(VEO_PROVIDER_MIGRATION))
        rows = await v.core.rows(select(v.T["mentor_match_videos"]))
        return {r["id"]: r["provider"] for r in rows}

    got = v.run(go)
    assert got["m_video"] == "veo" and got["m_other"] == "veo" and got["m_fake"] == "video" and got["m_yt"] == "youtube"


def test_stary_zapis_other_przed_migracja_jest_odczytany_jako_veo(v):
    async def go():
        await veo_row(v, "old", provider="video", url=CANON)
        actor = await actor_for(v)
        ctx = await v.core.pair_context(PAIR, actor)
        shaped, _ = await v.media.video_list(ctx, "m1")
        return next(x for x in shaped if x["id"] == "old")

    got = v.run(go)
    assert got["provider"] == "veo" and got["play_url"] == MP4


# ─── Trasa „Sprawdź ponownie” ───────────────────────────────────────────────


def test_trasa_veo_check_odswieza_stan_i_pilnuje_szybkich_powtorek(v):
    async def go():
        await veo_row(v, state={**ok_state(8), "attempt_at": (datetime.now(timezone.utc) - timedelta(hours=8)).isoformat()})
        actor = await actor_for(v)
        v.fake.videos = (200, videos_json(MP4_NEW))
        first = await v.veo.veo_check(PAIR, "m1", "vv", actor)
        n = len(v.fake.api_calls())
        v.fake.match = (404, {})
        second = await v.veo.veo_check(PAIR, "m1", "vv", actor)  # w ciągu 10 s: zapis, bez wołania Veo
        return first, n, second, len(v.fake.api_calls()), await failure(v.veo.veo_check(PAIR, "m1", "v1", actor))

    first, n, second, n2, notveo = v.run(go)
    assert first["play_url"] == MP4_NEW and first["veo_status"] == "ok" and n == 2
    assert second["play_url"] == MP4_NEW and n2 == n
    assert notveo["code"] == "NOT_VEO"


# ─── Klipy ──────────────────────────────────────────────────────────────────


def test_klip_na_nagraniu_veo_tnie_z_odswiezonego_adresu_przez_range(v):
    async def go():
        await seed(v, file=False)
        await veo_row(v, state=ok_state(1))
        await add_clip(v, video_id="vv")
        actor = await actor_for(v)
        plan = await plan_of(v, actor=actor)
        v.fake.videos = (200, videos_json(MP4_NEW))  # adres zmienił się po zapisie
        ordered = await v.media.request_mp4("c1", actor)
        v.fake.videos = (200, videos_json("https://c.veocdn.com/last/standard/video.mp4"))
        worked = await v.media.process_next()
        return plan, ordered, worked, await clip_row(v)

    plan, ordered, worked, row = v.run(go)
    assert plan["can_download"] is True and plan["source"] == "veo" and plan["reason"] is None and plan["estimated_s"] >= 20
    assert ordered == {"mp4_status": "queued"} and worked is True and row["mp4_status"] == "ready"
    cut = v.runs[0]
    assert cut[0] == "ffmpeg" and cut.index("-ss") < cut.index("-i")
    assert cut[cut.index("-i") + 1] == "https://c.veocdn.com/last/standard/video.mp4"  # odświeżony tuż przed cięciem
    assert cut[cut.index("-ss") + 1] == "1500.00" and cut[cut.index("-t") + 1] == "20.00"
    assert cut[cut.index("-protocol_whitelist") + 1] == "https,tls,tcp,crypto" and cut.index("-protocol_whitelist") < cut.index("-ss")
    assert any(c[2] == "bytes=0-0" for c in v.fake.calls if "veocdn" in c[1])  # sprawdzenie łańcucha przekierowań przez Range
    assert v.puts and v.puts[0].endswith("c1.mp4")


def test_klip_z_youtube_przelicza_czas_na_nagranie_veo(v):
    async def go():
        await seed(v, file=False)
        await veo_row(v, state=ok_state(1))
        await add_clip(v)  # na YouTube: 1500-1520, gwizdki 100/2000 -> Veo 60/3000
        actor = await actor_for(v)
        plan = await plan_of(v, actor=actor)
        await v.media.request_mp4("c1", actor)
        await v.media.process_next()
        return plan, await clip_row(v)

    plan, row = v.run(go)
    assert plan["source"] == "veo" and plan["source_range"] == {"video_id": "vv", "start_s": 1460.0, "end_s": 1480.0}
    assert json.loads(row["mp4_source_json"])["video_id"] == "vv" and row["mp4_status"] == "ready"
    assert v.runs[0][v.runs[0].index("-ss") + 1] == "1460.00"


def test_klip_z_prywatnego_i_usunietego_veo_ma_polski_blad_bez_cieca(v):
    async def go():
        out = {}
        await seed(v, file=False)
        await veo_row(v, state=ok_state(1))
        await add_clip(v, video_id="vv")
        actor = await actor_for(v)
        for name, match in (("private", (403, {})), ("gone", (404, {}))):
            v.fake.match = match
            out[name] = await failure(v.media.request_mp4("c1", actor))
            # po zamówieniu stan jest zapisany: plan też zna powód
            out[name + "_plan"] = await plan_of(v, actor=actor)
            await v.db.execute(v.T["mentor_match_videos"].update().where(v.T["mentor_match_videos"].c.id == "vv")
                               .values(veo_json=json.dumps(ok_state(1))))
        return out

    got = v.run(go)
    assert got["private"]["code"] == "VEO_PRIVATE" and "prywatne" in got["private"]["message"]
    assert got["gone"]["code"] == "VEO_GONE" and "usunięte" in got["gone"]["message"]
    assert got["private_plan"]["reason"] == "VEO_PRIVATE" and got["private_plan"]["can_download"] is False and "prywatne" in got["private_plan"]["hint"]
    assert got["gone_plan"]["reason"] == "VEO_GONE"
    assert v.runs == []


def test_obca_domena_przy_przekierowaniu_pliku_przerywa_ciecie(v):
    async def go():
        await seed(v, file=False)
        await veo_row(v, state=ok_state(1))
        await add_clip(v, video_id="vv")
        actor = await actor_for(v)
        await v.media.request_mp4("c1", actor)
        v.fake.redirect_cdn = "https://evil.example/video.mp4"
        worked = await v.media.process_next()
        return worked, await clip_row(v)

    worked, row = v.run(go)
    assert worked is True and row["mp4_status"] == "failed" and v.runs == []
    assert all("evil.example" not in c[1] for c in v.fake.calls)


def test_komunikat_o_wideo_linku_wspomina_veo(v):
    async def go():
        await seed(v, file=False)
        await add_clip(v)
        return await plan_of(v)

    plan = v.run(go)
    assert plan["reason"] == "NO_SOURCE" and "Veo" in plan["hint"] and "wideo-linku" in plan["hint"]
