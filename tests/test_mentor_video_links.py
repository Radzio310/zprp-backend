"""Nagrania meczu dla mentorów: podgląd linku (SSRF), znaczniki, status prośby."""

from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import MetaData

from app import link_preview
from app.link_preview_rules import (
    TtlCache,
    UnsafeUrl,
    all_ips_allowed,
    check_url_shape,
    iso_duration_seconds,
    oembed_endpoint,
    parse_html_preview,
    provider_of,
    redirect_target,
    vimeo_id,
    youtube_id,
)
from app.mentor_evaluation_tables import MIGRATIONS, define_tables
from app.mentor_video_rules import (
    MAX_MARKERS,
    clean_markers,
    clean_sync,
    mentor_states,
    should_mark_read,
    timeline_from_blob,
)


# ─── Kształt adresu i adresy IP ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/film",
        "javascript:alert(1)",
        "http://localhost/admin",
        "http://127.0.0.1/",
        "http://10.0.0.5/x",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]/",
        "http://user:pass@example.com/",
        "http://example.com:8080/",
        "http://printer.local/",
    ],
)
def test_unsafe_urls_are_rejected_before_any_network(url):
    with pytest.raises(UnsafeUrl):
        check_url_shape(url)


def test_public_https_url_passes_shape_check():
    assert check_url_shape(" https://www.youtube.com/watch?v=dQw4w9WgXcQ ") == "https://www.youtube.com/watch?v=dQw4w9WgXcQ"


def test_every_resolved_address_must_be_public():
    assert all_ips_allowed(["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"])
    with pytest.raises(UnsafeUrl):
        all_ips_allowed(["93.184.216.34", "192.168.1.10"])
    with pytest.raises(UnsafeUrl):
        all_ips_allowed(["::ffff:127.0.0.1"])
    with pytest.raises(UnsafeUrl):
        all_ips_allowed([])


def test_redirect_is_checked_with_the_same_rules():
    assert redirect_target("https://a.example/x", "/y") == "https://a.example/y"
    with pytest.raises(UnsafeUrl):
        redirect_target("https://a.example/x", "http://127.0.0.1/admin")


# ─── Rozpoznanie dostawcy ───────────────────────────────────────────────────


def test_youtube_and_vimeo_ids():
    assert youtube_id("https://youtu.be/dQw4w9WgXcQ?t=42") == "dQw4w9WgXcQ"
    assert youtube_id("https://m.youtube.com/watch?v=dQw4w9WgXcQ&t=1m") == "dQw4w9WgXcQ"
    assert youtube_id("https://www.youtube.com/live/Sitswd4YP4k?si=x") == "Sitswd4YP4k"
    assert youtube_id("https://www.youtube.com/shorts/abcDEF12345") == "abcDEF12345"
    assert youtube_id("https://example.com/watch?v=dQw4w9WgXcQ") == ""
    assert vimeo_id("https://vimeo.com/76979871") == ("76979871", "")
    assert vimeo_id("https://vimeo.com/76979871/abc123def0") == ("76979871", "abc123def0")
    assert vimeo_id("https://player.vimeo.com/video/76979871?h=ffee00") == ("76979871", "ffee00")
    assert provider_of("https://fb.watch/abc") == "facebook"
    assert provider_of("https://tv.example.pl/mecz") == "video"


def test_oembed_endpoint_only_for_known_providers():
    assert oembed_endpoint("https://youtu.be/dQw4w9WgXcQ").startswith("https://www.youtube.com/oembed?")
    assert oembed_endpoint("https://vimeo.com/76979871").startswith("https://vimeo.com/api/oembed.json?")
    assert oembed_endpoint("https://tv.example.pl/mecz") is None


def test_iso_duration_and_og_parsing():
    assert iso_duration_seconds("PT1H2M3S") == 3723
    assert iso_duration_seconds("PT45M") == 2700
    assert iso_duration_seconds("nonsense") is None
    page = (
        "<html><head><title>Zapas</title>"
        '<meta property="og:title" content="Mecz &amp; skrót">'
        "<meta content='/img/okladka.jpg' property='og:image'>"
        '<meta property="og:site_name" content="Telewizja Klubowa">'
        '<meta itemprop="duration" content="PT1H30M">'
        "</head></html>"
    )
    out = parse_html_preview(page, "https://tv.example.pl/mecz/1")
    assert out["title"] == "Mecz & skrót"
    assert out["thumbnail_url"] == "https://tv.example.pl/img/okladka.jpg"
    assert out["site_name"] == "Telewizja Klubowa"
    assert out["duration_s"] == 5400


def test_og_image_with_unsafe_scheme_is_dropped():
    out = parse_html_preview('<meta property="og:image" content="javascript:alert(1)">', "https://a.example/")
    assert out["thumbnail_url"] == ""


def test_ttl_cache_expires_and_evicts():
    cache = TtlCache(max_items=2)
    cache.put("a", {"v": 1}, now=0, ttl=10)
    cache.put("b", {"v": 2}, now=0, ttl=10)
    assert cache.get("a", now=5) == {"v": 1}
    cache.put("c", {"v": 3}, now=5, ttl=10)  # wypycha najdawniej używane „b"
    assert cache.get("b", now=6) is None
    assert cache.get("a", now=11) is None  # przeterminowane


# ─── Pobieranie (bez prawdziwej sieci) ──────────────────────────────────────


async def _public(host):
    return ["93.184.216.34"]


async def test_fetch_preview_reads_og_tags_with_limit(monkeypatch):
    monkeypatch.setattr(link_preview, "_cache", TtlCache())
    calls = []

    def handler(request: httpx.Request):
        calls.append(str(request.url))
        body = '<meta property="og:title" content="Finał okręgu"><meta property="og:image" content="https://cdn.example.pl/o.jpg">'
        return httpx.Response(200, text=body + ("x" * 2_000_000), headers={"content-type": "text/html; charset=utf-8"})

    out = await link_preview.fetch_preview("https://tv.example.pl/final", resolver=_public, transport=httpx.MockTransport(handler))
    assert out["title"] == "Finał okręgu"
    assert out["thumbnail_url"] == "https://cdn.example.pl/o.jpg"
    # Drugie pytanie idzie z pamięci - bez sieci.
    again = await link_preview.fetch_preview("https://tv.example.pl/final", resolver=_public, transport=httpx.MockTransport(handler))
    assert again == out and len(calls) == 1


async def test_fetch_preview_blocks_private_dns_answer(monkeypatch):
    monkeypatch.setattr(link_preview, "_cache", TtlCache())

    async def private(host):
        return ["10.1.2.3"]

    def handler(request):  # pragma: no cover - nie może zostać wywołany
        raise AssertionError("połączenie z siecią prywatną")

    with pytest.raises(UnsafeUrl):
        await link_preview.fetch_preview("https://evil.example.com/", resolver=private, transport=httpx.MockTransport(handler))


async def test_fetch_preview_blocks_redirect_to_internal(monkeypatch):
    monkeypatch.setattr(link_preview, "_cache", TtlCache())

    def handler(request):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})

    # Przekierowanie do metadanych chmury przerywa pobieranie z komunikatem.
    with pytest.raises(UnsafeUrl):
        await link_preview.fetch_preview("https://redirect.example.com/", resolver=_public, transport=httpx.MockTransport(handler))
    # Zapis nagrania nie pada - dostaje podgląd z samego adresu.
    out = await link_preview.preview_or_instant("http://127.0.0.1/admin")  # bez sieci: odpada na kształcie
    assert out["title"] == ""


async def test_fetch_preview_uses_youtube_oembed(monkeypatch):
    monkeypatch.setattr(link_preview, "_cache", TtlCache())

    def handler(request: httpx.Request):
        if request.url.path == "/oembed":
            return httpx.Response(200, json={"title": "PGNiG Superliga - skrót", "author_name": "Kanał", "thumbnail_url": "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg"})
        return httpx.Response(200, text='<script>{"lengthSeconds":"3605"}</script>')

    out = await link_preview.fetch_preview("https://youtu.be/dQw4w9WgXcQ", resolver=_public, transport=httpx.MockTransport(handler))
    assert out["provider"] == "youtube"
    assert out["title"] == "PGNiG Superliga - skrót"
    assert out["thumbnail_url"] == "https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg"
    assert out["duration_s"] == 3605


# ─── Znaczniki, synchronizacja, oś meczu ────────────────────────────────────


def test_markers_are_cleaned_and_limited():
    raw = [
        {"id": "m1", "label": "Kara 2 min — nr 7", "kind": "penalty", "match_ms": 754000, "half": 1},
        {"id": "m1", "label": "duplikat", "video_s": 10},
        {"id": "bad id!", "video_s": 10},
        {"id": "m2", "label": "", "video_s": -5},
        {"id": "m3", "label": "Ręczny", "kind": "hack", "video_s": 125.6},
        "śmieć",
    ]
    out = clean_markers(raw)
    assert [m["id"] for m in out] == ["m1", "m3"]
    assert out[0]["label"] == "Kara 2 min - nr 7"
    assert out[0]["video_s"] is None and out[0]["match_ms"] == 754000 and out[0]["half"] == 1
    assert out[1]["kind"] == "manual" and out[1]["video_s"] == 126
    many = [{"id": f"x{i}", "label": "a", "video_s": i} for i in range(MAX_MARKERS + 20)]
    assert len(clean_markers(many)) == MAX_MARKERS


def test_markers_categories_map_legacy_and_keep_ranges():
    raw = [
        {"id": "a", "video_s": 100, "end_s": 122, "important": True, "category": "zla"},
        {"id": "b", "video_s": 100, "important": True, "category": "trafna"},
        {"id": "c", "video_s": 100, "important": True, "category": "ustawienie"},
        {"id": "d", "video_s": 100, "important": True, "category": "dyskusja", "legacy_category": "gwizdek"},
        {"id": "e", "video_s": 100, "important": True, "category": "hack"},
        {"id": "f", "video_s": 100, "end_s": 90},
        {"id": "g", "match_ms": 5000, "end_s": 90},
        {"id": "h", "video_s": 100, "end_s": 100 + 601},
    ]
    out = {m["id"]: m for m in clean_markers(raw)}
    assert out["a"]["category"] == "zla" and out["a"]["end_s"] == 122
    assert out["b"]["category"] == "dobra" and out["b"]["legacy_category"] is None
    assert out["c"]["category"] == "dyskusja" and out["c"]["legacy_category"] == "ustawienie"
    assert out["d"]["legacy_category"] == "gwizdek"
    assert out["e"]["category"] == "dyskusja"
    assert out["f"]["end_s"] is None and out["g"]["end_s"] is None and out["h"]["end_s"] is None


def test_sync_is_bounded():
    assert clean_sync({"match_start_s": 312.4, "second_half_s": "2400", "half_minutes": 30, "break_minutes": 10}) == {
        "match_start_s": 312,
        "second_half_s": 2400,
        "half_minutes": 30,
        "break_minutes": 10,
        "stream_start_ms": None,
        "kickoff_wall_ms": None,
        "second_half_wall_ms": None,
    }
    assert clean_sync({"match_start_s": -1, "half_minutes": 500}) == {
        "match_start_s": None,
        "second_half_s": None,
        "half_minutes": None,
        "break_minutes": None,
        "stream_start_ms": None,
        "kickoff_wall_ms": None,
        "second_half_wall_ms": None,
    }


def test_timeline_from_proel_blob():
    blob = {
        "matchConfig": {
            "hostTeamName": "MKS Zagłębie",
            "guestTeamName": "KPR Ruch",
            "halfTime": 30,
            "halfBreak": 15,
            "hostPlayerCards": [{"number": 7, "fullName": "KOWALSKI Jan"}],
        },
        "protocol": [
            {"type": "goal", "team": "host", "player": 7, "time": 65000, "half": 1, "score": "1-0"},
            {"type": "penalty1", "team": "guest", "player": 11, "time": 754000, "half": 1},
            {"type": "goalRemoved", "team": "host", "player": 7, "time": 70000, "half": 1},
            {"type": "teamTime", "team": "host", "time": 1900000, "half": 2},
            {"type": "penalty1", "team": "host", "player": 3, "time": 3600000, "half": 2, "shootout": True},
            {"type": "warning", "team": "host", "player": "Tr", "time": 30000, "half": 1},
        ],
    }
    out = timeline_from_blob(blob)
    assert out["available"] and out["half_minutes"] == 30 and out["break_minutes"] == 15
    labels = [e["label"] for e in out["events"]]
    assert labels == [
        "Upomnienie - trener (MKS Zagłębie)",
        "Bramka - nr 7 KOWALSKI (MKS Zagłębie)",
        "Kara 2 min - nr 11 (KPR Ruch)",
        "Czas dla drużyny (MKS Zagłębie)",
    ]
    assert out["events"][2]["clock"] == "12:34" and out["events"][2]["kind"] == "penalty"
    assert timeline_from_blob(None)["available"] is False


def test_mentor_states_sent_read_rated():
    requests = [
        {"mentor_id": "10", "last_sent_at": "t1", "read_at": None, "fulfilled_at": None},
        {"mentor_id": "11", "last_sent_at": "t1", "read_at": "t2", "fulfilled_at": None},
        {"mentor_id": "12", "last_sent_at": "t1", "read_at": "t2", "fulfilled_at": "t3"},
    ]
    out = mentor_states(
        assigned=["10", "11", "12", "13"],
        requests=requests,
        published_authors=["12"],
        drafting_authors=["11"],
    )
    assert {k: v["state"] for k, v in out.items()} == {"10": "sent", "11": "read", "12": "rated", "13": "none"}
    assert out["11"]["drafting"] is True and out["12"]["drafting"] is False


def test_only_addressee_marks_request_read_once():
    req = {"mentor_id": "10", "read_at": None, "fulfilled_at": None}
    assert should_mark_read(actor_id="10", request=req)
    assert not should_mark_read(actor_id="1", request=req)
    assert not should_mark_read(actor_id="10", request={**req, "read_at": "x"})
    assert not should_mark_read(actor_id="10", request={**req, "fulfilled_at": "x"})


def test_tables_have_new_columns_and_migrations():
    _, _, requests, videos = define_tables(MetaData())
    assert "read_at" in {c.name for c in requests.columns}
    assert {"title", "thumbnail_url", "duration_s", "sync_json", "markers_json"} <= {c.name for c in videos.columns}
    joined = " ".join(MIGRATIONS)
    for column in ("read_at", "title", "thumbnail_url", "site_name", "duration_s", "sync_json", "markers_json", "updated_at"):
        assert f"IF NOT EXISTS {column} " in joined
    json.dumps(list(MIGRATIONS))
