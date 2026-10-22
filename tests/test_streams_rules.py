"""Transmisje: czyste parsery (próbki w tests/fixtures/streams/), dopasowanie, pewność, plan sprawdzeń."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.streams import parsers as P
from app.streams import rules as R
from app.streams.seeds import TV_LINKS

FIX = Path(__file__).parent / "fixtures" / "streams"
UTC = timezone.utc


def fx(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


def ctx(match_id="m1", home="MKS Wybrzeże Gdańsk", away="Pogoń Szczecin", comp="Liga Centralna mężczyzn",
        code="LCM/12", when=datetime(2026, 10, 18, 18, 0), hc="c1", ac="c2", gender="M", category="Seniorzy"):
    return R.match_context({"match_id": match_id, "competition_name": comp, "comp_name": comp, "match_code": code,
                            "home_team_name": home, "away_team_name": away, "home_club_id": hc, "away_club_id": ac,
                            "scheduled_at": when, "comp_gender": gender, "comp_category": category})


OFFICIAL = {"id": 1, "kind": "official", "verified": True, "platform": "youtube", "scope_json": '["LC"]',
            "channel_id": "UCabcdefghijklmnopqrstuv", "title": "Handball Polska"}


# ---------------------------------------------------------------------------
# Parsery
# ---------------------------------------------------------------------------


def test_rss_kanalu_i_playlisty():
    feed = P.parse_feed(fx("channel_feed.xml"))
    assert feed["channel_id"] == "UCabcdefghijklmnopqrstuv" and feed["title"] == "Handball Polska"
    assert [e["video_id"] for e in feed["entries"]] == ["LCvid000001", "LCvid000002", "LCvid000003"]
    first = feed["entries"][0]
    assert first["published"] == datetime(2026, 10, 14, 9, 0, 12, tzinfo=UTC)
    assert first["thumbnail_url"].endswith("LCvid000001/hqdefault.jpg") and first["channel_title"] == "Handball Polska"
    playlist = P.parse_feed(fx("playlist_feed.xml"))
    assert playlist["channel_id"] == "UCczarnypiotrusmedia0001"
    assert playlist["entries"][0]["channel_title"] == "Czarny Piotruś MEDIA"
    # Śmieci i XML z encjami (billion laughs) - pusto, bez wyjątku.
    assert P.parse_feed("<feed")["entries"] == []
    assert P.parse_feed('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaa">]><feed/>')["entries"] == []


def test_odpowiedzi_youtube_api():
    videos = {v["video_id"]: v for v in P.parse_api_videos(fx("api_videos.json"))}
    assert set(videos) == {"LCvid000001", "ILvid000001", "LCvid000003"}  # „bad” odrzucony
    live, upcoming, vod = videos["LCvid000001"], videos["ILvid000001"], videos["LCvid000003"]
    assert live["state"] == "live" and live["starts_at"] == datetime(2026, 10, 18, 15, 57, 31, tzinfo=UTC)
    assert live["duration_s"] is None and live["thumbnail_url"].endswith("hqdefault_live.jpg") and live["is_broadcast"]
    assert upcoming["state"] == "upcoming" and upcoming["starts_at"] == datetime(2026, 10, 18, 15, 50, tzinfo=UTC)
    assert vod["state"] == "vod" and vod["duration_s"] == 6072 and vod["ended_at"] is not None
    assert vod["thumbnail_url"].endswith("maxresdefault.jpg")
    assert P.parse_api_search(fx("api_search.json")) == ["SRvid000001", "SRvid000002"]
    channel = P.parse_api_channel(fx("api_channels.json"))
    assert channel == {"channel_id": "UCabcdefghijklmnopqrstuv", "title": "Handball Polska", "handle": "@handballpolska",
                       "uploads": "UUabcdefghijklmnopqrstuv"}
    items = P.parse_api_playlist_items(fx("api_playlist_items.json"))
    assert [i["video_id"] for i in items] == ["ILvid000001"] and items[0]["channel_id"] == "UCczarnypiotrusmedia0001"
    assert P.parse_api_videos("nie json") == [] and P.parse_api_channel({"items": []}) is None


def test_strona_klubu_kanaly_bez_stopki_zwiazku():
    links = P.parse_club_links(fx("club_home.html"), "MKS Wybrzeże Gdańsk")
    assert links["youtube"][0] == {"handle": "@WybrzezeGdanskTV", "url": "https://www.youtube.com/@WybrzezeGdanskTV"}
    assert all(i.get("handle") != "@HandballPolska" for i in links["youtube"])  # stopka „Partnerzy”
    assert [f["url"] for f in links["facebook"]] == ["https://www.facebook.com/WybrzezeGdansk"]  # bez sharer/ZPRP/plugins
    assert P.parse_club_links("") == {"youtube": [], "facebook": []}


def test_strony_youtube_bez_klucza():
    assert P.parse_channel_page(fx("channel_page.html")) == {"channel_id": "UCabcdefghijklmnopqrstuv", "title": "Handball Polska"}
    live = P.parse_live_page(fx("live_page.html"))
    assert live["video_id"] == "LCvid000001" and live["live_now"] is True and "Pogoń" in live["title"]
    assert P.parse_live_page(fx("live_page_offline.html")) is None
    assert P.parse_channel_page(fx("live_page_offline.html"))["channel_id"] == "UCwybrzezegdansktv000001"


def test_strona_podpowiedzi():
    items = {i["video_id"]: i for i in P.parse_hint_page(fx("hint_page.html"))}
    assert set(items) == {"LCvid000001", "ILvid000001", "JRvid000001", "XXvid000001"}
    assert "Wybrzeże Gdańsk – Pogoń Szczecin" in items["LCvid000001"]["context"] and items["LCvid000001"]["time_hint"] == "18:00"
    assert items["ILvid000001"]["time_hint"] == "17:30" and items["XXvid000001"]["context"] == ""
    assert P.parse_hint_page("") == []


def test_adres_kanalu_od_admina():
    assert P.youtube_url_parts("https://www.youtube.com/@HandballPolska") == {"handle": "@HandballPolska"}
    assert P.youtube_url_parts("youtube.com/channel/UCabcdefghijklmnopqrstuv/videos") == {"channel_id": "UCabcdefghijklmnopqrstuv"}
    assert P.youtube_url_parts("https://www.youtube.com/playlist?list=PL3NkJuwI5L5d7vPRyvudHKhgP8Q1AMGeP") == {
        "playlist_id": "PL3NkJuwI5L5d7vPRyvudHKhgP8Q1AMGeP"}
    assert P.youtube_url_parts("https://vimeo.com/123") == {}


# ---------------------------------------------------------------------------
# Rozgrywki i dopasowanie
# ---------------------------------------------------------------------------


def test_poziom_rozgrywek():
    assert R.competition_tier("ORLEN Superliga Kobiet") == "OS"
    assert R.competition_tier("Liga Centralna Kobiet") == "LC"
    assert R.competition_tier("I liga mężczyzn gr. A") == "I"
    assert R.competition_tier("II liga mężczyzn") == "II"
    assert R.competition_tier("Mistrzostwa Polski Juniorów", category="Junior") == "MP-J"
    assert R.competition_tier("", "LCM/3") == "LC" and R.competition_tier("", "S/IM/4") == "I"
    assert R.competition_tier("Liga wojewódzka juniorów", "S/JM/3", "Junior") == "other"
    assert R.gender_of("Kobiety") == "K" and R.gender_of("", "IIK3/1") == "K"
    m = ctx()
    assert (m["tier"], m["gender"], m["youth"]) == ("LC", "M", False)
    assert m["kickoff"] == datetime(2026, 10, 18, 16, 0, tzinfo=UTC)  # 18:00 w Warszawie (CEST)


def test_oficjalny_kanal_obie_druzyny_live():
    m = ctx()
    video = next(v for v in P.parse_api_videos(fx("api_videos.json")) if v["video_id"] == "LCvid000001")
    assert R.best_match(video, [m], OFFICIAL) == (m, "official")
    # Ten sam film z wyszukiwania (kanał nieznany): czas transmisji pewny → confirmed.
    assert R.best_match(video, [m], None) == (m, "confirmed")


def test_rss_bez_api_data_w_tytule_i_odrzucenia():
    m = ctx()
    feed = {e["video_id"]: e for e in P.parse_feed(fx("channel_feed.xml"))["entries"]}
    assert R.best_match(feed["LCvid000001"], [m], OFFICIAL) == (m, "official")
    assert R.best_match(feed["LCvid000002"], [m], OFFICIAL) is None  # wywiad
    assert R.best_match(feed["LCvid000003"], [m], OFFICIAL) is None  # inne drużyny
    other_day = {**feed["LCvid000001"], "title": "Wybrzeże Gdańsk - Pogoń Szczecin 12.04.2026"}
    assert R.best_match(other_day, [m], OFFICIAL) is None
    juniors = {**feed["LCvid000001"], "title": "Juniorzy: Wybrzeże Gdańsk - Pogoń Szczecin"}
    assert R.best_match(juniors, [m], OFFICIAL) is None
    women = {**feed["LCvid000001"], "title": "Wybrzeże Gdańsk - Pogoń Szczecin (kobiety)"}
    assert R.best_match(women, [m], OFFICIAL) is None
    old = {**feed["LCvid000001"], "title": "Wybrzeże Gdańsk - Pogoń Szczecin",
           "published": datetime(2026, 9, 1, tzinfo=UTC)}
    assert R.best_match(old, [m], OFFICIAL) is None


def test_kanal_klubu_wlasna_druzyna_domyslna():
    m = ctx()
    club = {"id": 5, "kind": "club", "verified": False, "club_id": "c1", "platform": "youtube"}
    live = {"video_id": "CLvid000001", "title": "Zapraszamy na mecz z Pogonią Szczecin!", "state": "live",
            "is_broadcast": True, "starts_at": datetime(2026, 10, 18, 15, 55, tzinfo=UTC)}
    assert R.best_match(live, [m], club) == (m, "confirmed")
    assert R.best_match(live, [m], {**club, "verified": True}) == (m, "official")
    # Bez pewnego czasu transmisji (sam RSS) - nic: klub wrzuca też zapowiedzi i wywiady.
    rss = {"video_id": "CLvid000001", "title": "Mecz z Pogonią Szczecin", "published": datetime(2026, 10, 17, tzinfo=UTC)}
    assert R.best_match(rss, [m], club) is None
    # Kanał obcego klubu - pełne nazwy wymagane, najwyżej confirmed.
    both = {**live, "title": "Wybrzeże Gdańsk vs Pogoń Szczecin"}
    assert R.best_match(both, [m], {**club, "club_id": "c9"}) == (m, "confirmed")


def test_slabe_dopasowanie_i_remis():
    m = ctx(home="AZS AWFiS Gdańsk")
    video = {"video_id": "WKvid000001", "title": "AZS Gdańsk - Pogoń Szczecin", "state": "live", "is_broadcast": True,
             "starts_at": datetime(2026, 10, 18, 16, 2, tzinfo=UTC)}
    assert R.best_match(video, [m], None) == (m, "possible")
    short = {**video, "title": "Wybrzeże Gdańsk - Pogoń Szczecin", "state": "vod", "duration_s": 300, "is_broadcast": False,
             "published": datetime(2026, 10, 18, 19, 0, tzinfo=UTC)}
    assert R.best_match(short, [ctx()], None) is None  # skrót
    twin = ctx(match_id="m2")
    full = {**video, "title": "Wybrzeże Gdańsk - Pogoń Szczecin"}
    assert R.best_match(full, [ctx(), twin], None) is None  # dwa identyczne mecze - niepewne
    assert R.team_level("Pogoń Szczecin", "pogoni szczecin") == "strong"
    assert R.team_level("Zagłębie Lubin", "Zagłębie Sosnowiec") == "weak"
    assert R.team_level("Zagłębie Lubin", "Lublin") == "none"


def test_scalanie_pewnosci_i_stan_bez_api():
    assert R.merge_confidence("possible", "official", locked=False) == "official"
    assert R.merge_confidence("official", "possible", locked=False) == "official"
    assert R.merge_confidence("possible", "official", locked=True) == "possible"
    k = datetime(2026, 10, 18, 16, 0, tzinfo=UTC)
    assert R.state_without_api(k, k + timedelta(hours=1)) == "upcoming"
    assert R.state_without_api(k, k + timedelta(hours=3)) == "vod"


# ---------------------------------------------------------------------------
# Plan sprawdzeń i wyszukiwań
# ---------------------------------------------------------------------------


def test_plan_sprawdzen_kanalu():
    k = datetime(2026, 10, 18, 16, 0, tzinfo=UTC)
    assert R.next_check_at([k], k - timedelta(hours=5)) == k - timedelta(minutes=60)
    assert R.next_check_at([k], k - timedelta(minutes=30)) == k - timedelta(minutes=25)
    assert R.next_check_at([k], k + timedelta(hours=1)) == k + timedelta(hours=1, minutes=3)
    assert R.next_check_at([k], k + timedelta(hours=5)) == k + timedelta(hours=6)
    assert R.next_check_at([k], k + timedelta(hours=30)) == k + timedelta(hours=54)
    assert R.next_check_at([], k) == k + timedelta(hours=24)
    # Dwa mecze: wygrywa najczęstszy interwał.
    assert R.next_check_at([k, k + timedelta(hours=4)], k + timedelta(minutes=10)) == k + timedelta(minutes=13)


def test_ktore_mecze_dotycza_kanalu():
    lc, i_liga = ctx(), ctx(match_id="m2", comp="I liga mężczyzn", code="IM/1", hc="c3", ac="c4")
    assert R.relevant_matches(OFFICIAL, [lc, i_liga]) == [lc]
    assert R.relevant_matches({"kind": "club", "club_id": "c3", "platform": "youtube"}, [lc, i_liga]) == [i_liga]
    assert R.relevant_matches({"kind": "tv", "platform": "youtube"}, [lc]) == []
    assert R.relevant_matches({"kind": "club", "club_id": "c1", "platform": "facebook"}, [lc]) == []
    assert R.relevant_matches({"kind": "broadcaster", "platform": "youtube", "scope_json": "[]"}, [lc, i_liga]) == [lc, i_liga]


def test_wybor_wyszukiwan_wg_wagi_i_limitu():
    base = datetime(2026, 10, 18, 18, 0)
    os_m = ctx(match_id="os", comp="ORLEN Superliga", code="SM/1", when=base)
    lc_m = ctx(match_id="lc", when=base)
    i_m = ctx(match_id="i", comp="I liga mężczyzn", code="IM/1", when=base)
    ii_m = ctx(match_id="ii", comp="II liga mężczyzn", code="IIM1/1", when=base)
    k = os_m["kickoff"]
    picked = R.pick_search_targets([ii_m, i_m, lc_m, os_m], set(), {}, k - timedelta(minutes=10), remaining=80)
    assert [(m["match_id"], e) for m, e in picked] == [("os", "upcoming"), ("lc", "upcoming")]
    picked = R.pick_search_targets([i_m, lc_m, os_m], {"os"}, {"lc:live": 1}, k + timedelta(minutes=20), remaining=80)
    assert [(m["match_id"], e) for m, e in picked] == [("i", "live")]
    assert R.pick_search_targets([os_m], set(), {}, k - timedelta(hours=2), remaining=80) == []
    assert R.pick_search_targets([os_m], set(), {}, k, remaining=0) == []
    assert R.search_query(lc_m) == "Wybrzeże Gdańsk Pogoń Szczecin"


# ---------------------------------------------------------------------------
# Kształty
# ---------------------------------------------------------------------------


def test_ksztalty_stream_i_gdzie_ogladac():
    row = {"id": 3, "match_id": "m1", "platform": "youtube", "url": "https://www.youtube.com/watch?v=LCvid000001",
           "video_id": "LCvid000001", "state": "vod", "duration_s": 5400, "confidence": "official",
           "starts_at": datetime(2026, 10, 18, 16, 0)}
    view = R.stream_view(row, {"title": "Handball Polska", "url": "u", "kind": "official", "verified": True})
    assert view["embed_url"] == "https://www.youtube-nocookie.com/embed/LCvid000001"
    assert view["starts_at"] == "2026-10-18T18:00:00" and view["duration_s"] == 5400
    assert view["channel"] == {"title": "Handball Polska", "url": "u", "kind": "official", "verified": True}
    link = R.stream_view({"platform": "facebook", "url": "https://fb.watch/x", "state": "link", "duration_s": 9})
    assert link["embed_url"] is None and link["duration_s"] is None and link["channel"] is None
    tiles = R.where_to_watch("OS", [], [{"platform": "facebook", "url": "https://www.facebook.com/klub", "title": "Klub"},
                                        {"platform": "youtube", "url": "https://www.youtube.com/@klub", "title": "Klub TV"}],
                             TV_LINKS)
    assert [t["kind"] for t in tiles] == ["tv", "paid", "channel", "channel", "facebook"]
    assert tiles[3]["url"].endswith("@klub")
    ordered = R.sort_streams([{"state": "vod", "confidence": "official"}, {"state": "live", "confidence": "possible"},
                              {"state": "live", "confidence": "official"}])
    assert [(s["state"], s["confidence"]) for s in ordered] == [("live", "official"), ("live", "possible"), ("vod", "official")]
