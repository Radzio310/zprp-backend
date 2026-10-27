"""Czyste reguły panelu „Mentor" (`app/mentor_panel_rules.py`) - bez bazy."""

from datetime import datetime, timedelta, timezone

import pytest

from app import mentor_panel_rules as R

PAIR = {"id": "p1", "judge_ids": ["1", "2"], "province": "ŚLĄSKIE", "program": "province"}
LINKS = [{"pair_id": "p1", "mentor_id": "7", "ended_at": None}, {"pair_id": "p1", "mentor_id": "8", "ended_at": datetime.now()}]
NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


def actor(judge_id, **extra):
    return {"judge_id": judge_id, "is_admin": False, "province": "ŚLĄSKIE", "badges": [], **extra}


# ─── Rola i uprawnienia ─────────────────────────────────────────────────────


def test_rola_w_parze_po_kolei():
    assert R.role_in_pair(actor("1"), PAIR, LINKS) == "pair"
    assert R.role_in_pair(actor("7"), PAIR, LINKS) == "mentor"
    # Zakończona opieka nie daje dostępu.
    assert R.role_in_pair(actor("8"), PAIR, LINKS) is None
    assert R.role_in_pair(actor("9", is_admin=True), PAIR, LINKS) == "admin"
    # Para wygrywa z administratorem - edytuje wtedy jak para, ale `is_admin` i tak pozwala na wszystko.
    assert R.role_in_pair(actor("1", is_admin=True), PAIR, LINKS) == "pair"
    assert R.role_in_pair(actor(""), PAIR, LINKS) is None


def test_komisja_tylko_okregowe_swojego_okregu():
    committee = actor("5", badges=["Komisja Sędziowska"])
    assert R.role_in_pair(committee, PAIR, [], {"enabled": True, "manager_ids": []}) == "committee"
    assert R.role_in_pair({**committee, "province": "OPOLSKIE"}, PAIR, [], {"enabled": True, "manager_ids": []}) is None
    # Okręg wyłączony przez administratora.
    assert R.role_in_pair(committee, PAIR, [], {"enabled": False, "manager_ids": []}) is None
    # Mentor 2028 i pary międzyokręgowe - tylko administrator.
    assert R.role_in_pair(committee, {**PAIR, "program": "mentor2028"}, [], {"enabled": True, "manager_ids": []}) is None
    assert R.role_in_pair(committee, {**PAIR, "province": "MIĘDZYOKRĘGOWE"}, [], {"enabled": True, "manager_ids": []}) is None
    # Menedżer z listy administratora - bez odznaki.
    assert R.role_in_pair(actor("6"), PAIR, [], {"enabled": True, "manager_ids": ["6"]}) == "committee"


@pytest.mark.parametrize("role,action,expected", [
    ("pair", "view", True), ("mentor", "view", True), ("committee", "view", True), (None, "view", False),
    ("pair", "create", True), ("mentor", "flag", True), ("committee", "create", False), ("committee", "flag", False),
    ("committee", "sheets", True), ("pair", "publish", True), ("committee", "publish", False),
    ("pair", "categories", True), ("mentor", "video", True), ("committee", "video", False),
    ("pair", "toggle", False), ("mentor", "toggle", False),
])
def test_macierz_uprawnien(role, action, expected):
    assert R.can(action, role) is expected


def test_edycja_tylko_swoich_admin_wszystko():
    assert R.can("edit", "pair", owner=True)
    assert not R.can("edit", "pair", owner=False)
    assert not R.can("edit", "mentor", owner=False)
    assert R.can("edit", "admin", is_admin=True, owner=False)
    assert not R.can("edit", "committee", owner=True)


def test_wylaczony_panel():
    assert not R.can("view", "pair", enabled=False)
    assert not R.can("view", "committee", enabled=False)
    assert R.can("view", "admin", is_admin=True, enabled=False)
    with pytest.raises(R.RuleError) as error:
        R.require("view", "mentor", enabled=False)
    assert error.value.code == "PANEL_DISABLED"


def test_wlaczanie_panelu():
    assert R.can("toggle", "committee", manages=True)
    assert not R.can("toggle", "committee", manages=False)
    assert R.can("toggle", None, is_admin=True)
    with pytest.raises(R.RuleError) as error:
        R.require("create", "committee")
    assert error.value.code == "READ_ONLY"


def test_arkusze_delegata_nowa_regula():
    assert R.pair_role_sees_delegate_sheet("mentor", ["2", "1"], ["1", "2"])
    assert R.pair_role_sees_delegate_sheet("committee", ["1", "2"], ["1", "2"])
    assert not R.pair_role_sees_delegate_sheet(None, ["1", "2"], ["1", "2"])
    assert not R.pair_role_sees_delegate_sheet("pair", ["1", "3"], ["1", "2"])
    assert not R.pair_role_sees_delegate_sheet("pair", ["1"], ["1", "2"])


# ─── QR ─────────────────────────────────────────────────────────────────────


def test_kod_qr_bez_dwuznacznych_znakow():
    code = R.new_qr_code()
    assert len(code) == 8
    assert not set(code) & set("0O1IL")
    assert R.normalize_qr_code(code.lower()[:4] + "-" + code[4:]) == code
    assert R.normalize_qr_code("ABCD0OIL") == ""


def test_stan_kodu_qr():
    row = {"expires_at": NOW + timedelta(minutes=1)}
    assert R.qr_status(row, NOW) == "waiting"
    assert R.qr_status({**row, "approved_by": "1", "approved_at": NOW}, NOW) == "approved"
    assert R.qr_status({**row, "approved_by": "1", "approved_at": NOW, "consumed_at": NOW}, NOW) == "expired"
    assert R.qr_status({"expires_at": NOW - timedelta(seconds=1)}, NOW) == "expired"
    assert R.qr_status(None, NOW) == "expired"


def test_podpowiedz_urzadzenia():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
    assert R.device_hint(ua) == "Chrome na Windows"
    assert R.device_hint("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605 Version/17 Safari/605") == "Safari na macOS"
    assert R.device_hint("") == "Nieznana przeglądarka"


# ─── Kategorie ──────────────────────────────────────────────────────────────


def test_domyslne_kategorie_to_piec_dzisiejszych():
    rows = R.default_category_rows("p1", "1", NOW, make_id=iter(["a", "b", "c", "d", "e"]).__next__)
    assert [r["key"] for r in rows] == ["dobra", "zla", "dyskusja", "pytanie", "kluczowa"]
    assert rows[0]["name"] == "Dobra decyzja" and rows[0]["color"] == "emerald"
    assert rows[3]["color"] == "sky" and rows[4]["color"] == "pink"
    assert all(r["color"] in R.PALETTE and r["icon"] in R.ICONS for r in rows)


def test_walidacja_kategorii():
    assert R.clean_category({"name": " Ustawienie — ", "color": "teal", "icon": "walk"})["name"] == "Ustawienie -"
    with pytest.raises(R.RuleError):
        R.clean_category({"name": "", "color": "teal", "icon": "walk"})
    with pytest.raises(R.RuleError):
        R.clean_category({"name": "X", "color": "#ff0000", "icon": "walk"})
    with pytest.raises(R.RuleError):
        R.clean_category({"name": "X", "color": "teal", "icon": "nieznana"})
    assert R.clean_category({"color": "rose"}, partial=True) == {"color": "rose"}


def test_przywroc_domyslne():
    existing = [
        {"id": "d1", "pair_id": "p1", "key": "dobra", "name": "Zmieniona", "archived": False},
        {"id": "d2", "pair_id": "p1", "key": "zla", "name": "Zła", "archived": True},
        {"id": "own", "pair_id": "p1", "key": None, "name": "Własna", "archived": False},
        {"id": "g", "pair_id": None, "key": None, "name": "Globalna", "archived": False},
    ]
    plan = R.reset_plan(existing)
    assert [r[0] for r in plan["restore"]] == ["d1", "d2"]
    assert plan["restore"][0][1]["name"] == "Dobra decyzja" and plan["restore"][1][1]["archived"] is False
    assert plan["archive"] == ["own"]
    assert [d["key"] for d in plan["create"]] == ["dyskusja", "pytanie", "kluczowa"]


def test_klip_ma_kategorie_tylko_z_listy():
    assert R.clean_category_ids(["a", "x", "a", "b"], ["a", "b"]) == ["a", "b"]


# ─── Klipy ──────────────────────────────────────────────────────────────────


def test_walidacja_klipu():
    assert R.validate_clip(10, 20.456) == (10.0, 20.46)
    with pytest.raises(R.RuleError) as error:
        R.validate_clip(20, 10)
    assert error.value.code == "CLIP_ORDER"
    with pytest.raises(R.RuleError) as error:
        R.validate_clip(0, 601)
    assert error.value.code == "CLIP_TOO_LONG"
    assert R.validate_clip(0, 600) == (0.0, 600.0)
    with pytest.raises(R.RuleError):
        R.validate_clip(-1, 5)
    with pytest.raises(R.RuleError):
        R.validate_clip(100, 130, video_duration=110)
    assert R.validate_clip(100, 110.5, video_duration=110) == (100.0, 110.5)
    with pytest.raises(R.RuleError):
        R.validate_clip("x", 5)


def test_ciecie_klipu_i_nazwa_pliku():
    assert R.clip_cut_mode(0, 60) == "reencode"
    assert R.clip_cut_mode(0, 400) == "copy"
    args = R.cut_args("src", "out.mp4", 12.5, 30)
    assert args[args.index("-ss") + 1] == "12.50" and args[args.index("-t") + 1] == "17.50"
    assert "libx264" in args
    assert "copy" in R.cut_args("src", "out.mp4", 0, 500)
    assert R.clip_filename("Faul w ataku – zła", "ISM/1", 754) == "ISM-1 Faul w ataku - zla 12-34.mp4"


def test_znaczniki_z_zakresem_jako_klipy_do_odczytu():
    video = {"id": "v1", "match_id": "m1"}
    markers = [
        {"id": "a", "label": "Akcja", "video_s": 10, "end_s": 30, "category": "dobra"},
        {"id": "b", "video_s": 5, "important": True},
        # Ręczny punkt bez oznaczenia - też klip (decyzja 27.10.2026).
        {"id": "c", "video_s": 50},
        # Nieoznaczony punkt z importu osi ProEla - nie klip.
        {"id": "d", "video_s": 70, "type": "goal", "kind": "goal", "source_key": "goal:host:7:65000"},
    ]
    clips = R.markers_as_clips(video, markers)
    by = {c["marker_id"]: c for c in clips}
    assert set(by) == {"a", "b", "c"}
    # Punkt: okno -5/+3 s wokół sekundy (start przycięty do 0).
    assert by["b"]["point"] and (by["b"]["start_s"], by["b"]["end_s"]) == (0.0, 8.0)
    assert (by["c"]["start_s"], by["c"]["end_s"]) == (45.0, 53.0)
    assert by["a"]["read_only"] and by["a"]["source"] == "marker"
    assert by["a"]["id"] == "marker:v1:a" and by["a"]["category_key"] == "dobra"


def test_znacznik_jest_klipem_tylko_gdy_reczny_albo_oznaczony():
    assert R.marker_is_clip({"video_s": 3, "end_s": 9})
    assert R.marker_is_clip({"video_s": 3, "kind": "manual"})
    assert R.marker_is_clip({"video_s": 3, "comment": "Wznowienie"})
    assert R.marker_is_clip({"video_s": 3, "type": "goal", "source_key": "k", "important": True})
    assert not R.marker_is_clip({"video_s": 3, "type": "penalty1", "kind": "penalty", "source_key": "k"})
    assert not R.marker_is_clip({"video_s": 3, "kind": "goal"})


def test_znacznik_z_klipem_nie_wraca_drugi_raz():
    video = {"id": "v1", "match_id": "m1"}
    clips = R.markers_as_clips(video, [{"id": "a", "video_s": 10}, {"id": "b", "video_s": 20}, {"id": "c", "video_s": 30}])
    # "a" ma klip, "b" miał klip i go usunięto (nagrobek) - zostaje tylko "c".
    left = R.unclaimed_marker_clips(clips, [R.marker_clip_key("v1", "a"), R.marker_clip_key("v1", "b"), R.marker_clip_key("v2", "c")])
    assert [c["marker_id"] for c in left] == ["c"]


def test_wiersz_klipu_ze_znacznika():
    video = {"id": "v1", "match_id": "m1"}
    mc = R.markers_as_clips(video, [{"id": "a", "label": "Dobra decyzja", "video_s": 100, "category": "dobra", "comment": "Błędne wznowienie", "match_ms": 61000, "half": 1}])[0]
    row = R.clip_row_from_marker(mc, {"dobra": "cat-1"})
    assert row["source"] == "marker" and row["source_key"] == "a"
    assert (row["start_s"], row["end_s"]) == (95.0, 103.0)
    assert row["note"] == "Błędne wznowienie" and row["title"] == "Dobra decyzja"
    assert row["category_ids"] == ["cat-1"] and row["match_ms"] == 61000 and row["half"] == 1
    assert R.clip_row_from_marker(mc, {})["category_ids"] == []


# ─── Zestawienia ────────────────────────────────────────────────────────────


def test_kolejnosc_zestawienia():
    items = [{"clip_id": "c2", "column": "b"}, {"clip_id": "c1"}, {"clip_id": "c2"}, {"clip_id": "c3", "column": "x"}]
    ordered = R.order_items(items, "contrast")
    assert [(i["clip_id"], i["column"], i["position"]) for i in ordered] == [("c2", "b", 0), ("c1", "a", 1), ("c3", "a", 2)]
    free = R.order_items(items, "free")
    assert all(i["column"] is None for i in free)


def test_dodaj_do_zestawienia():
    existing = [{"clip_id": "c1", "position": 1, "column": "a"}, {"clip_id": "c0", "position": 0, "column": "b"}]
    out = R.append_item(existing, "c9", "b", "contrast")
    assert [i["clip_id"] for i in out] == ["c0", "c1", "c9"] and out[-1]["column"] == "b"
    assert [i["clip_id"] for i in R.append_item(existing, "c1", None, "contrast")] == ["c0", "c1"]


def test_playlista_etykiety_i_stary_kontrast():
    items = [{"clip_id": "c1", "label": "  Dobra decyzja ", "note": "n"}, {"clip_id": "c2", "label": "x" * 90}]
    out = R.order_items(items, "free")
    assert out[0]["label"] == "Dobra decyzja" and len(out[1]["label"]) == R.MAX_ITEM_LABEL and out[0]["note"] == "n"
    # Stary kontrast: A1, A2, B1 zapisane po kolei -> playlista A1, B1, A2, kolumny w etykietach.
    legacy = [{"clip_id": "a1", "column": "a", "position": 0}, {"clip_id": "a2", "column": "a", "position": 1},
              {"clip_id": "b1", "column": "b", "position": 2, "label": "Balans"}]
    playlist = R.playlist_items(legacy, "contrast")
    assert [(i["clip_id"], i["label"], i["column"], i["position"]) for i in playlist] == [
        ("a1", "Wzorzec", None, 0), ("b1", "Balans", None, 1), ("a2", "Wzorzec", None, 2)]
    assert R.legacy_label({"column": "b"}, "contrast") == "Do poprawy"
    assert R.legacy_label({"column": "b"}, "free") is None
    assert R.append_item([], "c5", None, "free", "Wzorzec")[0]["label"] == "Wzorzec"
    assert R.slim_match(None) is None
    assert R.slim_match({"match_id": "m1", "match_code": "KS1", "venue": "x", "home": {"name": "A"}}) == {
        "match_id": "m1", "season": None, "scheduled_at": None, "match_code": "KS1", "category": None,
        "competition_name": None, "home": {"name": "A"}, "away": None}


# ─── Wątki i flagi ──────────────────────────────────────────────────────────


def test_rysunek_na_stopklatce():
    shapes = [{"kind": "arrow", "points": [[0.1, 0.2], [2, -1]], "color": "rose"}] + [{"kind": "circle", "points": [[0.5, 0.5]]}] * 30
    out = R.clean_drawing(shapes)
    assert len(out) == R.MAX_SHAPES
    assert out[0]["points"] == [[0.1, 0.2], [1.0, 0.0]]
    assert out[1]["color"] == "amber"
    assert R.clean_drawing([{"kind": "smok", "points": [[0, 0]]}]) is None
    assert R.clean_drawing(None) is None


def test_wzmianki_tylko_osob_pary():
    assert R.clean_mentions(["1", "9", "1", "7"], ["1", "2", "7"]) == ["1", "7"]


def test_zgloszenie_meczu():
    row, newly = R.apply_flag(None, {"submitted": True, "due_at": "2026-10-30T18:00:00Z"}, "1", NOW)
    assert newly and row["review_status"] == "open" and row["submitted_by"] == "1"
    assert row["due_at"] == datetime(2026, 10, 30, 18, 0, tzinfo=timezone.utc)
    again, newly2 = R.apply_flag(row, {"submitted": True}, "2", NOW)
    assert not newly2 and again["submitted_by"] == "1"
    starred, _ = R.apply_flag(None, {"starred": True, "star_reason": "x" * 300}, "1", NOW)
    assert starred["starred"] and len(starred["star_reason"]) == 120
    off, _ = R.apply_flag(starred, {"starred": False}, "1", NOW)
    assert off["star_reason"] is None
    with pytest.raises(R.RuleError):
        R.apply_flag(None, {"review_status": "zle"}, "1", NOW)


# ─── Mecze ──────────────────────────────────────────────────────────────────


def test_sezon_od_wrzesnia():
    assert R.season_key(datetime(2026, 8, 31, 12, tzinfo=timezone.utc)) == "2025/2026"
    assert R.season_key(datetime(2026, 9, 1, 12, tzinfo=timezone.utc)) == "2026/2027"
    assert R.season_key(None) == ""


def test_para_w_dowolnej_kolejnosci():
    assert R.pair_refs_match(["1", "2"], "2", "1")
    assert not R.pair_refs_match(["1", "2"], "1", "")
    assert not R.pair_refs_match(["1", "2"], "1", "3")


def test_scalanie_meczow_bez_duplikatow():
    public = R.card_from_public({"match_id": "m1", "scheduled_at": datetime(2026, 10, 10, 18), "home_team_name": "A",
                                 "away_team_name": "B", "score_home": 30, "score_away": 28, "home_club_id": "c1",
                                 "competition_name": "Liga"}, {"c1": "https://logo"}, "Seniorzy")
    province = R.card_from_state("m1", {"Hala_miasto": "Gliwice", "ID_zespoly_gosp_ZespolNazwa": "A2", "RozgrywkiCode": "X/1"},
                                 datetime(2026, 10, 10, 16, tzinfo=timezone.utc))
    other = R.card_from_state("m2", {"ID_zespoly_gosp_ZespolNazwa": "C"}, datetime(2026, 11, 1, tzinfo=timezone.utc))
    archive = R.card_from_archive({"match_id": "m3", "match_at": datetime(2024, 3, 1, tzinfo=timezone.utc),
                                   "slim_json": {"home": "Stary", "away": "Mecz", "gH": 1, "gA": 2, "cat": "Junior"}})
    merged = R.merge_matches([public], [province, other], [archive])
    assert [c["match_id"] for c in merged] == ["m2", "m1", "m3"]
    m1 = merged[1]
    assert m1["home"] == {"name": "A", "logo_url": "https://logo", "score": 30}
    assert m1["venue_city"] == "Gliwice" and m1["match_code"] == "X/1" and m1["category"] == "Seniorzy"
    assert m1["source"] == "public" and m1["season"] == "2026/2027"
    assert merged[2]["season"] == "2023/2024" and merged[2]["category"] == "Junior"
    seasons = R.seasons_of(merged)
    assert [s["season"] for s in seasons] == ["2026/2027", "2023/2024"] and seasons[0]["matches"] == 2


def test_hurtownia_trzyma_czas_polski():
    card = R.card_from_public({"match_id": "m", "scheduled_at": datetime(2026, 7, 1, 18, 0)})
    assert card["scheduled_at"] == datetime(2026, 7, 1, 16, 0, tzinfo=timezone.utc)


def test_filtry_i_nastepny_mecz():
    cards = [
        {"match_id": "a", "season": "2026/2027", "scheduled_at": NOW + timedelta(days=2), "home": {"score": None}, "starred": True,
         "competition_name": "Liga juniorów"},
        {"match_id": "b", "season": "2026/2027", "scheduled_at": NOW - timedelta(days=2), "home": {"score": 3}, "submitted": True},
        {"match_id": "c", "season": "2025/2026", "scheduled_at": NOW - timedelta(days=200), "home": {"score": 3}},
    ]
    assert [c["match_id"] for c in R.filter_cards(cards, season="2026/2027")] == ["a", "b"]
    assert [c["match_id"] for c in R.filter_cards(cards, starred=True)] == ["a"]
    assert [c["match_id"] for c in R.filter_cards(cards, submitted=False)] == ["a", "c"]
    assert [c["match_id"] for c in R.filter_cards(cards, q="JUNIOR")] == ["a"]
    nxt, last = R.next_and_last(cards, NOW)
    assert nxt["match_id"] == "a" and last["match_id"] == "b"


def test_mecz_mlodziezowy():
    assert R.is_youth("Junior młodszy", "")
    assert R.is_youth("", "Liga Młodzików")
    assert not R.is_youth("Seniorzy", "Superliga")


# ─── Arkusze i trendy ───────────────────────────────────────────────────────


def test_trendy_sekcji_priorytety_i_porownanie():
    delegate = [
        {"match_id": "m1", "date": "2026-10-01", "evaluation": {"sections": [{"key": "I", "mainGrade": "D"}, {"title": "V. Linia karania", "mainGrade": "B"}],
                                                                "priorities": [{"title": "Linia karania"}]}},
        {"match_id": "m2", "date": "15.10.2026", "evaluation": {"sections": [{"key": "I", "mainGrade": "F"}],
                                                               "priorities": [{"title": "linia  karania!"}, {"title": "Ustawienie"}]}},
    ]
    mentor = [{"match_id": "m1", "date": datetime(2026, 10, 1, 18, tzinfo=timezone.utc), "points": 5.0,
               "evaluation": {"sections": [{"key": "I", "mainGrade": "E"}], "priorities": [{"title": "Priorytet 1", "body": "Ustawienie"}]}}]
    out = R.trends(delegate, mentor)
    section_i = out["sections"][0]
    assert section_i["key"] == "I" and section_i["label"] == "I. Zarządzanie widowiskiem"
    assert [(p["date"], p["value"], p["source"]) for p in section_i["points"]] == [
        ("2026-10-01", 4, "delegate"), ("2026-10-01", 5, "mentor"), ("2026-10-15", 6, "delegate")]
    assert out["sections"][4]["points"][0]["value"] == 2
    top = out["priorities"]
    assert top[0]["count"] == 2 and {p["text"] for p in top} == {"linia  karania!", "Ustawienie"}
    assert out["delegate_vs_mentor"] == [{"match_id": "m1", "delegate": 3.0, "mentor": 5.0}]


def test_punkty_arkusza_i_sytuacje():
    assert R.sheet_points({"sections": [{"key": "I", "mainGrade": "A"}, {"key": "II", "mainGrade": "G"}, {"key": "III", "mainGrade": "ND"}]}) == 4.0
    assert R.sheet_points({}) is None
    situations = R.situations_from_sheet({"keySituations": [{"time": "23:05", "description": "x"}, {"time": "47'"}, {"time": ""}]}, "delegate", "D")
    assert [s["match_ms"] for s in situations] == [1_385_000, 2_820_000, None]


def test_forma_rosnie_gdy_oceny_lepsze():
    assert R.form_direction([3, 3, 5, 5]) == "up"
    assert R.form_direction([5, 5, 3, 3]) == "down"
    assert R.form_direction([4, 4.1]) == "steady"
    assert R.form_direction([4]) is None


def test_podsumowanie_raportu():
    matches = [{"starred": True}, {}, {}]
    summary = R.report_summary(matches, [{}, {}], [{"status": "open"}, {"status": "resolved"}],
                               [{"date": "2026-09-01", "points": 3.0}, {"date": "2026-10-01", "points": 5.0}], [])
    assert summary["matches"] == 3 and summary["starred"] == 1 and summary["clips"] == 2
    assert summary["delegate_avg"] == 4.0 and summary["form"] == "up"
    assert summary["story"][0] == "3 mecze w zakresie raportu, w tym 1 istotny."
    assert "Średnia z arkuszy delegatów: 4,00." in summary["story"]


def test_zakres_raportu():
    cfg = R.clean_report_config({"scope": {"kind": "range", "from": "2026-10-01", "to": "2026-10-31"}, "sections": ["clips", "zle", "clips"]})
    assert cfg["sections"] == ["clips"]
    assert R.in_scope({"scheduled_at": datetime(2026, 10, 5, tzinfo=timezone.utc)}, cfg["scope"])
    assert not R.in_scope({"scheduled_at": datetime(2026, 11, 5, tzinfo=timezone.utc)}, cfg["scope"])
    with pytest.raises(R.RuleError):
        R.clean_report_config({"scope": {"kind": "range", "from": "2026-11-01", "to": "2026-10-01"}})
    with pytest.raises(R.RuleError):
        R.clean_report_config({"scope": {"kind": "match"}})
    assert R.clean_report_config({})["sections"] == ["summary", "matches", "clips"]


def test_polska_odmiana():
    assert [R.plural(n, "mecz", "mecze", "meczów") for n in (1, 2, 5, 12, 22, 25)] == ["mecz", "mecze", "meczów", "meczów", "mecze", "meczów"]


# ─── Projekcja publiczna ────────────────────────────────────────────────────


def test_publiczny_klip_bez_nazwisk_i_autorow():
    clip = {"id": "c1", "title": "Kara 2 min - nr 7 Kowalski (SPR)", "note": "nr 12 Żak i nr 3", "start_s": 1, "end_s": 9,
            "category_ids": '["k1", "k2"]', "author_id": "1", "match_id": "m1"}
    video = {"kind": "link", "provider": "youtube", "url": "https://youtu.be/x", "added_by": {"name": "Anna"}}
    match = {"match_id": "m1", "category": "Junior", "competition_name": "Liga", "home": {"name": "A", "score": 1, "secret": 1},
             "away": {"name": "B"}, "delegate_name": "Delegat"}
    out = R.public_clip(clip, video=video, match=match, categories=[{"id": "k1", "name": "Dobra", "color": "emerald", "icon": "star", "created_by": "1"}])
    assert out["title"] == "Kara 2 min - nr 7 (SPR)" and out["note"] == "nr 12 i nr 3"
    assert out["categories"] == [{"name": "Dobra", "color": "emerald", "icon": "star"}]
    assert out["youth"] is True
    assert "author" not in out and "delegate_name" not in out["match"] and "secret" not in out["match"]["home"]
    assert out["source"]["url"] == "https://youtu.be/x"


def test_publiczny_raport_bez_arkuszy():
    snapshot = {"title": "R", "sections": ["summary", "sheets", "trends", "clips"],
                "summary": {"matches": 2, "delegate_avg": 4.0, "story": ["2 mecze.", "Średnia z arkuszy delegatów: 4,00."]},
                "delegate_sheets": [{"points": 4}], "trends": {"x": 1},
                "clips": [{"id": "c", "title": "nr 5 Nowak", "author": {"name": "Anna"}}]}
    out = R.public_report(snapshot)
    assert out["sections"] == ["summary", "clips"]
    assert "delegate_sheets" not in out and "trends" not in out
    assert "delegate_avg" not in out["summary"] and out["summary"]["story"] == ["2 mecze."]
    assert out["clips"][0]["title"] == "nr 5" and "author" not in out["clips"][0]


def test_adresy_publiczne():
    assert R.public_url("clip", "abc") == "https://www.bazapodreka.app/mentor/k/abc"
    assert R.public_url("compilation", "abc").endswith("/mentor/z/abc")
    assert R.public_url("report", "abc").endswith("/mentor/r/abc")
    assert R.public_url("clip", None) is None


# ─── Retencja i wgrywanie ───────────────────────────────────────────────────


def test_retencja_12_miesiecy_od_meczu():
    assert R.upload_expires_at(datetime(2026, 2, 28, tzinfo=timezone.utc), NOW) == datetime(2027, 2, 28, tzinfo=timezone.utc)
    assert R.upload_expires_at(None, NOW) == datetime(2027, 10, 21, 12, 0, tzinfo=timezone.utc)
    assert R.add_months(datetime(2024, 2, 29), 12) == datetime(2025, 2, 28)


def test_akcje_retencji():
    ready = {"status": "ready", "r2_key": "o", "play_key": "p", "expires_at": NOW + timedelta(days=1), "created_at": NOW}
    assert R.retention_actions(ready, NOW) == {"expire": False, "delete_original": True, "abort": False}
    assert R.retention_actions({**ready, "r2_key": None}, NOW)["delete_original"] is False
    assert R.retention_actions({**ready, "expires_at": NOW}, NOW)["expire"] is True
    stale = {"status": "uploading", "created_at": NOW - timedelta(days=2), "expires_at": NOW + timedelta(days=300)}
    assert R.retention_actions(stale, NOW)["abort"] is True
    assert R.retention_actions({**stale, "created_at": NOW}, NOW)["abort"] is False


def test_wgrywanie_czesci():
    assert R.validate_upload("mecz.mp4", 1000, "video/mp4") == ("mecz.mp4", 1000, "video/mp4")
    with pytest.raises(R.RuleError):
        R.validate_upload("a.mp4", R.MAX_UPLOAD_BYTES + 1, "video/mp4")
    with pytest.raises(R.RuleError):
        R.validate_upload("a.pdf", 10, "application/pdf")
    assert R.upload_parts(R.PART_SIZE * 2 + 1) == 3
    assert R.part_batch(100, 1) == list(range(1, 41)) and R.part_batch(100, 81) == list(range(81, 101))
    assert R.part_batch(3, 5) == []
    assert R.clean_parts([{"n": 2, "etag": "b"}, {"n": 1, "etag": "a"}], 2) == [{"PartNumber": 1, "ETag": "a"}, {"PartNumber": 2, "ETag": "b"}]
    with pytest.raises(R.RuleError):
        R.clean_parts([{"n": 1, "etag": "a"}], 2)


def test_postep_ffmpeg_i_transkodowanie():
    assert R.ffmpeg_progress("out_time_ms=30000000", 60) == 0.5
    assert R.ffmpeg_progress("out_time_ms=90000000", 60) == 0.99
    assert R.ffmpeg_progress("frame=1", 60) is None
    args = R.transcode_args("in", "out.mp4", 2160)
    assert "scale=-2:1080" in args and "+faststart" in args and args[args.index("-crf") + 1] == "23"
    assert "-vf" not in R.transcode_args("in", "out.mp4", 720)


def test_obecnosc_i_nieprzeczytane():
    assert R.clean_where("match:m1") == "match:m1"
    assert R.clean_where("javascript:alert(1)") == "dashboard"
    items = [{"author_id": "1", "created_at": NOW}, {"author_id": "2", "created_at": NOW}, {"author_id": "2", "created_at": NOW - timedelta(days=2)}]
    assert R.unread_count(items, "1", NOW - timedelta(days=1)) == 1
    assert R.unread_count(items, "1", None) == 2
