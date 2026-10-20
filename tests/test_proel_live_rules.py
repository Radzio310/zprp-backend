"""Przebieg meczu z ProEla dla portalu: strony, cofnięte bramki, wynik po zdarzeniu, prywatność."""

from app.zprp_public import proel_live_rules as L


def _blob(**over):
    base = {
        "matchConfig": {"matchNumber": "P/JK/6", "matchId": "212530", "hostTeamName": "SMS Enea Gniezno",
                        "guestTeamName": "KS Pyrki Poznań", "halfTime": 30,
                        "hostPlayerCards": [{"number": 7, "fullName": "TAJNE Nazwisko", "licence": "X"}]},
        "scoreHost": 2, "scoreGuest": 1,
        "protocol": [
            {"type": "goal", "team": "host", "player": 7, "time": 65_000, "half": 1},
            {"type": "goal", "team": "guest", "player": "3", "time": 120_000, "half": 1},
            {"type": "goal", "team": "host", "player": 9, "time": 200_000, "half": 1},
            {"type": "goalRemoved", "team": "host", "player": 9, "time": 210_000, "half": 1, "extra": '{"origTime": 200000}'},
            {"type": "penaltyKickScored", "team": "host", "player": 7, "time": 1_900_000, "half": 2},
            {"type": "penalty2", "team": "guest", "player": 3, "time": 1_950_000, "half": 2},
            {"type": "warning", "team": "guest", "player": "B", "time": 300_000, "half": 1},
            {"type": "teamTime", "team": "guest", "time": 1_000_000, "half": 1, "extra": "T1"},
            {"type": "goal", "team": "guest", "player": 5, "time": 3_600_000, "half": 2, "shootout": True},
        ],
        "penaltyShots": {"host": [{"player": 7, "result": 1}], "guest": [{"player": 5, "result": 0}]},
        "penaltyTiles": [{"team": "guest", "playerNumber": 3, "type": "II", "assignedAt": 1_950_000, "duration": 120_000}],
        "teamTimeouts": {"host": {"first": None}, "guest": {"first": 1_000_000, "second": None}},
        "penaltyStats": {"host": {"total": 1, "goals": 1}},
        "mainTime": 1_960_000, "isFirstHalf": False, "isGameRunning": True, "savedAtMs": 1_700_000_000_000,
        "halfScore": {"host": 1, "guest": 1},
    }
    base.update(over)
    return base


def test_przebieg_chronologicznie_z_wynikiem_i_bez_cofnietej_bramki():
    tl = L.timeline(_blob())
    kinds = [(e["kind"], e["side"], e["number"], e["staff"]) for e in tl["events"]]
    assert ("goal", "home", 9, None) not in kinds  # cofnięta
    assert kinds[0] == ("goal", "home", 7, None)
    assert ("warning", "away", None, "B") in kinds
    assert tl["events"][-1]["kind"] == "two_min" and tl["events"][-1]["step"] == 2
    assert [e["score"] for e in tl["events"] if e["kind"] in ("goal", "seven_goal")] == [
        {"home": 1, "away": 0}, {"home": 1, "away": 1}, {"home": 2, "away": 1}]
    assert tl["half_ms"] == 1_800_000
    assert all(not e.get("shootout") for e in tl["events"])  # seria karnych osobno
    assert tl["shootout"]["home"] == [{"number": 7, "scored": True}]


def test_zamiana_stron_po_nazwach():
    cfg = _blob()["matchConfig"]
    assert L.host_is_home(cfg, "SMS Enea Gniezno", "KS Pyrki Poznań") is True
    assert L.host_is_home(cfg, "KS Pyrki Poznań", "SMS Enea Gniezno") is False
    # nazwy nic nie mówią - decyduje flaga z konfiguratora
    assert L.host_is_home({**cfg, "hostTeamName": "?", "guestTeamName": "?", "hostSwapped": True}, "A", "B") is False
    tl = L.timeline(_blob(), host_home=False)
    assert tl["events"][0]["side"] == "away"


def test_tablica_wyniku():
    b = L.board(_blob())
    assert b["score"] == {"home": 2, "away": 1}
    assert b["half_score"] == {"home": 1, "away": 1}
    assert b["clock"]["running"] is True and b["clock"]["first_half"] is False
    assert b["penalties"][0]["side"] == "away" and b["penalties"][0]["duration_ms"] == 120_000
    assert b["timeouts"] == {"home": 0, "away": 1}
    assert b["sevens"]["home"] == {"total": 1, "goals": 1}
    # w pierwszej połowie wynik do przerwy jeszcze nie istnieje
    assert L.board(_blob(isFirstHalf=True))["half_score"] is None


def test_prywatnosc_tylko_dane_sportowe():
    blob = _blob()
    text = repr(L.timeline(blob)) + repr(L.board(blob))
    assert "TAJNE" not in text and "licence" not in text


def test_cwiczenia_i_testy_nie_sa_publiczne():
    assert L.is_public_blob(_blob()) is True
    assert L.is_public_blob(_blob(matchConfig={"isTest": True})) is False
    assert L.is_public_blob(_blob(matchConfig={"training": {"eventId": "x"}})) is False
    assert L.is_public_blob(None) is False


def test_odcisk_zmienia_sie_przy_zapisie():
    a = L.doc_token([("P/1", 3, "2026-10-20T15:00:00")])
    assert a == L.doc_token([("P/1", 3, "2026-10-20T15:00:00")])
    assert a != L.doc_token([("P/1", 4, "2026-10-20T15:00:00")])
