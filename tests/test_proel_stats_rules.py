"""Statystyki ProEla - reguły bez bazy.

Wszystko, co decyduje o liczbach w panelu, mieszka w `app/proel_stats_rules.py`
i jest sprawdzane tutaj. Router tylko zbiera wiersze.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.proel_stats_rules import (
    CENTRAL,
    UNKNOWN,
    build_stats,
    canon_province,
    learn_prefix_provinces,
    match_province,
    match_summary,
    person_kind,
    person_province,
    prefix_of,
)

NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)


def _at(hours_ago: float) -> str:
    return (NOW - timedelta(hours=hours_ago)).isoformat()


# ─────────────────────────── województwo meczu ───────────────────────────


def test_przedrostek_okregu_czytamy_tylko_z_pierwszego_czlonu():
    assert prefix_of("S/PPK/2") == "S"
    assert prefix_of("KP/JM/3") == "KP"
    # Kod rozgrywek na początku to NIE jest okręg.
    assert prefix_of("SM/8") == ""
    assert prefix_of("MP/JM/12") == ""
    assert prefix_of("LC/5") == ""
    assert prefix_of("IIM4/1") == ""
    assert prefix_of("") == ""


def test_mape_przedrostkow_uczymy_z_terminarzy_a_nie_zgadujemy():
    rows = [
        ("ŚLĄSKIE", "S/JM/1"),
        ("ŚLĄSKIE", "S/JK/2"),
        ("ŚLĄSKIE", "S/IIIM/3"),
        ("MAZOWIECKIE", "W/JM/1"),
    ]
    learned = learn_prefix_provinces(rows)
    assert learned == {"S": "SLASKIE", "W": "MAZOWIECKIE"}


def test_remis_w_glosowaniu_nie_przypisuje_wojewodztwa():
    # Lepiej „nieznane" niż mecz przypisany cudzemu okręgowi.
    rows = [("ŚLĄSKIE", "X/JM/1"), ("OPOLSKIE", "X/JM/2")]
    assert "X" not in learn_prefix_provinces(rows)


def test_runda_centralna_pucharu_nie_uczy_mapy():
    # „L/PM/1" to runda centralna Pucharu Polski - przedrostek nie jest okręgiem.
    rows = [("LUBELSKIE", "L/PM/1"), ("LUBELSKIE", "L/PM/2")]
    assert learn_prefix_provinces(rows) == {}


def test_wojewodztwo_meczu():
    learned = {"S": "SLASKIE"}
    assert match_province("S/JM/5", "district", learned) == "SLASKIE"
    assert match_province("SM/8", "central", learned) == CENTRAL
    assert match_province("L/PM/1", "cup", learned) == CENTRAL
    # Przedrostek, którego terminarze nie znają - nie zgadujemy.
    assert match_province("Q/JM/1", "district", learned) == UNKNOWN


def test_kanoniczne_wojewodztwo_laczy_zapisy():
    assert canon_province("Śląskie") == canon_province("SLASKIE") == "SLASKIE"
    assert canon_province("łódzkie") == "LODZKIE"
    assert canon_province("") == ""


# ─────────────────────────── podsumowanie meczu ───────────────────────────


def _blob(**over):
    base = {
        "date": "2026-09-06T16:00:00.000Z",
        "scoreHost": 30,
        "scoreGuest": 27,
        "matchConfig": {
            "matchNumber": "SM/8",
            "hostTeamName": "Gospodarze",
            "guestTeamName": "Goście",
            "venueCity": "Kielce",
            "origin": "account",
        },
        "hostPlayerStats": [
            {"number": 7, "goals": 5, "penalty1": "12:00", "penalty2": "40:00"},
            {"number": 9, "goals": 0, "warning": "5:00"},
            {"number": 11, "goals": 0, "disqualification": "50:00"},
        ],
        "guestPlayerStats": [
            {"number": 3, "goals": 2, "disqualification": "20:00", "disqualificationDesc": "x"},
            {"number": 4, "goals": 0, "penaltyExtra": "30:00", "entered": True},
        ],
        "protocol": [
            {"type": "penaltyKickScored", "team": "host"},
            {"type": "penaltyKickMissed", "team": "guest"},
            # Karne z SERII po remisie nie są rzutami karnymi z gry.
            {"type": "penaltyKickScored", "team": "host", "shootout": True},
            {"type": "teamTime", "team": "host"},
        ],
    }
    base.update(over)
    return base


def test_podsumowanie_liczy_sport_i_klasyfikuje_mecz():
    s = match_summary("SM/8", "approved", _blob())
    assert s["competition"] == "superliga"
    assert s["gender"] == "M"
    assert s["level"] == "central"
    assert s["season"] == 2026
    assert s["goals"] == 57
    assert s["suspensions"] == 2
    assert s["extra_suspensions"] == 1
    assert s["warnings"] == 1
    # Czerwona z niebieską to NIE jest zwykła czerwona.
    assert s["red"] == 1
    assert s["blue"] == 1
    assert s["pk_scored"] == 1
    assert s["pk_missed"] == 1
    assert s["timeouts"] == 1
    assert s["players_entered"] == 3
    assert s["training"] is False


def test_podsumowanie_nie_niesie_danych_osobowych_zawodnikow():
    s = match_summary("SM/8", "approved", _blob())
    assert "hostPlayerStats" not in s
    assert "protocol" not in s
    assert "Gospodarze" == s["host"]  # nazwa drużyny tak, nazwiska nie


def test_blob_jako_napis_tez_sie_liczy():
    # asyncpg bez kodeka oddaje JSON jako surowy napis.
    import json

    s = match_summary("SM/8", "approved", json.dumps(_blob()))
    assert s["goals"] == 57


def test_mecz_szkoleniowy_rozpoznajemy_po_kluczu():
    s = match_summary("T-K3N8P2WQ/SPM/1", "finished", _blob())
    assert s["training"] is True
    assert s["number"] == "SPM/1"
    assert s["competition"] == "superpuchar"


def test_seria_karnych():
    assert match_summary("SM/8", "finished", _blob(penaltyScore="4 - 3"))["shootout"] is True
    assert match_summary("SM/8", "finished", _blob())["shootout"] is False


# ─────────────────────────── ludzie ───────────────────────────


def test_rodzaj_osoby():
    assert person_kind("12345") == "judge"
    assert person_kind("proel:7") == "account"
    assert person_kind("inst:abc") == "device"


def test_wojewodztwo_osoby():
    kw = dict(judges={"1": "ŚLĄSKIE"}, logins={"2": "opolskie"}, accounts={"7": "Pomorskie"})
    assert person_province("1", **kw) == "SLASKIE"
    assert person_province("2", **kw) == "OPOLSKIE"
    assert person_province("proel:7", **kw) == "POMORSKIE"
    assert person_province("inst:x", **kw) == UNKNOWN


# ─────────────────────────── całość ───────────────────────────


def _ev(match, event, actor, name, hours_ago, **details):
    return {
        "match_number": match,
        "event": event,
        "actor_judge_id": actor,
        "actor_name": name,
        "app_version": "2.0.2",
        "details": details,
        "created_at": _at(hours_ago),
    }


def _stats(summaries, events, **kw):
    return build_stats(
        summaries=summaries,
        events=events,
        learned_prefixes={"S": "SLASKIE"},
        judge_provinces={"100": "ŚLĄSKIE", "200": "MAZOWIECKIE"},
        login_provinces={},
        account_provinces={},
        now=NOW,
        **kw,
    )


def _two_matches():
    a = match_summary("SM/8", "approved", _blob())
    b = match_summary("S/JM/5", "finished", _blob(date=_at(80)))
    t = match_summary("T-K3N8P2WQ/SPM/1", "finished", _blob())
    events = [
        # SM/8: prowadził 100, dokończył 200 (sesja podniesiona)
        _ev("SM/8", "match.created", "100", "STOLIK Adam", 50),
        _ev("SM/8", "match.live_started", "100", "STOLIK Adam", 49),
        _ev("SM/8", "match.finished", "100", "STOLIK Adam", 48),
        _ev("SM/8", "zprp.summary_sent", "200", "BOISKO Jan", 47),
        _ev("SM/8", "zprp.full_data_sent", "200", "BOISKO Jan", 46, via="legacy", admin=True),
        _ev("SM/8", "protocol.pdf_generated", "200", "BOISKO Jan", 45),
        _ev("SM/8", "match.approved", "200", "BOISKO Jan", 44),
        _ev("SM/8", "zprp.send_failed", "200", "BOISKO Jan", 46.5),
        # S/JM/5: bez startu na żywo - prowadzącym jest zakładający
        _ev("S/JM/5", "match.created", "200", "BOISKO Jan", 80),
        _ev("S/JM/5", "match.finished", "200", "BOISKO Jan", 70),
        # szkolenie
        _ev("T-K3N8P2WQ/SPM/1", "match.live_started", "300", "KURSANT", 5),
    ]
    return [a, b, t], events


def test_prowadzacy_i_wykonawcy_to_dwie_osie():
    summaries, events = _two_matches()
    out = _stats(summaries, events)
    people = {p["id"]: p for p in out["people"]["list"]}
    assert people["100"]["ran"] == 1  # SM/8 prowadził stolikowy
    assert people["100"]["finished"] == 0
    assert people["200"]["ran"] == 1  # S/JM/5 - tylko zakładał
    assert people["200"]["finished"] == 1  # dokończył SM/8
    assert people["200"]["actions"]["zprp.full_data_sent"] == 1


def test_szkolenia_domyslnie_poza_liczbami_ale_w_swojej_zakladce():
    summaries, events = _two_matches()
    out = _stats(summaries, events)
    assert out["pulse"]["matches"] == 2
    assert "300" not in {p["id"] for p in out["people"]["list"]}
    assert out["training"]["matches"] == 1
    with_training = _stats(summaries, events, filters={"training": True})
    assert with_training["pulse"]["matches"] == 3


def test_obieg_i_utkniete_mecze():
    summaries, events = _two_matches()
    out = _stats(summaries, events)
    stages = {s["key"]: s["count"] for s in out["flow"]["stages"]}
    assert stages["created"] == 2
    assert stages["finished"] == 2
    assert stages["summary"] == 1
    assert stages["approved"] == 1
    # S/JM/5 zakończony 70 h temu i niezatwierdzony.
    assert out["pulse"]["stuck"] == 1
    assert out["flow"]["stuck"][0]["number"] == "S/JM/5"
    assert "Zatwierdzony" in out["flow"]["stuck"][0]["missing"]


def test_czasy_od_gwizdka():
    summaries, events = _two_matches()
    out = _stats(summaries, events)
    assert out["time"]["durations"]["to_summary_h"] == 1.0
    assert out["time"]["durations"]["to_approved_h"] == 4.0


def test_jakosc_liczy_droge_awaryjna_i_admina():
    summaries, events = _two_matches()
    out = _stats(summaries, events)
    q = out["quality"]
    assert q["legacy_route"] == 1
    assert q["admin_actions"] == 1
    assert q["failed_matches"] == 1
    assert q["recovered_matches"] == 1  # pełne dane w końcu poszły
    failed = {e["key"]: e["count"] for e in q["events"]}
    assert failed["zprp.send_failed"] == 1


def test_dwa_wymiary_wojewodztwa():
    summaries, events = _two_matches()
    out = _stats(summaries, events)
    by_match = {r["key"]: r["count"] for r in out["provinces"]["matches"]}
    assert by_match == {CENTRAL: 1, "SLASKIE": 1}
    by_runner = {r["key"]: r["count"] for r in out["provinces"]["runners"]}
    assert by_runner == {"SLASKIE": 1, "MAZOWIECKIE": 1}


def test_filtry():
    summaries, events = _two_matches()
    assert _stats(summaries, events, filters={"competition": "superliga"})["pulse"]["matches"] == 1
    assert _stats(summaries, events, filters={"level": "district"})["pulse"]["matches"] == 1
    assert _stats(summaries, events, filters={"match_province": "SLASKIE"})["pulse"]["matches"] == 1
    assert (
        _stats(summaries, events, filters={"person_province": "MAZOWIECKIE"})["pulse"]["matches"]
        == 1
    )
    # Filtr nie zmienia listy dostępnych wartości - inaczej nie dałoby się
    # przełączyć z jednej ligi na drugą.
    facets = _stats(summaries, events, filters={"competition": "superliga"})["facets"]
    assert "junior" in facets["competitions"]


def test_mapa_ciepla_w_czasie_polskim():
    summaries, events = _two_matches()
    out = _stats(summaries, events)
    heat = out["time"]["heatmap"]
    assert len(heat) == 7 and all(len(row) == 24 for row in heat)
    assert sum(sum(row) for row in heat) == 2


def test_sport_per_liga():
    summaries, events = _two_matches()
    out = _stats(summaries, events)
    overall = out["sport"]["overall"]
    assert overall["matches"] == 2
    assert overall["goals"] == 57.0
    assert overall["home_wins"] == 1.0
    assert out["sport"]["records"]["goals"][0]["value"] == 57
