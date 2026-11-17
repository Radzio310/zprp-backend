"""Miejsce oglądania nagrania (17.11.2026): czyste reguły i trasy na małej bazie SQLite."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app import mentor_watch_rules as W
from tests.mentor_panel_support import ADMIN, JUDGES, MENTOR, PAIR, STRANGER, Env

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
SYNC = {"match_start_s": 300, "second_half_s": 2400, "half_minutes": 30, "break_minutes": 10}


def ms(dt):
    return int(dt.timestamp() * 1000)


# ─── Reguły ─────────────────────────────────────────────────────────────────


def test_koniec_oglądania_klient_zna_czas_gry_serwer_ma_tylko_regule_zastepcza():
    # Serwer NIE liczy czasu gry (zegar staje przy przerwach w grze, liniowo rozjeżdża się o minuty).
    assert not hasattr(W, "game_seconds") and not hasattr(W, "end_threshold_s")
    # Bez znacznika od klienta: tylko 95% długości albo ostatnie 180 s; bez długości nigdy.
    assert W.is_finished(3800, 4000) is True and W.is_finished(3700, 4000) is False and W.is_finished(3850, 4000) is True
    assert W.is_finished(99999, None) is False
    # Klient ze śladem zegara stwierdził koniec (reached_end -> finished_at): obowiązuje niezależnie od długości nagrania.
    assert W.is_finished(1000, 9999, NOW) is True


def test_zapis_czysty_i_ostatni_wygrywa():
    s1 = W.clean_save({"position_s": 100, "device": "tablet", "saved_at": ms(NOW)}, NOW)
    assert s1["device"] == "tablet" and s1["saved_at"] == NOW
    assert W.clean_save({"position_s": 10, "source": "calibration"}, NOW) == {"ignored": "source"}
    assert W.clean_save({"position_s": 10, "device": "toster"}, NOW)["device"] is None
    assert W.clean_save({"position_s": 10, "saved_at": ms(NOW + timedelta(days=3))}, NOW)["saved_at"] <= NOW + timedelta(minutes=5)
    first = W.merge_save(None, s1)
    assert first["apply"] and first["values"]["furthest_s"] == 100
    row = {**first["values"]}
    older = W.clean_save({"position_s": 500, "saved_at": ms(NOW - timedelta(minutes=1))}, NOW)
    res = W.merge_save(row, older)
    assert res["apply"] is False and res["values"] == {"furthest_s": 500}       # starszy zapis: miejsce zostaje, najdalsze rośnie
    newer = W.clean_save({"position_s": 40, "saved_at": ms(NOW + timedelta(minutes=1))}, NOW)
    res = W.merge_save({**row, "furthest_s": 500}, newer)
    assert res["apply"] and res["values"]["position_s"] == 40 and res["values"]["furthest_s"] == 500
    assert W.merge_save(None, W.clean_save({"position_s": 2}, NOW))["values"] is None   # otwarcie filmu nic nie tworzy
    assert W.merge_save(row, W.clean_save({"position_s": 1, "saved_at": ms(NOW + timedelta(minutes=2))}, NOW))["apply"] is False


def test_ksztalt_propozycja_odrzucenie_i_procent():
    base = {"video_id": "v", "match_id": "m", "pair_id": "p", "position_s": 2461, "furthest_s": 2461, "duration_s": 4000, "device": "phone", "saved_at": NOW}
    shaped = W.shape(base)
    assert shaped["propose"] is True and shaped["percent"] == 61 and shaped["device"] == "phone" and "match_s" not in shaped
    assert W.shape({**base, "dismissed_saved_at": NOW})["propose"] is False
    assert W.shape({**base, "dismissed_saved_at": NOW - timedelta(minutes=1)})["propose"] is True  # odrzucone było starsze miejsce
    assert W.shape({**base, "position_s": 10, "furthest_s": 10})["propose"] is False
    done = W.shape({**base, "position_s": 100, "furthest_s": 3900})
    assert done["finished"] and done["propose"] is False and done["percent"] == 100
    flagged = W.shape({**base, "finished_at": NOW})
    assert flagged["finished"] and flagged["percent"] == 100


def test_reached_end_jest_lepkie_i_scala_sie_ze_starszym_zapisem():
    first = W.merge_save(None, W.clean_save({"position_s": 3000, "saved_at": ms(NOW), "reached_end": True}, NOW))
    assert first["values"]["finished_at"] == NOW
    row = {**first["values"]}
    later = W.merge_save(row, W.clean_save({"position_s": 100, "saved_at": ms(NOW + timedelta(minutes=5))}, NOW + timedelta(minutes=5)))
    assert later["apply"] and "finished_at" not in later["values"]                   # nie nadpisuje, istniejące zostaje
    stale = W.merge_save({"position_s": 50, "furthest_s": 50, "saved_at": NOW}, W.clean_save({"position_s": 3000, "saved_at": ms(NOW - timedelta(minutes=1)), "reached_end": True}, NOW))
    assert stale["apply"] is False and stale["values"]["finished_at"] == NOW - timedelta(minutes=1)


# ─── Trasy ──────────────────────────────────────────────────────────────────


@pytest.fixture
def env(monkeypatch, tmp_path):
    return Env(monkeypatch, tmp_path)


async def code(coro):
    try:
        await coro
    except HTTPException as exc:
        return exc.status_code
    raise AssertionError("oczekiwano odmowy")


def test_trasy_miejsce_prywatne_miedzy_urzadzeniami(env):
    async def go():
        P = env.watch
        a, b, mentor = await env.actor(JUDGES[0]), await env.actor(JUDGES[1]), await env.actor(MENTOR)
        await env.db.execute(env.T["mentor_match_videos"].update().where(env.T["mentor_match_videos"].c.id == "v1")
                             .values(sync_json='{"match_start_s": 300, "second_half_s": 2400, "half_minutes": 30, "break_minutes": 10}'))
        t0 = datetime.now(timezone.utc)
        phone = await P.save_watch(PAIR, "m1", "v1", P.WatchBody(position_s=2461, duration_s=4000, device="phone", saved_at=ms(t0)), a)
        stale = await P.save_watch(PAIR, "m1", "v1", P.WatchBody(position_s=50, device="desktop", saved_at=ms(t0 - timedelta(minutes=5))), a)
        early = await P.save_watch(PAIR, "m1", "v1", P.WatchBody(position_s=2, device="desktop", saved_at=ms(t0 + timedelta(seconds=30))), a)
        calib = await P.save_watch(PAIR, "m1", "v1", P.WatchBody(position_s=3000, source="calibration", saved_at=ms(t0 + timedelta(minutes=1))), a)
        desktop = await P.get_watch(PAIR, "m1", "v1", a)
        partner = await P.get_watch(PAIR, "m1", "v1", b)
        mentor_view = await P.get_watch(PAIR, "m1", "v1", mentor)
        batch = await P.watch_for_matches(PAIR, "m1,m2", a)
        recent = await P.recent_for_pair(PAIR, 10, a)
        dismissed = await P.dismiss_watch(PAIR, "m1", "v1", P.DismissBody(saved_at=desktop["watch"]["saved_at"]), a)
        recent_after = await P.recent_all(10, a)
        newer = await P.save_watch(PAIR, "m1", "v1", P.WatchBody(position_s=2400, device="tablet", saved_at=ms(t0 + timedelta(minutes=10))), a)
        denied = await code(P.get_watch(PAIR, "m1", "v1", await env.actor(STRANGER)))
        missing = await code(P.get_watch(PAIR, "m1", "nie-ma", a))
        return phone, stale, early, calib, desktop, partner, mentor_view, batch, recent, dismissed, recent_after, newer, denied, missing

    phone, stale, early, calib, desktop, partner, mentor_view, batch, recent, dismissed, recent_after, newer, denied, missing = env.run(go)
    assert phone["applied"] and phone["watch"]["device"] == "phone" and "match_s" not in phone["watch"]
    assert stale["applied"] is False and stale["watch"]["position_s"] == 2461      # starszy zapis z drugiego urządzenia nie nadpisuje
    assert early["applied"] is False and early["watch"]["position_s"] == 2461      # otwarcie filmu (2 s) nie kasuje miejsca
    assert calib["ignored"] == "source" and calib["watch"]["position_s"] == 2461
    assert desktop["watch"]["propose"] is True and desktop["watch"]["percent"] == 61
    assert partner["watch"] is None and mentor_view["watch"] is None                 # miejsce jest tylko moje
    assert list(batch["progress"]) == ["m1"] and batch["progress"]["m1"]["video_id"] == "v1"
    assert [i["match_id"] for i in recent["items"]] == ["m1"] and recent["items"][0]["video"]["id"] == "v1" and recent["items"][0]["match"]
    assert dismissed["dismissed"] is True and dismissed["watch"]["propose"] is False
    assert recent_after["items"] == []                                               # odrzucone nie wraca do „Oglądaj dalej"
    assert newer["watch"]["propose"] is True and newer["watch"]["device"] == "tablet"  # nowsze miejsce znów proponowane
    assert denied == 403 and missing == 404


def test_usuniete_nagranie_znika_z_odczytow(env):
    async def go():
        P = env.watch
        a = await env.actor(JUDGES[0])
        await P.save_watch(PAIR, "m1", "v1", P.WatchBody(position_s=600, duration_s=4000), a)
        V = env.T["mentor_match_videos"]
        await env.db.execute(V.update().where(V.c.id == "v1").values(deleted_at=datetime.now(timezone.utc)))
        batch = await P.watch_for_matches(PAIR, "m1", a)
        recent = await P.recent_for_pair(PAIR, 10, a)
        await env.db.execute(V.update().where(V.c.id == "v1").values(deleted_at=None))      # przywrócone z kosza
        back = await P.watch_for_matches(PAIR, "m1", a)
        await P.forget_video("v1")
        gone = await P.get_watch(PAIR, "m1", "v1", a)
        return batch, recent, back, gone

    batch, recent, back, gone = env.run(go)
    assert batch["progress"] == {} and recent["items"] == []
    assert back["progress"]["m1"]["position_s"] == 600 and gone["watch"] is None
