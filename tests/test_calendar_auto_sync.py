"""Kalendarz Google w tle (BAZA 2.1.8): reguły i silnik na atrapach, bez bazy i bez Google."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from app.calendar_auto_sync import Deps, sync_user
from app.calendar_auto_sync_rules import (
    Known,
    Profile,
    desired_event,
    fingerprint_of,
    judge_role,
    match_start,
    plan_sync,
    reminders_for_start,
)

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc)
PROFILE = Profile(user_login="radzio", judge_id="865", match_color="9", table_color="10", reminder_rules=None)


def state(**over):
    base = {
        "Id": "211647",
        "RozgrywkiCode": "IIM4/12",
        "data_fakt": "2026-11-21 18:00",
        "ID_zespoly_gosp_ZespolNazwa": "MKS Mysłowice",
        "ID_zespoly_gosc_ZespolNazwa": "Pogoń Zabrze",
        "Hala_miasto": "Mysłowice",
        "Hala_ulica": "Bończyka",
        "Hala_numer": "34",
        "NrSedzia_pierwszy": "865",
        "NrSedzia_drugi": "900",
    }
    base.update(over)
    return base


def test_tytul_miejsce_i_godzina_jak_z_telefonu():
    ev = desired_event(state(), "211647", PROFILE)
    assert ev["summary"] == "⚽️ IIM4/12 - MKS Mysłowice vs Pogoń Zabrze"
    assert ev["location"] == "Mysłowice ul. Bończyka 34"
    # 18:00 w Polsce zimą = 17:00 UTC.
    assert ev["start"] == datetime(2026, 11, 21, 17, 0, tzinfo=timezone.utc)
    assert ev["colorId"] == "9"


def test_stolik_ma_stoper_i_kolor_stolikowy_a_zamiana_odwraca_druzyny():
    ev = desired_event(state(NrSedzia_pierwszy="1", NrSedzia_sekretarz="865", host_swapped=True), "211647", PROFILE)
    assert ev["summary"].startswith("⏱️ ")
    assert ev["summary"].endswith("Pogoń Zabrze vs MKS Mysłowice")
    assert ev["colorId"] == "10"


def test_bez_godziny_albo_bez_roli_nie_ma_wpisu():
    assert desired_event(state(data_fakt="2026-11-21"), "1", PROFILE) is None
    assert desired_event(state(data_fakt_time_known=False), "1", PROFILE) is None
    assert judge_role(state(NrSedzia_pierwszy="1"), "865") is None


def test_przypomnienia_domyslne_i_o_siodmej():
    start = match_start(state())
    assert reminders_for_start(start, None) == [
        {"method": "popup", "minutes": 1440},
        {"method": "popup", "minutes": 180},
        {"method": "popup", "minutes": 660},  # 7:00 -> 18:00
    ]
    assert reminders_for_start(start, []) == []


def test_plan_nowy_zmieniony_usuniety_i_bez_odcisku():
    a = desired_event(state(Id="a"), "a", PROFILE)
    b = desired_event(state(Id="b", data_fakt="2026-11-22 12:00"), "b", PROFILE)
    c = desired_event(state(Id="c"), "c", PROFILE)
    plan = plan_sync(
        desired={"a": a, "b": b, "c": c},
        known=[
            Known("b", "stary-odcisk"),
            Known("c", None),
            Known("gone", "x"),
            Known("poza-monitorem", "x"),
        ],
        monitored_future={"gone"},
    )
    assert [e["matchId"] for e in plan.create] == ["a"]
    assert [e["matchId"] for e in plan.update] == ["b"]
    assert [e["matchId"] for e in plan.seed] == ["c"]
    # Mecz spoza monitora (inny okręg, liga centralna) zostaje nietknięty.
    assert plan.delete == ["gone"]


def test_ten_sam_odcisk_nie_daje_zapisu():
    a = desired_event(state(), "a", PROFILE)
    plan = plan_sync(desired={"a": a}, known=[Known("a", fingerprint_of(a))], monitored_future=set())
    assert not plan.create and not plan.update and not plan.delete


def test_silnik_wykonuje_plan_i_liczy_bledy():
    log = []

    async def my_matches(judge_id, now):
        return [("new", state(Id="new")), ("moved", state(Id="moved", data_fakt="2026-11-23 10:00"))]

    async def known(user):
        return [Known("moved", "old"), Known("cancelled", "x")]

    async def monitored(ids, now):
        return {"cancelled"}

    async def write(user, ev):
        log.append(("write", ev["matchId"]))
        if ev["matchId"] == "new":
            raise RuntimeError("google 500")

    async def remove(user, match_id):
        log.append(("remove", match_id))

    async def seed(user, ev):
        log.append(("seed", ev["matchId"]))

    deps = Deps(my_matches=my_matches, known=known, monitored_future=monitored, write=write, remove=remove, seed=seed)
    res = asyncio.run(sync_user(PROFILE, deps, now=NOW))
    assert ("write", "moved") in log and ("remove", "cancelled") in log and ("write", "new") in log
    assert (res.updated, res.deleted, res.created, res.errors) == (1, 1, 0, 1)
    assert res.first_error and "google 500" in res.first_error


def test_limit_zapisow_na_przebieg():
    async def my_matches(judge_id, now):
        return [(str(i), state(Id=str(i))) for i in range(10)]

    async def none(*_a):
        return []

    async def empty(*_a):
        return set()

    writes = []

    async def write(user, ev):
        writes.append(ev["matchId"])

    async def noop(*_a):
        return None

    deps = Deps(my_matches=my_matches, known=none, monitored_future=empty, write=write, remove=noop, seed=noop)
    res = asyncio.run(sync_user(PROFILE, deps, now=NOW, limit=3))
    assert res.created == 3 and len(writes) == 3
