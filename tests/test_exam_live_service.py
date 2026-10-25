"""Egzamin na żywo - serwis na SQLite: uprawnienia, fazy, ocena, punkty, goście, wyniki trwałe."""

import json
from datetime import timedelta

import pytest
import pytest_asyncio

from app import exam_live_rules as L
from app import exam_live_service as V
from app import exam_service as S
from app.exam_rules import ExamError
from exam_live_support import (ADMIN, CORRECT, HOST, OPOLE, OTHER, PLAIN, PLAYERS, SINGLES, T0, TEACH,
                               create_body, make_store, who)


@pytest_asyncio.fixture
async def ls(tmp_path):
    store = make_store(tmp_path / "live.db")
    await store.database.connect()
    yield store
    await store.database.disconnect()


async def new_session(ls, w=HOST, now=T0, **over):
    state = await V.create_session(ls, w, create_body(**over), now)
    return state["session"]["id"], state


async def join_players(ls, sid, count, now=T0):
    out = []
    for w in PLAYERS[:count]:
        joined = await V.join_user(ls, w, {"pin": (await V.session_row(ls, sid))["pin"]}, now)
        out.append(joined["participant"])
    return out


async def code_of(ls, expr):
    with pytest.raises(ExamError) as err:
        await expr
    return err.value.code


# --- uprawnienia i tworzenie ----------------------------------------------


async def test_tworzenie_uprawnienia_jak_egzamin_okregowy_i_krajowy(ls):
    for allowed in (HOST, ADMIN, TEACH):
        state = await V.create_session(ls, allowed, create_body(), T0)
        assert state["session"]["phase"] == "lobby" and state["session"]["q_total"] == 3
    for denied in (PLAIN, OTHER, OPOLE):
        assert await code_of(ls, V.create_session(ls, denied, create_body(), T0)) == "EXAM_FORBIDDEN"
    assert await code_of(ls, V.create_session(ls, HOST, create_body(scope="national", province=None), T0)) == "EXAM_FORBIDDEN"
    national = await V.create_session(ls, ADMIN, create_body(scope="national", province=None), T0)
    assert national["session"]["scope"] == "national"


async def test_pin_unikalny_wsrod_aktywnych_i_wraca_po_zakonczeniu(ls):
    ids = [(await new_session(ls, now=T0))[0] for _ in range(4)]
    pins = [(await V.session_row(ls, i))["pin"] for i in ids]
    assert len(set(pins)) == 4 and all(len(p) == 6 and p.isdigit() for p in pins)
    await V.control(ls, HOST, ids[0], "end", T0 + timedelta(minutes=1))
    active = await V._active_pins(ls, T0 + timedelta(minutes=2))
    assert pins[0] not in active and pins[1] in active
    # wygasła z bezczynności też zwalnia PIN
    assert pins[1] not in await V._active_pins(ls, T0 + timedelta(hours=9))


async def test_limit_aktywnych_sesji_prowadzacego(ls):
    for _ in range(V.MAX_ACTIVE_PER_HOST):
        await new_session(ls)
    assert await code_of(ls, new_session(ls)) == "LIVE_TOO_MANY"


async def test_sesja_z_definicji_egzaminu(ls):
    cfg = {"scope": {"manual_ids": SINGLES}, "question_count": 3, "window_start": T0.isoformat(),
           "window_end": (T0 + timedelta(days=3)).isoformat(), "pass_percent": 60, "time_per_question_s": 40}
    exam, _ = await S.create_exam(ls.exam, HOST, {"name": "Egzamin sezonowy", "scope": "province", "province": "ŚLĄSKIE", "config": cfg}, now=T0)
    state = await V.create_session(ls, HOST, {"exam_id": exam["id"], "character": "exam"}, T0)
    s = L.view_for("host", state, None, T0)["session"]
    assert s["title"] == "Egzamin sezonowy" and s["q_total"] == 3 and s["pass_percent"] == 60.0 and s["question_time_s"] == 40
    assert await code_of(ls, V.create_session(ls, PLAIN, {"exam_id": exam["id"]}, T0)) == "EXAM_FORBIDDEN"
    pooled = await V.create_session(ls, HOST, {"scope": "province", "province": "ŚLĄSKIE", "pool": {"scope": {"rules": [1]}, "count": 4}}, T0)
    assert pooled["session"]["q_total"] == 4
    assert await code_of(ls, V.create_session(ls, HOST, {"scope": "province", "province": "ŚLĄSKIE"}, T0)) == "LIVE_NO_QUESTIONS"
    assert await code_of(ls, V.create_session(ls, HOST, create_body(question_ids=["q9-99"]), T0)) == "BAD_SCOPE"


# --- fazy -----------------------------------------------------------------


async def test_fazy_tylko_prowadzacy_i_pelny_cykl(ls):
    sid, _ = await new_session(ls)
    assert await code_of(ls, V.control(ls, PLAIN, sid, "next", T0)) == "LIVE_NOT_HOST"
    assert await code_of(ls, V.control(ls, ADMIN, sid, "next", T0)) == "LIVE_NOT_HOST"
    assert await code_of(ls, V.control(ls, HOST, sid, "reveal", T0)) == "LIVE_BAD_PHASE"
    now = T0
    seen = []
    for _ in range(100):
        state = await V.control(ls, HOST, sid, "next", now)
        s = state["session"]
        seen.append((s["phase"], s["q_index"]))
        if s["phase"] == "end":
            break
        now += timedelta(seconds=3)
    assert seen == [("question", 0), ("reveal", 0), ("leaderboard", 0), ("question", 1), ("reveal", 1), ("leaderboard", 1),
                    ("question", 2), ("reveal", 2), ("leaderboard", 2), ("end", 2)]
    assert await code_of(ls, V.control(ls, HOST, sid, "next", now)) == "LIVE_ENDED"


async def test_termin_pytania_i_ochrona_przed_podwojnym_kliknieciem(ls):
    sid, _ = await new_session(ls)
    state = await V.control(ls, HOST, sid, "next", T0)
    assert state["session"]["deadline_at"] == T0 + timedelta(seconds=20)
    # host klika „dalej" z widoku fazy question, ale czas już minął i serwer sam odsłonił
    late = T0 + timedelta(seconds=25)
    err = await code_of(ls, V.control(ls, HOST, sid, "next", late, {"from_phase": "question", "from_index": 0}))
    assert err == "LIVE_STALE"
    assert (await V.session_row(ls, sid))["phase"] == "reveal"
    # to samo, gdy host kliknął dwa razy: drugie kliknięcie ma stary from_phase
    state = await V.control(ls, HOST, sid, "next", late, {"from_phase": "reveal", "from_index": 0})
    assert state["session"]["phase"] == "leaderboard"
    assert await code_of(ls, V.control(ls, HOST, sid, "next", late, {"from_phase": "reveal", "from_index": 0})) == "LIVE_STALE"


async def test_leniwy_tick_odslania_po_terminie(ls):
    sid, _ = await new_session(ls)
    await V.control(ls, HOST, sid, "next", T0)
    assert await V.tick(ls, sid, T0 + timedelta(seconds=19)) is False
    # po terminie (20 s) czekamy jeszcze ANSWER_GRACE_S na auto-wysyłki z końca czasu
    assert await V.tick(ls, sid, T0 + timedelta(seconds=21)) is False
    assert await V.tick(ls, sid, T0 + timedelta(seconds=20 + L.ANSWER_GRACE_S + 0.1)) is True
    assert (await V.session_row(ls, sid))["phase"] == "reveal"
    await V.patch_session(ls, HOST, sid, {"auto_reveal": False}, T0)  # w reveal nic nie zmienia
    sid2, _ = await new_session(ls, config={"auto_reveal": False})
    await V.control(ls, HOST, sid2, "next", T0)
    assert await V.tick(ls, sid2, T0 + timedelta(minutes=5)) is False


async def test_auto_wysylka_z_konca_czasu_w_tolerancji(ls):
    """Koniec czasu: telefon dosyła zaznaczoną, niezatwierdzoną odpowiedź. Serwer przyjmuje ją do
    ANSWER_GRACE_S po terminie (zegar serwera) i liczy jak zwykłą odpowiedź (tryb speed: minimum 500)."""
    sid, _ = await new_session(ls)
    p = await join_players(ls, sid, 3)
    await V.control(ls, HOST, sid, "next", T0)
    late = T0 + timedelta(seconds=20 + L.ANSWER_GRACE_S - 0.3)
    res = await V.submit_answer(ls, sid, p[0]["id"], [CORRECT["q1-1"]], late)
    assert res["accepted"] is True
    state = await V.load_state(ls, sid, late)
    assert state["session"]["phase"] == "question"
    row = state["answers"][p[0]["id"]]
    assert row["points"] == 500
    too_late = T0 + timedelta(seconds=20 + L.ANSWER_GRACE_S + 0.2)
    code = await code_of(ls, V.submit_answer(ls, sid, p[1]["id"], ["a"], too_late))
    assert code in ("LIVE_TIME_UP", "LIVE_NOT_ACCEPTING")
    assert (await V.session_row(ls, sid))["phase"] == "reveal"


async def test_auto_wysylka_odrzucona_w_pauzie(ls):
    sid, _ = await new_session(ls)
    p = await join_players(ls, sid, 2)
    await V.control(ls, HOST, sid, "next", T0)
    await V.control(ls, HOST, sid, "pause", T0 + timedelta(seconds=5))
    assert await code_of(ls, V.submit_answer(ls, sid, p[0]["id"], ["a"], T0 + timedelta(seconds=21))) == "LIVE_PAUSED"
    assert await V.tick(ls, sid, T0 + timedelta(minutes=2)) is False


# --- ocena i punkty ---------------------------------------------------------


async def test_ocena_i_punkty_za_szybkosc_po_stronie_serwera(ls):
    sid, _ = await new_session(ls)
    p = await join_players(ls, sid, 4)  # czwarty nie odpowiada, więc pytanie nie odsłoni się samo
    await V.control(ls, HOST, sid, "next", T0)
    fast = await V.submit_answer(ls, sid, p[0]["id"], ["a"], T0 + timedelta(seconds=2))
    assert fast["accepted"] is True and set(fast) == {"accepted", "qid", "answered", "everyone_answered"}  # bez poprawności
    await V.submit_answer(ls, sid, p[1]["id"], ["a"], T0 + timedelta(seconds=18))
    await V.submit_answer(ls, sid, p[2]["id"], ["b"], T0 + timedelta(seconds=1))
    state = await V.load_state(ls, sid, T0)
    pts = {pid: row["points"] for pid, row in state["answers"].items()}
    assert pts == {p[0]["id"]: 950, p[1]["id"]: 550, p[2]["id"]: 0}
    # punkty trafiają do rankingu dopiero w reveal
    assert all(x["score"] == 0 for x in state["participants"])
    state = await V.control(ls, HOST, sid, "reveal", T0 + timedelta(seconds=19))
    scores = {x["id"]: x["score"] for x in state["participants"]}
    assert scores == {p[0]["id"]: 950, p[1]["id"]: 550, p[2]["id"]: 0, p[3]["id"]: 0}


async def test_odpowiedz_odrzucana_po_terminie_podwojna_i_poza_pytaniem(ls):
    sid, _ = await new_session(ls, config={"auto_reveal": False})
    p = await join_players(ls, sid, 2)
    assert await code_of(ls, V.submit_answer(ls, sid, p[0]["id"], ["a"], T0)) == "LIVE_NOT_ACCEPTING"
    await V.control(ls, HOST, sid, "next", T0)
    await V.submit_answer(ls, sid, p[0]["id"], ["a"], T0 + timedelta(seconds=1))
    assert await code_of(ls, V.submit_answer(ls, sid, p[0]["id"], ["b"], T0 + timedelta(seconds=2))) == "LIVE_ALREADY_ANSWERED"
    assert await code_of(ls, V.submit_answer(ls, sid, p[1]["id"], ["a"], T0 + timedelta(seconds=25))) == "LIVE_TIME_UP"
    assert await code_of(ls, V.submit_answer(ls, sid, p[1]["id"], ["zz"], T0 + timedelta(seconds=2))) == "LIVE_BAD_KEY"
    assert await code_of(ls, V.submit_answer(ls, sid, p[1]["id"], [], T0 + timedelta(seconds=2))) == "LIVE_EMPTY_ANSWER"


async def test_wielokrotny_wybor_czesciowo_i_wszystko_albo_nic(ls):
    bank = await S.load_bank(ls.exam, await S.ensure_bank(ls.exam))
    multi = next(q for q in bank.values() if q["multi"] and len(L.X.correct_keys(q)) >= 2)
    right = sorted(L.X.correct_keys(multi))
    sid, _ = await new_session(ls, question_ids=[multi["qid"]], config={"multi_scoring": "partial", "ranking": {"mode": "correct"}})
    p = await join_players(ls, sid, 2)
    await V.control(ls, HOST, sid, "next", T0)
    await V.submit_answer(ls, sid, p[0]["id"], right[:1], T0 + timedelta(seconds=1))
    await V.submit_answer(ls, sid, p[1]["id"], right, T0 + timedelta(seconds=1))
    rows = (await V.load_state(ls, sid, T0))["answers"]
    assert rows[p[1]["id"]]["points"] == 1000 and 0 < rows[p[0]["id"]]["points"] < 1000


async def test_automatyczne_odslonieci_gdy_wszyscy_odpowiedzieli(ls):
    sid, _ = await new_session(ls)
    p = await join_players(ls, sid, 2)
    await V.control(ls, HOST, sid, "next", T0)
    first = await V.submit_answer(ls, sid, p[0]["id"], ["a"], T0 + timedelta(seconds=1))
    assert first["everyone_answered"] is False
    second = await V.submit_answer(ls, sid, p[1]["id"], ["a"], T0 + timedelta(seconds=2))
    assert second["everyone_answered"] is True and (await V.session_row(ls, sid))["phase"] == "reveal"


# --- goście i dołączanie ----------------------------------------------------


async def test_goscie_domyslnie_wylaczeni_i_przelacznik_prowadzacego(ls):
    sid, state = await new_session(ls)
    assert state["session"]["guests_allowed"] is False
    pin = state["session"]["pin"]
    assert await code_of(ls, V.join_guest(ls, {"pin": pin}, "Gosc", T0)) == "LIVE_GUESTS_OFF"
    assert await code_of(ls, V.patch_session(ls, PLAIN, sid, {"guests_allowed": True}, T0)) == "LIVE_NOT_HOST"
    await V.patch_session(ls, HOST, sid, {"guests_allowed": True}, T0)
    joined = await V.join_guest(ls, {"pin": pin}, "  Gość  Jan ", T0)
    assert joined["participant"]["name"] == "Gość Jan" and joined["participant"]["guest_token"] and joined["participant"]["kind"] == "guest"
    assert await code_of(ls, V.join_guest(ls, {"pin": pin}, "gość jan", T0)) == "LIVE_NICK_TAKEN"
    assert await code_of(ls, V.join_guest(ls, {"pin": pin}, "x", T0)) == "LIVE_BAD_NICK"
    # token z QR też wpuszcza
    token = (await V.session_row(ls, sid))["token"]
    assert (await V.join_guest(ls, {"token": token}, "Druga Osoba", T0))["participant"]["name"] == "Druga Osoba"
    await V.patch_session(ls, HOST, sid, {"guests_allowed": False}, T0)
    assert await code_of(ls, V.join_guest(ls, {"pin": pin}, "Trzeci", T0)) == "LIVE_GUESTS_OFF"


async def test_dolaczanie_uzytkownika_idempotentne_zly_pin_i_pozno(ls):
    sid, state = await new_session(ls)
    pin = state["session"]["pin"]
    first = await V.join_user(ls, PLAYERS[0], {"pin": pin}, T0)
    again = await V.join_user(ls, PLAYERS[0], {"pin": pin}, T0)
    assert first["participant"]["id"] == again["participant"]["id"] and again["rejoined"] is True
    assert await code_of(ls, V.join_user(ls, PLAYERS[1], {"pin": "000000"}, T0)) == "LIVE_PIN_UNKNOWN"
    assert await code_of(ls, V.join_user(ls, PLAYERS[1], {"pin": "12"}, T0)) == "LIVE_BAD_PIN"
    exam_sid, exam_state = await new_session(ls, character="exam")
    await V.control(ls, HOST, exam_sid, "next", T0)
    assert await code_of(ls, V.join_user(ls, PLAYERS[1], {"pin": exam_state["session"]["pin"]}, T0)) == "LIVE_STARTED"
    await V.control(ls, HOST, sid, "next", T0)
    assert (await V.join_user(ls, PLAYERS[1], {"pin": pin}, T0))["participant"]["name"] == "Sędzia 2"  # quiz pozwala dołączyć po starcie


# --- widoki, wynik trwały ---------------------------------------------------


async def test_widok_z_serwisu_nie_zdradza_klucza_przed_reveal(ls):
    sid, _ = await new_session(ls, phone_view="tiles")
    p = await join_players(ls, sid, 1)
    await V.control(ls, HOST, sid, "next", T0)
    state = await V.load_state(ls, sid, T0)
    for role, viewer in (("host", None), ("projector", None), ("player", p[0])):
        flat = json.dumps(L.view_for(role, state, viewer, T0), ensure_ascii=False)
        assert "correct_keys" not in flat
    assert "text" not in L.view_for("player", state, p[0], T0)["question"]
    state = await V.control(ls, HOST, sid, "reveal", T0 + timedelta(seconds=3))
    assert L.view_for("projector", state, None, T0)["reveal"]["correct_keys"] == [CORRECT["q1-1"]]


async def test_egzamin_na_sali_wynik_trwaly_z_progiem(ls):
    sid, _ = await new_session(ls, character="exam", config={"pass_percent": 60})
    p = await join_players(ls, sid, 3)
    now = T0
    await V.control(ls, HOST, sid, "next", now)
    for qid in SINGLES:
        # p0 trafia wszystko, p1 tylko pierwsze, p2 nic; trzecia odpowiedź odsłania pytanie sama
        await V.submit_answer(ls, sid, p[0]["id"], [CORRECT[qid]], now + timedelta(seconds=5))
        await V.submit_answer(ls, sid, p[1]["id"], [CORRECT[qid] if qid == "q1-1" else "d"], now + timedelta(seconds=9))
        await V.submit_answer(ls, sid, p[2]["id"], ["d"], now + timedelta(seconds=1))
        assert (await V.session_row(ls, sid))["phase"] == "reveal"
        await V.control(ls, HOST, sid, "next", now + timedelta(seconds=10))  # leaderboard
        now += timedelta(seconds=11)
        state = await V.control(ls, HOST, sid, "next", now)  # następne pytanie albo koniec
    assert state["session"]["phase"] == "end"
    result = (await V.results(ls, HOST, sid, now))["result"]
    by = {e["judge_id"]: e for e in result["ranking"]}
    assert by["101"]["percent"] == 100.0 and by["101"]["passed"] is True and by["101"]["place"] == 1
    assert by["102"]["passed"] is False and round(by["102"]["percent"], 1) == 33.3
    assert result["passed"] == 1 and result["pass_percent"] == 60.0 and len(result["questions"]) == 3
    assert result["questions"][0]["distribution"]["a"] == 2
    persisted = await ls.database.fetch_one(ls.t.sessions.select().where(ls.t.sessions.c.id == sid))
    assert json.loads(persisted["result_json"])["participants"] == 3
    # uprawnienia do wyników: prowadzący i komisja okręgu tak, obcy nie
    assert await code_of(ls, V.results(ls, PLAIN, sid, now)) == "EXAM_FORBIDDEN"
    assert (await V.results(ls, ADMIN, sid, now))["result"]["participants"] == 3


async def test_wyniki_przed_koncem_i_lista_prowadzacego(ls):
    sid, _ = await new_session(ls)
    assert await code_of(ls, V.results(ls, HOST, sid, T0)) == "LIVE_NOT_ENDED"
    listing = await V.hosted_list(ls, HOST, T0)
    assert listing["sessions"][0]["id"] == sid and listing["sessions"][0]["active"] is True and len(listing["sessions"][0]["pin"]) == 6
    assert (await V.hosted_list(ls, PLAIN, T0))["sessions"] == []
    state = await V.control(ls, ADMIN, sid, "end", T0)  # admin może zakończyć cudzą sesję
    assert state["session"]["phase"] == "end"


async def test_zmiana_trybu_punktow_tylko_w_lobby(ls):
    sid, _ = await new_session(ls)
    await V.patch_session(ls, HOST, sid, {"ranking": {"mode": "correct", "top_n": 3}}, T0)
    assert (await V.session_row(ls, sid))["config"]["ranking"]["top_n"] == 3
    await V.control(ls, HOST, sid, "next", T0)
    assert await code_of(ls, V.patch_session(ls, HOST, sid, {"ranking": {"mode": "speed"}}, T0)) == "LIVE_LOCKED"
    await V.patch_session(ls, HOST, sid, {"ranking": {"top_n": 8}}, T0)
