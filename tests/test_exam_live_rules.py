"""Egzamin na żywo - reguły bez bazy: konfiguracja, PIN, fazy, punkty, ranking, widoki per rola."""

import json
import random
from datetime import datetime, timedelta, timezone

import pytest

from app import exam_live_rules as L
from app.exam_rules import ExamError

NOW = datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc)
Q = {"qid": "q1-1", "number": "1.1", "rule": 1, "kind": "wiedza", "multi": False, "text": "Treść pytania?",
     "answers": [{"key": "a", "text": "A", "correct": True}, {"key": "b", "text": "B", "correct": False}],
     "curiosity": "Ciekawostka"}


def state(phase="question", answers=None, parts=None, character="quiz", phone_view="full", result=None):
    cfg = L.clean_live_config({}, character)
    return {
        "session": {"id": "s1", "pin": "123456", "token": "tok", "title": "T", "character": character, "phone_view": phone_view,
                    "guests_allowed": False, "config": cfg, "phase": phase, "q_index": 0, "q_total": 2, "rev": 7,
                    "phase_started_at": NOW, "deadline_at": NOW + timedelta(seconds=20), "scope": "province", "province": "ŚLĄSKIE"},
        "participants": parts if parts is not None else [
            {"id": "p1", "kind": "user", "name": "Ala", "judge_id": "1", "score": 950, "correct_count": 1},
            {"id": "p2", "kind": "guest", "name": "Bob", "judge_id": None, "score": 0, "correct_count": 0}],
        "answers": answers if answers is not None else {}, "question": Q, "result": result,
        "links": {"join_url": "/x"}, "server_now": NOW,
    }


def test_konfiguracja_quiz_i_egzamin():
    quiz = L.clean_live_config({}, "quiz")
    assert quiz["ranking"] == {"mode": "speed", "top_n": 5, "show_own_rank": True, "leaderboard_each": True}
    assert quiz["pass_percent"] is None and quiz["late_join"] is True
    exam = L.clean_live_config({}, "exam")
    assert exam["ranking"]["mode"] == "correct" and exam["pass_percent"] == 75.0 and exam["late_join"] is False
    with pytest.raises(ExamError):
        L.clean_live_config({"question_time_s": 1}, "quiz")
    with pytest.raises(ExamError):
        L.clean_live_config({"ranking": {"mode": "magia"}}, "quiz")


def test_pin_szesc_cyfr_i_unikalny_wsrod_zajetych():
    rng = random.Random(1)
    taken = set()
    for _ in range(300):
        pin = L.generate_pin(taken, rng)
        assert len(pin) == 6 and pin.isdigit() and pin[0] != "0" and pin not in taken
        taken.add(pin)
    assert len(taken) == 300
    assert L.clean_pin("12 34-56") == "123456"


def test_nick_i_aktywnosc():
    assert L.clean_nick("  Ala   Ma  ") == "Ala Ma"
    for bad in ("", "a", "x" * 40):
        with pytest.raises(ExamError):
            L.clean_nick(bad)
    assert "<" not in L.clean_nick("Ala<script>")
    assert L.session_active("lobby", NOW, NOW + timedelta(hours=1))
    assert not L.session_active("lobby", NOW, NOW + timedelta(hours=9))
    assert not L.session_active("end", NOW, NOW)


def test_fazy_pelny_cykl_i_pomijanie_rankingu():
    seq, phase, idx = [], "lobby", -1
    while phase != "end":
        phase, idx = L.next_phase(phase, idx, 2, True)
        seq.append((phase, idx))
    assert seq == [("question", 0), ("reveal", 0), ("leaderboard", 0), ("question", 1), ("reveal", 1), ("leaderboard", 1), ("end", 1)]
    assert L.next_phase("reveal", 0, 3, False) == ("question", 1)
    assert L.next_phase("reveal", 2, 3, False) == ("leaderboard", 2)
    with pytest.raises(ExamError) as err:
        L.next_phase("end", 1, 2, True)
    assert err.value.code == "LIVE_ENDED"
    with pytest.raises(ExamError):
        L.next_phase("lobby", -1, 0, True)
    with pytest.raises(ExamError) as err:
        L.control_action("reveal", "lobby")
    assert err.value.code == "LIVE_BAD_PHASE"
    with pytest.raises(ExamError):
        L.control_action("skocz", "lobby")


def test_punkty_za_szybkosc():
    assert L.speed_points("speed", 1.0, 0, 20) == 1000
    assert L.speed_points("speed", 1.0, 2000, 20) == 950
    assert L.speed_points("speed", 1.0, 20000, 20) == 500
    assert L.speed_points("speed", 1.0, 99000, 20) == 500
    assert L.speed_points("speed", 0.0, 100, 20) == 0
    assert L.speed_points("speed", 0.5, 0, 20) == 500
    assert L.speed_points("correct", 1.0, 19000, 20) == 1000


def test_odpowiedz_walidacja_i_termin():
    assert L.clean_selection(Q, ["a", "a"]) == ["a"]
    for bad in ([], ["z"]):
        with pytest.raises(ExamError):
            L.clean_selection(Q, bad)
    # Domyślnie wolno zaznaczyć kilka (jak w egzaminie indywidualnym); blokuje to tylko podpowiedź "jedna poprawna".
    assert L.clean_selection(Q, ["a", "b"]) == ["a", "b"]
    assert L.clean_selection(Q, ["a", "b"], L.clean_live_config({}, "quiz")) == ["a", "b"]
    for hinted in ({"single_hint_all": True}, {"single_hint_ids": ["q1-1"]}):
        cfg = L.clean_live_config(hinted, "quiz")
        with pytest.raises(ExamError) as e:
            L.clean_selection(Q, ["a", "b"], cfg)
        assert e.value.code == "LIVE_SINGLE_ONLY"
        assert L.clean_selection(Q, ["a"], cfg) == ["a"]
    pub = L._public_question(Q, tiles=False, cfg=L.clean_live_config({"single_hint_all": True}, "quiz"))
    assert pub["multi"] is False and pub["single_hint"] is True
    assert L._public_question(Q, tiles=False, cfg=L.clean_live_config({}, "quiz"))["multi"] is True
    dl = NOW + timedelta(seconds=20)
    assert L.answer_refusal("question", dl, NOW + timedelta(seconds=20)) is None
    assert L.answer_refusal("question", dl, NOW + timedelta(seconds=21)) is None  # zapas sieci
    assert L.answer_refusal("question", dl, NOW + timedelta(seconds=22)).code == "LIVE_TIME_UP"
    assert L.answer_refusal("reveal", dl, NOW).code == "LIVE_NOT_ACCEPTING"


def test_ranking_ex_aequo():
    parts = [{"id": str(i), "name": n, "kind": "user", "score": s} for i, (n, s) in enumerate([("A", 900), ("B", 900), ("C", 500), ("D", 500), ("E", 100)])]
    assert [r["place"] for r in L.rank_participants(parts)] == [1, 1, 3, 3, 5]


def test_klucz_tylko_w_reveal_per_rola():
    answers = {"p1": {"selected": ["a"], "fraction": 1.0, "points": 950}}
    me = state()["participants"][0]
    for role in ("host", "player", "projector"):
        view = L.view_for(role, state("question", answers), me if role == "player" else None, NOW)
        flat = json.dumps(view, ensure_ascii=False)
        assert "correct_keys" not in flat and "Ciekawostka" not in flat and view["reveal"] is None
        assert '"correct": true' not in flat.lower() and '"correct":true' not in flat.lower()
        assert not any("correct" in a for a in view["question"]["answers"])
    for role in ("host", "player", "projector"):
        view = L.view_for(role, state("reveal", answers), me if role == "player" else None, NOW)
        assert view["reveal"]["correct_keys"] == ["a"] and view["reveal"]["distribution"] == {"a": 1, "b": 0}
        assert view["reveal"]["curiosity"] == "Ciekawostka" and view["reveal"]["skipped"] == 1


def test_widok_kafli_ukrywa_tresc_tylko_dla_telefonu():
    me = state()["participants"][0]
    tiles = L.view_for("player", state(phone_view="tiles"), me, NOW)
    assert tiles["question"]["tiles_only"] is True and "text" not in tiles["question"]
    assert all(set(a) == {"key"} for a in tiles["question"]["answers"])
    assert "Treść pytania?" not in json.dumps(tiles, ensure_ascii=False)
    for role in ("host", "projector"):
        assert L.view_for(role, state(phone_view="tiles"), None, NOW)["question"]["text"] == "Treść pytania?"
    assert L.view_for("player", state(phone_view="full"), me, NOW)["question"]["text"] == "Treść pytania?"
    # po odsłonięciu telefon zawsze dostaje pełne pytanie
    assert L.view_for("player", state("reveal", phone_view="tiles"), me, NOW)["question"]["text"]


def test_widoki_per_rola_lobby_i_ranking():
    parts = state()["participants"]
    host = L.view_for("host", state("lobby"), None, NOW)
    proj = L.view_for("projector", state("lobby"), None, NOW)
    play = L.view_for("player", state("lobby"), parts[0], NOW)
    assert host["session"]["pin"] == "123456" and proj["session"]["pin"] == "123456" and "pin" not in play["session"]
    assert host["participants"][0]["id"] and "id" not in proj["participants"][0] and "participants" not in play
    assert play["me"]["name"] == "Ala" and host["me"] is None and proj["me"] is None
    board_host = L.view_for("host", state("leaderboard"), None, NOW)["leaderboard"]
    board_play = L.view_for("player", state("leaderboard"), parts[1], NOW)["leaderboard"]
    board_proj = L.view_for("projector", state("leaderboard"), None, NOW)["leaderboard"]
    assert "full" in board_host and "full" not in board_play and "full" not in board_proj
    assert all("participant_id" not in r for r in board_play["top"] + board_proj["top"])
    assert board_play["you"]["place"] == 2 and board_play["top"][0]["place"] == 1


def test_top_n_i_wlasne_miejsce():
    parts = [{"id": f"p{i}", "kind": "user", "name": f"G{i}", "score": 1000 - i * 10} for i in range(12)]
    st = state("leaderboard", parts=parts)
    st["session"]["config"]["ranking"]["top_n"] = 5
    view = L.view_for("player", st, parts[9], NOW)
    assert len(view["leaderboard"]["top"]) == 5 and view["leaderboard"]["you"]["place"] == 10
    st["session"]["config"]["ranking"]["show_own_rank"] = False
    assert L.view_for("player", st, parts[9], NOW)["leaderboard"]["you"] is None


def test_wynik_trwaly_egzamin_z_progiem():
    bank = {"q1-1": Q}
    parts = [{"id": "p1", "kind": "user", "name": "Ala", "judge_id": "1", "score": 1000},
             {"id": "p2", "kind": "guest", "name": "Bob", "judge_id": None, "score": 0}]
    answers = [{"participant_id": "p1", "qid": "q1-1", "fraction": 1.0, "points": 1000, "selected": ["a"]},
               {"participant_id": "p2", "qid": "q1-1", "fraction": 0.0, "points": 0, "selected": ["b"]}]
    res = L.build_result(character="exam", pass_percent=75, question_ids=["q1-1"], bank=bank, participants=parts, answers=answers)
    by = {e["name"]: e for e in res["ranking"]}
    assert by["Ala"]["passed"] is True and by["Ala"]["percent"] == 100.0 and by["Bob"]["passed"] is False
    assert res["passed"] == 1 and res["questions"][0]["distribution"] == {"a": 1, "b": 1} and res["questions"][0]["correct_keys"] == ["a"]
    quiz = L.build_result(character="quiz", pass_percent=None, question_ids=["q1-1"], bank=bank, participants=parts, answers=answers)
    assert quiz["passed"] is None and all(e["passed"] is None for e in quiz["ranking"])
