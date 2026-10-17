"""Teczka komisji: miniatura wyników przy liście zarządzanych egzaminów (`summary`) i druki 25/30/15."""

from datetime import timedelta

from app import exam_rules as X
from app import exam_service as S
from test_exam_service import (  # noqa: F401 - fixture `st` i pomocnicze
    CLOSE, COMMISSION, CORRECT, DELEGATE, OPEN, PLAIN, T0, TEACH, answer_all, make, st,
)


def wrong(qid):
    return ["b"] if CORRECT[qid] == "a" else ["a"]


async def test_miniatura_liczy_osoby_raz_i_nie_przystapionych(st):
    exam, _ = await make(st)
    empty, _ = await make(st)
    now = OPEN + timedelta(minutes=1)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=now)
    await answer_all(st, PLAIN, state["attempt"]["id"], now, state=state)
    state = await S.start_attempt(st, DELEGATE, exam["id"], {}, now=now)
    await answer_all(st, DELEGATE, state["attempt"]["id"], now, choose=wrong, state=state)
    await S.start_attempt(st, TEACH, exam["id"], {}, now=now)  # pisze, nie skończył

    out = await S.list_manage(st, COMMISSION, "ŚLĄSKIE", now=now + timedelta(minutes=5))
    by_id = {e["id"]: e for e in out["exams"]}
    s = by_id[exam["id"]]["summary"]
    assert s == {"attempted": 3, "finished": 2, "passed": 1, "avg_percent": 50.0, "pass_rate": 0.5,
                 "not_started": 2, "invited": 5}
    assert by_id[exam["id"]]["attempt_counts"] == {"submitted": 2, "in_progress": 1}
    e = by_id[empty["id"]]["summary"]
    assert e == {"attempted": 0, "finished": 0, "passed": 0, "avg_percent": None, "pass_rate": None,
                 "not_started": 5, "invited": 5}
    assert by_id[empty["id"]]["attempt_counts"] == {}


def test_summary_view_bez_danych():
    assert S.summary_view(None, []) == {"attempted": 0, "finished": 0, "passed": 0, "avg_percent": None,
                                        "pass_rate": None, "not_started": 0, "invited": 0}


def test_druki_25_30_15():
    assert list(X.TEMPLATES) == ["exam25", "exam30", "exam15"]
    win = {"window_start": T0.isoformat(), "window_end": CLOSE.isoformat()}
    for key, count, excluded in (("exam25", 25, ["Ligowcy", "Delegaci"]), ("exam30", 30, []), ("exam15", 15, ["Ligowcy", "Delegaci"])):
        tpl = X.TEMPLATES[key]
        assert tpl["label"] == f"Egzamin {count}" and tpl["window_days"] == 7
        c = X.clean_config(win, template=key)
        assert c["question_count"] == count and c["time_per_question_s"] == 100 and c["time_total_min"] is None
        assert c["pass_percent"] == 75 and c["result_release"] == "after_close" and c["mandatory"] is True
        assert c["scope"]["rules"] == [] and c["scope"]["manual_ids"] == [] and c["allow_back"] is False
        assert c["target"]["include_all"] is True and c["target"]["exclude_badges"] == excluded


async def test_druk_25_omija_delegatow(st):
    exam, _ = await make(st, target=X.template_config("exam25")["target"])
    out = await S.list_manage(st, COMMISSION, "ŚLĄSKIE", now=OPEN)
    assert out["exams"][0]["summary"]["invited"] == 4  # Ola Delegat poza adresatami
