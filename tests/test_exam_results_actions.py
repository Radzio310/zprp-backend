"""Ekran wyników egzaminu (25.10.2026): kto jak odpowiedział, sygnały z czasem,
przypomnienie niepiszącym, kolejne podejście, arkusz jednej osoby w eksporcie."""

from datetime import timedelta

import pytest

from app import exam_report_rules as R
from app import exam_results_actions as A
from app import exam_rules as X
from app import exam_service as S
from tests.test_exam_service import COMMISSION, DELEGATE, OPEN, OTHER_COMMISSION, PLAIN, answer_all, make, st  # noqa: F401


async def test_kto_jak_odpowiedzial_na_pytanie(st):
    exam, _ = await make(st, result_release="immediate")
    t = OPEN + timedelta(minutes=5)
    for w, pick in ((PLAIN, "a"), (DELEGATE, "b")):
        state = await S.start_attempt(st, w, exam["id"], {}, now=t)
        await answer_all(st, w, state["attempt"]["id"], t, choose=(lambda q, k=pick: [k]), state=state)
    out = await A.question_answers(st, COMMISSION, exam["id"], "q1-1")
    by = {a["judge_id"]: a for a in out["answers"]}
    assert by["3"]["selected"] == ["a"] and by["3"]["correct"] is True
    assert by["4"]["selected"] == ["b"] and by["4"]["correct"] is False
    with pytest.raises(X.ExamError) as err:
        await A.question_answers(st, OTHER_COMMISSION, exam["id"], "q1-1")
    assert err.value.status == 403


async def test_sygnaly_rzetelnosci_z_czasem(st):
    exam, _ = await make(st, result_release="immediate")
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    await S.post_events(st, PLAIN, state["attempt"]["id"], {"events": [{"kind": "app_background", "detail": {"seconds": 12}}]}, now=t)
    out = await A.signals(st, COMMISSION, exam["id"])
    kinds = [(s["judge_id"], s["kind"]) for s in out["signals"]]
    assert ("3", "app_background") in kinds
    assert all(s["at"] for s in out["signals"])


async def test_przypomnienie_tylko_w_oknie_z_przerwa(st):
    exam, _ = await make(st)
    with pytest.raises(X.ExamError) as err:
        await A.remind_missing(st, COMMISSION, exam["id"], now=OPEN - timedelta(minutes=1))
    assert err.value.code == "EXAM_NOT_OPEN"
    t = OPEN + timedelta(minutes=5)
    out = await A.remind_missing(st, COMMISSION, exam["id"], now=t)
    assert out["sent"] > 0 and out["reminders"]["last_count"] == out["sent"]
    assert st.pushes and st.pushes[-1]["data"]["notice"] == "exam_reminder"
    with pytest.raises(X.ExamError) as err:
        await A.remind_missing(st, COMMISSION, exam["id"], now=t + timedelta(minutes=3))
    assert err.value.code == "REMIND_TOO_SOON" and "min" in err.value.message
    again = await A.remind_missing(st, COMMISSION, exam["id"], now=t + timedelta(minutes=20))
    assert again["reminders"]["times"] == 2
    with pytest.raises(X.ExamError):
        await A.remind_missing(st, PLAIN, exam["id"], now=t + timedelta(minutes=40))


async def test_kolejne_podejscie_ponad_limit_i_mimo_zdania(st):
    exam, _ = await make(st, result_release="immediate", max_attempts=1, retake="only_failed")
    t = OPEN + timedelta(minutes=5)
    s1 = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    await answer_all(st, PLAIN, s1["attempt"]["id"], t, state=s1)
    with pytest.raises(X.ExamError):
        await S.start_attempt(st, PLAIN, exam["id"], {}, now=t + timedelta(hours=1))
    out = await A.grant_attempt(st, COMMISSION, exam["id"], "3", now=t + timedelta(hours=1))
    assert out["extra"] == 1 and out["attempts_left"] == 1
    s2 = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t + timedelta(hours=2))
    assert s2["attempt"]["attempt_no"] == 2
    # Edycja egzaminu nie gubi danych podejść.
    await S.update_exam(st, COMMISSION, exam["id"], {"name": "Nowa nazwa"}, now=t + timedelta(hours=3))
    assert X.extra_attempts_for((await S._exam(st, exam["id"]))["config"], "3") == 1
    with pytest.raises(X.ExamError):
        await A.grant_attempt(st, PLAIN, exam["id"], "3", now=t)


def test_start_refusal_z_dodatkowym_podejsciem():
    cfg = {"max_attempts": 1, "retake": "only_failed"}
    now = OPEN
    done = [{"status": "finished", "attempt_no": 1, "score": {"passed": True}}]
    assert X.start_refusal(cfg, now, done).code == "EXAM_NO_ATTEMPTS"
    assert X.start_refusal(cfg, now, done, 1) is None
    assert X.clean_extra_attempts({"3": "2", "x": 0, "": 4, "9": 99}) == {"3": 2, "9": X.MAX_EXTRA_ATTEMPTS}


def test_integrity_signal_mapuje_rodzaj_i_flage():
    assert X.integrity_signal({"kind": "app_background", "detail": {}}) == ("app_background", None)
    assert X.integrity_signal({"kind": "time_flag", "detail": {"flag": "buffered_late"}}) == ("time_flag", "buffered_late")
    assert X.integrity_signal({"kind": "resume", "detail": {}}) is None


def test_eksport_arkusza_jednej_osoby():
    opts = R.clean_export_options({"sections": ["cards"], "people": {"judge_ids": ["3", " ", "3"]}}, national=False)
    assert opts["people"]["judge_ids"] == ["3"]
    rows = [{"judge_id": "3", "percent": 80}, {"judge_id": "4", "percent": 90}]
    assert [r["judge_id"] for r in R.apply_people(rows, opts["people"])] == ["3"]
