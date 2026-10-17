"""Egzamin krajowy oglądany przez komisję okręgu: tylko jej okręg, tylko odczyt (decyzja 17.10)."""

from datetime import timedelta

import pytest

from app import exam_report_service as RS
from app import exam_service as S
from app import exam_stats_service as SS
from app.exam_rules import ExamError
from test_exam_service import (  # noqa: F401 - fixture `st` i pomocnicze
    ADMIN, COMMISSION, CORRECT, OPEN, OTHER_COMMISSION, PLAIN, T0, answer_all, body, st, who,
)
from test_exam_stats import ss_of

OPOLE_PLAIN = who("9", "Opole Zwykły", province="OPOLSKIE")
PLAIN2 = who("3", "Jan Zwykły")


async def _national(st):
    b = body()
    b.update(scope="national", province=None)
    exam, _ = await S.create_exam(st, ADMIN, b, now=T0)
    t = OPEN + timedelta(minutes=5)
    for w in (PLAIN, OPOLE_PLAIN):
        state = await S.start_attempt(st, w, exam["id"], {}, now=t)
        await answer_all(st, w, state["attempt"]["id"], t, state=state)
    return exam


async def test_raport_przyciety_do_okregu(st):
    exam = await _national(st)
    rep = await RS.build_report(st, COMMISSION, exam["id"])
    assert rep["summary"]["people"] == 1 and [a["judge_id"] for a in rep["attempts"]] == ["3"]
    assert rep["provinces"] == [] and all(m["province"] == "ŚLĄSKIE" for m in rep["missing"])
    assert rep["exam"]["read_only"] is True and rep["exam"]["cut_province"] == "ŚLĄSKIE" and rep["exam"]["can_manage"] is False
    assert rep["exam"]["province"] is None
    other = await RS.build_report(st, OTHER_COMMISSION, exam["id"])
    assert [a["judge_id"] for a in other["attempts"]] == ["9"]
    full = await RS.build_report(st, ADMIN, exam["id"])
    assert full["summary"]["people"] == 2 and "read_only" not in full["exam"]


async def test_karta_cudzego_okregu_niedostepna_i_statystyki_pytan(st):
    exam = await _national(st)
    att = await S.attempts_list(st, ADMIN, exam["id"])
    opole = next(a for a in att["attempts"] if a["judge_id"] == "9")
    with pytest.raises(ExamError) as err:
        await S.attempt_card(st, COMMISSION, exam["id"], opole["attempt_id"])
    assert err.value.status == 404
    assert (await S.exam_stats(st, COMMISSION, exam["id"]))["summary"]["finished"] == 1
    assert (await S.exam_stats(st, ADMIN, exam["id"]))["summary"]["finished"] == 2


async def test_komisja_nie_zmienia_egzaminu_krajowego(st):
    exam = await _national(st)
    for call in (S.void_question(st, COMMISSION, exam["id"], "q1-1", "drop"),
                 S.update_exam(st, COMMISSION, exam["id"], {"name": "Inna"}),
                 S.delete_exam(st, COMMISSION, exam["id"]),
                 RS.void_preview(st, COMMISSION, exam["id"], "q1-1")):
        with pytest.raises(ExamError) as err:
            await call
        assert err.value.status == 403 and err.value.code == "EXAM_FORBIDDEN" and "administrator" in err.value.message
    # zwykły sędzia nie dostaje nawet odczytu
    with pytest.raises(ExamError) as err:
        await RS.build_report(st, PLAIN, exam["id"])
    assert err.value.status == 403


async def test_teczka_okregu_pokazuje_krajowe_tylko_do_odczytu(st):
    exam = await _national(st)
    out = await S.list_manage(st, COMMISSION, "ŚLĄSKIE", now=OPEN + timedelta(minutes=30))
    e = next(x for x in out["exams"] if x["id"] == exam["id"])
    assert e["read_only"] is True and e["scope"] == "national" and e["can_manage"] is False
    assert e["summary"]["attempted"] == 1 and e["summary"]["finished"] == 1
    assert e["attempt_counts"] == {"submitted": 1}
    adm = await S.list_manage(st, ADMIN, "ŚLĄSKIE", now=OPEN + timedelta(minutes=30))
    assert all(x["id"] != exam["id"] for x in adm["exams"])
    got = await S.get_exam(st, COMMISSION, exam["id"], now=OPEN)
    assert got["read_only"] is True and got["can_manage"] is False


async def test_statystyki_okregu_licza_krajowe_tylko_z_okregu(st):
    exam = await _national(st)
    ss = ss_of(st)
    now = OPEN + timedelta(days=6)
    com = await SS.stats_overview(ss, COMMISSION, "ŚLĄSKIE", {}, now=now)
    row = next(x for x in com["exams"] if x["id"] == exam["id"])
    assert row["scope"] == "national" and row["people"] == 1
    adm = await SS.stats_overview(ss, ADMIN, "ŚLĄSKIE", {}, now=now)
    assert all(x["id"] != exam["id"] for x in adm["exams"])
