"""Kosz teczki komisji (24.10.2026): egzamin i wynik sędziego 30 dni do przywrócenia,
usunięte od razu znika z teczki, raportu i statystyk; po 30 dniach trwale.
Do tego regresja 500 teczki: CASE z liczbami jako parametrami (asyncpg: expected str, got int)."""

from datetime import timedelta

import pytest
from sqlalchemy import select

from app import exam_report_service as RS
from app import exam_service as S
from app import exam_trash as T
from app.exam_rules import ExamError
from test_exam_service import (  # noqa: F401 - fixture `st` i pomocnicze
    COMMISSION, DELEGATE, OPEN, PLAIN, answer_all, make, st,
)


async def _two_results(st):
    exam, _ = await make(st)
    now = OPEN + timedelta(minutes=1)
    for who in (PLAIN, DELEGATE):
        state = await S.start_attempt(st, who, exam["id"], {}, now=now)
        await answer_all(st, who, state["attempt"]["id"], now, state=state)
    return exam, now + timedelta(minutes=5)


async def test_wynik_w_koszu_znika_z_teczki_i_raportu_i_wraca(st):
    exam, now = await _two_results(st)
    out = await T.delete_result(st, COMMISSION, exam["id"], PLAIN.judge_id, now=now)
    assert out["deleted"] and out["attempts"] == 1

    folder = await S.list_manage(st, COMMISSION, "ŚLĄSKIE", now=now)
    summary = {e["id"]: e for e in folder["exams"]}[exam["id"]]["summary"]
    assert summary["finished"] == 1
    report = await RS.build_report(st, COMMISSION, exam["id"], now=now)
    assert [r["judge_id"] for r in report["ranking"]] == [DELEGATE.judge_id]

    trash = await T.trash_list(st, COMMISSION, "ŚLĄSKIE", now=now)
    assert [r["judge_id"] for r in trash["results"]] == [PLAIN.judge_id]
    assert trash["results"][0]["purge_at"]

    await T.restore_result(st, COMMISSION, exam["id"], PLAIN.judge_id)
    report = await RS.build_report(st, COMMISSION, exam["id"], now=now)
    assert len(report["ranking"]) == 2


async def test_egzamin_w_koszu_i_przywrocenie(st):
    exam, now = await _two_results(st)
    await S.delete_exam(st, COMMISSION, exam["id"], now=now)
    folder = await S.list_manage(st, COMMISSION, "ŚLĄSKIE", now=now)
    assert exam["id"] not in {e["id"] for e in folder["exams"]}
    trash = await T.trash_list(st, COMMISSION, "ŚLĄSKIE", now=now)
    assert trash["exams"][0]["id"] == exam["id"] and trash["exams"][0]["finished"] == 2
    back = await T.restore_exam(st, COMMISSION, exam["id"], now=now)
    assert back["restored"]
    folder = await S.list_manage(st, COMMISSION, "ŚLĄSKIE", now=now)
    assert exam["id"] in {e["id"] for e in folder["exams"]}


async def test_po_30_dniach_trwale(st):
    exam, now = await _two_results(st)
    await T.delete_result(st, COMMISSION, exam["id"], PLAIN.judge_id, now=now)
    await S.delete_exam(st, COMMISSION, exam["id"], now=now + timedelta(days=1))
    assert (await T.purge_trash(st, now + timedelta(days=29)))["attempts"] == 0
    done = await T.purge_trash(st, now + timedelta(days=31, hours=1))
    assert done["exams"] == 1 and done["attempts"] == 2
    rows = await st.database.fetch_all(select(st.t.attempts.c.id).where(st.t.attempts.c.exam_id == exam["id"]))
    assert not rows


async def test_zwykly_sedzia_nie_usuwa_wyniku(st):
    exam, now = await _two_results(st)
    with pytest.raises(ExamError):
        await T.delete_result(st, PLAIN, exam["id"], DELEGATE.judge_id, now=now)


def test_miniatura_bez_parametrow_w_case():
    """Postgres odgaduje typ parametru w CASE jako text - liczby muszą być wpisane w SQL."""
    from databases.backends.dialects.psycopg import dialect as D
    from sqlalchemy import Boolean, Column, Float, MetaData, String, Table

    from app.exam_service import Store, Tables

    md = MetaData()
    attempts = Table("exam_attempts", md, Column("exam_id", String), Column("judge_id", String), Column("status", String),
                     Column("percent", Float), Column("passed", Boolean), Column("province", String), Column("deleted_at", String))
    captured = {}

    class DB:
        async def fetch_all(self, q):
            captured["sql"] = q.compile(dialect=D(paramstyle="pyformat"))
            return []

    import asyncio

    st = Store(database=DB(), t=Tables(*([None] * 3), attempts, *([None] * 4)), judges=None, push=None)
    asyncio.run(S._people_summary(st, ["x"]))
    params = captured["sql"].params
    assert not any(isinstance(v, int) and not isinstance(v, bool) for v in params.values()), params


async def test_wynik_w_koszu_pozwala_podejsc_ponownie(st):
    exam, now = await _two_results(st)
    await T.delete_result(st, COMMISSION, exam["id"], PLAIN.judge_id, now=now)
    # Limit to jedno podejście, ale to z kosza się nie liczy.
    listing = await S.list_for_judge(st, PLAIN, now=now)
    mine = {e["id"]: e for e in listing["exams"]}[exam["id"]]
    assert mine["my_attempts"] == [] and mine["attempts_left"] == 1
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=now)
    assert state["attempt"]["attempt_no"] == 2  # numer rośnie ponad podejście z kosza


async def test_przywrocenie_przy_nowszym_podejsciu_sie_tlumaczy(st):
    exam, now = await _two_results(st)
    await T.delete_result(st, COMMISSION, exam["id"], PLAIN.judge_id, now=now)
    await S.start_attempt(st, PLAIN, exam["id"], {}, now=now)
    with pytest.raises(ExamError) as e:
        await T.restore_result(st, COMMISSION, exam["id"], PLAIN.judge_id)
    assert e.value.code == "RESULT_NEWER_ATTEMPT" and e.value.status == 409 and e.value.message


async def test_os_czasu_podejscia_ma_litery_pozycji(st):
    exam, now = await _two_results(st)
    report = await RS.build_report(st, COMMISSION, exam["id"], now=now)
    aid = next(r["attempt_id"] for r in report["ranking"] if r["judge_id"] == PLAIN.judge_id)
    card = await S.attempt_card(st, COMMISSION, exam["id"], aid)
    for step in card["timeline"]:
        assert len(step["keys"]) >= 2
        for k, letter in zip(step["selected"] or [], step["selected_letters"]):
            assert letter == chr(97 + step["keys"].index(k))
