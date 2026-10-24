"""Pytanie z wyprzedzenia i czas na pytaniu wg telefonu (24.10.2026).

Telefon dostaje `next_question` razem z bieżącym i pokazuje je w chwili zatwierdzenia,
bez czekania na sieć. Zegar następnego pytania startuje chwilą odpowiedzi (`advance`)
albo chwilą zamknięcia poprzedniego (`lookahead`), nigdy chwilą dojścia paczki."""

from datetime import timedelta

from app import exam_rules as X
from tests.test_exam_rules import BANK, T0, attempt, cfg


def ms(dt, skew_s=0.0):
    return (dt.timestamp() + skew_s) * 1000


def test_advance_startuje_zegar_nastepnego_chwila_odpowiedzi_nawet_bez_zasiegu():
    c = cfg(time_per_question_s=30)
    a, answers = attempt(c), {}
    X.serve_question(c, a, answers, T0)
    now = T0 + timedelta(seconds=300)
    items = [
        {"qid": "q1", "selected": ["a"], "client_ts_ms": ms(T0 + timedelta(seconds=10)), "advance": True, "time_ms": 9800},
        {"qid": "q2", "selected": ["b", "c"], "client_ts_ms": ms(T0 + timedelta(seconds=25)), "time_ms": 15000},
    ]
    res = X.apply_answers(c, a, answers, items, BANK, now, ms(now), buffered=True)
    assert [r["status"] for r in res] == ["accepted", "accepted"]
    assert answers["q2"]["shown_at"] == T0 + timedelta(seconds=10)
    assert answers["q2"]["elapsed_ms"] == 15000
    assert answers["q1"]["client_time_ms"] == 9800 and answers["q2"]["client_time_ms"] == 15000


def test_bez_advance_drugie_pytanie_z_bufora_nie_jest_wydane():
    c = cfg(time_per_question_s=30)
    a, answers = attempt(c), {}
    X.serve_question(c, a, answers, T0)
    now = T0 + timedelta(seconds=300)
    items = [
        {"qid": "q1", "selected": ["a"], "client_ts_ms": ms(T0 + timedelta(seconds=10))},
        {"qid": "q2", "selected": ["b"], "client_ts_ms": ms(T0 + timedelta(seconds=25))},
    ]
    res = X.apply_answers(c, a, answers, items, BANK, now, ms(now), buffered=True)
    assert res[1]["code"] == "EXAM_NOT_SERVED"


def test_lookahead_po_czasie_poprzedniego_liczy_od_zamkniecia_z_limitem_przesuniecia():
    c = cfg(time_per_question_s=30)
    a, answers = attempt(c), {}
    X.serve_question(c, a, answers, T0)
    now = T0 + timedelta(seconds=200)
    # q1 przepadło (30 s), telefon pokazał q2 po tolerancji (33 s), odpowiedź w 50. sekundzie
    item = {"qid": "q2", "selected": ["b", "c"], "client_ts_ms": ms(T0 + timedelta(seconds=50)),
            "shown_ts_ms": ms(T0 + timedelta(seconds=33)), "lookahead": True}
    res = X.apply_answers(c, a, answers, [item], BANK, now, ms(now), buffered=True)
    assert res[0]["status"] == "accepted" and "lookahead" in res[0]["flags"]
    assert answers["q1"]["timed_out"]
    assert answers["q2"]["shown_at"] == T0 + timedelta(seconds=33)


def test_lookahead_nie_pozwala_odsunac_startu_zegara_dowolnie():
    c = cfg(time_per_question_s=30)
    a, answers = attempt(c), {}
    X.serve_question(c, a, answers, T0)
    now = T0 + timedelta(seconds=200)
    item = {"qid": "q2", "selected": ["b"], "client_ts_ms": ms(T0 + timedelta(seconds=70)),
            "shown_ts_ms": ms(T0 + timedelta(seconds=60)), "lookahead": True}
    res = X.apply_answers(c, a, answers, [item], BANK, now, ms(now), buffered=True)
    # start najpóźniej 30 + 5 s; odpowiedź w 70. s to 35 s po starcie = po limicie i tolerancji
    assert answers["q2"]["shown_at"] == T0 + timedelta(seconds=30 + X.LOOKAHEAD_SLACK_S)
    assert res[0]["code"] == "EXAM_QUESTION_TIME_UP"


def test_ponowna_paczka_jest_duplikatem_nie_druga_odpowiedzia():
    c = cfg(time_per_question_s=30)
    a, answers = attempt(c), {}
    X.serve_question(c, a, answers, T0)
    item = {"qid": "q1", "selected": ["a"], "client_ts_ms": ms(T0 + timedelta(seconds=10)), "advance": True}
    now = T0 + timedelta(seconds=12)
    first = X.apply_answers(c, a, answers, [item], BANK, now, ms(now), buffered=True)
    again = X.apply_answers(c, a, answers, [item], BANK, now + timedelta(seconds=2), ms(now + timedelta(seconds=2)), buffered=True)
    assert first[0]["status"] == "accepted" and again[0]["status"] == "duplicate"
    assert answers["q1"]["changes"] == 0 and a["current_index"] == 1


def test_czas_telefonu_poza_zakresem_jest_pomijany():
    assert X._client_time_ms("abc") is None
    assert X._client_time_ms(-5) is None
    assert X._client_time_ms(1234.7) == 1234
