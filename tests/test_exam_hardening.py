"""Egzamin - poprawki po krytyce: bufor offline, stemple, zdarzenia, idempotencja, blokady, uprawnienia, eksport."""

from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app import exam_report_rules as R
from app import exam_rules as X
from app import exam_service as S
from test_exam_service import (  # noqa: F401 - fixture `st` i pomocnicze
    ADMIN, CLOSE, COMMISSION, CORRECT, OPEN, PLAIN, TEACH, body, make, st,
)

def ms(moment):
    return moment.timestamp() * 1000


async def test_bufor_po_zabiciu_aplikacji_i_terminie_calosci_jest_przyjety(st):
    exam, _ = await make(st, time_total_min=10, result_release="immediate")
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    aid, q = state["attempt"]["id"], state["question"]
    # aplikacja zabita, telefon wraca po terminie: serwer zamyka podejście przy pierwszym odczycie
    back = t + timedelta(minutes=11)
    closed = await S.attempt_state(st, PLAIN, aid, None, None, back)
    assert closed["attempt"]["status"] == "expired"
    item = {"qid": q["qid"], "selected": [CORRECT[q["qid"]]], "client_ts_ms": ms(t + timedelta(seconds=20))}
    # bez deklaracji bufora nadal EXAM_FINISHED
    plain = await S.post_answers(st, PLAIN, aid, {"client_now_ms": ms(back), "answers": [item]}, back)
    assert plain["results"][0]["code"] == "EXAM_FINISHED"
    out = await S.post_answers(st, PLAIN, aid, {"client_now_ms": ms(back), "buffered": True, "answers": [item]}, back)
    res = out["results"][0]
    assert res["status"] == "accepted" and "buffered_late" in res["flags"]
    assert out["state"]["attempt"]["status"] == "expired"
    result = await S.attempt_result(st, PLAIN, aid, back)
    assert result["result"]["visible"] and result["result"]["points"] > 0


async def test_bufor_stempel_po_terminie_albo_po_oknie_przyjmowania_odpada(st):
    exam, _ = await make(st, time_total_min=10)
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    aid, q = state["attempt"]["id"], state["question"]
    back = t + timedelta(minutes=12)
    await S.attempt_state(st, PLAIN, aid, None, None, back)
    after = {"qid": q["qid"], "selected": ["a"], "client_ts_ms": ms(t + timedelta(minutes=11))}
    out = await S.post_answers(st, PLAIN, aid, {"client_now_ms": ms(back), "buffered": True, "answers": [after]}, back)
    assert out["results"][0]["code"] == "EXAM_TIME_UP"
    on_time = {"qid": q["qid"], "selected": ["a"], "client_ts_ms": ms(t + timedelta(seconds=30))}
    far = CLOSE + timedelta(hours=7)
    late = await S.post_answers(st, PLAIN, aid, {"client_now_ms": ms(far), "buffered": True, "answers": [on_time]}, far)
    assert late["results"][0]["code"] == "EXAM_FINISHED"


async def test_bufor_przy_wznowieniu_przyjmuje_odpowiedz_przed_zamknieciem_pytania(st):
    exam, _ = await make(st, time_per_question_s=30)
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    q = state["question"]
    back = t + timedelta(seconds=200)
    item = {"qid": q["qid"], "selected": [CORRECT[q["qid"]]], "client_ts_ms": ms(t + timedelta(seconds=10))}
    resumed = await S.start_attempt(st, PLAIN, exam["id"], {"buffered": [item], "client_now_ms": ms(back)}, now=back)
    got = resumed["buffered_results"][0]
    assert got["status"] == "accepted" and "buffered" in got["flags"] and "buffered_over_limit" in got["flags"]
    assert resumed["resumed"] is True and resumed["attempt"]["current_index"] == 1


async def test_bufor_przez_post_answers_po_odczycie_stanu_ozywia_pytanie_zamkniete_zegarem_serwera(st):
    exam, _ = await make(st, time_per_question_s=30)
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    aid, q = state["attempt"]["id"], state["question"]
    back = t + timedelta(seconds=200)
    await S.attempt_state(st, PLAIN, aid, None, None, back)  # settle: pierwsze pytanie przepadło
    item = {"qid": q["qid"], "selected": [CORRECT[q["qid"]]], "client_ts_ms": ms(t + timedelta(seconds=10))}
    out = await S.post_answers(st, PLAIN, aid, {"client_now_ms": ms(back), "buffered": True, "answers": [item]}, back)
    assert out["results"][0]["status"] == "accepted" and "buffered_revived" in out["results"][0]["flags"]


async def test_stempel_bez_deklaracji_bufora_nie_omija_limitu_pytania(st):
    exam, _ = await make(st, time_per_question_s=30)
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    aid, q = state["attempt"]["id"], state["question"]
    now = t + timedelta(seconds=100)
    item = {"qid": q["qid"], "selected": [CORRECT[q["qid"]]], "client_ts_ms": ms(t + timedelta(seconds=10))}
    out = await S.post_answers(st, PLAIN, aid, {"client_now_ms": ms(now), "answers": [item]}, now)
    res = out["results"][0]
    assert res["code"] == "EXAM_QUESTION_TIME_UP" and "stamp_ignored" in res["flags"]
    card = await S.attempt_card(st, COMMISSION, exam["id"], aid)
    assert any(e["detail"].get("flag") == "stamp_ignored" for e in card["events"])


async def test_bufor_starszy_niz_limit_pytania_dostaje_flage_dla_komisji_bez_dyskwalifikacji(st):
    exam, _ = await make(st, time_per_question_s=30)
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    aid, q = state["attempt"]["id"], state["question"]
    now = t + timedelta(seconds=100)
    item = {"qid": q["qid"], "selected": [CORRECT[q["qid"]]], "client_ts_ms": ms(t + timedelta(seconds=10))}
    out = await S.post_answers(st, PLAIN, aid, {"client_now_ms": ms(now), "buffered": True, "answers": [item]}, now)
    res = out["results"][0]
    assert res["status"] == "accepted" and "buffered_over_limit" in res["flags"]
    card = await S.attempt_card(st, COMMISSION, exam["id"], aid)
    assert any(e["detail"].get("flag") == "buffered_over_limit" for e in card["events"])
    assert out["state"]["attempt"]["status"] == "in_progress"


async def test_zdarzenie_niebedace_slownikiem_to_400_nie_500(st):
    exam, _ = await make(st)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=OPEN + timedelta(minutes=5))
    with pytest.raises(X.ExamError) as err:
        await S.post_events(st, PLAIN, state["attempt"]["id"], {"events": ["app_background", 5]}, OPEN + timedelta(minutes=6))
    assert err.value.status == 400 and err.value.code == "EXAM_BAD_EVENT"


async def test_limit_zdarzen_nie_wylacza_polityki_wyjscia(st, monkeypatch):
    exam, _ = await make(st, anti={"leave_app": "end"})
    t = OPEN + timedelta(minutes=5)
    state = await S.start_attempt(st, PLAIN, exam["id"], {}, now=t)
    aid = state["attempt"]["id"]
    monkeypatch.setattr(S, "MAX_EVENTS_PER_ATTEMPT", 1)
    shot = {"kind": "resume", "detail": {}}
    first = await S.post_events(st, PLAIN, aid, {"events": [shot]}, t + timedelta(seconds=5))
    assert first["recorded"] == 1
    other = await S.post_events(st, PLAIN, aid, {"events": [shot]}, t + timedelta(seconds=6))
    assert other["recorded"] == 0 and other["ignored"]
    out = await S.post_events(st, PLAIN, aid, {"events": [{"kind": "app_background", "detail": {"seconds": 40}}]}, t + timedelta(seconds=10))
    assert out["policy"] is not None
    assert out["state"]["attempt"]["status"] != "in_progress"


async def test_tworzenie_egzaminu_jest_idempotentne_po_client_key(st):
    payload = {**body(), "client_key": "szkic-1"}
    first, published = await S.create_exam(st, COMMISSION, payload, now=OPEN - timedelta(days=1))
    assert published and not first.get("existing")
    events_before = await st.database.fetch_val(select(func.count()).select_from(st.t.province_events))
    again, published2 = await S.create_exam(st, COMMISSION, payload, now=OPEN - timedelta(days=1))
    assert again["id"] == first["id"] and again["existing"] is True and published2 == []
    assert await st.database.fetch_val(select(func.count()).select_from(st.t.definitions)) == 1
    assert await st.database.fetch_val(select(func.count()).select_from(st.t.province_events)) == events_before
    other = await S.create_exam(st, ADMIN, payload, now=OPEN - timedelta(days=1))
    assert other[0]["id"] != first["id"]
    no_key = await S.create_exam(st, COMMISSION, body(), now=OPEN - timedelta(days=1))
    assert no_key[0]["id"] != first["id"]


async def test_po_starcie_result_release_i_anti_sa_zablokowane(st):
    exam, _ = await make(st, result_release="after_close")
    await S.start_attempt(st, PLAIN, exam["id"], {}, now=OPEN + timedelta(minutes=5))
    for patch, fragment in (({"result_release": "immediate"}, "result_release"), ({"anti": {"leave_app": "end"}}, "anti")):
        with pytest.raises(X.ExamError) as err:
            await S.update_exam(st, COMMISSION, exam["id"], {"config": patch}, now=OPEN + timedelta(minutes=10))
        assert err.value.code == "EXAM_LOCKED" and fragment in err.value.message and fragment in err.value.extra["locked"]


async def test_szablony_i_pula_tylko_dla_zarzadzajacych(st):
    for allowed in (ADMIN, COMMISSION, TEACH):
        await S.require_any_manage(allowed)
    with pytest.raises(X.ExamError) as err:
        await S.require_any_manage(PLAIN)
    assert err.value.status == 403 and err.value.code == "EXAM_FORBIDDEN" and err.value.message


def test_eksport_z_kartami_domyslnie_anonimowy():
    assert R.clean_export_options({"sections": ["summary", "cards"]}, national=False)["anonymize"] is True
    assert R.clean_export_options({}, national=False)["anonymize"] is False
    assert R.clean_export_options({"sections": ["cards"], "anonymize": False}, national=False)["anonymize"] is False
    assert R.clean_export_options({"sections": ["summary"], "anonymize": True}, national=False)["anonymize"] is True
